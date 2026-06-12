//! Role: append-only decision/audit store for fusion outcomes. Two backends
//! behind one type (an enum, not a trait — native async-fn-in-trait is not
//! dyn-safe and two variants do not justify generics through the pipeline):
//! in-memory (tests, default PoC) and JSONL (one serialized `DecisionRecord`
//! per line, flushed per record — it is an audit log; a crash must not lose
//! an issued ban). Records carry a store-assigned monotonic sequence number so
//! audit-log gaps are detectable, plus the full inputs of the decision —
//! inculpatory AND exculpatory (skipped events, pairing misses, shed counts)
//! — and the exact parameter values used, not just a version (versions rot in
//! disputes).
//!
//! Target platforms: server.
//!
//! Guardrails: #8 — fully async (tokio fs), `thiserror` via `BanEngineError`,
//! no `unwrap()` outside tests. Data category: persisted ban-decision records
//! are declared in `server/api/data-categories.md` (guardrail #11).

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::arrival_cadence::CadenceObservation;
use crate::error::BanEngineError;
use crate::fusion::{Contribution, FusionParams, SkippedEvent, Verdict};

/// Why this record was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RecordKind {
    /// The session's latched verdict transitioned upward (Clean->Review->Ban).
    Transition,
    /// The session was evicted/ended while carrying live suspicion state.
    SessionSummary,
}

/// One audit record. Everything needed to defend (or overturn) the decision
/// without replaying the session.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DecisionRecord {
    /// Store-assigned monotonic sequence number (gap = tampered/lost log).
    pub seq: u64,
    pub kind: RecordKind,
    /// Wall-clock ns since UNIX epoch at decision time.
    pub decided_at_ns: u64,
    pub player_id: u64,
    /// Wall-clock ns the session started (disambiguates sessions across
    /// evictions — `player_id` alone is not a session key).
    pub session_start_ns: u64,
    pub prev_verdict: Verdict,
    pub verdict: Verdict,
    pub score: u32,
    pub contributions: Vec<Contribution>,
    pub skipped: Vec<SkippedEvent>,
    pub cadence: Option<CadenceObservation>,
    /// The exact fusion parameters used for THIS decision.
    pub params: FusionParams,
    /// Tick window the evidence spans.
    pub window_first_tick: u64,
    pub window_last_tick: u64,
    /// Evidence quality: how much telemetry arrived and how much of it could
    /// be paired with authoritative snapshots. A verdict issued under heavy
    /// pairing loss says so on its face.
    pub ticks_received: u64,
    pub ticks_paired: u64,
    pub pairing_misses: u64,
    /// True when the verdict was raised by the pairing-integrity anomaly
    /// (sustained zero pairing), not by analyzer evidence.
    pub pairing_anomaly: bool,
    /// Payload schema versions seen this session.
    pub schema_versions_seen: Vec<u32>,
}

#[derive(Debug)]
enum Inner {
    Memory(Mutex<Vec<DecisionRecord>>),
    Jsonl(Mutex<tokio::fs::File>),
}

/// Append-only decision store. Shared across pipeline shards via `Arc`.
#[derive(Debug)]
pub struct DecisionStore {
    seq: AtomicU64,
    inner: Inner,
}

impl DecisionStore {
    /// In-memory store (tests, default PoC run without `HORKOS_DECISION_LOG`).
    pub fn memory() -> Self {
        DecisionStore {
            seq: AtomicU64::new(0),
            inner: Inner::Memory(Mutex::new(Vec::new())),
        }
    }

    /// JSONL store appending to `path`. Opens synchronously (startup-time
    /// call, before the runtime is under load) and hands the handle to tokio.
    pub fn jsonl(path: &Path) -> Result<Self, BanEngineError> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(DecisionStore {
            seq: AtomicU64::new(0),
            inner: Inner::Jsonl(Mutex::new(tokio::fs::File::from_std(file))),
        })
    }

    /// Append one record, assigning its sequence number. Returns the seq.
    pub async fn append(&self, mut rec: DecisionRecord) -> Result<u64, BanEngineError> {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        rec.seq = seq;
        match &self.inner {
            Inner::Memory(v) => {
                v.lock().await.push(rec);
            }
            Inner::Jsonl(f) => {
                let mut line = serde_json::to_vec(&rec)?;
                line.push(b'\n');
                let mut f = f.lock().await;
                f.write_all(&line).await?;
                f.flush().await?;
            }
        }
        Ok(seq)
    }

    /// Snapshot of all records (memory backend only; JSONL returns empty —
    /// the file is the source of truth there).
    pub async fn records(&self) -> Vec<DecisionRecord> {
        match &self.inner {
            Inner::Memory(v) => v.lock().await.clone(),
            Inner::Jsonl(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fusion::Verdict;

    fn rec(player_id: u64) -> DecisionRecord {
        DecisionRecord {
            seq: 0,
            kind: RecordKind::Transition,
            decided_at_ns: 1,
            player_id,
            session_start_ns: 0,
            prev_verdict: Verdict::Clean,
            verdict: Verdict::Review,
            score: 40,
            contributions: Vec::new(),
            skipped: Vec::new(),
            cadence: None,
            params: FusionParams::default(),
            window_first_tick: 0,
            window_last_tick: 100,
            ticks_received: 100,
            ticks_paired: 100,
            pairing_misses: 0,
            pairing_anomaly: false,
            schema_versions_seen: vec![6],
        }
    }

    #[tokio::test]
    async fn memory_store_assigns_monotonic_seq() {
        let s = DecisionStore::memory();
        assert_eq!(s.append(rec(1)).await.expect("append"), 0);
        assert_eq!(s.append(rec(2)).await.expect("append"), 1);
        let records = s.records().await;
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].seq, 0);
        assert_eq!(records[1].seq, 1);
    }

    #[tokio::test]
    async fn jsonl_store_writes_one_line_per_record() {
        let dir = std::env::temp_dir().join("horkos_store_test");
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let path = dir.join(format!("decisions-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let s = DecisionStore::jsonl(&path).expect("open");
        s.append(rec(1)).await.expect("append");
        s.append(rec(2)).await.expect("append");

        let content = std::fs::read_to_string(&path).expect("read back");
        let lines: Vec<_> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        let parsed: serde_json::Value = serde_json::from_str(lines[1]).expect("valid json");
        assert_eq!(parsed["seq"], 1);
        assert_eq!(parsed["player_id"], 2);
        std::fs::remove_file(&path).ok();
    }
}
