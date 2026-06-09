//! src/macos_inject.rs
//!
//! Role: Server-side serde/`#[repr(C)]` mirror + scoring for the macOS
//! process-inspection / injection payloads (`hk_es_*`, catalog signals
//! 109-117). Decodes the macOS daemon-sink byte records into mirrors of the C99
//! wire structs in `sdk/include/horkos/event_schema_macos.h`, then applies the
//! catalog false-positive gates (platform-binary exclusion, signed-allowlist,
//! debugger-session suppression, GET_TASK_NAME suppression, PROC_CHECK rate
//! threshold, ptrace release-channel gate) and produces a per-event score
//! contribution. This module extracts/scores only — it never bans (that
//! authority is the ban-engine's, server-side).
//!
//! Target platforms: server.
//!
//! Guardrail #8: pure/sync decoders run inline on the async path (CPU-bound,
//! short); `thiserror` error type; NO `unwrap()`/`expect()` outside `#[cfg(test)]`.
//! A malformed/short record yields a typed `MacInjectError`, never a panic.
//!
//! HK-TODO(schema): the event-type discriminants (`HK_EVENT_ES_*` = 5..12) live
//! in `event_schema_macos.h` (a macOS-only header, NOT the frozen shared
//! `event_schema.h`). They are mirrored here as local consts in lockstep.

use thiserror::Error;

// Event-type discriminants — mirror of event_schema_macos.h HK_EVENT_ES_*.
pub const HK_EVENT_ES_GET_TASK: u32 = 5;
pub const HK_EVENT_ES_MMAP: u32 = 6;
pub const HK_EVENT_ES_DYLD_INJECT: u32 = 7;
pub const HK_EVENT_ES_PROC_CHECK: u32 = 8;
pub const HK_EVENT_ES_EXC_PORT: u32 = 9;
pub const HK_EVENT_ES_THREAD_ORIGIN: u32 = 10;
pub const HK_EVENT_ES_PTRACE: u32 = 11;
pub const HK_EVENT_ES_TEXT_WX: u32 = 12;

// GET_TASK flavor — mirror of HK_GET_TASK_*.
pub const HK_GET_TASK_CONTROL: u32 = 0;
pub const HK_GET_TASK_READ: u32 = 1;
pub const HK_GET_TASK_NAME: u32 = 2;

// Source-process classification flags — mirror of HK_ESPROC_*.
pub const HK_ESPROC_PLATFORM_BINARY: u32 = 0x0000_0001;
pub const HK_ESPROC_ALLOWLISTED: u32 = 0x0000_0002;
pub const HK_ESPROC_DEBUGGER: u32 = 0x0000_0004;

// MMAP baseline classification — mirror of HK_MMAP_BASELINE_*.
pub const HK_MMAP_BASELINE_KNOWN: u32 = 0;
pub const HK_MMAP_BASELINE_UNKNOWN: u32 = 1;
pub const HK_MMAP_BASELINE_ANON_RWX: u32 = 2;

// Thread-origin region kind — mirror of HK_REGION_*.
pub const HK_REGION_IMAGE: u32 = 0;
pub const HK_REGION_ANON: u32 = 1;
pub const HK_REGION_JIT_SANCTIONED: u32 = 2;

/// PROC_CHECK recon rate threshold: a source must exceed this aggregated count
/// within a sampling window before signal 115 scores. Below it, benign polling
/// (a single `PIDTASKINFO`) is suppressed. Unvalidated under real load (plan
/// uncertainty #3) — tuned server-side, not client-side.
pub const PROC_CHECK_RATE_THRESHOLD: u32 = 8;

/// Decode errors. A short or otherwise malformed record surfaces as one of
/// these — never a panic (guardrail #8).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MacInjectError {
    #[error("record too short: need {need} bytes for {what}, got {got}")]
    Short {
        what: &'static str,
        need: usize,
        got: usize,
    },

    #[error("unknown macOS injection event type {0}")]
    UnknownType(u32),
}

// ---------------------------------------------------------------------------
// Little-endian fixed-width readers. The macOS daemon emits native-endian on a
// little-endian host (arm64-LE / x86_64); each reader bounds-checks.
// ---------------------------------------------------------------------------

fn read_u32(buf: &[u8], off: usize, what: &'static str) -> Result<u32, MacInjectError> {
    let end = off + 4;
    if buf.len() < end {
        return Err(MacInjectError::Short {
            what,
            need: end,
            got: buf.len(),
        });
    }
    let mut a = [0u8; 4];
    a.copy_from_slice(&buf[off..end]);
    Ok(u32::from_le_bytes(a))
}

fn read_u64(buf: &[u8], off: usize, what: &'static str) -> Result<u64, MacInjectError> {
    let end = off + 8;
    if buf.len() < end {
        return Err(MacInjectError::Short {
            what,
            need: end,
            got: buf.len(),
        });
    }
    let mut a = [0u8; 8];
    a.copy_from_slice(&buf[off..end]);
    Ok(u64::from_le_bytes(a))
}

fn read_bytes<const N: usize>(
    buf: &[u8],
    off: usize,
    what: &'static str,
) -> Result<[u8; N], MacInjectError> {
    let end = off + N;
    if buf.len() < end {
        return Err(MacInjectError::Short {
            what,
            need: end,
            got: buf.len(),
        });
    }
    let mut a = [0u8; N];
    a.copy_from_slice(&buf[off..end]);
    Ok(a)
}

// ---------------------------------------------------------------------------
// `#[repr(C)]` mirrors. Field names and sizes track event_schema_macos.h
// exactly; sizes are pinned at compile time mirroring the C HK_STATIC_ASSERTs.
// ---------------------------------------------------------------------------

/// Mirror of `hk_es_get_task` (64 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetTask {
    pub source_pid: u32,
    pub target_pid: u32,
    pub flavor: u32,
    pub source_flags: u32,
    pub source_team_id: [u8; 16],
    pub source_signing_id: [u8; 32],
}

/// Mirror of `hk_es_mmap` (56 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mmap {
    pub target_pid: u32,
    pub source_pid: u32,
    pub protection: u32,
    pub flags: u32,
    pub baseline_match: u32,
    pub reserved: u32,
    pub source_path_sha256: [u8; 32],
}

/// Mirror of `hk_es_dyld_inject` (48 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DyldInject {
    pub pid: u32,
    pub cs_flags: u32,
    pub dyld_var_present: u32,
    pub injected_load_seen: u32,
    pub inserted_path_sha256: [u8; 32],
}

/// Mirror of `hk_es_proc_check` (24 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcCheck {
    pub source_pid: u32,
    pub target_pid: u32,
    pub flavor: u32,
    pub rate_per_window: u32,
    pub flavor_cardinality: u32,
    pub source_flags: u32,
}

/// Mirror of `hk_es_exc_port` (16 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExcPort {
    pub game_pid: u32,
    pub owner_pid: u32,
    pub mask: u32,
    pub is_foreign: u32,
}

/// Mirror of `hk_es_thread_origin` (24 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadOrigin {
    pub game_pid: u32,
    pub thread_id: u32,
    pub entry_pc: u64,
    pub region_kind: u32,
    pub reserved: u32,
}

/// Mirror of `hk_es_ptrace` (16 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ptrace {
    pub game_pid: u32,
    pub tracer_pid: u32,
    pub traced_now: u32,
    pub cs_release_signed: u32,
}

/// Mirror of `hk_es_text_wx` (24 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextWx {
    pub game_pid: u32,
    pub protection: u32,
    pub share_mode: u32,
    pub csops_valid: u32,
    pub region_addr: u64,
}

// Compile-time size pins mirroring the C HK_STATIC_ASSERTs.
const _: () = assert!(core::mem::size_of::<GetTask>() == 64);
const _: () = assert!(core::mem::size_of::<Mmap>() == 56);
const _: () = assert!(core::mem::size_of::<DyldInject>() == 48);
const _: () = assert!(core::mem::size_of::<ProcCheck>() == 24);
const _: () = assert!(core::mem::size_of::<ExcPort>() == 16);
const _: () = assert!(core::mem::size_of::<ThreadOrigin>() == 24);
const _: () = assert!(core::mem::size_of::<Ptrace>() == 16);
const _: () = assert!(core::mem::size_of::<TextWx>() == 24);

impl GetTask {
    pub fn decode(buf: &[u8]) -> Result<Self, MacInjectError> {
        Ok(Self {
            source_pid: read_u32(buf, 0, "get_task.source_pid")?,
            target_pid: read_u32(buf, 4, "get_task.target_pid")?,
            flavor: read_u32(buf, 8, "get_task.flavor")?,
            source_flags: read_u32(buf, 12, "get_task.source_flags")?,
            source_team_id: read_bytes::<16>(buf, 16, "get_task.source_team_id")?,
            source_signing_id: read_bytes::<32>(buf, 32, "get_task.source_signing_id")?,
        })
    }
}

impl Mmap {
    pub fn decode(buf: &[u8]) -> Result<Self, MacInjectError> {
        Ok(Self {
            target_pid: read_u32(buf, 0, "mmap.target_pid")?,
            source_pid: read_u32(buf, 4, "mmap.source_pid")?,
            protection: read_u32(buf, 8, "mmap.protection")?,
            flags: read_u32(buf, 12, "mmap.flags")?,
            baseline_match: read_u32(buf, 16, "mmap.baseline_match")?,
            reserved: read_u32(buf, 20, "mmap.reserved")?,
            source_path_sha256: read_bytes::<32>(buf, 24, "mmap.source_path_sha256")?,
        })
    }
}

impl DyldInject {
    pub fn decode(buf: &[u8]) -> Result<Self, MacInjectError> {
        Ok(Self {
            pid: read_u32(buf, 0, "dyld_inject.pid")?,
            cs_flags: read_u32(buf, 4, "dyld_inject.cs_flags")?,
            dyld_var_present: read_u32(buf, 8, "dyld_inject.dyld_var_present")?,
            injected_load_seen: read_u32(buf, 12, "dyld_inject.injected_load_seen")?,
            inserted_path_sha256: read_bytes::<32>(buf, 16, "dyld_inject.inserted_path_sha256")?,
        })
    }
}

impl ProcCheck {
    pub fn decode(buf: &[u8]) -> Result<Self, MacInjectError> {
        Ok(Self {
            source_pid: read_u32(buf, 0, "proc_check.source_pid")?,
            target_pid: read_u32(buf, 4, "proc_check.target_pid")?,
            flavor: read_u32(buf, 8, "proc_check.flavor")?,
            rate_per_window: read_u32(buf, 12, "proc_check.rate_per_window")?,
            flavor_cardinality: read_u32(buf, 16, "proc_check.flavor_cardinality")?,
            source_flags: read_u32(buf, 20, "proc_check.source_flags")?,
        })
    }
}

impl ExcPort {
    pub fn decode(buf: &[u8]) -> Result<Self, MacInjectError> {
        Ok(Self {
            game_pid: read_u32(buf, 0, "exc_port.game_pid")?,
            owner_pid: read_u32(buf, 4, "exc_port.owner_pid")?,
            mask: read_u32(buf, 8, "exc_port.mask")?,
            is_foreign: read_u32(buf, 12, "exc_port.is_foreign")?,
        })
    }
}

impl ThreadOrigin {
    pub fn decode(buf: &[u8]) -> Result<Self, MacInjectError> {
        Ok(Self {
            game_pid: read_u32(buf, 0, "thread_origin.game_pid")?,
            thread_id: read_u32(buf, 4, "thread_origin.thread_id")?,
            entry_pc: read_u64(buf, 8, "thread_origin.entry_pc")?,
            region_kind: read_u32(buf, 16, "thread_origin.region_kind")?,
            reserved: read_u32(buf, 20, "thread_origin.reserved")?,
        })
    }
}

impl Ptrace {
    pub fn decode(buf: &[u8]) -> Result<Self, MacInjectError> {
        Ok(Self {
            game_pid: read_u32(buf, 0, "ptrace.game_pid")?,
            tracer_pid: read_u32(buf, 4, "ptrace.tracer_pid")?,
            traced_now: read_u32(buf, 8, "ptrace.traced_now")?,
            cs_release_signed: read_u32(buf, 12, "ptrace.cs_release_signed")?,
        })
    }
}

impl TextWx {
    pub fn decode(buf: &[u8]) -> Result<Self, MacInjectError> {
        Ok(Self {
            game_pid: read_u32(buf, 0, "text_wx.game_pid")?,
            protection: read_u32(buf, 4, "text_wx.protection")?,
            share_mode: read_u32(buf, 8, "text_wx.share_mode")?,
            csops_valid: read_u32(buf, 12, "text_wx.csops_valid")?,
            region_addr: read_u64(buf, 16, "text_wx.region_addr")?,
        })
    }
}

/// A decoded macOS injection payload, tagged by wire type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacInjectEvent {
    GetTask(GetTask),
    Mmap(Mmap),
    DyldInject(DyldInject),
    ProcCheck(ProcCheck),
    ExcPort(ExcPort),
    ThreadOrigin(ThreadOrigin),
    Ptrace(Ptrace),
    TextWx(TextWx),
}

/// Decode one payload buffer given its wire event type.
pub fn decode_event(event_type: u32, payload: &[u8]) -> Result<MacInjectEvent, MacInjectError> {
    match event_type {
        HK_EVENT_ES_GET_TASK => Ok(MacInjectEvent::GetTask(GetTask::decode(payload)?)),
        HK_EVENT_ES_MMAP => Ok(MacInjectEvent::Mmap(Mmap::decode(payload)?)),
        HK_EVENT_ES_DYLD_INJECT => Ok(MacInjectEvent::DyldInject(DyldInject::decode(payload)?)),
        HK_EVENT_ES_PROC_CHECK => Ok(MacInjectEvent::ProcCheck(ProcCheck::decode(payload)?)),
        HK_EVENT_ES_EXC_PORT => Ok(MacInjectEvent::ExcPort(ExcPort::decode(payload)?)),
        HK_EVENT_ES_THREAD_ORIGIN => {
            Ok(MacInjectEvent::ThreadOrigin(ThreadOrigin::decode(payload)?))
        }
        HK_EVENT_ES_PTRACE => Ok(MacInjectEvent::Ptrace(Ptrace::decode(payload)?)),
        HK_EVENT_ES_TEXT_WX => Ok(MacInjectEvent::TextWx(TextWx::decode(payload)?)),
        other => Err(MacInjectError::UnknownType(other)),
    }
}

// ---------------------------------------------------------------------------
// Scoring / FP gates. Each event maps to a confidence contribution after the
// catalog gates. A SUPPRESSED event scores 0.0; the client emitted it raw and
// the server is the sole gate (plan risk #7). No banning here.
// ---------------------------------------------------------------------------

/// Outcome of scoring one event: a 0.0..=1.0 contribution plus whether a gate
/// suppressed it (for observability / test assertions).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Score {
    pub confidence: f32,
    pub suppressed: bool,
}

impl Score {
    const SUPPRESSED: Score = Score {
        confidence: 0.0,
        suppressed: true,
    };
    fn flag(confidence: f32) -> Score {
        Score {
            confidence,
            suppressed: false,
        }
    }
}

impl GetTask {
    /// Signal 109/110. NAME flavor is never flagged (110). A platform-binary or
    /// allowlisted source is suppressed; a debugger-session source is suppressed.
    /// CONTROL is higher-confidence than READ.
    pub fn score(&self) -> Score {
        if self.flavor == HK_GET_TASK_NAME {
            return Score::SUPPRESSED;
        }
        if self.source_flags
            & (HK_ESPROC_PLATFORM_BINARY | HK_ESPROC_ALLOWLISTED | HK_ESPROC_DEBUGGER)
            != 0
        {
            return Score::SUPPRESSED;
        }
        match self.flavor {
            HK_GET_TASK_CONTROL => Score::flag(0.9),
            HK_GET_TASK_READ => Score::flag(0.6),
            _ => Score::SUPPRESSED,
        }
    }
}

impl Mmap {
    /// Signal 111. KNOWN baseline (signed dylib / sanctioned JIT) is suppressed;
    /// ANON_RWX is the highest-confidence; UNKNOWN is mid pending the manifest.
    pub fn score(&self) -> Score {
        match self.baseline_match {
            HK_MMAP_BASELINE_KNOWN => Score::SUPPRESSED,
            HK_MMAP_BASELINE_ANON_RWX => Score::flag(0.85),
            HK_MMAP_BASELINE_UNKNOWN => Score::flag(0.5),
            _ => Score::SUPPRESSED,
        }
    }
}

impl ProcCheck {
    /// Signal 115. Below the rate threshold = benign polling, suppressed. A
    /// platform-binary/allowlisted source is suppressed. Confidence scales with
    /// distinct-flavor cardinality (broad recon is more suspicious).
    pub fn score(&self) -> Score {
        if self.source_flags & (HK_ESPROC_PLATFORM_BINARY | HK_ESPROC_ALLOWLISTED) != 0 {
            return Score::SUPPRESSED;
        }
        if self.rate_per_window <= PROC_CHECK_RATE_THRESHOLD {
            return Score::SUPPRESSED;
        }
        let card_bonus = (self.flavor_cardinality.min(4) as f32) * 0.05;
        Score::flag((0.55 + card_bonus).min(0.9))
    }
}

impl Ptrace {
    /// Signal 116. Only score the release-signed channel (a dev / get-task-allow
    /// build is suppressed). Only the traced edge (traced_now=1) scores.
    pub fn score(&self) -> Score {
        if self.cs_release_signed == 0 || self.traced_now == 0 {
            return Score::SUPPRESSED;
        }
        Score::flag(0.8)
    }
}

impl ExcPort {
    /// Signal 113. Only a foreign owner scores; the server may still clear this
    /// after correlating owner_pid with the game / Apple diagnostics.
    pub fn score(&self) -> Score {
        if self.is_foreign == 0 {
            return Score::SUPPRESSED;
        }
        Score::flag(0.7)
    }
}

impl ThreadOrigin {
    /// Signal 114. IMAGE and sanctioned-JIT entries are suppressed; an ANON
    /// entry is the high-signal case.
    pub fn score(&self) -> Score {
        match self.region_kind {
            HK_REGION_IMAGE | HK_REGION_JIT_SANCTIONED => Score::SUPPRESSED,
            HK_REGION_ANON => Score::flag(0.75),
            _ => Score::SUPPRESSED,
        }
    }
}

impl DyldInject {
    /// Signal 112. Highest confidence when an insert-libraries var SURVIVED on a
    /// hardened-runtime (CS_RUNTIME) binary AND a non-system load was confirmed.
    pub fn score(&self) -> Score {
        if self.dyld_var_present & HK_DYLD_VAR_INSERT_LIBRARIES == 0 {
            return Score::SUPPRESSED;
        }
        // CS_RUNTIME = 0x10000 (hardened runtime). Survival of the var past a
        // hardened-runtime strip is the signal.
        const CS_RUNTIME: u32 = 0x0001_0000;
        let hardened = self.cs_flags & CS_RUNTIME != 0;
        match (hardened, self.injected_load_seen != 0) {
            (true, true) => Score::flag(0.95),
            (true, false) => Score::flag(0.7),
            (false, true) => Score::flag(0.6),
            (false, false) => Score::flag(0.4),
        }
    }
}

// DYLD env-var bit mirror (event_schema_macos.h HK_DYLD_VAR_*).
pub const HK_DYLD_VAR_INSERT_LIBRARIES: u32 = 0x0000_0001;
pub const HK_DYLD_VAR_FRAMEWORK_PATH: u32 = 0x0000_0002;

impl TextWx {
    /// Signal 117. A writable or COW-broken page inside signed __TEXT scores; an
    /// invalidated signature (csops_valid=0) raises confidence.
    pub fn score(&self) -> Score {
        // VM_PROT_WRITE = 0x2; SM_COW = 1 (vm_region share_mode).
        const VM_PROT_WRITE: u32 = 0x2;
        const SM_COW: u32 = 1;
        let writable = self.protection & VM_PROT_WRITE != 0;
        let cow_broken = self.share_mode == SM_COW;
        if !writable && !cow_broken {
            return Score::SUPPRESSED;
        }
        if self.csops_valid == 0 {
            Score::flag(0.95)
        } else {
            Score::flag(0.7)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_get_task(g: &GetTask) -> Vec<u8> {
        let mut v = Vec::with_capacity(64);
        v.extend_from_slice(&g.source_pid.to_le_bytes());
        v.extend_from_slice(&g.target_pid.to_le_bytes());
        v.extend_from_slice(&g.flavor.to_le_bytes());
        v.extend_from_slice(&g.source_flags.to_le_bytes());
        v.extend_from_slice(&g.source_team_id);
        v.extend_from_slice(&g.source_signing_id);
        v
    }

    fn encode_proc_check(p: &ProcCheck) -> Vec<u8> {
        let mut v = Vec::with_capacity(24);
        v.extend_from_slice(&p.source_pid.to_le_bytes());
        v.extend_from_slice(&p.target_pid.to_le_bytes());
        v.extend_from_slice(&p.flavor.to_le_bytes());
        v.extend_from_slice(&p.rate_per_window.to_le_bytes());
        v.extend_from_slice(&p.flavor_cardinality.to_le_bytes());
        v.extend_from_slice(&p.source_flags.to_le_bytes());
        v
    }

    fn encode_ptrace(p: &Ptrace) -> Vec<u8> {
        let mut v = Vec::with_capacity(16);
        v.extend_from_slice(&p.game_pid.to_le_bytes());
        v.extend_from_slice(&p.tracer_pid.to_le_bytes());
        v.extend_from_slice(&p.traced_now.to_le_bytes());
        v.extend_from_slice(&p.cs_release_signed.to_le_bytes());
        v
    }

    fn encode_text_wx(t: &TextWx) -> Vec<u8> {
        let mut v = Vec::with_capacity(24);
        v.extend_from_slice(&t.game_pid.to_le_bytes());
        v.extend_from_slice(&t.protection.to_le_bytes());
        v.extend_from_slice(&t.share_mode.to_le_bytes());
        v.extend_from_slice(&t.csops_valid.to_le_bytes());
        v.extend_from_slice(&t.region_addr.to_le_bytes());
        v
    }

    #[test]
    fn get_task_round_trip() {
        let g = GetTask {
            source_pid: 0x1111,
            target_pid: 0x2222,
            flavor: HK_GET_TASK_CONTROL,
            source_flags: 0,
            source_team_id: [7u8; 16],
            source_signing_id: [9u8; 32],
        };
        let bytes = encode_get_task(&g);
        assert_eq!(bytes.len(), 64);
        let decoded = GetTask::decode(&bytes).expect("decode");
        assert_eq!(decoded, g);
    }

    #[test]
    fn get_task_name_flavor_suppressed() {
        // Signal 110: a NAME-port acquisition must NOT be flagged.
        let g = GetTask {
            source_pid: 1,
            target_pid: 2,
            flavor: HK_GET_TASK_NAME,
            source_flags: 0,
            source_team_id: [0; 16],
            source_signing_id: [0; 32],
        };
        assert!(g.score().suppressed);
    }

    #[test]
    fn get_task_control_from_foreign_flags() {
        let g = GetTask {
            source_pid: 1,
            target_pid: 2,
            flavor: HK_GET_TASK_CONTROL,
            source_flags: 0,
            source_team_id: [0; 16],
            source_signing_id: [0; 32],
        };
        let s = g.score();
        assert!(!s.suppressed);
        assert!(s.confidence > 0.8);
    }

    #[test]
    fn get_task_platform_binary_suppressed() {
        let g = GetTask {
            source_pid: 1,
            target_pid: 2,
            flavor: HK_GET_TASK_CONTROL,
            source_flags: HK_ESPROC_PLATFORM_BINARY,
            source_team_id: [0; 16],
            source_signing_id: [0; 32],
        };
        assert!(g.score().suppressed);
    }

    #[test]
    fn mmap_anon_rwx_high_known_suppressed() {
        let mut m = Mmap {
            target_pid: 1,
            source_pid: 1,
            protection: 0,
            flags: 0,
            baseline_match: HK_MMAP_BASELINE_ANON_RWX,
            reserved: 0,
            source_path_sha256: [0; 32],
        };
        assert!(!m.score().suppressed);
        m.baseline_match = HK_MMAP_BASELINE_KNOWN;
        assert!(m.score().suppressed);
    }

    #[test]
    fn proc_check_rate_gate() {
        // Below threshold = benign single poll, suppressed.
        let low = ProcCheck {
            source_pid: 1,
            target_pid: 2,
            flavor: 0,
            rate_per_window: 1,
            flavor_cardinality: 1,
            source_flags: 0,
        };
        let bytes = encode_proc_check(&low);
        assert_eq!(bytes.len(), 24);
        assert_eq!(ProcCheck::decode(&bytes).expect("decode"), low);
        assert!(low.score().suppressed);

        // Over threshold = recon, flagged.
        let high = ProcCheck {
            rate_per_window: PROC_CHECK_RATE_THRESHOLD + 1,
            flavor_cardinality: 3,
            ..low
        };
        assert!(!high.score().suppressed);
    }

    #[test]
    fn proc_check_platform_binary_suppressed() {
        let p = ProcCheck {
            source_pid: 1,
            target_pid: 2,
            flavor: 0,
            rate_per_window: 100,
            flavor_cardinality: 4,
            source_flags: HK_ESPROC_PLATFORM_BINARY,
        };
        assert!(p.score().suppressed);
    }

    #[test]
    fn ptrace_release_channel_gate() {
        // Dev / get-task-allow build (release_signed=0) is suppressed.
        let dev = Ptrace {
            game_pid: 1,
            tracer_pid: 2,
            traced_now: 1,
            cs_release_signed: 0,
        };
        let bytes = encode_ptrace(&dev);
        assert_eq!(bytes.len(), 16);
        assert_eq!(Ptrace::decode(&bytes).expect("decode"), dev);
        assert!(dev.score().suppressed);

        // Release-signed + traced edge = flagged.
        let rel = Ptrace {
            cs_release_signed: 1,
            ..dev
        };
        assert!(!rel.score().suppressed);
    }

    #[test]
    fn exc_port_foreign_only() {
        let own = ExcPort {
            game_pid: 1,
            owner_pid: 1,
            mask: 0xff,
            is_foreign: 0,
        };
        assert!(own.score().suppressed);
        let foreign = ExcPort {
            is_foreign: 1,
            ..own
        };
        assert!(!foreign.score().suppressed);
    }

    #[test]
    fn thread_origin_anon_only() {
        let img = ThreadOrigin {
            game_pid: 1,
            thread_id: 0,
            entry_pc: 0x1000,
            region_kind: HK_REGION_IMAGE,
            reserved: 0,
        };
        assert!(img.score().suppressed);
        let jit = ThreadOrigin {
            region_kind: HK_REGION_JIT_SANCTIONED,
            ..img
        };
        assert!(jit.score().suppressed);
        let anon = ThreadOrigin {
            region_kind: HK_REGION_ANON,
            ..img
        };
        assert!(!anon.score().suppressed);
    }

    #[test]
    fn dyld_inject_hardened_with_load_is_top_confidence() {
        let d = DyldInject {
            pid: 1,
            cs_flags: 0x0001_0000, // CS_RUNTIME
            dyld_var_present: HK_DYLD_VAR_INSERT_LIBRARIES,
            injected_load_seen: 1,
            inserted_path_sha256: [0; 32],
        };
        let s = d.score();
        assert!(!s.suppressed);
        assert!(s.confidence > 0.9);

        let no_var = DyldInject {
            dyld_var_present: 0,
            ..d
        };
        assert!(no_var.score().suppressed);
    }

    #[test]
    fn text_wx_writable_invalidated_sig() {
        let t = TextWx {
            game_pid: 1,
            protection: 0x2, // VM_PROT_WRITE
            share_mode: 0,
            csops_valid: 0, // signature invalidated
            region_addr: 0x1_0000,
        };
        let bytes = encode_text_wx(&t);
        assert_eq!(bytes.len(), 24);
        assert_eq!(TextWx::decode(&bytes).expect("decode"), t);
        let s = t.score();
        assert!(!s.suppressed);
        assert!(s.confidence > 0.9);

        // Read-only, intact signature = no W^X violation.
        let clean = TextWx {
            protection: 0x1, // VM_PROT_READ only
            csops_valid: 1,
            ..t
        };
        assert!(clean.score().suppressed);
    }

    #[test]
    fn short_buffer_is_typed_error_not_panic() {
        let short = [0u8; 10];
        let err = GetTask::decode(&short).expect_err("must be Short");
        match err {
            MacInjectError::Short { got, .. } => assert_eq!(got, 10),
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn unknown_type_is_typed_error() {
        let err = decode_event(99, &[0u8; 64]).expect_err("unknown");
        assert_eq!(err, MacInjectError::UnknownType(99));
    }

    #[test]
    fn decode_event_dispatches_by_type() {
        let g = GetTask {
            source_pid: 7,
            target_pid: 8,
            flavor: HK_GET_TASK_CONTROL,
            source_flags: 0,
            source_team_id: [0; 16],
            source_signing_id: [0; 32],
        };
        let bytes = encode_get_task(&g);
        match decode_event(HK_EVENT_ES_GET_TASK, &bytes).expect("decode") {
            MacInjectEvent::GetTask(d) => assert_eq!(d.source_pid, 7),
            other => panic!("wrong variant: {other:?}"),
        }
    }
}
