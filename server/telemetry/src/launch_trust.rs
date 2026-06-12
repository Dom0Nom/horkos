//! Role: Server-side ingest + correlation for the process-genealogy launch-trust
//! report (signals 199-207): true-creator-vs-parent reparenting, suspended-launch
//! window, LOLBin ancestry, manual-mapped module, token/integrity divergence,
//! job/silo containment, and the POSIX equivalents (traced launch, loader taint,
//! macOS responsibility). The client/kernel ship RAW launch facts + flags
//! (mirroring `hk_event_process_create_ex.proc_flags` + the `LaunchTrustReport`
//! JSON fields); ALL FP gating lives here, against a signed-launcher / LOLBin /
//! overlay baseline. Ban authority is the ban-engine's — this module produces a
//! correlated, gated verdict-input, never a ban.
//!
//! Target platforms: server.
//!
//! Guardrail #8: pure correlation, no blocking, `thiserror` error type, NO
//! `unwrap()`/`expect()` outside `#[cfg(test)]`. A malformed report yields a typed
//! `LaunchTrustError`, never a panic.

use serde::{Deserialize, Serialize};

// ---- proc_flags mirror (event_schema.h HK_PROC_FLAG_*) ----------------------
pub const HK_PROC_FLAG_REPARENT_SUSPECT: u32 = 0x1;
pub const HK_PROC_FLAG_SUSPENDED_LAUNCH: u32 = 0x2;
pub const HK_PROC_FLAG_LOLBIN_ANCESTOR: u32 = 0x4;
pub const HK_PROC_FLAG_TRACED_LAUNCH: u32 = 0x8;
pub const HK_PROC_FLAG_LOADER_TAINT: u32 = 0x10;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LaunchTrustError {
    #[error("ancestry chain too long: {0} (max {1})")]
    ChainTooLong(usize, usize),
    #[error("empty ancestry chain")]
    EmptyChain,
}

/// One launch-trust report from a protected client (mirrors the plan's
/// `LaunchTrustReport`). Serde JSON plane, independent of the C kernel schema.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct LaunchTrustReport {
    pub schema_version: u32,
    pub player_id: u64,
    pub game_pid: u32,
    pub true_creator_pid: u32,
    pub declared_parent_pid: u32,
    /// HK_PROC_FLAG_* mirror.
    pub proc_flags: u32,
    /// Ordered root -> game image identities (hash or normalized path) (signal 201).
    #[serde(default)]
    pub ancestry_image_hashes: Vec<String>,
    /// game integrity level minus launcher integrity level (signal 203).
    #[serde(default)]
    pub token_integrity_delta: i32,
    /// signal 204 (advisory).
    #[serde(default)]
    pub job_silo_anomaly: bool,
    /// signal 207 (macOS responsible team id).
    #[serde(default)]
    pub responsible_team_id: String,
    #[serde(default)]
    pub server_received_ts: u64,
}

const MAX_CHAIN: usize = 64;

/// The signed-launcher / LOLBin / overlay baseline the gates consult. In
/// production this is a signed bundle (`server/api/launcher-baseline.md`); here it
/// is a plain in-memory struct so the correlation is testable.
#[derive(Debug, Clone, Default)]
pub struct LauncherBaseline {
    /// Accepted chain-root launcher identities (e.g. the store client).
    pub accepted_roots: Vec<String>,
    /// Known signed-binary-proxy (LOLBin) image identities.
    pub lolbin_catalog: Vec<String>,
    /// Accepted (true_creator, declared_parent) pairs that legitimately reparent
    /// (Battle.net, Steam helper relaunch, AppContainer brokers).
    pub accepted_reparent_pairs: Vec<(String, String)>,
    /// Expected token-integrity delta for the launcher (e.g. +0x1000 for a
    /// UAC-elevated admin launcher); a report matching this is not flagged.
    pub expected_token_delta: i32,
    /// Accepted responsible Team IDs (signal 207).
    pub accepted_team_ids: Vec<String>,
}

/// The gated outcome: which raw flags survived FP gating into verdict inputs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LaunchTrustVerdict {
    pub reparent_confirmed: bool,
    pub lolbin_confirmed: bool,
    pub token_divergence_confirmed: bool,
    pub traced_launch_confirmed: bool,
    pub loader_taint_confirmed: bool,
    /// advisory only — never a standalone ban input.
    pub job_silo_advisory: bool,
}

impl LaunchTrustReport {
    fn validate(&self) -> Result<(), LaunchTrustError> {
        if self.ancestry_image_hashes.is_empty() {
            return Err(LaunchTrustError::EmptyChain);
        }
        if self.ancestry_image_hashes.len() > MAX_CHAIN {
            return Err(LaunchTrustError::ChainTooLong(
                self.ancestry_image_hashes.len(),
                MAX_CHAIN,
            ));
        }
        Ok(())
    }

    /// Correlate the raw report against the baseline into a gated verdict. Pure;
    /// returns a typed error on a malformed chain, never panics.
    pub fn correlate(
        &self,
        baseline: &LauncherBaseline,
    ) -> Result<LaunchTrustVerdict, LaunchTrustError> {
        self.validate()?;
        let mut v = LaunchTrustVerdict::default();

        let chain_root = self.ancestry_image_hashes.first();
        let root_accepted = match chain_root {
            Some(r) => baseline.accepted_roots.iter().any(|a| a == r),
            None => false,
        };

        // 199 reparent: raw flag set AND the (creator,parent) pair is NOT an
        // accepted benign-reparent pair. The pair is keyed by the first two
        // ancestry images (true creator, declared parent) when present.
        if self.proc_flags & HK_PROC_FLAG_REPARENT_SUSPECT != 0 {
            let pair_accepted = if self.ancestry_image_hashes.len() >= 2 {
                let creator = &self.ancestry_image_hashes[0];
                let parent = &self.ancestry_image_hashes[1];
                baseline
                    .accepted_reparent_pairs
                    .iter()
                    .any(|(c, p)| c == creator && p == parent)
            } else {
                false
            };
            v.reparent_confirmed = !pair_accepted;
        }

        // 201 LOLBin: a catalog binary appears in the ancestry AND the chain root
        // is NOT an accepted launcher (a bare rundll32 -> game with no store root
        // is the strong signal; a store-rooted chain with a signed proxy is benign).
        let has_lolbin = self
            .ancestry_image_hashes
            .iter()
            .any(|img| baseline.lolbin_catalog.iter().any(|l| l == img));
        if has_lolbin && !root_accepted {
            v.lolbin_confirmed = true;
        }

        // 203 token divergence: the delta differs from the launcher's expected
        // baseline (a UAC High-from-Medium under a known admin launcher matches the
        // baseline and is NOT flagged).
        if self.token_integrity_delta != baseline.expected_token_delta {
            v.token_divergence_confirmed = true;
        }

        // 205/206 POSIX: traced launch / loader taint are confirmed straight from
        // the flags (the BPF side already allowlisted the Steam/Proton tracer +
        // overlay .so before tagging; an unallowlisted tag reaches here).
        v.traced_launch_confirmed = self.proc_flags & HK_PROC_FLAG_TRACED_LAUNCH != 0;
        v.loader_taint_confirmed = self.proc_flags & HK_PROC_FLAG_LOADER_TAINT != 0;

        // 204 job/silo: advisory only, never a standalone ban input.
        v.job_silo_advisory = self.job_silo_anomaly;

        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_baseline() -> LauncherBaseline {
        LauncherBaseline {
            accepted_roots: vec!["store_client".into()],
            lolbin_catalog: vec!["rundll32".into(), "regsvr32".into(), "mshta".into()],
            accepted_reparent_pairs: vec![("battlenet".into(), "explorer".into())],
            expected_token_delta: 0x1000, // UAC-elevated admin launcher baseline.
            accepted_team_ids: vec!["STEAMTEAMID".into()],
        }
    }

    #[test]
    fn reparent_with_whitelisted_pair_not_flagged() {
        let r = LaunchTrustReport {
            proc_flags: HK_PROC_FLAG_REPARENT_SUSPECT,
            ancestry_image_hashes: vec!["battlenet".into(), "explorer".into()],
            token_integrity_delta: 0x1000,
            ..Default::default()
        };
        let v = r.correlate(&store_baseline()).expect("correlate");
        assert!(!v.reparent_confirmed);
    }

    #[test]
    fn reparent_with_unknown_pair_is_confirmed() {
        let r = LaunchTrustReport {
            proc_flags: HK_PROC_FLAG_REPARENT_SUSPECT,
            ancestry_image_hashes: vec!["evil".into(), "game".into()],
            token_integrity_delta: 0x1000,
            ..Default::default()
        };
        let v = r.correlate(&store_baseline()).expect("correlate");
        assert!(v.reparent_confirmed);
    }

    #[test]
    fn bare_lolbin_without_store_root_is_confirmed() {
        let r = LaunchTrustReport {
            ancestry_image_hashes: vec!["rundll32".into(), "game".into()],
            token_integrity_delta: 0x1000,
            ..Default::default()
        };
        let v = r.correlate(&store_baseline()).expect("correlate");
        assert!(v.lolbin_confirmed);
    }

    #[test]
    fn lolbin_under_store_root_not_confirmed() {
        let r = LaunchTrustReport {
            ancestry_image_hashes: vec!["store_client".into(), "rundll32".into(), "game".into()],
            token_integrity_delta: 0x1000,
            ..Default::default()
        };
        let v = r.correlate(&store_baseline()).expect("correlate");
        assert!(!v.lolbin_confirmed);
    }

    #[test]
    fn token_delta_matching_baseline_not_flagged() {
        let r = LaunchTrustReport {
            token_integrity_delta: 0x1000, // matches the admin-launcher baseline.
            ancestry_image_hashes: vec!["store_client".into()],
            ..Default::default()
        };
        let v = r.correlate(&store_baseline()).expect("correlate");
        assert!(!v.token_divergence_confirmed);
    }

    #[test]
    fn token_delta_off_baseline_flagged() {
        let r = LaunchTrustReport {
            token_integrity_delta: 0x2000,
            ancestry_image_hashes: vec!["store_client".into()],
            ..Default::default()
        };
        let v = r.correlate(&store_baseline()).expect("correlate");
        assert!(v.token_divergence_confirmed);
    }

    #[test]
    fn job_silo_is_advisory_only() {
        let r = LaunchTrustReport {
            job_silo_anomaly: true,
            token_integrity_delta: 0x1000,
            ancestry_image_hashes: vec!["store_client".into()],
            ..Default::default()
        };
        let v = r.correlate(&store_baseline()).expect("correlate");
        assert!(v.job_silo_advisory);
        // advisory does not set any ban-input flag.
        assert!(!v.reparent_confirmed && !v.lolbin_confirmed);
    }

    #[test]
    fn overlong_chain_is_rejected() {
        let r = LaunchTrustReport {
            ancestry_image_hashes: vec!["x".to_string(); MAX_CHAIN + 1],
            ..Default::default()
        };
        assert!(matches!(
            r.correlate(&store_baseline()),
            Err(LaunchTrustError::ChainTooLong(_, _))
        ));
    }

    #[test]
    fn empty_chain_is_rejected() {
        let r = LaunchTrustReport {
            ancestry_image_hashes: vec![],
            ..Default::default()
        };
        assert!(matches!(
            r.correlate(&store_baseline()),
            Err(LaunchTrustError::EmptyChain)
        ));
    }

    #[test]
    fn zero_baseline_delta_unelevated_game_not_flagged() {
        // A game launched unelevated under an unelevated launcher: both process
        // tokens share the same integrity level, so the delta is 0. A baseline
        // that declares expected_token_delta = 0 (no elevation) must NOT flag a
        // matching delta of 0. A delta != 0 (e.g. +0x1000) must be flagged.
        let unelevated_baseline = LauncherBaseline {
            expected_token_delta: 0,
            accepted_roots: vec!["store_client".into()],
            ..LauncherBaseline::default()
        };

        let no_elevation = LaunchTrustReport {
            token_integrity_delta: 0,
            ancestry_image_hashes: vec!["store_client".into()],
            ..Default::default()
        };
        let v = no_elevation
            .correlate(&unelevated_baseline)
            .expect("correlate");
        assert!(
            !v.token_divergence_confirmed,
            "delta == baseline (both 0) must not be flagged"
        );

        let elevated = LaunchTrustReport {
            token_integrity_delta: 0x1000,
            ancestry_image_hashes: vec!["store_client".into()],
            ..Default::default()
        };
        let v2 = elevated.correlate(&unelevated_baseline).expect("correlate");
        assert!(
            v2.token_divergence_confirmed,
            "delta != baseline (0x1000 vs 0) must be flagged"
        );
    }
}
