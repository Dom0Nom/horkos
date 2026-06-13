//! Role: Ban-engine scoring weights for the Linux eBPF loader-injection signals
//! (linux-ebpf-injection, catalog 82-90). Two load-bearing scoring rules:
//! (1) signal 87 (load-order inversion) is
//! CORROBORATING-ONLY — it can never reach the ban threshold standalone; its
//! weight only counts when at least one independent injection signal is also
//! present. (2) signal 85 (transient preload) carries the env-setting ancestor
//! pid for attribution. Fail-closed posture mirrors the bundle verifier: an
//! unknown/zeroed feature set scores 0 (no ban) — the client never acts; all ban
//! authority is server-side.
//!
//! Target platforms: server.
//!
//! Guardrail #8: pure, no blocking, no `unwrap()`/`expect()` outside tests.

/// Per-signal contribution weights (arbitrary integer units; the real model
/// learns these — these are the conservative hand-set priors that preserve the
/// catalog's FP posture: low-FP signals weigh more, the corroborating-only
/// signal weighs near-zero standalone). Tuned so NO single low-confidence signal
/// crosses `BAN_THRESHOLD` alone.
pub const W_DSO_NO_PROVENANCE: u32 = 40; // signal 82 (fileless + no DT_NEEDED)
pub const W_GOT_REDIRECT: u32 = 60; // signal 83 (strong: code-pointer redirect)
pub const W_INTERP_MISMATCH: u32 = 35; // signal 84
pub const W_PRELOAD_TRANSIENT: u32 = 45; // signal 85
pub const W_DLOPEN_FILELESS: u32 = 50; // signal 86
pub const W_LOADORDER_CORROBORATING: u32 = 10; // signal 87 — corroborating-only
pub const W_RDEBUG_FOREIGN: u32 = 55; // signal 88
pub const W_LD_AUDIT_ACTIVE: u32 = 40; // signal 89
pub const W_TEXT_COW_BROKEN: u32 = 60; // signal 90

/// Score at/above which the engine would propose a ban (server-side action).
/// Set so that the corroborating-only signal 87 alone (weight 10) is far below it,
/// AND a single low-FP signal alone is below it (a ban needs corroboration or a
/// high-confidence memory-integrity signal), but a high-confidence signal plus
/// any corroboration crosses it.
pub const BAN_THRESHOLD: u32 = 70;

/// The evidence bundle for one subject, accumulated from
/// `telemetry::loader_inject::LoaderInjectFeatures`. Booleans mirror that struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InjectionEvidence {
    pub dso_no_provenance: bool, // 82: no DT_NEEDED + outside allowlist + fileless
    pub got_redirect: bool,      // 83
    pub interp_mismatch: bool,   // 84
    pub preload_transient: bool, // 85
    pub dlopen_fileless: bool,   // 86
    pub loadorder_invert: bool,  // 87 — corroborating-only
    pub rdebug_foreign: bool,    // 88
    pub ld_audit_active: bool,   // 89
    pub text_cow_broken: bool,   // 90
    /// Env-setting ancestor pid for signal 85 attribution (0 = unknown).
    pub preload_ancestor_pid: u32,
}

impl InjectionEvidence {
    /// True if any INDEPENDENT (non-corroborating) injection signal is present.
    /// Signal 87 is excluded — it cannot stand on its own.
    fn has_independent_signal(&self) -> bool {
        self.dso_no_provenance
            || self.got_redirect
            || self.interp_mismatch
            || self.preload_transient
            || self.dlopen_fileless
            || self.rdebug_foreign
            || self.ld_audit_active
            || self.text_cow_broken
    }

    /// Compute the aggregate suspicion score. Signal 87's weight is added ONLY
    /// when an independent signal is also present (corroborating-only rule).
    pub fn score(&self) -> u32 {
        let mut s: u32 = 0;
        if self.dso_no_provenance {
            s = s.saturating_add(W_DSO_NO_PROVENANCE);
        }
        if self.got_redirect {
            s = s.saturating_add(W_GOT_REDIRECT);
        }
        if self.interp_mismatch {
            s = s.saturating_add(W_INTERP_MISMATCH);
        }
        if self.preload_transient {
            s = s.saturating_add(W_PRELOAD_TRANSIENT);
        }
        if self.dlopen_fileless {
            s = s.saturating_add(W_DLOPEN_FILELESS);
        }
        if self.rdebug_foreign {
            s = s.saturating_add(W_RDEBUG_FOREIGN);
        }
        if self.ld_audit_active {
            s = s.saturating_add(W_LD_AUDIT_ACTIVE);
        }
        if self.text_cow_broken {
            s = s.saturating_add(W_TEXT_COW_BROKEN);
        }
        // Corroborating-only: only count 87 when it corroborates something else.
        if self.loadorder_invert && self.has_independent_signal() {
            s = s.saturating_add(W_LOADORDER_CORROBORATING);
        }
        s
    }

    /// Whether the engine would propose a ban for this evidence. Fail-closed: an
    /// empty/zeroed evidence set scores 0 and never proposes a ban.
    pub fn proposes_ban(&self) -> bool {
        self.score() >= BAN_THRESHOLD
    }
}
