//! src/hv.rs
//!
//! Role: Server-side ingest contract for the hypervisor/virtualization-state
//! report sub-payload (win-hypervisor-detection, catalog signals 37/38/40/42/43/
//! 44/45). Serde mirror of the usermode POD field names in
//! `ac/include/horkos/hv_signals.h` (`hv_report`). This is the INDEPENDENT
//! periodic JSON plane (NOT byte-compatible with the C struct — the same
//! separation `schema.rs` documents for `TickPayload`); it rides the
//! `TickPayload` HTTP plane as an OPTIONAL sub-payload (see
//! `schema.rs::TickPayload::hv`). The bulky raw HV data (CPUID leaf vectors,
//! vmexit latency histograms, per-vCPU skew) rides here; the four kernel HV
//! records (signals 39/41/42/44) are folded usermode into `kern` before upload,
//! so the server sees one coherent report.
//!
//! FEATURES/EVIDENCE ONLY — there is deliberately no verdict field. Every signal
//! here is medium/high FP (nested Hyper-V, WSL2, Sandbox, Cloud PC, GPU-passthrough
//! VMs, multi-socket TSC skew, HVCI exec/read asymmetry); ALL classification
//! (population modeling, per-SKU skew, known-good nested-Hyper-V vectors,
//! attested-fleet allowlists) is server-side. The client ships raw vectors/
//! histograms/tuples plus a raw structural class the server may override.
//!
//! Target platforms: server.
//!
//! Guardrail #8: pure validation, no blocking, `thiserror` error type, NO
//! `unwrap()`/`expect()` outside `#[cfg(test)]`. A malformed payload (out-of-range
//! VM-identity class) yields a typed `HvError`, never a panic.

use serde::{Deserialize, Serialize};

/// HV report schema version. Bump on every additive change; independent of the
/// tick-stream `SCHEMA_VERSION` and the kernel `HK_EVENT_SCHEMA_VERSION`.
pub const HV_SCHEMA_VERSION: u32 = 1;

/// Highest valid VM-identity classification (`HK_HV_VMID_COVERT_INSPECTION`).
pub const HK_HV_VMID_MAX: u32 = 3;

/// Typed validation error for the HV sub-payload.
#[derive(Debug, thiserror::Error)]
pub enum HvError {
    /// The VM-identity classification is outside its enum range.
    #[error("vm-identity classification {value} out of range (0..={max})")]
    ClassOutOfRange { value: u32, max: u32 },
}

impl From<HvError> for crate::error::TelemetryError {
    fn from(e: HvError) -> Self {
        crate::error::TelemetryError::Hv(e.to_string())
    }
}

/// Signal 37 — TLFS hypervisor CPUID leaves + OS posture. Mirrors `hv_tlfs_leaves`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct HvTlfsLeaves {
    /// CPUID 0x40000000..0x4000000A, EAX/EBX/ECX/EDX.
    #[serde(default)]
    pub leaf: [[u32; 4]; 11],
    #[serde(default)]
    pub cpuid1_ecx31_hv: u32,
    #[serde(default)]
    pub os_vbs_running: u32,
    #[serde(default)]
    pub os_hv_present: u32,
}

/// Signal 38 — vmexit latency histogram. Mirrors `hv_vmexit_latency`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct HvVmexitLatency {
    #[serde(default)]
    pub hist: [u32; 32],
    #[serde(default)]
    pub cpu_model: u32,
    #[serde(default)]
    pub qpc_span: u64,
    #[serde(default)]
    pub shared_interrupt_dt: u64,
}

/// Signal 40 — VBS/HVCI enablement vs attestation. Mirrors `hv_vbs_attest`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct HvVbsAttest {
    #[serde(default)]
    pub vbs_status: u32,
    #[serde(default)]
    pub security_services: u32,
    #[serde(default)]
    pub ci_policy: u32,
    #[serde(default)]
    pub attest_quote_avail: u32,
    #[serde(default)]
    pub attest_contradiction: u32,
}

/// Signal 43 — sanctioned-VM identity vs covert inspection. Mirrors `hv_vm_identity`.
/// `classification` is the raw structural class; the server makes the trust
/// decision against attested-fleet allowlists.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct HvVmIdentity {
    #[serde(default)]
    pub cpuid_hv_present: u32,
    #[serde(default)]
    pub smbios_vm_marker: u32,
    #[serde(default)]
    pub devicetree_vm_marker: u32,
    #[serde(default)]
    pub vtpm_ek_present: u32,
    #[serde(default)]
    pub classification: u32,
}

/// Signal 45 — cross-vCPU TSC coherence. Mirrors `hv_tsc_coherence`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct HvTscCoherence {
    #[serde(default)]
    pub lp_count: u32,
    #[serde(default)]
    pub invariant_tsc: u32,
    #[serde(default)]
    pub max_abs_skew: u64,
    #[serde(default)]
    pub monotonic: u32,
    #[serde(default)]
    pub aux_pin_verified: u32,
}

/// Kernel-record summary folded from the ring (signals 39/41/42/44). Mirrors
/// `hv_kernel_summary`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct HvKernelSummary {
    #[serde(default)]
    pub synth_msr_flags: u32,
    #[serde(default)]
    pub ept_flags: u32,
    #[serde(default)]
    pub sk_flags: u32,
    #[serde(default)]
    pub apic_idt_flags: u32,
    #[serde(default)]
    pub records_seen: u32,
}

/// The HV report sub-payload (mirrors `hv_report`). A clear `sensors_ok` bit means
/// the sampler did NOT run on the client; the server reads the zeroed sub-struct
/// as "not collected", never "clean / bare-metal".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct HvReport {
    /// Sub-payload schema version; should equal `HV_SCHEMA_VERSION`.
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub tlfs: HvTlfsLeaves,
    #[serde(default)]
    pub vmexit: HvVmexitLatency,
    #[serde(default)]
    pub vbs: HvVbsAttest,
    #[serde(default)]
    pub identity: HvVmIdentity,
    #[serde(default)]
    pub tsc: HvTscCoherence,
    #[serde(default)]
    pub kern: HvKernelSummary,
    /// `HK_HV_OK_*` bitmask: which samplers ran cleanly this cycle.
    #[serde(default)]
    pub sensors_ok: u32,
}

impl HvReport {
    /// Validate the sub-payload's range invariants. Returns a typed error on any
    /// violation (never panics). Safe to call from async context (pure). Missing
    /// fields are tolerated (they deserialize to zero per the optional-sub-payload
    /// precedent); only an out-of-range VM-identity class is rejected — all other
    /// fields are raw vectors/counters the server models, with no client-side
    /// enumerated range to enforce.
    pub fn validate(&self) -> Result<(), HvError> {
        if self.identity.classification > HK_HV_VMID_MAX {
            return Err(HvError::ClassOutOfRange {
                value: self.identity.classification,
                max: HK_HV_VMID_MAX,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> HvReport {
        HvReport {
            schema_version: HV_SCHEMA_VERSION,
            identity: HvVmIdentity {
                cpuid_hv_present: 1,
                classification: HK_HV_VMID_MAX, // covert-inspection, in range
                ..Default::default()
            },
            sensors_ok: 0x3F,
            ..Default::default()
        }
    }

    #[test]
    fn round_trips_through_json() {
        let r = sample();
        let json = serde_json::to_string(&r).expect("serialize");
        let back: HvReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(r, back);
        assert!(back.validate().is_ok());
    }

    #[test]
    fn missing_fields_default_to_zero() {
        // A client that omits every sub-struct still deserializes (None -> zeros),
        // read by the server as "not collected", never a fabricated positive.
        let back: HvReport = serde_json::from_str("{}").expect("deserialize empty");
        assert_eq!(back.sensors_ok, 0);
        assert_eq!(back.identity.classification, 0);
        assert!(back.validate().is_ok());
    }

    #[test]
    fn out_of_range_classification_rejected() {
        let mut r = sample();
        r.identity.classification = HK_HV_VMID_MAX + 1;
        assert!(matches!(r.validate(), Err(HvError::ClassOutOfRange { .. })));
    }

    #[test]
    fn leaf_vector_round_trips() {
        let mut r = sample();
        r.tlfs.leaf[0][0] = 0x4000_0006;
        r.tlfs.leaf[1][1] = 0x7263_694D;
        let json = serde_json::to_string(&r).expect("serialize");
        let back: HvReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.tlfs.leaf[0][0], 0x4000_0006);
        assert_eq!(back.tlfs.leaf[1][1], 0x7263_694D);
    }
}
