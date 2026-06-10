//! src/kernel_events.rs
//!
//! Role: Server-side decode + feature extraction for the Linux kernel/module-trust
//! event records (linux-module-integrity, signals 91-99): kallsyms drift
//! (`hk_event_ksym_drift`), module cross-view diff (`hk_event_module_view_diff`),
//! ftrace ownership (`hk_event_ftrace_hook`), sensitive-symbol kprobes
//! (`hk_event_kprobe_sensitive`), module disk drift (`hk_event_module_disk_drift`),
//! kernel posture (`hk_event_kernel_posture`), foreign BPF (`hk_event_foreign_bpf`),
//! devmem access (`hk_event_devmem_access`), MSR writes (`hk_event_msr_write`), and
//! the coverage-gap marker (`hk_event_sensor_unavailable`). Decodes the Loader
//! sink byte stream into `#[repr(C)]` mirrors of the C99 payload structs (the
//! provisional layouts in `kernel/linux/userspace/HostIntegritySensors.h`), then
//! extracts normalized features. This module extracts features only — it never
//! bans (that authority is the ban-engine's, server-side). Posture / sensor-
//! unavailable are trust-tier WEIGHTS, never standalone evidence.
//!
//! Target platforms: server.
//!
//! Guardrail #8: fully async-compatible (pure, no blocking), `thiserror` error
//! type, NO `unwrap()`/`expect()` outside `#[cfg(test)]`. A malformed/short wire
//! record yields a typed `KernelEventError`, never a panic.
//!
//! Schema: the event-type discriminants (`HK_EVENT_KSYM_DRIFT` = 19 ..
//! `HK_EVENT_SENSOR_UNAVAILABLE` = 28) are now FROZEN in
//! `sdk/include/horkos/event_schema.h` (schema v6). The consts below mirror the
//! enum exactly and match the C producer header
//! `kernel/linux/userspace/HostIntegritySensors.h` (`kEvt*`). The decoders are
//! written against the plan's pinned field layout/sizes.

use thiserror::Error;

/// Kernel-event mirror version. HK-TODO(schema): tracks `HK_EVENT_SCHEMA_VERSION`
/// (bumps 2 -> 3 in lockstep when the Schema phase lands these payloads).
pub const KERNEL_EVENT_MIRROR_VERSION: u32 = 3;

/// Event-type discriminants for the Linux module-trust records.
///
/// These start at 19 to avoid every frozen range in `event_schema.h`:
///   1..=4  — core events (process/image/handle)
///   5..=13 — Windows mem-injection family (HK_EVENT_MEM_UNBACKED_EXEC..
///             HK_EVENT_MEM_UNSIGNED_IMAGE; v3 schema)
///   14..=17 — HV/virtualization family (HK_EVENT_HV_SYNTH_MSR..
///              HK_EVENT_HV_APIC_IDT; v4 schema)
///   18     — HK_EVENT_PROCESS_CREATE_EX (launch-trust; v5 schema)
///   19..=28 — Linux module-trust family (this file; assigned here, pending
///             Schema-phase ratification that appends them to hk_event_type).
///
/// The matching C producer constants live in
/// `kernel/linux/userspace/HostIntegritySensors.h` (`kEvt*`); those must be
/// updated in lockstep with any change here.
pub const HK_EVENT_KSYM_DRIFT: u32 = 19;
pub const HK_EVENT_MODULE_VIEW_DIFF: u32 = 20;
pub const HK_EVENT_FTRACE_HOOK: u32 = 21;
pub const HK_EVENT_KPROBE_SENSITIVE: u32 = 22;
pub const HK_EVENT_MODULE_DISK_DRIFT: u32 = 23;
pub const HK_EVENT_KERNEL_POSTURE: u32 = 24;
pub const HK_EVENT_FOREIGN_BPF: u32 = 25;
pub const HK_EVENT_DEVMEM_ACCESS: u32 = 26;
pub const HK_EVENT_MSR_WRITE_SENSITIVE: u32 = 27;
pub const HK_EVENT_SENSOR_UNAVAILABLE: u32 = 28;

// ---- ksym-drift reasons (mirror HkKsymDriftReason) -------------------------
pub const HK_KSYM_OOB: u32 = 0;
pub const HK_KSYM_COLLISION: u32 = 1;
pub const HK_KSYM_SHADOW: u32 = 2;

// ---- module-view present-mask bits (mirror HkModuleViewBit) ----------------
pub const HK_MV_PROCMODULES: u32 = 0x1;
pub const HK_MV_SYSFS: u32 = 0x2;
pub const HK_MV_BPF_OR_LKM: u32 = 0x4;

// ---- kprobe flags (mirror HkKprobeFlag) ------------------------------------
pub const HK_KP_OPTIMIZED: u32 = 0x1;
pub const HK_KP_DISABLED: u32 = 0x2;
pub const HK_KP_MODULELESS: u32 = 0x4;

// ---- module-disk-drift reasons (mirror HkModuleDiskReason) -----------------
pub const HK_MD_BUILDID_MISMATCH: u32 = 0;
pub const HK_MD_CRC_MISMATCH: u32 = 1;
pub const HK_MD_NO_DISK_KO: u32 = 2;

// ---- posture "unknown" sentinel (mirror HK_POSTURE_UNKNOWN) ----------------
pub const HK_POSTURE_UNKNOWN: u32 = 0xFFFF_FFFF;

/// Decode errors. A short or malformed Loader-sink record surfaces as one of
/// these — never a panic (guardrail #8).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KernelEventError {
    #[error("record too short: need {need} bytes for {what}, got {got}")]
    Short {
        what: &'static str,
        need: usize,
        got: usize,
    },

    #[error("unknown kernel event type {0}")]
    UnknownType(u32),
}

// ---------------------------------------------------------------------------
// Little-endian fixed-width readers (LE wire; Horkos targets LE hosts).
// ---------------------------------------------------------------------------

fn read_u32(buf: &[u8], off: usize, what: &'static str) -> Result<u32, KernelEventError> {
    let end = off + 4;
    if buf.len() < end {
        return Err(KernelEventError::Short {
            what,
            need: end,
            got: buf.len(),
        });
    }
    let mut a = [0u8; 4];
    a.copy_from_slice(&buf[off..end]);
    Ok(u32::from_le_bytes(a))
}

fn read_u64(buf: &[u8], off: usize, what: &'static str) -> Result<u64, KernelEventError> {
    let end = off + 8;
    if buf.len() < end {
        return Err(KernelEventError::Short {
            what,
            need: end,
            got: buf.len(),
        });
    }
    let mut a = [0u8; 8];
    a.copy_from_slice(&buf[off..end]);
    Ok(u64::from_le_bytes(a))
}

// ---------------------------------------------------------------------------
// `#[repr(C)]` mirrors of the wire payloads. Field names/sizes track the
// provisional structs in kernel/linux/userspace/HostIntegritySensors.h exactly
// (32/16/24/24/16/16/16/16/16/8).
// ---------------------------------------------------------------------------

/// Mirror of `hk_event_ksym_drift` (32 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KsymDrift {
    pub resolved_addr: u64,
    pub expected_lo: u64,
    pub expected_hi: u64,
    pub reason: u32,
    pub symbol_id: u32,
}

/// Mirror of `hk_event_module_view_diff` (16 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleViewDiff {
    pub name_hash: u64,
    pub present_mask: u32,
    pub module_state: u32,
}

/// Mirror of `hk_event_ftrace_hook` (24 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FtraceHook {
    pub func_addr: u64,
    pub ops_owner_addr: u64,
    pub owner_attributed: u32,
    pub func_id: u32,
}

/// Mirror of `hk_event_kprobe_sensitive` (24 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KprobeSensitive {
    pub probe_addr: u64,
    pub symbol_id: u32,
    pub flags: u32,
    pub owner_signed: u32,
    pub reserved: u32,
}

/// Mirror of `hk_event_module_disk_drift` (16 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleDiskDrift {
    pub name_hash: u64,
    pub reason: u32,
    pub reserved: u32,
}

/// Mirror of `hk_event_kernel_posture` (16 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelPosture {
    pub lockdown_level: u32,
    pub sig_enforce: u32,
    pub secure_boot: u32,
    pub taint_flags: u32,
}

/// Mirror of `hk_event_foreign_bpf` (16 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForeignBpf {
    pub prog_tag_hash: u64,
    pub prog_id: u32,
    pub prog_type: u32,
}

/// Mirror of `hk_event_devmem_access` (16 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DevmemAccess {
    pub requesting_pid: u32,
    pub dev_minor: u32,
    pub write_intent: u32,
    pub mmap_prot_write: u32,
}

/// Mirror of `hk_event_msr_write` (16 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsrWrite {
    pub requesting_pid: u32,
    pub msr_index: u32,
    pub sensitive: u32,
    pub reserved: u32,
}

/// Mirror of `hk_event_sensor_unavailable` (8 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SensorUnavailable {
    pub signal_id: u32,
    pub errno_value: u32,
}

// Compile-time size pins mirroring the C static_asserts.
const _: () = assert!(core::mem::size_of::<KsymDrift>() == 32);
const _: () = assert!(core::mem::size_of::<ModuleViewDiff>() == 16);
const _: () = assert!(core::mem::size_of::<FtraceHook>() == 24);
const _: () = assert!(core::mem::size_of::<KprobeSensitive>() == 24);
const _: () = assert!(core::mem::size_of::<ModuleDiskDrift>() == 16);
const _: () = assert!(core::mem::size_of::<KernelPosture>() == 16);
const _: () = assert!(core::mem::size_of::<ForeignBpf>() == 16);
const _: () = assert!(core::mem::size_of::<DevmemAccess>() == 16);
const _: () = assert!(core::mem::size_of::<MsrWrite>() == 16);
const _: () = assert!(core::mem::size_of::<SensorUnavailable>() == 8);

impl KsymDrift {
    pub fn decode(buf: &[u8]) -> Result<Self, KernelEventError> {
        Ok(Self {
            resolved_addr: read_u64(buf, 0, "ksym_drift.resolved_addr")?,
            expected_lo: read_u64(buf, 8, "ksym_drift.expected_lo")?,
            expected_hi: read_u64(buf, 16, "ksym_drift.expected_hi")?,
            reason: read_u32(buf, 24, "ksym_drift.reason")?,
            symbol_id: read_u32(buf, 28, "ksym_drift.symbol_id")?,
        })
    }
}

impl ModuleViewDiff {
    pub fn decode(buf: &[u8]) -> Result<Self, KernelEventError> {
        Ok(Self {
            name_hash: read_u64(buf, 0, "module_view_diff.name_hash")?,
            present_mask: read_u32(buf, 8, "module_view_diff.present_mask")?,
            module_state: read_u32(buf, 12, "module_view_diff.module_state")?,
        })
    }
}

impl FtraceHook {
    pub fn decode(buf: &[u8]) -> Result<Self, KernelEventError> {
        Ok(Self {
            func_addr: read_u64(buf, 0, "ftrace_hook.func_addr")?,
            ops_owner_addr: read_u64(buf, 8, "ftrace_hook.ops_owner_addr")?,
            owner_attributed: read_u32(buf, 16, "ftrace_hook.owner_attributed")?,
            func_id: read_u32(buf, 20, "ftrace_hook.func_id")?,
        })
    }
}

impl KprobeSensitive {
    pub fn decode(buf: &[u8]) -> Result<Self, KernelEventError> {
        Ok(Self {
            probe_addr: read_u64(buf, 0, "kprobe_sensitive.probe_addr")?,
            symbol_id: read_u32(buf, 8, "kprobe_sensitive.symbol_id")?,
            flags: read_u32(buf, 12, "kprobe_sensitive.flags")?,
            owner_signed: read_u32(buf, 16, "kprobe_sensitive.owner_signed")?,
            reserved: read_u32(buf, 20, "kprobe_sensitive.reserved")?,
        })
    }
}

impl ModuleDiskDrift {
    pub fn decode(buf: &[u8]) -> Result<Self, KernelEventError> {
        Ok(Self {
            name_hash: read_u64(buf, 0, "module_disk_drift.name_hash")?,
            reason: read_u32(buf, 8, "module_disk_drift.reason")?,
            reserved: read_u32(buf, 12, "module_disk_drift.reserved")?,
        })
    }
}

impl KernelPosture {
    pub fn decode(buf: &[u8]) -> Result<Self, KernelEventError> {
        Ok(Self {
            lockdown_level: read_u32(buf, 0, "kernel_posture.lockdown_level")?,
            sig_enforce: read_u32(buf, 4, "kernel_posture.sig_enforce")?,
            secure_boot: read_u32(buf, 8, "kernel_posture.secure_boot")?,
            taint_flags: read_u32(buf, 12, "kernel_posture.taint_flags")?,
        })
    }
}

impl ForeignBpf {
    pub fn decode(buf: &[u8]) -> Result<Self, KernelEventError> {
        Ok(Self {
            prog_tag_hash: read_u64(buf, 0, "foreign_bpf.prog_tag_hash")?,
            prog_id: read_u32(buf, 8, "foreign_bpf.prog_id")?,
            prog_type: read_u32(buf, 12, "foreign_bpf.prog_type")?,
        })
    }
}

impl DevmemAccess {
    pub fn decode(buf: &[u8]) -> Result<Self, KernelEventError> {
        Ok(Self {
            requesting_pid: read_u32(buf, 0, "devmem_access.requesting_pid")?,
            dev_minor: read_u32(buf, 4, "devmem_access.dev_minor")?,
            write_intent: read_u32(buf, 8, "devmem_access.write_intent")?,
            mmap_prot_write: read_u32(buf, 12, "devmem_access.mmap_prot_write")?,
        })
    }
}

impl MsrWrite {
    pub fn decode(buf: &[u8]) -> Result<Self, KernelEventError> {
        Ok(Self {
            requesting_pid: read_u32(buf, 0, "msr_write.requesting_pid")?,
            msr_index: read_u32(buf, 4, "msr_write.msr_index")?,
            sensitive: read_u32(buf, 8, "msr_write.sensitive")?,
            reserved: read_u32(buf, 12, "msr_write.reserved")?,
        })
    }
}

impl SensorUnavailable {
    pub fn decode(buf: &[u8]) -> Result<Self, KernelEventError> {
        Ok(Self {
            signal_id: read_u32(buf, 0, "sensor_unavailable.signal_id")?,
            errno_value: read_u32(buf, 4, "sensor_unavailable.errno_value")?,
        })
    }
}

/// A decoded module-trust payload, tagged by wire type. Mirrors `hk_event_type`'s
/// module-trust range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelEventKind {
    KsymDrift(KsymDrift),
    ModuleViewDiff(ModuleViewDiff),
    FtraceHook(FtraceHook),
    KprobeSensitive(KprobeSensitive),
    ModuleDiskDrift(ModuleDiskDrift),
    KernelPosture(KernelPosture),
    ForeignBpf(ForeignBpf),
    DevmemAccess(DevmemAccess),
    MsrWrite(MsrWrite),
    SensorUnavailable(SensorUnavailable),
}

/// Decode one payload buffer given its wire event type.
pub fn decode_event(event_type: u32, payload: &[u8]) -> Result<KernelEventKind, KernelEventError> {
    match event_type {
        HK_EVENT_KSYM_DRIFT => Ok(KernelEventKind::KsymDrift(KsymDrift::decode(payload)?)),
        HK_EVENT_MODULE_VIEW_DIFF => Ok(KernelEventKind::ModuleViewDiff(ModuleViewDiff::decode(
            payload,
        )?)),
        HK_EVENT_FTRACE_HOOK => Ok(KernelEventKind::FtraceHook(FtraceHook::decode(payload)?)),
        HK_EVENT_KPROBE_SENSITIVE => Ok(KernelEventKind::KprobeSensitive(KprobeSensitive::decode(
            payload,
        )?)),
        HK_EVENT_MODULE_DISK_DRIFT => Ok(KernelEventKind::ModuleDiskDrift(
            ModuleDiskDrift::decode(payload)?,
        )),
        HK_EVENT_KERNEL_POSTURE => Ok(KernelEventKind::KernelPosture(KernelPosture::decode(
            payload,
        )?)),
        HK_EVENT_FOREIGN_BPF => Ok(KernelEventKind::ForeignBpf(ForeignBpf::decode(payload)?)),
        HK_EVENT_DEVMEM_ACCESS => Ok(KernelEventKind::DevmemAccess(DevmemAccess::decode(
            payload,
        )?)),
        HK_EVENT_MSR_WRITE_SENSITIVE => Ok(KernelEventKind::MsrWrite(MsrWrite::decode(payload)?)),
        HK_EVENT_SENSOR_UNAVAILABLE => Ok(KernelEventKind::SensorUnavailable(
            SensorUnavailable::decode(payload)?,
        )),
        other => Err(KernelEventError::UnknownType(other)),
    }
}

// ---------------------------------------------------------------------------
// Feature extraction. Pure, allocation-free. No thresholding/ban here — these
// are trust-tier inputs the ban-engine model/rules consume. Posture and
// sensor-unavailable are WEIGHTS, never standalone evidence (cross-plane note,
// §1.6): the ban-engine requires corroboration for this domain.
// ---------------------------------------------------------------------------

/// Normalized trust-tier features. Booleans are derived evidence, not verdicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KernelTrustFeatures {
    /// A sensitive symbol resolved out of every known text range (#91 OOB).
    pub ksym_out_of_bounds: bool,
    /// A sensitive symbol was shadowed into a non-livepatch module (#91 shadow).
    pub ksym_shadowed: bool,
    /// A module is visible in one enumeration but not another (#92).
    pub module_view_mismatch: bool,
    /// An ftrace hook on a sensitive function has an unattributable owner (#93).
    pub ftrace_unattributed_hook: bool,
    /// A module-less kprobe sits on a sensitive symbol (#94).
    pub kprobe_moduleless_sensitive: bool,
    /// In-memory module diverges from its on-disk .ko (#95).
    pub module_disk_drift: bool,
    /// Posture is weak (lockdown=none AND sig_enforce off) — a WEIGHT only (#96).
    pub posture_weak: bool,
    /// A foreign BPF program sits on a protected hook point (#97).
    pub foreign_bpf_on_hook: bool,
    /// A write-intent open of a physmem/port node (#98).
    pub devmem_write_intent: bool,
    /// A write to a sensitive MSR (LSTAR/SYSENTER_EIP/...) (#99).
    pub msr_sensitive_write: bool,
    /// A sensor could not read its source — a COVERAGE GAP weight, never a
    /// detection (the dominant FP guard for this domain).
    pub coverage_gap: bool,
}

impl KsymDrift {
    pub fn features(&self) -> KernelTrustFeatures {
        KernelTrustFeatures {
            ksym_out_of_bounds: self.reason == HK_KSYM_OOB,
            ksym_shadowed: self.reason == HK_KSYM_SHADOW,
            ..Default::default()
        }
    }
}

impl ModuleViewDiff {
    pub fn features(&self) -> KernelTrustFeatures {
        KernelTrustFeatures {
            module_view_mismatch: true,
            ..Default::default()
        }
    }
}

impl FtraceHook {
    pub fn features(&self) -> KernelTrustFeatures {
        KernelTrustFeatures {
            ftrace_unattributed_hook: self.owner_attributed == 0,
            ..Default::default()
        }
    }
}

impl KprobeSensitive {
    pub fn features(&self) -> KernelTrustFeatures {
        KernelTrustFeatures {
            kprobe_moduleless_sensitive: (self.flags & HK_KP_MODULELESS) != 0
                && self.owner_signed == 0,
            ..Default::default()
        }
    }
}

impl ModuleDiskDrift {
    pub fn features(&self) -> KernelTrustFeatures {
        KernelTrustFeatures {
            module_disk_drift: true,
            ..Default::default()
        }
    }
}

impl KernelPosture {
    pub fn features(&self) -> KernelTrustFeatures {
        // posture_weak only when BOTH lockdown is none AND sig_enforce is off (and
        // both are KNOWN — an unknown posture is coverage, not weakness).
        let lockdown_none = self.lockdown_level == 0;
        let sig_off = self.sig_enforce == 0;
        let known =
            self.lockdown_level != HK_POSTURE_UNKNOWN && self.sig_enforce != HK_POSTURE_UNKNOWN;
        KernelTrustFeatures {
            posture_weak: known && lockdown_none && sig_off,
            coverage_gap: !known,
            ..Default::default()
        }
    }
}

impl ForeignBpf {
    pub fn features(&self) -> KernelTrustFeatures {
        KernelTrustFeatures {
            foreign_bpf_on_hook: true,
            ..Default::default()
        }
    }
}

impl DevmemAccess {
    pub fn features(&self) -> KernelTrustFeatures {
        KernelTrustFeatures {
            devmem_write_intent: self.write_intent != 0 || self.mmap_prot_write != 0,
            ..Default::default()
        }
    }
}

impl MsrWrite {
    pub fn features(&self) -> KernelTrustFeatures {
        KernelTrustFeatures {
            msr_sensitive_write: self.sensitive != 0,
            ..Default::default()
        }
    }
}

impl SensorUnavailable {
    pub fn features(&self) -> KernelTrustFeatures {
        KernelTrustFeatures {
            coverage_gap: true,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc_ksym(d: &KsymDrift) -> Vec<u8> {
        let mut b = Vec::with_capacity(32);
        b.extend_from_slice(&d.resolved_addr.to_le_bytes());
        b.extend_from_slice(&d.expected_lo.to_le_bytes());
        b.extend_from_slice(&d.expected_hi.to_le_bytes());
        b.extend_from_slice(&d.reason.to_le_bytes());
        b.extend_from_slice(&d.symbol_id.to_le_bytes());
        b
    }

    fn enc_posture(p: &KernelPosture) -> Vec<u8> {
        let mut b = Vec::with_capacity(16);
        b.extend_from_slice(&p.lockdown_level.to_le_bytes());
        b.extend_from_slice(&p.sig_enforce.to_le_bytes());
        b.extend_from_slice(&p.secure_boot.to_le_bytes());
        b.extend_from_slice(&p.taint_flags.to_le_bytes());
        b
    }

    fn enc_unavail(u: &SensorUnavailable) -> Vec<u8> {
        let mut b = Vec::with_capacity(8);
        b.extend_from_slice(&u.signal_id.to_le_bytes());
        b.extend_from_slice(&u.errno_value.to_le_bytes());
        b
    }

    #[test]
    fn ksym_drift_round_trip_and_reason() {
        let d = KsymDrift {
            resolved_addr: 0xffff_ffff_8128_a0b0,
            expected_lo: 0xffff_ffff_8100_0000,
            expected_hi: 0xffff_ffff_81e0_0000,
            reason: HK_KSYM_OOB,
            symbol_id: 0,
        };
        let bytes = enc_ksym(&d);
        assert_eq!(bytes.len(), 32);
        let got = KsymDrift::decode(&bytes).expect("decode");
        assert_eq!(got, d);
        assert!(got.features().ksym_out_of_bounds);
        assert!(!got.features().ksym_shadowed);
    }

    #[test]
    fn posture_weak_only_when_both_known_and_off() {
        let weak = KernelPosture {
            lockdown_level: 0,
            sig_enforce: 0,
            secure_boot: 0,
            taint_flags: 0,
        };
        assert!(weak.features().posture_weak);
        assert!(!weak.features().coverage_gap);

        let unknown = KernelPosture {
            lockdown_level: HK_POSTURE_UNKNOWN,
            sig_enforce: HK_POSTURE_UNKNOWN,
            secure_boot: HK_POSTURE_UNKNOWN,
            taint_flags: 0,
        };
        // Unknown posture is a coverage gap, NOT "weak" (no false insecurity).
        assert!(!unknown.features().posture_weak);
        assert!(unknown.features().coverage_gap);

        let enforced = KernelPosture {
            lockdown_level: 1,
            sig_enforce: 1,
            secure_boot: 1,
            taint_flags: 0,
        };
        assert!(!enforced.features().posture_weak);
    }

    #[test]
    fn sensor_unavailable_is_coverage_not_detection() {
        let u = SensorUnavailable {
            signal_id: 91,
            errno_value: 1,
        };
        let bytes = enc_unavail(&u);
        assert_eq!(bytes.len(), 8);
        let got = SensorUnavailable::decode(&bytes).expect("decode");
        assert_eq!(got, u);
        let f = got.features();
        assert!(f.coverage_gap);
        // It must NOT set any detection feature.
        assert!(!f.ksym_out_of_bounds);
        assert!(!f.module_disk_drift);
        assert!(!f.msr_sensitive_write);
    }

    #[test]
    fn dispatch_by_type_and_unknown() {
        let p = KernelPosture {
            lockdown_level: 0,
            sig_enforce: 0,
            secure_boot: 0,
            taint_flags: 0x40,
        };
        let bytes = enc_posture(&p);
        match decode_event(HK_EVENT_KERNEL_POSTURE, &bytes).expect("decode") {
            KernelEventKind::KernelPosture(d) => assert_eq!(d.taint_flags, 0x40),
            other => panic!("wrong variant: {other:?}"),
        }
        assert_eq!(
            decode_event(999, &[0u8; 32]).expect_err("unknown"),
            KernelEventError::UnknownType(999)
        );
    }

    #[test]
    fn short_buffer_is_typed_error_not_panic() {
        let short = [0u8; 4];
        match KsymDrift::decode(&short).expect_err("must be Short") {
            KernelEventError::Short { got, .. } => assert_eq!(got, 4),
            other => panic!("wrong error: {other:?}"),
        }
    }
}
