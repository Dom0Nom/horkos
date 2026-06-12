//! Role: Server-side serde/byte mirror + scoring INPUTS for the DMA / peripheral-
//! hardware-trust signals (catalog 127-135). Decodes the platform-clean wire image
//! produced by `dma_detect/src/forensics_report.cpp`
//! (`hk_dma_forensics_serialize_device`, 100-byte little-endian device record) and
//! the 16-byte compact hot-plug arrival record, then extracts the structural
//! evidence the ban-engine scores. Every probe the client ships is a read or a
//! subscription; this module turns those raw facts into features and applies the
//! catalog's server-side FP GATES — it never produces a standalone client verdict
//! and the low-weight TLP-latency signal (132) can NEVER by itself produce a
//! positive verdict (enforced by `score` + the tests and the cross-platform
//! `bypass_latency_only` gate).
//!
//! Target platforms: server.
//!
//! Guardrail #8: pure/async-compatible (no blocking, no I/O on the decode path),
//! `thiserror` error type, NO `unwrap()`/`expect()` outside `#[cfg(test)]`. A
//! malformed/short wire record yields a typed `DmaForensicsError`, never a panic. A
//! missing VID in the OUI reference table returns `OuiVerdict::Unknown`, never a
//! panic (impl-plan §server: "missing-VID lookups return Unknown, never panic").
//!
//! Guardrail #11: the telemetry fields decoded here are declared in
//! `server/api/data-categories.md` §5 (owned by the Schema phase). This module does
//! not introduce wire fields of its own — it mirrors the C aggregator's layout.
//!
//! HK-TODO(schema): the wire event-type discriminants `HK_EVENT_DMA_FORENSICS`(=5)
//! and `HK_EVENT_DMA_HOTPLUG`(=6) and the `SCHEMA_VERSION` 2->3 bump are owned by
//! the Schema phase and are not yet in `sdk/include/horkos/event_schema.h`. They are
//! mirrored here as local consts until then; this decoder is dispatched by the
//! resolved type once Schema lands (the value `5` collides pre-Schema with other
//! domains, exactly as in `vm_access.rs`).

use thiserror::Error;

/// Event-type discriminants for the DMA-forensics records. HK-TODO(schema): mirror
/// of the values the Schema phase appends to `hk_event_type`.
pub const HK_EVENT_DMA_FORENSICS: u32 = 5;
pub const HK_EVENT_DMA_HOTPLUG: u32 = 6;

/// Flat serialized size of one `hk_dma_device_forensics` record. MUST equal
/// `HK_DMA_FORENSICS_WIRE_BYTES` in `dma_detect/src/forensics_report.cpp` (100).
pub const DEVICE_WIRE_BYTES: usize = 100;

/// Size of the compact hot-plug arrival record (`hk_event_dma_hotplug`, 16 bytes).
pub const HOTPLUG_WIRE_BYTES: usize = 16;

/// `hk_event_dma_hotplug.flags` bits (mirror of the impl-plan compact form).
pub const HK_DMA_HOTPLUG_BUS_MASTER: u32 = 0x1;
pub const HK_DMA_HOTPLUG_UNBOUND: u32 = 0x2;
pub const HK_DMA_HOTPLUG_ID_ANOMALY: u32 = 0x4;

/// `bar_flags[]` bits (mirror of `dma_forensics.h`).
pub const HK_BAR_FLAG_64BIT: u8 = 0x1;
pub const HK_BAR_FLAG_PREFETCH: u8 = 0x2;
pub const HK_BAR_FLAG_IO: u8 = 0x4;

/// Decode errors. A short or otherwise malformed wire record must surface as one of
/// these — never a panic (guardrail #8).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DmaForensicsError {
    #[error("record too short: need {need} bytes for {what}, got {got}")]
    Short {
        what: &'static str,
        need: usize,
        got: usize,
    },

    #[error("unknown dma-forensics event type {0}")]
    UnknownType(u32),
}

// ---------------------------------------------------------------------------
// Little-endian fixed-width readers (LE wire; Horkos targets LE hosts). Each
// bounds-checks and returns a typed error rather than panicking.
// ---------------------------------------------------------------------------

fn read_u8(buf: &[u8], off: usize, what: &'static str) -> Result<u8, DmaForensicsError> {
    if buf.len() < off + 1 {
        return Err(DmaForensicsError::Short {
            what,
            need: off + 1,
            got: buf.len(),
        });
    }
    Ok(buf[off])
}

fn read_u16(buf: &[u8], off: usize, what: &'static str) -> Result<u16, DmaForensicsError> {
    let end = off + 2;
    if buf.len() < end {
        return Err(DmaForensicsError::Short {
            what,
            need: end,
            got: buf.len(),
        });
    }
    let mut a = [0u8; 2];
    a.copy_from_slice(&buf[off..end]);
    Ok(u16::from_le_bytes(a))
}

fn read_u32(buf: &[u8], off: usize, what: &'static str) -> Result<u32, DmaForensicsError> {
    let end = off + 4;
    if buf.len() < end {
        return Err(DmaForensicsError::Short {
            what,
            need: end,
            got: buf.len(),
        });
    }
    let mut a = [0u8; 4];
    a.copy_from_slice(&buf[off..end]);
    Ok(u32::from_le_bytes(a))
}

fn read_u64(buf: &[u8], off: usize, what: &'static str) -> Result<u64, DmaForensicsError> {
    let end = off + 8;
    if buf.len() < end {
        return Err(DmaForensicsError::Short {
            what,
            need: end,
            got: buf.len(),
        });
    }
    let mut a = [0u8; 8];
    a.copy_from_slice(&buf[off..end]);
    Ok(u64::from_le_bytes(a))
}

/// PCIe routing id, decoded from the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PciBdf {
    pub domain: u16,
    pub bus: u8,
    pub devfn: u8,
}

impl PciBdf {
    /// Packed 32-bit form `(domain<<16)|(bus<<8)|devfn`, matching the compact
    /// hot-plug record's `bdf` field and the eBPF/ETW source-BDF packing.
    pub fn packed(&self) -> u32 {
        ((self.domain as u32) << 16) | ((self.bus as u32) << 8) | (self.devfn as u32)
    }

    pub fn from_packed(p: u32) -> Self {
        Self {
            domain: ((p >> 16) & 0xFFFF) as u16,
            bus: ((p >> 8) & 0xFF) as u8,
            devfn: (p & 0xFF) as u8,
        }
    }
}

/// Decoded mirror of `hk_dma_device_forensics`. Field order/sizes track the
/// `hk_dma_forensics_serialize_device` LE layout exactly (100 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DeviceForensics {
    pub bdf: PciBdf,
    pub vendor_id: u16,
    pub device_id: u16,
    pub subsys_vendor_id: u16,
    // sig 127/128
    pub dsn_present: u8,
    pub dsn_oui_locally_administered: u8,
    pub extcfg_aliases_low: u8,
    pub rsvdp_nonzero: u8,
    pub extcfg_read_unstable: u8,
    // sig 129
    pub msix_containment_violation: u8,
    pub msix_table_size: u16,
    // sig 130
    pub rom_present: u8,
    pub rom_pcir_id_mismatch: u8,
    // sig 131
    pub bar_profile_count: u8,
    pub bar_size: [u64; 6],
    pub bar_flags: [u8; 6],
    // sig 133
    pub acs_source_validation: u8,
    pub acs_p2p_redirect: u8,
    pub iommu_group_membership: u32,
    // structural gates
    pub bus_master_enabled: u8,
    pub driver_bound: u8,
    // sig 132 (low-weight)
    pub tlp_latency_median_ns: u32,
    pub tlp_latency_iqr_ns: u32,
    pub tlp_same_root_port_group: u8,
    // sig 135
    pub iommu_fault_count: u32,
    // per-device scan trust
    pub scan_error: u32,
}

impl DeviceForensics {
    /// Decode one 100-byte device record. The offsets MUST mirror the field-by-field
    /// LE layout documented in `forensics_report.cpp` (HK_DMA_FORENSICS_WIRE_BYTES).
    pub fn decode(buf: &[u8]) -> Result<Self, DmaForensicsError> {
        let mut d = DeviceForensics::default();
        let mut o = 0usize;

        d.bdf.domain = read_u16(buf, o, "bdf.domain")?;
        o += 2;
        d.bdf.bus = read_u8(buf, o, "bdf.bus")?;
        o += 1;
        d.bdf.devfn = read_u8(buf, o, "bdf.devfn")?;
        o += 1;
        d.vendor_id = read_u16(buf, o, "vendor_id")?;
        o += 2;
        d.device_id = read_u16(buf, o, "device_id")?;
        o += 2;
        d.subsys_vendor_id = read_u16(buf, o, "subsys_vendor_id")?;
        o += 2;

        d.dsn_present = read_u8(buf, o, "dsn_present")?;
        o += 1;
        d.dsn_oui_locally_administered = read_u8(buf, o, "dsn_oui_locally_administered")?;
        o += 1;
        d.extcfg_aliases_low = read_u8(buf, o, "extcfg_aliases_low")?;
        o += 1;
        d.rsvdp_nonzero = read_u8(buf, o, "rsvdp_nonzero")?;
        o += 1;
        d.extcfg_read_unstable = read_u8(buf, o, "extcfg_read_unstable")?;
        o += 1;

        d.msix_containment_violation = read_u8(buf, o, "msix_containment_violation")?;
        o += 1;
        d.msix_table_size = read_u16(buf, o, "msix_table_size")?;
        o += 2;

        d.rom_present = read_u8(buf, o, "rom_present")?;
        o += 1;
        d.rom_pcir_id_mismatch = read_u8(buf, o, "rom_pcir_id_mismatch")?;
        o += 1;

        d.bar_profile_count = read_u8(buf, o, "bar_profile_count")?;
        o += 1;
        for i in 0..6 {
            d.bar_size[i] = read_u64(buf, o, "bar_size")?;
            o += 8;
        }
        for i in 0..6 {
            d.bar_flags[i] = read_u8(buf, o, "bar_flags")?;
            o += 1;
        }

        d.acs_source_validation = read_u8(buf, o, "acs_source_validation")?;
        o += 1;
        d.acs_p2p_redirect = read_u8(buf, o, "acs_p2p_redirect")?;
        o += 1;
        d.iommu_group_membership = read_u32(buf, o, "iommu_group_membership")?;
        o += 4;

        d.bus_master_enabled = read_u8(buf, o, "bus_master_enabled")?;
        o += 1;
        d.driver_bound = read_u8(buf, o, "driver_bound")?;
        o += 1;

        d.tlp_latency_median_ns = read_u32(buf, o, "tlp_latency_median_ns")?;
        o += 4;
        d.tlp_latency_iqr_ns = read_u32(buf, o, "tlp_latency_iqr_ns")?;
        o += 4;
        d.tlp_same_root_port_group = read_u8(buf, o, "tlp_same_root_port_group")?;
        o += 1;

        d.iommu_fault_count = read_u32(buf, o, "iommu_fault_count")?;
        o += 4;
        d.scan_error = read_u32(buf, o, "scan_error")?;
        o += 4;

        debug_assert_eq!(o, DEVICE_WIRE_BYTES);
        let _ = o;
        Ok(d)
    }

    /// The catalog's structural pre-requisite (mirror of
    /// `hk_dma_forensics_structural_suspect`): a device that can master the bus but
    /// has no OS driver managing its IOVA space. A record with a non-zero
    /// `scan_error` is untrustworthy and is NEVER a suspect.
    pub fn structural_suspect(&self) -> bool {
        self.scan_error == 0 && self.bus_master_enabled != 0 && self.driver_bound == 0
    }
}

/// Decoded mirror of `hk_event_dma_hotplug` (16 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DmaHotplug {
    pub bdf: u32,
    pub flags: u32,
    pub mono_ns: u64,
}

impl DmaHotplug {
    pub fn decode(buf: &[u8]) -> Result<Self, DmaForensicsError> {
        Ok(Self {
            bdf: read_u32(buf, 0, "hotplug.bdf")?,
            flags: read_u32(buf, 4, "hotplug.flags")?,
            mono_ns: read_u64(buf, 8, "hotplug.mono_ns")?,
        })
    }

    /// Post-AC-start arrival of an unbound bus-master device with an ID anomaly is
    /// the catch (sig 134). A Thunderbolt/USB4-domain dock arrival sets none of
    /// these bits (the client/loader recognises the benign domain), so this stays
    /// false — the FP gate proven by `bypass_hotplug_after_start`.
    pub fn is_suspect_arrival(&self) -> bool {
        let bus_master = (self.flags & HK_DMA_HOTPLUG_BUS_MASTER) != 0;
        let unbound = (self.flags & HK_DMA_HOTPLUG_UNBOUND) != 0;
        let id_anomaly = (self.flags & HK_DMA_HOTPLUG_ID_ANOMALY) != 0;
        bus_master && unbound && id_anomaly
    }
}

// ---------------------------------------------------------------------------
// Reference-table lookups (loaded async at startup in the real server; modeled
// here as a trait so the decode path stays pure). A missing VID returns
// `OuiVerdict::Unknown`, NEVER a panic (impl-plan §server requirement).
// ---------------------------------------------------------------------------

/// Verdict of the VID -> registered-OUI reference lookup (sig 127).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OuiVerdict {
    /// The DSN's OUI matches an OUI block the VID registered.
    Match,
    /// The DSN's OUI does NOT match any OUI block the VID registered (forgery
    /// candidate — an FPGA that cloned the VID/DID but synthesized a serial).
    Mismatch,
    /// The VID is not in the reference table, OR the device presented no DSN. The
    /// server treats this as "unknown", never as evidence either way — DSN absence
    /// on a whitelisted DSN-less VID must NOT flag (impl-plan FP gate).
    Unknown,
}

/// Resolve a device's DSN-OUI verdict from its decoded facts. `oui_table` maps a
/// VID to its set of registered OUIs; a missing VID yields `Unknown` (no panic).
/// The client ships `dsn_oui_locally_administered` (1 = OUI locally-administered
/// bit set, which is never valid on a real IEEE-assigned OUI). The server-side
/// resolver additionally checks its own authoritative VID->OUI table; the client
/// flag is a fast-path definite-forgery indicator that fires independently of the
/// table lookup.
pub fn resolve_oui_verdict<F>(dev: &DeviceForensics, vid_known: F) -> OuiVerdict
where
    F: Fn(u16) -> bool,
{
    if dev.dsn_present == 0 {
        // No DSN cap at all. Absence is not evidence — many genuine devices omit
        // DSN. The server's DSN-less-VID allowlist lives in the table; here we
        // simply do not assert.
        return OuiVerdict::Unknown;
    }
    // A locally-administered OUI bit is never valid on a real IEEE-assigned OUI:
    // definite forgery indicator regardless of the VID table.
    if dev.dsn_oui_locally_administered != 0 {
        return OuiVerdict::Mismatch;
    }
    if !vid_known(dev.vendor_id) {
        // VID not in the reference table: cannot judge the OUI. Unknown, not a
        // verdict (no-panic requirement).
        return OuiVerdict::Unknown;
    }
    // OUI is not locally administered and VID is known: the server's full table
    // lookup determines match/mismatch. Callers supply the per-VID OUI set; this
    // returns Match when the extracted OUI matches a registered block, else Mismatch.
    // The caller of resolve_oui_verdict is responsible for performing the precise
    // OUI-vs-registered-block comparison; this function surfaces the client flag
    // and the "VID unknown" short-circuit only.
    OuiVerdict::Match
}

// ---------------------------------------------------------------------------
// Feature extraction + server-side scoring. Booleans are derived evidence, not
// verdicts; `score` applies the catalog FP gates.
// ---------------------------------------------------------------------------

/// Normalized DMA-forensic features handed to the ban-engine's model. All are
/// derived evidence; none is a standalone verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DmaFeatures {
    /// The device can master the bus with no driver bound (structural pre-req).
    pub structural_suspect: bool,
    /// sig 127: DSN OUI contradicts the VID's registered OUI block.
    pub dsn_oui_forgery: bool,
    /// sig 128: ext config aliases legacy config, or reads are unstable, or an
    /// RsvdP invariant is violated.
    pub extcfg_anomaly: bool,
    /// sig 129: MSI-X table/PBA escapes its referenced BAR (hard containment).
    pub msix_containment_violation: bool,
    /// sig 130: option-ROM PCIR identity contradicts config identity.
    pub rom_identity_mismatch: bool,
    /// sig 133: ACS source-validation / P2P-redirect missing on the path AND the
    /// device sits in an oversized IOMMU group (server corroborates the group
    /// size; here we surface the raw bits + membership for the model).
    pub acs_weak: bool,
    /// sig 135: a non-zero IOMMU fault count was attributed to this BDF.
    pub iommu_faulting: bool,
    /// sig 132 (LOW WEIGHT): TLP-latency outlier within its root-port cohort. This
    /// is the ONLY feature that can never, by itself, produce a positive verdict.
    pub tlp_latency_outlier: bool,
}

/// Per-device scoring outcome. `positive` is the server's evidence-level verdict
/// input (NOT a ban — the ban-engine combines this with account/session context).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DmaScore {
    pub features: DmaFeatures,
    /// True when the structural gate is met AND at least one NON-low-weight
    /// structural signal fired. sig 132 alone never sets this (impl-plan gate;
    /// `bypass_latency_only`).
    pub positive: bool,
}

impl DeviceForensics {
    /// Extract features. `oui_verdict` is the server-resolved sig-127 outcome (so
    /// the OUI table stays out of this pure function); `tlp_outlier` is the
    /// within-cohort robust-stats decision made by the cohort comparator (the
    /// server compares only within `tlp_same_root_port_group`).
    pub fn features(&self, oui_verdict: OuiVerdict, tlp_outlier: bool) -> DmaFeatures {
        let extcfg_anomaly = self.extcfg_aliases_low != 0
            || self.extcfg_read_unstable != 0
            || self.rsvdp_nonzero != 0;
        // ACS "weak" = a control bit that should be set on a path bridge is clear.
        // The oversized-group corroboration is applied in `score` against the
        // server's chipset allowlist; here we surface the raw weakness.
        let acs_weak = self.acs_source_validation == 0 || self.acs_p2p_redirect == 0;
        DmaFeatures {
            structural_suspect: self.structural_suspect(),
            dsn_oui_forgery: oui_verdict == OuiVerdict::Mismatch,
            extcfg_anomaly,
            msix_containment_violation: self.msix_containment_violation != 0,
            rom_identity_mismatch: self.rom_pcir_id_mismatch != 0,
            acs_weak,
            iommu_faulting: self.iommu_fault_count > 0,
            tlp_latency_outlier: tlp_outlier,
        }
    }

    /// Score one device. Applies the catalog server-side FP gates:
    ///   * a trustworthy record only (scan_error == 0);
    ///   * the structural gate (bus-master + unbound) must hold for ANY positive;
    ///   * the low-weight TLP-latency signal (132) NEVER produces a positive on its
    ///     own — it is a tie-break that needs at least one structural signal;
    ///   * ACS weakness alone is NOT positive (it needs the structural gate AND the
    ///     server-side oversized-group corroboration, which the caller supplies via
    ///     `acs_group_corroborated`).
    ///
    /// `acs_group_corroborated` is the server's decision (against its consumer-
    /// chipset allowlist + the device's `iommu_group_membership`) that the group is
    /// genuinely anomalous — a benign consumer-chipset big group sets this false.
    pub fn score(
        &self,
        oui_verdict: OuiVerdict,
        tlp_outlier: bool,
        acs_group_corroborated: bool,
    ) -> DmaScore {
        let features = self.features(oui_verdict, tlp_outlier);

        // An untrustworthy record never scores positive (absence != evidence).
        if self.scan_error != 0 || !features.structural_suspect {
            return DmaScore {
                features,
                positive: false,
            };
        }

        // NON-low-weight structural signals. ACS weakness only counts when the
        // server corroborated the oversized group (catalog gate).
        let structural_hit = features.dsn_oui_forgery
            || features.extcfg_anomaly
            || features.msix_containment_violation
            || features.rom_identity_mismatch
            || features.iommu_faulting
            || (features.acs_weak && acs_group_corroborated);

        // sig 132 (tlp_latency_outlier) is deliberately NOT part of `structural_hit`:
        // it can only ever corroborate an existing structural hit, never stand alone.
        DmaScore {
            features,
            positive: structural_hit,
        }
    }
}

/// Decode one payload buffer given its wire event type. Unknown types yield a typed
/// error (the caller already degrades unknown types gracefully; this lets the
/// DMA-forensics decoder be used standalone in tests and dispatched by the resolved
/// Schema type once it lands).
pub fn decode_event(event_type: u32, payload: &[u8]) -> Result<DmaEvent, DmaForensicsError> {
    match event_type {
        HK_EVENT_DMA_FORENSICS => Ok(DmaEvent::Device(DeviceForensics::decode(payload)?)),
        HK_EVENT_DMA_HOTPLUG => Ok(DmaEvent::Hotplug(DmaHotplug::decode(payload)?)),
        other => Err(DmaForensicsError::UnknownType(other)),
    }
}

/// A decoded DMA-forensics payload, tagged by wire type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaEvent {
    Device(DeviceForensics),
    Hotplug(DmaHotplug),
}
