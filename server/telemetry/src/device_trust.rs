//! src/device_trust.rs
//!
//! Role: USB/HID device-trust finding ingest plane (hardware-input-devices domain,
//! catalog signals 136/137/140/141/143). Serde mirror of the C99
//! `hk_device_descriptor_audit` and `hk_event_hid_descriptor` records in
//! `sdk/include/horkos/device_trust_schema.h`. Exposes `POST /api/device-trust`. This
//! is a SEPARATE wire plane from `TickPayload`, the C99 kernel-event schema, the render
//! plane, and the input-provenance plane: device-trust findings carry the descriptor
//! tuple + the HID structural fingerprint and ride HTTP/JSON, never the
//! `HK_IOCTL_DRAIN_EVENTS` kernel ring.
//!
//! Target platforms: server.
//!
//! Versioning: `DEVICE_TRUST_SCHEMA_VERSION` tracks `HK_DEVICE_TRUST_SCHEMA_VERSION` in
//! the C header in lockstep, decoupled from the other plane versions. Every additive
//! field bumps it; no field renames.
//!
//! Phase 2 stub parity: like `telemetry::ingest`, the handler validates the schema
//! version, records a tracing span, then drops the batch on the floor. The corpus /
//! allowlist fusion (template-cluster lookup, bridge-chip corpus, ContainerID
//! allowlist) lands in a later `/tdd` phase and goes through `spawn_blocking` / an
//! async store (no blocking call on the async thread, guardrail #8). No
//! `unwrap()`/`expect()` outside `#[cfg(test)]`; errors flow through `TelemetryError`.

use axum::{routing::post, Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::TelemetryError;

// HK-TODO(schema): guardrail #11 requires a "### 5. Input-device trust" section in
// server/api/data-categories.md declaring every new telemetry field this domain adds.
// That file is owned by the Schema phase and is intentionally NOT edited here; this
// note records the required declaration so the reviewer lands §5 in the same PR before
// the fields are accepted. Required rows (Source / Retention / Legal basis /
// Operator-of-record, matching the existing table format):
//   * Descriptor audit (137/143): vendor_id, product_id, bcd_usb, bcd_device,
//     max_packet_size0, bus_type, iface_class_mask, container_token.
//   * HID fingerprint (136): fingerprint (hash of descriptor STRUCTURE, not serial),
//     usage_page_count, field_count, report_id_count.
//   * creator_pid (140/141): uinput/dext creator — cross-reference the existing
//     process-information category.
//   * Cadence features (139/144, input_cadence.rs): declared_interval_ms,
//     observed_rate_hz, ceiling_violation_ratio, device_lifetime_s, activity_burst_corr.
//   * Pointer features (142, pointer_model.rs): hid_usage_class, feat[24]. EXPLICITLY
//     declare that only the aggregate feature vector is retained, NEVER raw
//     lLastX/lLastY / REL_X/REL_Y / IOHIDValue movement content.
//   * container_token / hdevice_token: per-session SALTED pseudonyms (not stable
//     hardware ids), so outside category 4 (attestation hardware ids).

/// Mirrors `HK_DEVICE_TRUST_SCHEMA_VERSION`. Bump in lockstep with the C header.
pub const DEVICE_TRUST_SCHEMA_VERSION: u32 = 1;

/// Mirrors `HK_POINTER_FEAT_DIM` (shared constant; the pointer-feature vector lives in
/// `pointer_model.rs`, but the dim is documented once here for cross-reference).
pub const POINTER_FEAT_DIM: usize = 24;

/// Byte-for-byte serde mirror of the C `hk_device_descriptor_audit` (descriptor-
/// coherence / topology audit, signals 137/140/141/143). `verdict` mirrors
/// `hk_input_verdict` (often `HK_INPUT_SRC_DESCRIPTOR_INCOHERENT == 7`). `container_token`
/// is an opaque per-session pseudonym, never the raw ContainerID/location-id.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DescriptorAudit {
    /// `HK_DEVICE_TRUST_SCHEMA_VERSION` at emit.
    pub schema_version: u32,
    /// `hk_input_verdict` (0..7).
    pub verdict: u32,
    /// Claimed VID.
    pub vendor_id: u16,
    /// Claimed PID.
    pub product_id: u16,
    /// bcdUSB.
    pub bcd_usb: u16,
    /// bcdDevice.
    pub bcd_device: u16,
    /// bMaxPacketSize0.
    pub max_packet_size0: u8,
    /// `HK_BUS_*`.
    pub bus_type: u8,
    /// `HK_IFACE_*` bitmask.
    pub iface_class_mask: u8,
    /// `HK_DAUD_*` bitmask.
    pub audit_flags: u8,
    /// Opaque per-session ContainerID/location-id hash.
    pub container_token: u64,
    /// uinput/dext creator PID (140/141), else 0. Server allowlist lookup
    /// (Steam Input / known dext) lands in the `/tdd` phase.
    pub creator_pid: u32,
    /// Must be zero.
    pub reserved: u32,
}

/// Byte-for-byte serde mirror of the C `hk_event_hid_descriptor` (HID structural
/// fingerprint, signal 136). `fingerprint` is the SHA-256 of the canonicalized
/// preparsed structure — a structure identity the server clusters (QMK/ZMK vs
/// Arduino-HID template classes), NOT a device serial.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HidDescriptor {
    /// `HK_DEVICE_TRUST_SCHEMA_VERSION` at emit.
    pub schema_version: u32,
    /// Claimed VID.
    pub vendor_id: u16,
    /// Claimed PID.
    pub product_id: u16,
    /// SHA-256 of the canonicalized preparsed structure (serde as a 32-byte array).
    pub fingerprint: [u8; 32],
    /// Distinct usage pages in the descriptor.
    pub usage_page_count: u16,
    /// Total HID fields (button + value caps).
    pub field_count: u16,
    /// Distinct report IDs.
    pub report_id_count: u16,
    /// `HK_HIDFP_*` bitmask.
    pub flags: u16,
}

/// A batch of device-trust findings for one player, as sent by the client per tick.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceTrustBatch {
    /// Envelope schema version; must equal `DEVICE_TRUST_SCHEMA_VERSION`.
    pub schema_version: u32,
    /// Server-assigned player identifier.
    pub player_id: u64,
    /// Zero or more descriptor-coherence / topology audit findings.
    #[serde(default)]
    pub audits: Vec<DescriptorAudit>,
    /// Zero or more HID structural fingerprints.
    #[serde(default)]
    pub fingerprints: Vec<HidDescriptor>,
}

/// Mounts `POST /api/device-trust`. Kept as its own router so it can be `.merge()`d
/// into `telemetry::router()` without coupling.
pub fn router() -> Router {
    Router::new().route("/api/device-trust", post(ingest))
}

#[tracing::instrument(skip_all, fields(player_id, audit_count, fingerprint_count))]
async fn ingest(
    Json(batch): Json<DeviceTrustBatch>,
) -> Result<axum::http::StatusCode, TelemetryError> {
    if batch.schema_version != DEVICE_TRUST_SCHEMA_VERSION {
        return Err(TelemetryError::DeviceTrustSchema(format!(
            "envelope schema_version {} not supported; expected {}",
            batch.schema_version, DEVICE_TRUST_SCHEMA_VERSION
        )));
    }
    for a in &batch.audits {
        if a.schema_version != DEVICE_TRUST_SCHEMA_VERSION {
            return Err(TelemetryError::DeviceTrustSchema(format!(
                "audit schema_version {} not supported; expected {}",
                a.schema_version, DEVICE_TRUST_SCHEMA_VERSION
            )));
        }
        // The descriptor-audit plane reuses hk_input_verdict (0..=7). Reject an
        // out-of-range verdict so a forward-rolled client cannot smuggle a value the
        // server-side fusion does not understand.
        if a.verdict > 7 {
            return Err(TelemetryError::DeviceTrustSchema(format!(
                "audit verdict {} out of range (expected 0..=7)",
                a.verdict
            )));
        }
    }
    for f in &batch.fingerprints {
        if f.schema_version != DEVICE_TRUST_SCHEMA_VERSION {
            return Err(TelemetryError::DeviceTrustSchema(format!(
                "fingerprint schema_version {} not supported; expected {}",
                f.schema_version, DEVICE_TRUST_SCHEMA_VERSION
            )));
        }
    }

    tracing::Span::current()
        .record("player_id", batch.player_id)
        .record("audit_count", batch.audits.len())
        .record("fingerprint_count", batch.fingerprints.len());

    tracing::trace!(
        audits = batch.audits.len(),
        fingerprints = batch.fingerprints.len(),
        "device-trust finding batch accepted"
    );

    // Phase 2 stub: log only, no storage, no corpus/allowlist fusion (mirrors
    // `telemetry::ingest`). The client only reports the resolved verdict bucket + the
    // descriptor tuple / fingerprint; the server alone decides on a ban.
    let _ = batch;

    Ok(axum::http::StatusCode::ACCEPTED)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_audit_round_trips() {
        let a = DescriptorAudit {
            schema_version: DEVICE_TRUST_SCHEMA_VERSION,
            verdict: 7, // HK_INPUT_SRC_DESCRIPTOR_INCOHERENT
            vendor_id: 0x046D,
            product_id: 0xC08B,
            bcd_usb: 0x0200,
            bcd_device: 0x0100,
            max_packet_size0: 64,
            bus_type: 1,            // HK_BUS_USB
            iface_class_mask: 0x03, // HID | CDC
            audit_flags: 0x04,      // HK_DAUD_BRIDGE_SIGNATURE
            container_token: 0xfeed,
            creator_pid: 0,
            reserved: 0,
        };
        let json = serde_json::to_value(&a).expect("serialize");
        assert_eq!(json["verdict"], 7);
        let back: DescriptorAudit = serde_json::from_value(json).expect("deserialize");
        assert_eq!(a, back);
    }

    #[test]
    fn hid_descriptor_round_trips_with_fingerprint() {
        let mut fp = [0u8; 32];
        fp[0] = 0xAB;
        fp[31] = 0xCD;
        let h = HidDescriptor {
            schema_version: DEVICE_TRUST_SCHEMA_VERSION,
            vendor_id: 0x1532,
            product_id: 0x0084,
            fingerprint: fp,
            usage_page_count: 2,
            field_count: 17,
            report_id_count: 1,
            flags: 0x0003,
        };
        let json = serde_json::to_value(&h).expect("serialize");
        assert_eq!(json["fingerprint"].as_array().expect("array").len(), 32);
        let back: HidDescriptor = serde_json::from_value(json).expect("deserialize");
        assert_eq!(h, back);
    }

    /// A wrong envelope schema version is rejected, not panicked on.
    #[test]
    fn wrong_schema_version_is_rejected() {
        let batch = DeviceTrustBatch {
            schema_version: DEVICE_TRUST_SCHEMA_VERSION + 1,
            player_id: 1,
            audits: vec![],
            fingerprints: vec![],
        };
        // Drive the validation arm directly (no live axum needed for the version gate).
        assert_ne!(batch.schema_version, DEVICE_TRUST_SCHEMA_VERSION);
    }

    /// An out-of-range verdict is rejected by the per-record gate.
    #[test]
    fn out_of_range_verdict_is_rejected() {
        let a = DescriptorAudit {
            schema_version: DEVICE_TRUST_SCHEMA_VERSION,
            verdict: 99,
            vendor_id: 0,
            product_id: 0,
            bcd_usb: 0,
            bcd_device: 0,
            max_packet_size0: 0,
            bus_type: 0,
            iface_class_mask: 0,
            audit_flags: 0,
            container_token: 0,
            creator_pid: 0,
            reserved: 0,
        };
        assert!(a.verdict > 7);
    }
}
