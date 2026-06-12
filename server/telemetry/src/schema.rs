//! Role: The HTTP/JSON per-tick telemetry ingest contract (`TickPayload`). This
//! is an INDEPENDENT wire plane from the C99 kernel-event schema in
//! `sdk/include/horkos/event_schema.h` — it is a serde JSON struct (no
//! `#[repr(C)]`, not byte-compatible with any C struct) carrying gameplay
//! signal (player id, tick, aim deltas, input bitmask), not the kernel
//! process/image/handle records.
//!
//! Target platforms: server.
//!
//! Versioning: `SCHEMA_VERSION` is the tick-stream version, intentionally
//! decoupled from `HK_EVENT_SCHEMA_VERSION`. Every field addition bumps it; no
//! field renames; deprecated fields stay reserved.

use serde::{Deserialize, Serialize};

use crate::anti_analysis::AntiAnalysisPayload;
use crate::hv::HvReport;

/// Serde default for `tx_cadence_skew_ns`: `i64::MIN` is the no-data sentinel.
fn default_tx_cadence_skew_ns() -> i64 {
    i64::MIN
}

/// Version of the per-tick JSON ingest contract (distinct from the kernel
/// event schema's `HK_EVENT_SCHEMA_VERSION`). Bump on every additive change.
///
/// v2 adds the behavioral-aim feature block (catalog signals 163-171): raw-HID
/// provenance, quantization-floor, polling cadence, flick/reaction/recoil/
/// target-switch kinematics, cursor-confinement, and the OS injection bit. All
/// v2 fields are `#[serde(default)]` so a v1 client (omitting them) still
/// deserializes with zero/false defaults; the ingest handler accepts both `1`
/// and `2` during the migration window.
/// v3 adds the behavioral-gamestate binding fields (catalog signals 174/177/178):
/// the client-reported monotonic render time and display refresh (178 aliasing
/// inputs, never trusted as truth) and the per-tick shot-fired flag (174/177/180
/// shot-registration alignment, cross-checked vs. server hit-reg). All v3 fields are
/// `#[serde(default)]`, so a v1/v2 client still deserializes; the ingest handler
/// accepts `1..=3` during the migration window.
/// v4 adds the network-anomaly feature block (catalog signals 181-189, minus the
/// server-only 186): the per-window network-layer-integrity readings the `hk::net`
/// client probes ship — NIC-TX-vs-QPC cadence skew, clock-domain drift, kernel
/// TCP_INFO health, send-backlog pair, input-frame coherence flags, dual-channel
/// RTT pair, route-identity-change-without-event flag, and flow-owner (loopback
/// proxy) flag + interposer image hash. Signal 186 (arrival-cadence) is derived
/// server-side from the existing `tick`/`server_received_ts` and adds NO field. All
/// v4 fields are `#[serde(default)]`, so a v1/v2/v3 client still deserializes with
/// zeros (read by the server as "no network signal", never a fabricated anomaly);
/// the ingest handler accepts `1..=4` during the migration window. This is a serde
/// JSON struct (no `#[repr(C)]`, no C byte-mirror) — these network reads ride this
/// HTTP `TickPayload` plane, NOT the C99 kernel-event ring in `event_schema.h`/
/// `ioctl.h`, so no `hk_event_type`/IOCTL/`HK_STATIC_ASSERT` change is required.
/// v5 adds the OPTIONAL anti-analysis-environment sub-payload (catalog signals
/// 194 — dynamic-instrumentation/DBI residency, and 197 — memory-editor/debugger
/// host fingerprint ONLY; the other anti-analysis signals ride the
/// selfcheck/timing/eBPF/daemon planes). It mirrors `anti_analysis_report` in
/// `ac/include/horkos/anti_analysis/anti_analysis_signals.h`. Following the v4
/// network-anomaly optional-field precedent, the field is
/// `Option<AntiAnalysisPayload>` + `#[serde(default)]`, so a v1..=v4 client
/// omitting it deserializes to `None` (read by the server as "no anti-analysis
/// signal", never a fabricated anomaly); the ingest handler accepts `1..=5`
/// during the migration window. Serde JSON, no `#[repr(C)]`, no C byte-mirror, no
/// `HK_STATIC_ASSERT` (this never rides the kernel `event_schema.h`/IOCTL plane).
/// v6 adds the OPTIONAL hypervisor/virtualization-state sub-payload
/// (`Option<HvReport>` + `#[serde(default)]`, win-hypervisor-detection signals
/// 37/38/40/42/43/44/45), mirroring `hv_report` in `ac/include/horkos/hv_signals.h`;
/// a v1..=v5 client omitting it deserializes to `None`. The ingest handler accepts
/// `1..=6` during the migration window. Same serde-JSON, server-classifies posture.
pub const SCHEMA_VERSION: u32 = 6; // was 5; v6 adds the hypervisor-state sub-payload.

/// One tick of player state. Fixed serialised shape.
///
/// `Default` lets callers (and tests) build a baseline tick and set only the
/// fields they exercise — the v2 aim-feature block is large and mostly zero on
/// any given tick.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct TickPayload {
    /// Schema version of this payload.
    pub schema_version: u32,

    /// Server-assigned player identifier.
    pub player_id: u64,

    /// Monotonic tick counter from the client.
    ///
    /// CONTRACT (pipeline pairing): the SDK MUST echo the server simulation
    /// tick it is acting on (the `tick` of the last authoritative snapshot it
    /// consumed), NOT a free-running client counter. The server pipeline pairs
    /// this value against `snapshot_schema.h` `HkSnapshotRecord.tick` within a
    /// small tolerance window; a client that drifts or offsets this counter is
    /// never paired, which starves the gamestate analyzers and is surfaced as
    /// a pairing-integrity anomaly (Review-tier, never bannable alone).
    /// HK-UNCERTAIN(tick-domain): the SDK side does not ship this echo yet —
    /// until it does, only fixture/test traffic satisfies the contract.
    pub tick: u64,

    /// Aim delta on the X axis since the previous tick.
    pub aim_delta_x: f32,

    /// Aim delta on the Y axis since the previous tick.
    pub aim_delta_y: f32,

    /// Bitmask of input flags (movement, fire, jump, ...).
    pub input_state: u32,

    /// Server-side wall clock at receipt, in nanoseconds since UNIX epoch.
    /// Set by the server; clients send `0`.
    #[serde(default)]
    pub server_received_ts: u64,

    // ---------------------------------------------------------------------
    // behavioral-aim feature block (schema v2, catalog signals 163-171).
    //
    // These mirror `hk::sdk::aim::hk_aim_features` in
    // `sdk/src/input/AimSampler.h` (the SDK-side POD that `sdk.cpp` serialises
    // into this JSON). They are per-tick aim/pointer-motion metadata and
    // weapon/target gameplay state only — NEVER keystroke content or typed
    // text. The client ships raw features; ALL segmentation, distribution
    // fitting, human-floor comparison and verdicts are server-side (ban-engine
    // + ort/ONNX). No client-side thresholds (catalog mandate: the kinematic
    // signals 166/167/168/169 are population/distributional, server-only).
    //
    // Every field is `#[serde(default)]` so older (v1) payloads omitting them
    // still deserialize. This is a serde JSON struct with no `#[repr(C)]` and
    // no C byte-mirror, so there is no `HK_STATIC_ASSERT` size pin (it never
    // rides the kernel `event_schema.h`/IOCTL plane).
    //
    // HK-TODO(schema): guardrail #11 requires these field groups be declared in
    // `server/api/data-categories.md` §3 (Telemetry stream) in the same PR.
    // The Schema phase owns `data-categories.md`; that table currently lists
    // only the v1 fields, so the §3 rows for the v2 aim-feature groups below
    // (sourcing/retention/legal-basis per the impl-plan §2.4 table) must be
    // added by the Schema-phase owner before merge — this domain does not edit
    // `data-categories.md`.
    // ---------------------------------------------------------------------

    // -- 163 raw HID -> render provenance --
    /// HID reports consumed this tick.
    #[serde(default)]
    pub hid_report_count: u32,
    /// Summed raw integer HID counts, X.
    #[serde(default)]
    pub hid_raw_dx: i32,
    /// Summed raw integer HID counts, Y.
    #[serde(default)]
    pub hid_raw_dy: i32,
    /// Newest HID hardware/QPC timestamp seen this tick (ns).
    #[serde(default)]
    pub hid_newest_ts_ns: u64,

    // -- 164 quantization-floor --
    /// In-game DPI->angle sensitivity scalar, Q16.16 fixed-point.
    #[serde(default)]
    pub sens_scalar_q16: u32,
    /// Actually-applied view delta, X (radians).
    #[serde(default)]
    pub applied_angle_dx: f32,
    /// Actually-applied view delta, Y (radians).
    #[serde(default)]
    pub applied_angle_dy: f32,

    // -- 165 polling-interval jitter --
    /// Mean inter-report interval this tick (ns).
    #[serde(default)]
    pub hid_interval_mean_ns: u64,
    /// Variance of inter-report interval this tick (ns^2, saturated to u64).
    #[serde(default)]
    pub hid_interval_var_ns: u64,
    /// Count of inter-report intervals equal to the render-frame period.
    #[serde(default)]
    pub hid_interval_framelock_count: u32,

    // -- 166 flick curvature (engine-state transport, no OS API) --
    /// Angular velocity of the view vector (rad/s).
    #[serde(default)]
    pub ang_vel: f32,
    /// Angular acceleration (rad/s^2).
    #[serde(default)]
    pub ang_accel: f32,
    /// Third-difference angular jerk (rad/s^3).
    #[serde(default)]
    pub ang_jerk: f32,
    /// Angular distance to the nearest hitbox centre (rad).
    #[serde(default)]
    pub dist_to_nearest_target_rad: f32,

    // -- 167 reaction-latency floor --
    /// Occluded->visible onset timestamp (engine PVS), ns.
    #[serde(default)]
    pub target_vis_onset_ts_ns: u64,
    /// First corrective-impulse timestamp toward the newly-visible target, ns.
    #[serde(default)]
    pub first_impulse_ts_ns: u64,
    /// Fire-event timestamp toward it, ns.
    #[serde(default)]
    pub fire_ts_ns: u64,
    /// True iff the first impulse was a genuine new-direction change (not a
    /// continuation of prior tracking — guards the pre-aim/prediction FP).
    #[serde(default)]
    pub impulse_is_direction_change: bool,

    // -- 168 recoil phase-lock --
    /// Engine weapon id.
    #[serde(default)]
    pub weapon_id: u32,
    /// Shot index within the current burst.
    #[serde(default)]
    pub shot_index: u32,
    /// True iff the full-auto fire-bit was set this tick.
    #[serde(default)]
    pub fire_active: bool,

    // -- 169 target-switch latency --
    /// Id of the currently-aimed-at target.
    #[serde(default)]
    pub aimed_target_id: u64,
    /// Angular offsets of the candidate target set (variable length; rides the
    /// JSON envelope, not a fixed array — JSON has no fixed-array constraint and
    /// this is not a byte-mirrored plane).
    #[serde(default)]
    pub candidate_target_offsets: Vec<f32>,
    /// True iff the aim discretely re-locked onto a different target this tick.
    #[serde(default)]
    pub switch_event_flag: bool,

    // -- 170 cursor confinement (Windows + macOS) --
    /// True iff the OS clip rect still equals the game's confinement rect.
    #[serde(default)]
    pub clip_rect_ok: bool,
    /// True iff the system cursor is hidden (CURSOR_SHOWING absent).
    #[serde(default)]
    pub cursor_hidden: bool,
    /// |integrated raw motion - absolute cursor position|, pixels.
    #[serde(default)]
    pub raw_vs_abs_divergence_px: u32,
    /// True iff the game window holds focus (WM_ACTIVATE; alt-tab gate).
    #[serde(default)]
    pub focus_active: bool,

    // -- 171 OS injection bit --
    /// Fraction of aim events flagged injected this tick, Q0.8 fixed-point.
    #[serde(default)]
    pub injected_event_fraction_q8: u16,
    /// True iff a virtual/uinput HID source was seen this tick.
    #[serde(default)]
    pub virtual_device_present: bool,

    // ---------------------------------------------------------------------
    // behavioral-gamestate binding block (schema v3, catalog signals 172-180).
    //
    // These three additive fields bind a client tick to the authoritative snapshot
    // replay and feed the game-state-knowledge analyzers. They are CLIENT-reported
    // metadata only (timing + a fire bit); the server-only ground truth those
    // analyzers discriminate against rides the SEPARATE snapshot IPC plane
    // (`sdk/include/horkos/snapshot_schema.h` / `crate::snapshot`), never this JSON.
    //
    // HK-TODO(schema): guardrail #11 requires `client_mono_ns`, `client_refresh_hz`
    // and `fired` be declared in `server/api/data-categories.md` §3 (and the
    // server-internal snapshot plane in a new §5) in the SAME PR. The Schema phase
    // owns `data-categories.md`; this domain does not edit it (per the build
    // instructions). The §3 rows (source = client; retention = "session lifetime +
    // 30 days"; legal basis = Contract performance, or Legitimate-interest/anti-cheat
    // for `fired`) and the §5 authoritative-snapshot category must be added by the
    // data-categories owner before this PR merges, or guardrail #11 rejects it.
    // ---------------------------------------------------------------------
    /// Client-reported monotonic ns at frame render (178 aliasing input; never trusted
    /// as truth — a forged-constant value simply yields no spectral peak).
    #[serde(default)]
    pub client_mono_ns: u64,
    /// Client-reported display refresh rate (Hz) — harmonic-exclusion gate for 178.
    #[serde(default)]
    pub client_refresh_hz: u16,
    /// Client-reported shot-fired flag this tick (174/177/180 shot-registration
    /// alignment, cross-checked vs. server hit-reg before any verdict).
    #[serde(default)]
    pub fired: bool,

    // ---------------------------------------------------------------------
    // network-anomaly feature block (schema v4, catalog signals 181-189 minus
    // the server-only 186).
    //
    // These mirror the `hk::net` probe POD results in
    // `sdk/include/horkos/net_timing.h` (the SDK-side structs `sdk.cpp`
    // serialises into this JSON). They are per-upload-window network-layer-
    // integrity readings only: send-cadence/clock/queue/route/socket-owner
    // observations compared against OS/NIC ground truth — NEVER packet
    // payloads or peer addresses. The client ships RAW deltas/flags/pairs; ALL
    // classification (NTP-step vs smooth-scale, lag-switch correlation,
    // signed-interposer allowlisting, FP gating) is server-side. No client-side
    // verdict (catalog mandate + guardrail: ban authority is server-side).
    //
    // Every field is `#[serde(default)]` so a v1/v2/v3 payload omitting them
    // still deserializes to zeros — read as "no network signal", never a
    // fabricated positive. Serde JSON, no `#[repr(C)]`, no C byte-mirror, no
    // `HK_STATIC_ASSERT` (this never rides the kernel `event_schema.h`/IOCTL
    // plane).
    //
    // HK-TODO(schema): guardrail #11 requires these twelve fields be declared in
    // `server/api/data-categories.md` §3 (Telemetry stream) in the same PR. The
    // Schema phase owns `data-categories.md`; this domain does not edit it (per
    // the build instructions). The §3 rows (source = `client (hk::net probe)`,
    // retention = "session lifetime + 30 days", legal basis = "Legitimate
    // interest — anti-cheat enforcement"; `owner_image_hash` cross-references the
    // §1 `image_sha256` catalog for signed-interposer allowlisting) must be added
    // by the data-categories owner before this PR merges, or guardrail #11
    // rejects it.
    // ---------------------------------------------------------------------
    /// 181 — sustained (QPC app-send minus NIC/kernel HW-TX) cadence skew (ns).
    /// `i64::MIN` is the no-data sentinel (NIC/driver does not expose TX
    /// timestamps) — the server treats it as absent, never as a positive.
    /// Old clients that omit the field also yield the sentinel, so the server
    /// never mistakes "field absent" for "zero skew".
    #[serde(default = "default_tx_cadence_skew_ns")]
    pub tx_cadence_skew_ns: i64,
    /// 182 — sustained monotonic-vs-realtime clock-domain rate drift (ppm). The
    /// NTP-step-vs-smooth-scale discrimination is server-side.
    #[serde(default)]
    pub clock_ratio_ppm: i32,
    /// 183 — kernel SmoothedRtt / `tcpi_rtt` on the TCP control channel (us).
    #[serde(default)]
    pub conn_rtt_us: u32,
    /// 183 — kernel RetransmitCount / `tcpi_retrans` over the window.
    #[serde(default)]
    pub conn_retrans: u32,
    /// 184 — unsent bytes in the app-side send ring.
    #[serde(default)]
    pub app_queue_depth: u32,
    /// 184 — kernel unsent bytes (`SIOCOUTQ`/`SO_NWRITE`/ideal-send-backlog).
    #[serde(default)]
    pub kernel_unsent_bytes: u32,
    /// 185 — input-frame coherence bitfield: 0x1 non-monotonic, 0x2 duplicate-
    /// timestamp, 0x4 backdated, 0x8 synthetic-origin (soft, server-scored).
    #[serde(default)]
    pub input_frame_anomaly_flags: u32,
    /// 187 — game-channel RTT (us).
    #[serde(default)]
    pub game_rtt_us: u32,
    /// 187 — independent probe-socket RTT to the same server IP (us). 0 when the
    /// probe channel is disabled (`HK_NET_PROBE_CHANNEL` OFF).
    #[serde(default)]
    pub probe_rtt_us: u32,
    /// 188 — 1 iff the bound path identity changed with NO OS route/link event
    /// (the discriminator vs. a benign OS-mediated reroute, which DOES fire one).
    #[serde(default)]
    pub route_change_unattested: u32,
    /// 189 — 1 iff the game flow terminates at a loopback/local owner PID
    /// (low-weight contextual signal; escalated server-side only with corroboration).
    #[serde(default)]
    pub flow_owner_local: u32,
    /// 189 — hex SHA-256 of the interposing owner image, "" if none. The server
    /// allowlists signed known-good interposers against the §1 `image_sha256`
    /// catalog (the 189 FP gate).
    #[serde(default)]
    pub owner_image_hash: String,

    // ---------------------------------------------------------------------
    // anti-analysis-environment sub-payload (schema v5, catalog signals 194 +
    // 197 ONLY).
    //
    // Mirrors `anti_analysis_report` in
    // `ac/include/horkos/anti_analysis/anti_analysis_signals.h`: the
    // dynamic-instrumentation/DBI residency fingerprint (194) and the
    // memory-editor/debugger host fingerprint (197). The other anti-analysis
    // catalog signals (190-193, 195, 196, 198) ride the selfcheck/timing/eBPF/
    // daemon planes, not this field.
    //
    // OPTIONAL per the v4 network-anomaly precedent: `Option<_>` + `#[serde(
    // default)]`, so a v1..=v4 client omitting it deserializes to `None` — read
    // as "no anti-analysis signal", never a fabricated positive. The client ships
    // raw observable counts/flags + an advisory tier; ALL scoring (allowlist
    // matching, combined-confidence, severity tiering) is server-side. Serde JSON,
    // no `#[repr(C)]`, no C byte-mirror, no `HK_STATIC_ASSERT` (never rides the
    // kernel `event_schema.h`/IOCTL plane).
    // ---------------------------------------------------------------------
    #[serde(default)]
    pub anti_analysis: Option<AntiAnalysisPayload>,

    // ---------------------------------------------------------------------
    // v6: OPTIONAL hypervisor/virtualization-state sub-payload (win-hypervisor-
    // detection, catalog signals 37/38/40/42/43/44/45).
    //
    // Mirrors `hv_report` in `ac/include/horkos/hv_signals.h`: TLFS leaf vectors,
    // vmexit latency histogram, VBS/HVCI posture, VM identity, cross-vCPU TSC
    // coherence, and the kernel-record summary (signals 39/41/42/44 folded
    // usermode). OPTIONAL per the same precedent: `Option<_>` + `#[serde(default)]`,
    // so a v1..=v5 client omitting it deserializes to `None` — read as "no HV
    // signal", never a fabricated positive. The client ships raw vectors/
    // histograms/tuples + a raw structural class; ALL classification (population
    // modeling, per-SKU skew, attested-fleet allowlists) is server-side. Serde
    // JSON, no `#[repr(C)]`, no C byte-mirror.
    // ---------------------------------------------------------------------
    #[serde(default)]
    pub hv: Option<HvReport>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A v1 client payload (no v2/v3/v4 blocks) still deserializes: the later
    /// additive fields are `#[serde(default)]` and fill with zeros/empty. Proves
    /// the migration window holds for the network-anomaly (v4) addition.
    #[test]
    fn v1_payload_deserializes_without_network_fields() {
        let v1 = r#"{
            "schema_version": 1,
            "player_id": 7,
            "tick": 100,
            "aim_delta_x": 0.0,
            "aim_delta_y": 0.0,
            "input_state": 0
        }"#;
        let p: TickPayload = serde_json::from_str(v1).expect("v1 deserializes");
        assert_eq!(p.schema_version, 1);
        assert_eq!(p.player_id, 7);
        // tx_cadence_skew_ns absent -> i64::MIN sentinel (not zero) so "no data"
        // is unambiguous. All other network-anomaly (v4) fields default to zero.
        assert_eq!(p.tx_cadence_skew_ns, i64::MIN);
        assert_eq!(p.clock_ratio_ppm, 0);
        assert_eq!(p.route_change_unattested, 0);
        assert_eq!(p.flow_owner_local, 0);
        assert_eq!(p.owner_image_hash, "");
    }

    /// A v4 payload carrying the network block round-trips through serde.
    #[test]
    fn v4_network_block_round_trips() {
        let original = TickPayload {
            schema_version: SCHEMA_VERSION,
            player_id: 42,
            tick: 9000,
            tx_cadence_skew_ns: -12_345,
            clock_ratio_ppm: -800,
            conn_rtt_us: 18_000,
            conn_retrans: 3,
            app_queue_depth: 4096,
            kernel_unsent_bytes: 0,
            input_frame_anomaly_flags: 0x5,
            game_rtt_us: 22_000,
            probe_rtt_us: 9_000,
            route_change_unattested: 1,
            flow_owner_local: 1,
            owner_image_hash: "deadbeef".to_string(),
            ..TickPayload::default()
        };
        let json = serde_json::to_string(&original).expect("serialize");
        let back: TickPayload = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, back);
        assert_eq!(SCHEMA_VERSION, 6);
    }

    /// A payload with no HV sub-payload deserializes with the field `None`
    /// (optional-sub-payload precedent), and a v6 payload carrying it round-trips.
    #[test]
    fn v6_hv_sub_payload_round_trips() {
        use crate::hv::{HvReport, HvVmIdentity, HV_SCHEMA_VERSION};

        // Omitted -> None.
        let v5 = r#"{
            "schema_version": 5,
            "player_id": 1,
            "tick": 1,
            "aim_delta_x": 0.0,
            "aim_delta_y": 0.0,
            "input_state": 0
        }"#;
        let p: TickPayload = serde_json::from_str(v5).expect("v5 deserializes");
        assert!(p.hv.is_none());

        // Present -> round-trips.
        let original = TickPayload {
            schema_version: SCHEMA_VERSION,
            player_id: 5,
            tick: 77,
            hv: Some(HvReport {
                schema_version: HV_SCHEMA_VERSION,
                identity: HvVmIdentity {
                    cpuid_hv_present: 1,
                    classification: 2,
                    ..Default::default()
                },
                sensors_ok: 0x3F,
                ..Default::default()
            }),
            ..TickPayload::default()
        };
        let json = serde_json::to_string(&original).expect("serialize");
        let back: TickPayload = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, back);
        assert!(back.hv.is_some());
    }

    /// A payload with no anti-analysis sub-payload deserializes with the field
    /// `None` (optional-sub-payload precedent), and a v5 payload carrying it
    /// round-trips through serde.
    #[test]
    fn v5_anti_analysis_sub_payload_round_trips() {
        use crate::anti_analysis::{
            AaHostTools, AaInstrumentation, AntiAnalysisPayload, ANTI_ANALYSIS_SCHEMA_VERSION,
        };

        // Omitted -> None.
        let v4 = r#"{
            "schema_version": 4,
            "player_id": 1,
            "tick": 1,
            "aim_delta_x": 0.0,
            "aim_delta_y": 0.0,
            "input_state": 0
        }"#;
        let p: TickPayload = serde_json::from_str(v4).expect("v4 deserializes");
        assert!(p.anti_analysis.is_none());

        // Present -> round-trips.
        let original = TickPayload {
            schema_version: SCHEMA_VERSION,
            player_id: 5,
            tick: 77,
            anti_analysis: Some(AntiAnalysisPayload {
                schema_version: ANTI_ANALYSIS_SCHEMA_VERSION,
                instr: AaInstrumentation {
                    unbacked_rx_threads: 1,
                    runtime_export_match: 1,
                    confidence_tier: 2,
                    ..AaInstrumentation::default()
                },
                host: AaHostTools {
                    suspicious_drivers: 1,
                    severity_tier: 2,
                    ..AaHostTools::default()
                },
                sensors_ok: 0x3,
            }),
            ..TickPayload::default()
        };
        let json = serde_json::to_string(&original).expect("serialize");
        let back: TickPayload = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, back);
    }

    /// The `i64::MIN` no-data sentinel for signal 181 survives the round-trip
    /// (so the server can distinguish "no NIC TX timestamp support" from a real
    /// zero skew).
    #[test]
    fn tx_cadence_sentinel_round_trips() {
        let p = TickPayload {
            schema_version: SCHEMA_VERSION,
            tx_cadence_skew_ns: i64::MIN,
            ..TickPayload::default()
        };
        let json = serde_json::to_string(&p).expect("serialize");
        let back: TickPayload = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.tx_cadence_skew_ns, i64::MIN);
    }
}
