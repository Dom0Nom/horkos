# Horkos Data Categories

This document is the canonical list of every data category Horkos collects,
processes, or persists. **Adding a telemetry field requires updating this file
in the same PR** (CLAUDE.md guardrail #11). Reviewer rejects undeclared fields.

EU shipment legal floor: GDPR Article 13 (information to be provided where
data are collected from the data subject) and Article 17 (right to erasure).
The deletion route lives at `DELETE /api/account/{id}/data`. Phase 2 returns
`503 Service Unavailable` with `Retry-After: 86400` until durable persistence
lands; see `docs/gdpr-17-rollout.md`.

## Categories

### 1. Process information

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `pid` | kernel hook (KMDF on Win, eBPF on Linux, daemon on macOS) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `parent_pid` | as above | 90 days | Legitimate interest | Horkos Service Operator |
| `create_time_ns` | process-create callback (`hk_event_process_create`) | 90 days | Legitimate interest | Horkos Service Operator |
| `exit_time_ns` | process-exit callback (`hk_event_process_exit`, schema v2) | 90 days | Legitimate interest | Horkos Service Operator |
| `image_name` | as above | 90 days | Legitimate interest | Horkos Service Operator |
| `image_sha256` | userspace verifier | 365 days (rule training) | Legitimate interest | Horkos Service Operator |

### 2. Module information

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `image_base` | image-load callback | 90 days | Legitimate interest | Horkos Service Operator |
| `image_flags` | image-load callback (`HK_IMAGE_FLAG_*`, e.g. BYOVD suspect; schema v2) | 90 days | Legitimate interest | Horkos Service Operator |
| `image_path` | image-load callback | 90 days | Legitimate interest | Horkos Service Operator |
| `image_signature_status` | userspace verifier (catalog DB) | 90 days | Legitimate interest | Horkos Service Operator |

### 2a. Handle access (Windows ObRegisterCallbacks)

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `requesting_pid` | Ob pre-callback (`hk_event_handle_open`) | 90 days | Legitimate interest | Horkos Service Operator |
| `target_pid` | Ob pre-callback | 90 days | Legitimate interest | Horkos Service Operator |
| `access_mask` | Ob pre-callback OriginalDesiredAccess (Windows); truncated ptrace request code (Linux eBPF) | 90 days | Legitimate interest | Horkos Service Operator |

### 3. Telemetry stream (per-tick)

Mirrors `server/telemetry/src/schema.rs::TickPayload`. This per-tick JSON stream
is a separate wire plane from the C99 kernel-event schema (`event_schema.h`).

#### v1 original fields

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `schema_version` | client | n/a (metadata) | n/a | n/a |
| `player_id` | server-assigned | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `tick` | client | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `aim_delta_x` | client | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `aim_delta_y` | client | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `input_state` | client (input bitmask) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `server_received_ts` | server clock | session lifetime + 30 days | Contract performance | Horkos Service Operator |

#### v2 input-provenance / aim-kinematics block (catalog signals 163–171)

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `hid_report_count` | client (HID stack) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `hid_raw_dx` | client (HID stack) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `hid_raw_dy` | client (HID stack) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `hid_newest_ts_ns` | client (HID stack — hardware/QPC timestamp) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `sens_scalar_q16` | client (engine sensitivity scalar, Q16.16) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `applied_angle_dx` | client (engine view delta, radians) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `applied_angle_dy` | client (engine view delta, radians) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `hid_interval_mean_ns` | client (HID stack — inter-report timing) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `hid_interval_var_ns` | client (HID stack — inter-report timing) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `hid_interval_framelock_count` | client (HID stack — frame-locked interval count) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `ang_vel` | client (engine state transport) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `ang_accel` | client (engine state transport) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `ang_jerk` | client (engine state transport) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `dist_to_nearest_target_rad` | client (engine state transport) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `target_vis_onset_ts_ns` | client (engine PVS onset timestamp) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `first_impulse_ts_ns` | client (engine — first corrective-impulse timestamp) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `fire_ts_ns` | client (engine — fire event timestamp) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `impulse_is_direction_change` | client (engine — direction-change flag) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `weapon_id` | client (engine weapon id) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `shot_index` | client (engine — shot index in burst) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `fire_active` | client (engine — full-auto fire bit) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `aimed_target_id` | client (engine — current target id) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `candidate_target_offsets` | client (engine — candidate target angular offsets) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `switch_event_flag` | client (engine — target-switch event) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `clip_rect_ok` | client (OS cursor confinement check) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `cursor_hidden` | client (OS cursor state) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `raw_vs_abs_divergence_px` | client (OS cursor position vs. raw motion) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `focus_active` | client (OS window focus state) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `injected_event_fraction_q8` | client (HID stack — injected-event fraction, Q0.8) | session lifetime + 30 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `virtual_device_present` | client (HID stack — virtual/uinput device flag) | session lifetime + 30 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |

#### v3 game-state binding fields (catalog signals 172–180)

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `client_mono_ns` | client (client-reported monotonic frame render time; never trusted as truth) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `client_refresh_hz` | client (client-reported display refresh rate, Hz) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `fired` | client (per-tick shot-fired flag; cross-checked vs. server hit-reg) | session lifetime + 30 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |

#### v4 network-anomaly block (catalog signals 181–189, minus server-only 186)

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `tx_cadence_skew_ns` | client (`hk::net` probe — NIC/kernel HW-TX cadence skew, ns; `i64::MIN` = no NIC TX timestamp support) | session lifetime + 30 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `clock_ratio_ppm` | client (`hk::net` probe — monotonic/realtime clock-domain drift, ppm) | session lifetime + 30 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `conn_rtt_us` | client (`hk::net` probe — kernel TCP SmoothedRtt / `tcpi_rtt`, µs) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `conn_retrans` | client (`hk::net` probe — kernel RetransmitCount / `tcpi_retrans`) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `app_queue_depth` | client (`hk::net` probe — app-side send ring unsent bytes) | session lifetime + 30 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `kernel_unsent_bytes` | client (`hk::net` probe — kernel unsent bytes, `SIOCOUTQ`/`SO_NWRITE`) | session lifetime + 30 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `input_frame_anomaly_flags` | client (`hk::net` probe — input-frame coherence bitfield) | session lifetime + 30 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `game_rtt_us` | client (`hk::net` probe — game-channel RTT, µs) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `probe_rtt_us` | client (`hk::net` probe — independent probe-socket RTT to same server IP, µs; 0 when probe channel disabled) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `route_change_unattested` | client (`hk::net` probe — path identity changed without OS route/link event) | session lifetime + 30 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `flow_owner_local` | client (`hk::net` probe — game flow terminates at loopback/local owner PID) | session lifetime + 30 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `owner_image_hash` | client (`hk::net` probe — SHA-256 hex of interposing owner image; "" if none; cross-referenced against §1 `image_sha256` catalog for signed-interposer allowlisting) | session lifetime + 30 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |

### 4. Hardware identifiers (attestation)

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `tpm_ek_pubkey_sha256` | TPM 2.0 EK public key digest | account lifetime + 30 days | Anti-fraud / anti-cheat | Horkos Service Operator |
| `platform_identifier` | Win/Linux/macOS platform fingerprint | account lifetime + 30 days | Anti-fraud / anti-cheat | Horkos Service Operator |
| `attestation_quote` | Attestation interface (TPM2_Quote / Secure Enclave / console SDK) | session lifetime + 30 days | Anti-fraud / anti-cheat | Horkos Service Operator |

### 5. Device trust — USB/HID hardware audit (`device_trust_schema.h`)

Source: IOHID transport audit / Windows HID stack / Linux evdev (`device_trust_schema.h`).
Retention 90 days. Legal basis: Legitimate interest — anti-cheat enforcement. Operator: Horkos Service Operator.

Privacy note: `hdevice_token` and `container_token` are per-session salted pseudonyms, never the raw device path, serial number, or location-id.

#### hk_event_hid_descriptor (catalog signal 136 — HID descriptor structural fingerprint)

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `schema_version` | IOHID transport audit (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `vendor_id` | IOHID transport audit (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `product_id` | IOHID transport audit (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `fingerprint` | IOHID transport audit — SHA-256 of canonicalized preparsed HID structure (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `usage_page_count` | IOHID transport audit (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `field_count` | IOHID transport audit (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `report_id_count` | IOHID transport audit (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `flags` | IOHID transport audit — `HK_HIDFP_*` bitmask (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |

#### hk_device_descriptor_audit (catalog signals 137/140/141/143 — descriptor-coherence / topology)

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `schema_version` | IOHID transport audit (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `verdict` | IOHID transport audit — `hk_input_verdict` bucket (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `vendor_id` | IOHID transport audit (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `product_id` | IOHID transport audit (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `bcd_usb` | IOHID transport audit (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `bcd_device` | IOHID transport audit (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `max_packet_size0` | IOHID transport audit — `bMaxPacketSize0` (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `bus_type` | IOHID transport audit — `HK_BUS_*` (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `iface_class_mask` | IOHID transport audit — `HK_IFACE_*` bitmask (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `audit_flags` | IOHID transport audit — `HK_DAUD_*` bitmask (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `container_token` | IOHID transport audit — opaque per-session pseudonym of ContainerID/location-id (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `creator_pid` | IOHID transport audit — uinput/DriverKit Extension creator PID (signals 140/141), else 0 (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `reserved` | reserved/padding — no data | n/a | n/a | n/a |

#### hk_pointer_cadence_features (catalog signals 139/144 — polling-interval ceiling + arrival/lifetime)

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `schema_version` | IOHID transport audit (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `reserved0` | reserved/padding — no data | n/a | n/a | n/a |
| `hdevice_token` | IOHID transport audit — opaque per-session device pseudonym (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `declared_interval_ms` | IOHID transport audit — bInterval-derived permitted period, ms (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `observed_rate_hz` | IOHID transport audit — sustained observed report rate, Hz (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `ceiling_violation_ratio` | IOHID transport audit — observed rate / descriptor-permitted ceiling (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `device_lifetime_s` | IOHID transport audit — arrival-to-now device lifetime, s (signal 144) (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `activity_burst_corr` | IOHID transport audit — correlation of new-source activity with gameplay bursts (signal 144) (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `flags` | IOHID transport audit — `HK_CAD_*` bitmask (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `reserved1` | reserved/padding — no data | n/a | n/a | n/a |

#### hk_event_pointer_features (catalog signal 142 — pointer-motion ML feature vector)

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `schema_version` | IOHID transport audit (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `hid_usage_class` | IOHID transport audit — `HK_PCLASS_*` sensor-class for model conditioning (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `hdevice_token` | IOHID transport audit — opaque per-session device pseudonym (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `feat[24]` | IOHID transport audit — aggregate moments / autocorrelation / GCD-lattice statistics; no raw lLastX/lLastY movement (`device_trust_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |

### 6. macOS endpoint events — process inspection / injection + code-signing

Source: macOS EndpointSecurity client (`event_schema_macos.h`, `event_schema_cs.h`).
Retention 90 days. Legal basis: Legitimate interest — anti-cheat enforcement. Operator: Horkos Service Operator.

#### hk_es_get_task (catalog signals 109/110 — task-port acquisition)

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `source_pid` | macOS ES client (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `target_pid` | macOS ES client (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `flavor` | macOS ES client — `HK_GET_TASK_*` (CONTROL/READ/NAME) (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `source_flags` | macOS ES client — `HK_ESPROC_*` bitmask (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `source_team_id` | macOS ES client — truncated team-id, NUL-padded (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `source_signing_id` | macOS ES client — truncated signing-id, NUL-padded (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |

#### hk_es_mmap (catalog signal 111 — non-self executable mmap into game)

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `target_pid` | macOS ES client (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `source_pid` | macOS ES client (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `protection` | macOS ES client — `es_event_mmap_t.protection` (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `flags` | macOS ES client — `es_event_mmap_t.flags` (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `baseline_match` | macOS ES client — `HK_MMAP_BASELINE_*` (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `reserved` | reserved/padding — no data | n/a | n/a | n/a |
| `source_path_sha256` | macOS ES client — SHA-256 of `es_event_mmap_t.source` path (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |

#### hk_es_dyld_inject (catalog signal 112 — DYLD_INSERT_LIBRARIES survival)

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `pid` | macOS ES client (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `cs_flags` | macOS ES client — `es_process_t.codesigning_flags` (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `dyld_var_present` | macOS ES client — `HK_DYLD_VAR_*` bitmask (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `injected_load_seen` | macOS ES client — 1 if a non-system dylib actually loaded (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `inserted_path_sha256` | macOS ES client — SHA-256 of inserted library path (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |

#### hk_es_proc_check (catalog signal 115 — proc_info reconnaissance rate)

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `source_pid` | macOS ES client (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `target_pid` | macOS ES client (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `flavor` | macOS ES client — `es_proc_check_type_t` (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `rate_per_window` | macOS ES client — aggregated count in sampling window (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `flavor_cardinality` | macOS ES client — distinct flavors seen from source (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `source_flags` | macOS ES client — `HK_ESPROC_*` bitmask (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |

#### hk_es_exc_port (catalog signal 113 — foreign exception-port owner)

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `game_pid` | macOS ES client (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `owner_pid` | macOS ES client — task owning the new exception port (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `mask` | macOS ES client — `exception_mask_t` bits that changed (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `is_foreign` | macOS ES client — 1 if owner is not game and not Apple diagnostics (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |

#### hk_es_thread_origin (catalog signal 114 — thread with non-bundle entry point)

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `game_pid` | macOS ES client (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `thread_id` | macOS ES client — Mach thread id (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `entry_pc` | macOS ES client — thread start address (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `region_kind` | macOS ES client — `HK_REGION_*` classification (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `reserved` | reserved/padding — no data | n/a | n/a | n/a |

#### hk_es_ptrace (catalog signal 116 — P_TRACED transition edge)

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `game_pid` | macOS ES client (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `tracer_pid` | macOS ES client — tracer PID (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `traced_now` | macOS ES client — current `P_TRACED` flag (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `cs_release_signed` | macOS ES client — 1 if release-signed without get-task-allow (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |

#### hk_es_text_wx (catalog signal 117 — writable/COW-broken page in signed __TEXT)

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `game_pid` | macOS ES client (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `protection` | macOS ES client — `vm_region_submap_info_64.protection` (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `share_mode` | macOS ES client — `SM_COW`/`SM_PRIVATE` (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `csops_valid` | macOS ES client — `csops(CS_OPS_STATUS)` validity (0 if invalidated) (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `region_addr` | macOS ES client — start address of the offending page (`event_schema_macos.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |

#### hk_event_cs_finding (catalog signals 118–126 — code-signing / platform-trust finding)

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `signal_id` | macOS daemon csops/seccode/trust probes (`event_schema_cs.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `finding` | macOS daemon csops/seccode/trust probes — `HK_CS_*` code (`event_schema_cs.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `target_pid` | macOS daemon csops/seccode/trust probes — game PID (`event_schema_cs.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `detail` | macOS daemon csops/seccode/trust probes — compact signal-specific discriminant; never a raw cdhash (`event_schema_cs.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |

### 7. Input provenance (`input_prov_schema.h`)

Source: Windows usermode input sensor (`input_prov_schema.h`).
Retention 90 days. Legal basis: Legitimate interest — anti-cheat enforcement. Operator: Horkos Service Operator.

Variable-length string fields (`device_path`, `filter_service`, `signer_subject`, `vidpid`, `owning_image`) travel in the JSON envelope keyed by record index, never inline in the fixed struct. They are not separately listed here but are subject to the same retention and legal basis as the fields below.

#### hk_input_finding (catalog signals 55–63 — numeric core)

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `schema_version` | Windows usermode input sensor (`input_prov_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `signal` | Windows usermode input sensor — `hk_input_signal` catalog number (`input_prov_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `verdict` | Windows usermode input sensor — `hk_input_verdict` (`input_prov_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `flags` | Windows usermode input sensor — `HK_INFLAG_*` bitmask (`input_prov_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `owning_pid` | Windows usermode input sensor — foreign PID for queue-attach / hook-owner signals (`input_prov_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `event_count` | Windows usermode input sensor — events observed in window (`input_prov_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `anomaly_count` | Windows usermode input sensor — events matching the anomaly (`input_prov_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `filter_count` | Windows usermode input sensor — ordered class-filter count (signal 56) (`input_prov_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `hdevice_token` | Windows usermode input sensor — opaque per-session hDevice pseudonym (`input_prov_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `llhook_latency_ns` | Windows usermode input sensor — measured `CallNextHookEx` call-out delay (signal 59) (`input_prov_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |

#### hk_input_timing_features (catalog signals 58/62 — timing entropy / poll-rate contradiction)

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `schema_version` | Windows usermode input sensor (`input_prov_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `signal` | Windows usermode input sensor — 58 or 62 (`input_prov_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `hdevice_token` | Windows usermode input sensor — opaque per-session hDevice pseudonym (`input_prov_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `sample_count` | Windows usermode input sensor — inter-arrival deltas summarized (`input_prov_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `declared_hz` | Windows usermode input sensor — HID/USB bInterval-derived declared rate (signal 62) (`input_prov_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `observed_hz_x100` | Windows usermode input sensor — measured WM_INPUT rate ×100 (`input_prov_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `transport_flags` | Windows usermode input sensor — `HK_INTRANSPORT_*` (Bluetooth/wireless exemption) (`input_prov_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `cov_x10000` | Windows usermode input sensor — coefficient of variation ×10000 (`input_prov_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `regularity_x10000` | Windows usermode input sensor — chi-square/autocorrelation regularity score ×10000 (`input_prov_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `period_hist[16]` | Windows usermode input sensor — inter-arrival delta histogram (16 buckets) (`input_prov_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |

### 8. Network timing probes (`net_timing.h`)

Source: `hk::net` client probe backends (`net_timing.h`). These are the individual per-signal sub-structs whose fields map 1:1 onto the `TickPayload` v4 fields documented in §3. The sub-structs are collected server-side from the same JSON payload; they are listed here for completeness.

| Struct | Fields | Cross-reference |
|---|---|---|
| `hk_net_tx_cadence` | `tx_cadence_skew_ns`, `queue_depth_growth`, `adapter_is_tunnel` | §3 v4 block (signal 181) |
| `hk_net_clock_drift` | `clock_ratio_ppm`, `step_detected` | §3 v4 block (signal 182) |
| `hk_net_conn_health` | `conn_rtt_us`, `conn_retrans`, `app_perceived_stall`, `reserved` | §3 v4 block (signal 183) |
| `hk_net_send_backlog` | `app_queue_depth`, `kernel_unsent_bytes`, `link_congested`, `proc_starved` | §3 v4 block (signal 184) |
| `hk_net_input_frame_coherence` | `input_frame_anomaly_flags` | §3 v4 block (signal 185) |
| `hk_net_rtt_divergence` | `game_rtt_us`, `probe_rtt_us`, `same_port_class`, `reserved` | §3 v4 block (signal 187) |
| `hk_net_route_integrity` | `route_identity_hash`, `route_change_unattested`, `reserved` | §3 v4 block (signal 188) |
| `hk_net_flow_owner` | `flow_owner_local`, `reserved`, `owner_image_hash[32]` | §3 v4 block (signal 189) |

Note: fields `queue_depth_growth`, `adapter_is_tunnel` (signal 181), `step_detected` (signal 182), `app_perceived_stall`, `link_congested`, `proc_starved` (signals 183/184), `same_port_class` (signal 187), and `route_identity_hash` (signal 188) are collected in the C-side sub-structs but fold into the `TickPayload` JSON plane. Retention and legal basis are identical to the §3 v4 entries above (session lifetime + 30 days; Legitimate interest — anti-cheat enforcement; Horkos Service Operator).

### 9. Render-hook observations (`render_hook_schema.h`)

Source: Windows usermode render/overlay sensor (`render_hook_schema.h`).
Retention 90 days. Legal basis: Legitimate interest — anti-cheat enforcement. Operator: Horkos Service Operator.

Variable-length string fields (`module_path`, `signer_subject`, `window_class`) travel in the JSON envelope keyed by record index and are subject to the same retention and legal basis.

#### hk_render_finding (catalog signals 46–54)

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `schema_version` | Windows usermode render sensor (`render_hook_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `signal` | Windows usermode render sensor — `hk_render_signal` catalog number (`render_hook_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `verdict` | Windows usermode render sensor — `hk_provenance_verdict` (`render_hook_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `style_bits` | Windows usermode render sensor — `HK_WSTYLE_*` bitmask (signals 49/51) (`render_hook_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `owning_pid` | Windows usermode render sensor — foreign PID for window/footprint signals (`render_hook_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `slot_index` | Windows usermode render sensor — vtable slot (signal 46) or export ordinal (signal 47) (`render_hook_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `target_addr` | Windows usermode render sensor — resolved vtable/prologue target virtual address (signals 46/47) (`render_hook_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `region_hash` | Windows usermode render sensor — divergent-region hash (signal 47) / cadence fingerprint (`render_hook_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `cadence_drift_ns` | Windows usermode render sensor — signed frame-stat/cadence drift (signals 48/50/53) (`render_hook_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |

### 10. Game-state snapshot — server-internal plane (`snapshot_schema.h`)

This plane is **server-internal** (game server → AC server shared-memory ring). These fields are authoritative game-state produced by the game server itself; they are NOT collected from the player's device. Retention: session lifetime.

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `schema_version` | game server (`snapshot_schema.h`) | session lifetime | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `entity_count` | game server (`snapshot_schema.h`) | session lifetime | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `tick` | game server (`snapshot_schema.h`) | session lifetime | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `mono_ns` | game server — `CLOCK_MONOTONIC` at simulation tick (signals 174/178) (`snapshot_schema.h`) | session lifetime | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `local_player_id` | game server — entity id of the judged local player (`snapshot_schema.h`) | session lifetime | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `cam_origin` | game server — local view origin (signals 173/177) (`snapshot_schema.h`) | session lifetime | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `cam_forward` | game server — local view forward unit vector (`snapshot_schema.h`) | session lifetime | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `cam_up` | game server — local view up unit vector (`snapshot_schema.h`) | session lifetime | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `cam_fov_rad` | game server — local horizontal FOV, radians (`snapshot_schema.h`) | session lifetime | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `visibility_bits[8]` | game server — per-entity server PVS/BVH line-of-sight to local player (`snapshot_schema.h`) | session lifetime | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `audiopath_bits[8]` | game server — per-entity authoritative audio-path existence (`snapshot_schema.h`) | session lifetime | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `occluder_count` | game server — dynamic smoke/particle occluder count in trailer (signal 175) (`snapshot_schema.h`) | session lifetime | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `recoil_rng_vec` | game server — per-shot authoritative recoil incl. random component (signal 180) (`snapshot_schema.h`) | session lifetime | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `objective_seed` | game server — server-random spawn/objective seed this match (signal 176) (`snapshot_schema.h`) | session lifetime | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `entities[].entity_id` | game server — stable per-match actor id (`snapshot_schema.h`) | session lifetime | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `entities[].position` | game server — authoritative world position (`snapshot_schema.h`) | session lifetime | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `entities[].velocity` | game server — authoritative world velocity (`snapshot_schema.h`) | session lifetime | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `entities[].flags` | game server — `HK_ENT_*` bitmask (alive/local/team) (`snapshot_schema.h`) | session lifetime | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `entities[]._pad` | reserved/padding — no data | n/a | n/a | n/a |
| `occluder[].aabb_min` | game server — AABB minimum corner (signal 175) (`snapshot_schema.h`) | session lifetime | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `occluder[].aabb_max` | game server — AABB maximum corner (signal 175) (`snapshot_schema.h`) | session lifetime | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `occluder[].born_tick` | game server — tick the occluder volume started (`snapshot_schema.h`) | session lifetime | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `occluder[].expire_tick` | game server — tick the occluder volume expires (exclusive) (`snapshot_schema.h`) | session lifetime | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |

### 11. Analysis-tooling presence (`anti_analysis_signals.h`)

Source: per-signal usermode anti-analysis sensor
(`ac/include/horkos/anti_analysis/anti_analysis_signals.h`). These mirror the
`aa_instrumentation` (catalog signal 194 — dynamic-instrumentation/DBI residency)
and `aa_host_tools` (catalog signal 197 — memory-editor/debugger host fingerprint)
sub-structs and ride the `TickPayload` v5 plane (`schema.rs`) as the optional
`anti_analysis` sub-payload. Each is a raw observable count/flag plus an advisory
tier; all classification is server-side. The other anti-analysis catalog signals
(190-193, 195, 196, 198) ride the selfcheck/timing/eBPF/daemon planes and are
documented under their own categories, not here. Retention 90 days. Legal basis:
Legitimate interest — anti-cheat enforcement. Operator: Horkos Service Operator.

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `instr.unbacked_rx_threads` | usermode signal-194 sensor (`anti_analysis_signals.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `instr.runtime_export_match` | usermode signal-194 sensor (`anti_analysis_signals.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `instr.control_port_listener` | usermode signal-194 sensor (`anti_analysis_signals.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `instr.jit_module_present` | usermode signal-194 sensor — FP context for server allowlisting (`anti_analysis_signals.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `instr.confidence_tier` | usermode signal-194 sensor — advisory tier, server may override (`anti_analysis_signals.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `host.debugger_window_classes` | usermode signal-197 sensor, Windows (`anti_analysis_signals.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `host.known_device_objects` | usermode signal-197 sensor, Windows (`anti_analysis_signals.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `host.suspicious_drivers` | usermode signal-197 sensor, Windows (`anti_analysis_signals.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `host.byovd_driver_match` | usermode signal-197 sensor — cross-checks kernel driver whitelist (`anti_analysis_signals.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `host.opened_handle_to_game` | usermode signal-197 sensor — from kernel ObRegisterCallbacks handle records (`anti_analysis_signals.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `host.severity_tier` | usermode signal-197 sensor — advisory tier, server may override (`anti_analysis_signals.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `sensors_ok` | aggregator (`anti_analysis_signals.h`) — bitmask of samplers that ran; a clear bit reads as "not collected", never "clean" | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |

Note: `instr.reserved` is padding and carries no data (n/a). The `confidence_tier`
(0..=2) and `severity_tier` (0..=3) are validated against their enum range on
ingest (`server/telemetry/src/anti_analysis.rs`).

### 12. Memory & image anomalies (Windows kernel scan, `event_schema.h`)

Source: the Windows kernel memory-scan worker (win-kernel-memory-injection,
catalog signals 10-18). The kernel attaches read-only to a target process,
walks its VAD tree / loader lists / on-disk image backing, and emits raw
structural evidence on the large-record wire plane (`hk_event_mem_record`,
`ioctl.h`), decoded server-side by `server/telemetry/src/mem_events.rs`. The
kernel ships raw observations + structural annotations (e.g. `has_jit_owner`)
only — never a verdict; all fusion and ban authority is server-side. Retention
90 days. Legal basis: Legitimate interest — anti-cheat enforcement. Operator:
Horkos Service Operator.

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `vad_type` | kernel mem-scan — normalized VadType (signals 10/14/15, `event_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `region_base` | kernel mem-scan — region start VA (`event_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `region_size` | kernel mem-scan — region byte size (`event_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `protection` | kernel mem-scan — normalized RWX mask (`event_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `region_flags` | kernel mem-scan — unbacked/large-page/JIT-owner annotations (`event_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `vad_says_exec` / `pte_says_exec` | kernel mem-scan — W^X divergence inputs (signal 11, `event_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `first_diff_rva` | kernel mem-scan — first unexplained code byte RVA (signal 12, `event_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `live_section_sha256` | kernel mem-scan — live code-section hash (signal 12, `event_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `disk_section_sha256` | kernel mem-scan — on-disk code-section hash (signal 12, `event_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `module_path` | kernel mem-scan — backing module path, truncated (signals 12/13/16, `event_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `section_name` | kernel mem-scan — code section name, e.g. `.text` (signal 12, `event_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `image_anomaly.flags` | kernel mem-scan — ghost/hollow + backing-state bits (signals 13/16, `event_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `thread_start_address` | kernel mem-scan — thread Win32 start / TLS callback VA (signal 17, `event_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `resolved_vad_type` | kernel mem-scan — VadType the origin resolved into (signal 17, `event_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `file_sha256` | kernel mem-scan — backing file hash (signal 18, `event_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `file_path` | kernel mem-scan — backing file path, truncated (signal 18, `event_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `signer_verdict` | userspace `ImageSigningWin.cpp` (WinVerifyTrust) — kernel ships UNKNOWN, userspace fills (signal 18, `event_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |

Note: `pid` / `thread_id` are process/thread identifiers already declared for the
process and handle categories (§1/§2a). Per-signal `reserved` words are padding
(n/a). All variable-length path fields are bounds-checked on ingest
(`server/telemetry/src/mem_events.rs`) — an out-of-range `*_len` is rejected as a
typed `MemEventError`, never sliced.

### 13. Hypervisor / virtualization state (`hv_signals.h`)

Source: the usermode hypervisor sensors (`ac/src/hv/*.cpp`, win-hypervisor-detection,
catalog signals 37/38/40/42/43/44/45) plus the four kernel HV records
(signals 39/41/42/44) folded usermode into the report. Mirrors `hv_report`
(`ac/include/horkos/hv_signals.h`) and rides the `TickPayload` v6 plane
(`schema.rs`) as the optional `hv` sub-payload. Each field is a raw vector /
histogram / tuple / counter plus a raw structural class; ALL classification
(population modeling, per-SKU TSC skew, known-good nested-Hyper-V vectors,
attested-fleet allowlists) is server-side — every signal here is medium/high FP.
Retention 90 days. Legal basis: Legitimate interest — anti-cheat enforcement.
Operator: Horkos Service Operator.

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `tlfs.leaf` | CPUID 0x40000000–0x4000000A leaf vector (signal 37, `hv_signals.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `tlfs.cpuid1_ecx31_hv` / `os_vbs_running` / `os_hv_present` | CPUID + NtQuerySystemInformation posture (signal 37) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `vmexit.hist` | CPUID vmexit round-trip latency histogram (signal 38) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `vmexit.qpc_span` / `shared_interrupt_dt` | independent-clock spans for the vmexit loop (signal 38) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `vbs.*` | Win32_DeviceGuard WMI + IUM posture + attestation contradiction (signal 40) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `identity.*` | SMBIOS / device-tree / vTPM-EK markers + structural class (signal 43) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `tsc.*` | per-vCPU RDTSCP skew + invariant-TSC capability (signal 45) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `kern.synth_msr_flags` | kernel signal 42 — Hyper-V synthetic-MSR coherence (`event_schema.h` v4) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `kern.ept_flags` | kernel signal 39 — EPT exec/read split (`event_schema.h` v4) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `kern.sk_flags` | kernel signal 41 — secure-kernel liveness, observe-only (`event_schema.h` v4) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `kern.apic_idt_flags` | kernel signal 44 — APIC/IDT residue, observe-only (`event_schema.h` v4) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `sensors_ok` | aggregator — bitmask of samplers that ran; a clear bit reads as "not collected", never "bare-metal" | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |

Note: the vTPM EK digest (signal 43) overlaps §4 (Hardware identifiers) — reuse
`tpm_ek_pubkey_sha256` semantics; only `identity.classification` (0..=3, validated
on ingest in `server/telemetry/src/hv.rs`) is new here. Signal 40 (`vbs.*`) is
report-only until a real Attestation backend lands; the kernel `kern.sk_flags` /
`kern.apic_idt_flags` are observe-only, low-weight corroborators.

### 14. Launch trust / process genealogy (`launch_trust.rs`)

Source: the process-genealogy sensors (win-kernel `proc_genealogy.c` /
`launch_timing.c` / `module_reconcile.c`, win-userspace `ancestry_walker.cpp` /
`token_check.cpp` / `job_silo_check.cpp`, Linux `genealogy.bpf.c` /
`loader_trust.bpf.c`, macOS `genealogy_handler.cpp`, catalog signals 199-207).
The kernel ships `true_creator_pid` + `proc_flags` on the v5
`hk_event_process_create_ex` record; the rest rides the `LaunchTrustReport` JSON
plane (`server/telemetry/src/launch_trust.rs`), correlated against a signed-
launcher / LOLBin / overlay baseline. The client ships raw launch facts + flags;
ALL FP gating is server-side. Retention 90 days (aligned with §1 process info).
Legal basis: Legitimate interest — anti-cheat enforcement. Operator: Horkos
Service Operator.

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `true_creator_pid` | win-kernel create-notify (signal 199, `event_schema.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `proc_flags` | reparent/suspended/lolbin/traced/loader-taint flags (199-206) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `ancestry_image_hashes` | ancestry-chain image identities, root->game (signal 201) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `token_integrity_delta` | game vs launcher integrity-level delta (signal 203) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `job_silo_anomaly` | job/silo containment, advisory-only (signal 204) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `responsible_team_id` | macOS NOTIFY_EXEC responsible Team ID (signal 207) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `loader_taint_flags` | LD_PRELOAD/LD_AUDIT/LD_LIBRARY_PATH at execve (signal 206, Linux) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |

Note: `game_pid` / `declared_parent_pid` are process identifiers already declared
in §1. The launcher baseline (accepted roots / LOLBin catalog / per-launcher
integrity) is a signed rule bundle (`server/api/launcher-baseline.md`), not a
collected field.

### 15. DMA / peripheral hardware trust (`dma_forensics.h`)

Source: the cross-platform DMA forensics sensor (`dma_detect/`, catalog signals
127-135). One `hk_dma_device_forensics` record per enumerated PCIe device, serialized
as a 100-byte little-endian flat image by `dma_detect/src/forensics_report.cpp`
(`hk_dma_forensics_serialize_device`) and decoded by
`server/telemetry/src/dma_forensics.rs`. Every probe is read-only; no device state
is mutated (exception: the sig-130 option-ROM probe briefly enables ROM decode and
restores it, only when no driver owns the ROM region). Fields with `scan_error != 0`
are untrustworthy and the server must not read positive facts from them.
Retention 90 days. Legal basis: Legitimate interest — anti-cheat enforcement.
Operator: Horkos Service Operator.

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `bdf.domain`, `bdf.bus`, `bdf.devfn` | PCIe routing id from sysfs/SetupAPI/IOKit (`dma_forensics.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `vendor_id` | sysfs `vendor` / PnP / IOKit property (`dma_forensics.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `device_id` | sysfs `device` / PnP / IOKit property (`dma_forensics.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `subsys_vendor_id` | sysfs `subsystem_vendor` / PnP / IOKit property (`dma_forensics.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `dsn_present` | PCIe DSN ext-cap (0x0003) found in extended config (sig 127, `dma_forensics.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `dsn_oui_locally_administered` | EUI-64 OUI locally-administered bit set — 1 = suspicious, never a real IEEE OUI (sig 127, `dma_forensics.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `extcfg_aliases_low` | ext-config 0x100-0x1FF mirrors legacy 0x000-0x0FF (sig 128, `dma_forensics.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `rsvdp_nonzero` | a PCIe-spec RsvdP reserved byte was non-zero (sig 128, `dma_forensics.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `extcfg_read_unstable` | repeated config reads not byte-identical (sig 128, `dma_forensics.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `msix_containment_violation` | MSI-X table or PBA escapes its referenced BAR (sig 129, `dma_forensics.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `msix_table_size` | MSI-X Table Size field + 1, entry count (sig 129, `dma_forensics.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `rom_present` | option ROM region present (sig 130, `dma_forensics.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `rom_pcir_id_mismatch` | PCIR VID/DID does not match config VID/DID (sig 130, `dma_forensics.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `bar_profile_count`, `bar_size[6]`, `bar_flags[6]` | decoded BAR lengths and type flags per BAR (sig 131, `dma_forensics.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `acs_source_validation`, `acs_p2p_redirect` | ACS SV/P2P-RR control bits on the path bridge (sig 133, `dma_forensics.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `iommu_group_membership` | device count in this device's IOMMU group (sig 133, `dma_forensics.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `bus_master_enabled` | PCI_COMMAND Bus Master Enable bit (structural gate, `dma_forensics.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `driver_bound` | a kernel driver owns this device (structural gate, `dma_forensics.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `tlp_latency_median_ns`, `tlp_latency_iqr_ns` | config-read TLP round-trip median + IQR (sig 132, LOW WEIGHT, `dma_forensics.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `tlp_same_root_port_group` | coarse root-port cohort id for within-cohort comparison (sig 132, `dma_forensics.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `iommu_fault_count` | IOMMU fault count attributed to this BDF (sig 135, `dma_forensics.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
| `scan_error` | per-device scan errno/HRESULT/IOReturn; non-zero means record is untrustworthy (`dma_forensics.h`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |

Note: PCIe BDF tuples identify a bus slot, not a player. They are device hardware
identifiers (§4-adjacent) used solely for anomaly gating; they do not identify a
natural person. `dsn_oui_locally_administered` is a one-bit structural fact about
the OUI prefix — it carries no unique-identifier weight. The sig-132 TLP-latency
fields are LOW WEIGHT and cannot by themselves produce a verdict
(`bypass_latency_only` merge-gate).

### 16. Ban-decision audit records (`server/ban-engine/src/store.rs`)

Server-side derived data, written by the fusion pipeline — not a client wire
plane. One append-only `DecisionRecord` per verdict TRANSITION (Clean→Review→
Ban) or session end with live suspicion state. Persisted to JSONL when
`HORKOS_DECISION_LOG` is set; in-memory otherwise (PoC default). Records carry
both inculpatory (contributing signals) and exculpatory (skipped events,
pairing-miss counts) evidence so a decision is defensible — and overturnable —
without replaying the session.

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `seq`, `kind`, `decided_at_ns` | store-assigned sequence + record kind + server clock (`store.rs`) | Life of the enforcement action + appeal window (longer than telemetry — appeals need it) | Legitimate interest — anti-cheat enforcement & appeals | Horkos Service Operator |
| `player_id`, `session_start_ns` | session identity (`pipeline.rs`) | same | same | Horkos Service Operator |
| `prev_verdict`, `verdict`, `score` | fusion output (`fusion.rs`) | same | same | Horkos Service Operator |
| `contributions[]` (signal id, z, samples, window, tier, weight) | analyzer `SuspicionEvent`s that counted | same | same | Horkos Service Operator |
| `skipped[]` (signal id, z, samples, reason) | events rejected by fusion gates (exculpatory) | same | same | Horkos Service Operator |
| `cadence` | signal-186 arrival-cadence observation, when present | same | same | Horkos Service Operator |
| `params` | exact `FusionParams` values used for THIS decision (inlined, not a version pointer) | same | same | Horkos Service Operator |
| `window_first_tick`, `window_last_tick`, `ticks_received`, `ticks_paired`, `pairing_misses`, `pairing_anomaly` | evidence-quality accounting (`pipeline.rs`) | same | same | Horkos Service Operator |
| `schema_versions_seen` | payload contract versions observed this session | same | same | Horkos Service Operator |

Note: these records are derived from categories already declared above; they
introduce no new client-collected field. Retention deliberately exceeds the
telemetry stream's: a ban outlives the telemetry that produced it, and the
record is the only artifact an appeal can audit.

## Cross-references

- Wire format source of truth: `sdk/include/horkos/event_schema.h`
- Phase 2 Rust mirror: `server/telemetry/src/schema.rs`
- macOS injection wire format: `sdk/include/horkos/event_schema_macos.h`
- macOS code-signing wire format: `sdk/include/horkos/event_schema_cs.h`
- Input provenance wire format: `sdk/include/horkos/input_prov_schema.h`
- Network timing sensor surface: `sdk/include/horkos/net_timing.h`
- Render-hook wire format: `sdk/include/horkos/render_hook_schema.h`
- Device trust wire format: `sdk/include/horkos/device_trust_schema.h`
- Game-state snapshot wire format: `sdk/include/horkos/snapshot_schema.h`
- Anti-analysis sensor surface (194 + 197): `ac/include/horkos/anti_analysis/anti_analysis_signals.h`; server mirror `server/telemetry/src/anti_analysis.rs`
- GDPR-17 rollout plan: `docs/gdpr-17-rollout.md`
