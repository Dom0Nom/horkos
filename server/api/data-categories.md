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
- GDPR-17 rollout plan: `docs/gdpr-17-rollout.md`
- Risk register entry: R10 in `plans/horkos-ac-drm-scaffold.md`
