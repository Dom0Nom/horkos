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

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `schema_version` | client | n/a (metadata) | n/a | n/a |
| `player_id` | server-assigned | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `tick` | client | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `aim_delta_x` | client | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `aim_delta_y` | client | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `input_state` | client (input bitmask) | session lifetime + 30 days | Contract performance | Horkos Service Operator |
| `server_received_ts` | server clock | session lifetime + 30 days | Contract performance | Horkos Service Operator |

### 4. Hardware identifiers (attestation)

| Field | Source | Retention default | Legal basis | Operator-of-record |
|---|---|---|---|---|
| `tpm_ek_pubkey_sha256` | TPM 2.0 EK public key digest | account lifetime + 30 days | Anti-fraud / anti-cheat | Horkos Service Operator |
| `platform_identifier` | Win/Linux/macOS platform fingerprint | account lifetime + 30 days | Anti-fraud / anti-cheat | Horkos Service Operator |
| `attestation_quote` | Attestation interface (TPM2_Quote / Secure Enclave / console SDK) | session lifetime + 30 days | Anti-fraud / anti-cheat | Horkos Service Operator |

## Cross-references

- Wire format source of truth: `sdk/include/horkos/event_schema.h`
- Phase 2 Rust mirror: `server/telemetry/src/schema.rs`
- GDPR-17 rollout plan: `docs/gdpr-17-rollout.md`
- Risk register entry: R10 in `plans/horkos-ac-drm-scaffold.md`
