/*
 * sdk/include/horkos/event_schema_cs.h
 * Role: macOS-only wire-format payload for the code-signing / platform-trust
 *       findings (catalog signals 118-126). A single fixed 16-byte
 *       `hk_event_cs_finding` carrying {signal_id, finding, target_pid, detail}
 *       rides the macOS daemon sink -> server transport path (the same
 *       HKEsEventSink / horkosd plane the hk_es_* injection payloads use), NOT
 *       the Windows IOCTL ring. Like event_schema_macos.h it is deliberately
 *       kept OUT of the shared `hk_event_record` union in event_schema.h so the
 *       Windows 40-byte HK_STATIC_ASSERT(sizeof(hk_event_record) == 40) and
 *       HK_EVENT_PAYLOAD_MAX stay untouched. The full evidence (cdhash hex,
 *       diffed entitlement keys, offending signing_id, CSR-config breakdown) is
 *       variable-length and travels on the separate daemon->server JSON report
 *       plane (server/telemetry CsEvidence), NEVER in this fixed record.
 * Target platforms: macOS (daemon csops/seccode/trust probes + ES correlator)
 *       and the server mirror. Plain C99, no platform headers — included by
 *       macOS TUs and mirrored field-for-field by
 *       server/telemetry/src/macos_codesign.rs.
 * Interface: declares hk_event_cs_finding + the HK_EVENT_CS_FINDING event-type
 *            discriminant and the HK_CS_* finding codes. Reuses HK_STATIC_ASSERT
 *            from event_schema.h.
 *
 * Guardrail compliance:
 *   #1  No platform #ifdef — CMake (`if(APPLE)`) gates which TUs include this.
 *   #3  This module comment covers role/platform/interface.
 *   #4  Pure C99 header, no kernel headers — safe to include from userspace TUs.
 *   #11 Every field below is telemetry; the matching data-categories.md section
 *       (§5 "macOS code-signing & platform-trust findings") is owned by the
 *       Schema phase. HK-TODO(schema): if that section is not yet present in
 *       server/api/data-categories.md it must land in the same PR that un-stubs
 *       these emitters — this domain does not edit that file.
 */

#pragma once

/* HK_STATIC_ASSERT, the hk_event_header, and HK_EVENT_SCHEMA_VERSION live in the
 * shared schema. We reuse the assert macro and the header struct verbatim; we do
 * NOT bump HK_EVENT_SCHEMA_VERSION here (the shared header owns that). */
#include "horkos/event_schema.h"

/* -------------------------------------------------------------------------
 * macOS code-signing event-type discriminant.
 *
 * HK-TODO(schema): the Schema phase appends HK_EVENT_CS_FINDING to the shared
 * `hk_event_type` enum. The plan coordinates value 6 with the Windows integrity
 * plan (which claims HK_EVENT_INTEGRITY_FINDING = 5) — but BOTH enums are frozen
 * this phase, and the macOS-only injection plane already locally mirrors 5..12 in
 * event_schema_macos.h (HK_EVENT_ES_MMAP == 6 there). To avoid a same-value clash
 * with that mirror WITHIN a macOS daemon TU that includes both headers, the CS
 * finding is mirrored here at the next free macOS-plane value 13 as a named
 * constant. The macOS daemon sink dispatches CS findings by THIS constant; the
 * server decoder mirrors it in lockstep (macos_codesign.rs). The final shared
 * enum value the Schema phase assigns is a mechanical rename — the byte layout
 * (16 bytes) and field order do not depend on the discriminant's value.
 * ------------------------------------------------------------------------- */
#define HK_EVENT_CS_FINDING 13u  /* signals 118-126; see schema HK-TODO above */

/* -------------------------------------------------------------------------
 * Finding codes. The compact verdict carried per event; the full evidence
 * rides the JSON report plane (CsEvidence). HK_CS_OK is a scan-completed
 * heartbeat, never a finding.
 * ------------------------------------------------------------------------- */
#define HK_CS_OK                    0x00u
#define HK_CS_FLAGS_DRIFT           0x01u  /* signal 118: CS_KILL/CS_HARD cleared */
#define HK_CS_CDHASH_MISMATCH       0x02u  /* signal 119: live vs on-disk cdhash */
#define HK_CS_DYNAMIC_INVALID       0x03u  /* signal 120: SecCodeCheckValidity fail */
#define HK_CS_INVALIDATED_TAMPER    0x04u  /* signal 121: CS_INVALIDATED + exec mmap */
#define HK_CS_LV_TEAMID_DIVERGENCE  0x05u  /* signal 122: per-dylib LV / team-id */
#define HK_CS_AMFID_TASKPORT        0x06u  /* signal 123: amfid task-port acquired */
#define HK_CS_AMFI_POSTURE_WEAK     0x07u  /* signal 124: SIP/Dev-Mode/boot-arg */
#define HK_CS_GATEKEEPER_BYPASS     0x08u  /* signal 125: corroborating only */
#define HK_CS_ENTITLEMENT_DRIFT     0x09u  /* signal 126: kernel vs signed entitlements */

/* -------------------------------------------------------------------------
 * team-id classification enum carried in `detail` for signal 122 (one byte,
 * low bits). Reported raw; the server applies the allowlist FP gate.
 * ------------------------------------------------------------------------- */
#define HK_CS_TEAMID_APPLE_PLATFORM 0u  /* es_process_t.is_platform_binary */
#define HK_CS_TEAMID_SAME_TEAM      1u  /* dylib team-id == host main-binary team-id */
#define HK_CS_TEAMID_ALLOWLISTED    2u  /* known-good Apple/Steam/AU signing-id */
#define HK_CS_TEAMID_FOREIGN        3u  /* differing team-id, not allowlisted */

/* -------------------------------------------------------------------------
 * Signals 118-126 — code-signing / platform-trust finding (16 bytes).
 *
 * `detail` is a compact signal-specific discriminant ONLY — a masked csflags
 * delta bitmask, a CSR-config bitfield, a one-byte team-id class, or the low 32
 * bits of a cdhash XOR-fold. It is NEVER a raw cdhash or a full pointer; full
 * digests stay server-side via the CsEvidence report plane. Keeping the record
 * at exactly 16 bytes leaves HK_EVENT_PAYLOAD_MAX == 16 and
 * sizeof(hk_event_record) == 40 untouched (no ioctl.h change, every existing
 * HK_STATIC_ASSERT in ioctl.h stays green).
 * ------------------------------------------------------------------------- */
typedef struct hk_event_cs_finding {
    uint32_t signal_id;   /* Catalog number 118..126 (0 on an HK_CS_OK heartbeat). */
    uint32_t finding;     /* HK_CS_* code. */
    uint32_t target_pid;  /* Game PID the finding pertains to (0 = host-wide, e.g.
                             AMFI posture / amfid). */
    uint32_t detail;      /* Compact discriminant — see note above. NEVER a raw
                             cdhash or full pointer. */
} hk_event_cs_finding;

HK_STATIC_ASSERT(sizeof(hk_event_cs_finding) == 16,
    "hk_event_cs_finding size mismatch");
