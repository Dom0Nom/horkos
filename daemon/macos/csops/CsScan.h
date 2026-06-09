/*
 * daemon/macos/csops/CsScan.h
 * Role: macOS code-signing scan orchestrator interface (signals 118-126).
 *       Declares HkCsScanInit/HkCsScanStop, the daemon-internal HkCsFinding
 *       struct probes fill before serialization, the in-process ES-observation
 *       struct the ES-driven probes (121/122/123) consume, and the probe
 *       registration table. The orchestrator owns the CsIntegrityProbe registry,
 *       the game-PID enumeration, the throttle/dedup, and the ES sink hookup.
 * Target platform: macOS only (CMake `if(APPLE)` gates the implementing TUs).
 * Interface: declared here; included by every probe .cpp, the orchestrator, and
 *            horkosd.cpp. Userspace daemon header (guardrail #4) — pure C/C++
 *            declarations, no kernel headers.
 *
 * Option A (plan §"New ES record types"): the ES-sourced facts the correlator /
 * team-id / amfid probes need ride this in-process HkEsObservation struct over
 * the EXISTING HKEsEventSink. They are NOT added to the public event_schema*.h
 * wire — only the HK_EVENT_CS_FINDING the orchestrator ultimately produces hits
 * the wire. This keeps the public schema to the single CS-finding addition and
 * preserves guardrail #4 (this is not a wire field, and no kernel TU includes it).
 */

#pragma once

#include "horkos/event_schema_cs.h"   /* hk_event_cs_finding, HK_CS_* codes */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * HkCsFinding — the daemon-internal finding a probe produces. The orchestrator
 * compacts {signal_id, finding, target_pid, detail} into the 16-byte
 * hk_event_cs_finding wire record and ships the full evidence (cdhash hex,
 * diffed entitlement keys, offending signing_id, CSR breakdown) on the JSON
 * report plane. `evidence`/`evidence_len` are an opaque, probe-owned blob the
 * orchestrator hands to the report serializer; it is NOT placed in the fixed
 * wire record (the masking discipline — no raw digest on the compact plane).
 * ------------------------------------------------------------------------- */
typedef struct HkCsFinding {
    uint32_t    signal_id;     /* 118..126 (0 = HK_CS_OK heartbeat) */
    uint32_t    finding;       /* HK_CS_* */
    uint32_t    target_pid;    /* 0 = host-wide */
    uint32_t    detail;        /* compact discriminant for the wire record */
    /* Opaque evidence for the JSON report plane (not the fixed record). The
     * probe owns this buffer's lifetime; the orchestrator copies before the
     * probe returns. Length 0 = no extended evidence. */
    const void *evidence;
    size_t      evidence_len;
} HkCsFinding;

/* -------------------------------------------------------------------------
 * HkCsProbeTarget — what a poll-based probe is asked to sample: one game PID
 * plus its translocation-resolved on-disk bundle path (resolved once by the
 * orchestrator and shared so each probe does not re-resolve). A probe may ignore
 * fields it does not need.
 * ------------------------------------------------------------------------- */
typedef struct HkCsProbeTarget {
    uint32_t    pid;             /* game PID to sample (0 = host-wide probes) */
    const char *bundle_path;     /* translocation-resolved on-disk path, or NULL
                                    if unavailable / not applicable */
    bool        is_game_main;    /* true iff pid is the game's main binary, not a
                                    helper/launcher (FP gate for 122) */
} HkCsProbeTarget;

/* -------------------------------------------------------------------------
 * HkEsObservation — in-process ES-sourced fact (Option A). EsClient.mm fills one
 * of these per relevant NOTIFY event and hands it to the orchestrator's sink
 * tap; the ES-driven probes (121/122/123) consume it. NOT a wire struct.
 * ------------------------------------------------------------------------- */
typedef enum HkEsObsKind {
    HK_ES_OBS_NONE            = 0,
    HK_ES_OBS_MMAP            = 1,  /* signal 121/122 input: exec mmap */
    HK_ES_OBS_CS_INVALIDATED  = 2,  /* signal 121 input */
    HK_ES_OBS_GET_TASK        = 3,  /* signal 123 input: task-port acquisition */
} HkEsObsKind;

typedef struct HkEsObservation {
    uint32_t kind;            /* HkEsObsKind */
    uint32_t source_pid;      /* the requester / mapping process */
    uint32_t target_pid;      /* the target (game / amfid), 0 if N/A */
    uint32_t protection;      /* mmap: protection bits (PROT_EXEC etc.) */
    uint32_t flags;           /* mmap: flags (MAP_ANON etc.) */
    uint32_t is_platform_src; /* 1 if the source FD / process is a platform binary */
    uint64_t timestamp_ns;    /* monotonic ns for the correlator window */
    /* truncated, NUL-padded signing-id of the mmap source FD / get-task target,
     * copied out of the es_message_t before it is freed (never retain the msg) */
    uint8_t  signing_id[32];
} HkEsObservation;

/* -------------------------------------------------------------------------
 * Probe vtable. Each probe registers a sample function the orchestrator calls on
 * its serial timer queue (poll-based probes) or a consume function it calls from
 * the ES-observation tap (ES-driven probes). A probe sets at most one. A probe
 * compiled OUT by its feature flag registers a no-op stub (links with any subset
 * — mirrors the Windows sensor-stub pattern).
 *
 * sample:  poll one HkCsProbeTarget; on a finding, fill *out and return true.
 * consume: fold one HkEsObservation; on a finding, fill *out and return true.
 * Returning false = nothing to report (emit nothing rather than a garbage
 * finding — the shared "every Sec-API / csops return checked, abort cleanly"
 * rule).
 * ------------------------------------------------------------------------- */
typedef bool (*HkCsProbeSampleFn)(const HkCsProbeTarget *target, HkCsFinding *out);
typedef bool (*HkCsProbeConsumeFn)(const HkEsObservation *obs, HkCsFinding *out);

typedef struct HkCsProbe {
    uint32_t           signal_id;   /* 118..126 */
    const char        *name;        /* for logging */
    HkCsProbeSampleFn  sample;      /* poll-based probes; NULL for ES-driven */
    HkCsProbeConsumeFn consume;     /* ES-driven probes; NULL for poll-based */
    bool               enabled;     /* gated by the per-signal HK_MACOS_CS_* flag */
} HkCsProbe;

/* -------------------------------------------------------------------------
 * Orchestrator lifecycle. HkCsScanInit builds the probe registry (only the
 * flag-enabled probes are live), enumerates the initial game-PID set, and
 * registers the ES-observation tap. HkCsScanStop tears it down. The emit
 * callback receives the compacted wire record + the opaque evidence blob; the
 * daemon wires it to its sink/report serializer.
 * ------------------------------------------------------------------------- */
typedef void (*HkCsEmitFn)(const hk_event_cs_finding *record,
                           const void *evidence, size_t evidence_len, void *ctx);

bool HkCsScanInit(HkCsEmitFn emit, void *ctx);
void HkCsScanStop(void);

/* Feed one ES observation into the ES-driven probes (called from the daemon's ES
 * sink tap). No-op if the orchestrator is not initialized. */
void HkCsScanOnEsObservation(const HkEsObservation *obs);

/* Run one poll pass over the current game-PID set (called from the orchestrator's
 * serial timer). Exposed for the host-side test harness to drive deterministically
 * without a real timer. */
void HkCsScanPollOnce(void);

/* -------------------------------------------------------------------------
 * Probe-registry accessor (test seam). Returns the static probe table and its
 * length so host tests can assert which signals are wired without a live daemon.
 * ------------------------------------------------------------------------- */
const HkCsProbe *HkCsScanProbeTable(size_t *out_count);

#ifdef __cplusplus
}  /* extern "C" */
#endif
