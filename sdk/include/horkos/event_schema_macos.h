/*
 * sdk/include/horkos/event_schema_macos.h
 * Role: macOS-only wire-format payloads for the process-inspection / injection
 *       sensors (catalog signals 109-117). These ride the macOS daemon sink ->
 *       server transport path (EsClient.mm HKEsEventSink / horkosd), NOT the
 *       Windows IOCTL ring. They are deliberately kept OUT of the shared
 *       `hk_event_record` union in event_schema.h so the Windows 40-byte
 *       HK_STATIC_ASSERT(sizeof(hk_event_record) == 40) and HK_EVENT_PAYLOAD_MAX
 *       stay untouched (see the design note in macos-injection.md). A future
 *       reader must NOT try to widen HK_EVENT_PAYLOAD_MAX to fit these — they are
 *       a separate, variable-size, macOS-only plane.
 * Target platforms: macOS (ES client + daemon pollers) and the server mirror.
 *       Plain C99, no platform headers — included by macOS TUs and conceptually
 *       mirrored (field-for-field) by server/telemetry/src/macos_inject.rs.
 * Interface: declares hk_es_* payload structs + the HK_EVENT_ES_* event-type
 *            discriminants and the HK_GET_TASK_* / HK_ESPROC_* / HK_MMAP_* /
 *            HK_REGION_* enums. Reuses HK_STATIC_ASSERT from event_schema.h.
 *
 * Guardrail compliance:
 *   #1  No platform #ifdef — CMake (`if(APPLE)`) gates which TUs include this.
 *   #3  This module comment covers role/platform/interface.
 *   #4  Pure C99 header, no kernel headers — safe to include from userspace TUs.
 *   #11 Every field below is telemetry; the matching data-categories.md rows are
 *       owned by the Schema phase. HK-TODO(schema): the "2b. Process inspection /
 *       injection (macOS)" subsection from macos-injection.md is NOT yet present
 *       in server/api/data-categories.md — it must land in the same PR that
 *       un-stubs these emitters (this scaffolding phase does not edit that file).
 */

#pragma once

/* HK_STATIC_ASSERT, the hk_event_header, and HK_EVENT_SCHEMA_VERSION live in the
 * shared schema. We reuse the assert macro and the header struct verbatim; we do
 * NOT bump HK_EVENT_SCHEMA_VERSION here (the shared header owns that). */
#include "horkos/event_schema.h"

/* -------------------------------------------------------------------------
 * macOS injection event-type discriminants.
 *
 * HK-TODO(schema): the Schema phase appends these to the shared `hk_event_type`
 * enum (values 5..12 per macos-injection.md). Until that lands they are mirrored
 * here as named constants so the macOS emitters and the server decoder share one
 * source of value. They are intentionally NOT redefinitions of `hk_event_type`
 * members (that enum is frozen this phase) — distinct names avoid an enum clash
 * with the Windows thread-injection domain, which also locally mirrors 5..8.
 * ------------------------------------------------------------------------- */
#define HK_EVENT_ES_GET_TASK      5u  /* signals 109, 110 (+113/116 source attr) */
#define HK_EVENT_ES_MMAP          6u  /* signal 111 */
#define HK_EVENT_ES_DYLD_INJECT   7u  /* signal 112 */
#define HK_EVENT_ES_PROC_CHECK    8u  /* signal 115 */
#define HK_EVENT_ES_EXC_PORT      9u  /* signal 113 */
#define HK_EVENT_ES_THREAD_ORIGIN 10u /* signal 114 */
#define HK_EVENT_ES_PTRACE        11u /* signal 116 */
#define HK_EVENT_ES_TEXT_WX       12u /* signal 117 */

/* -------------------------------------------------------------------------
 * GET_TASK flavor — mirrors es_get_task_type_t (CONTROL/READ/NAME). Signal 110
 * distinguishes the three; NAME is suppressed SERVER-side, not here.
 * ------------------------------------------------------------------------- */
#define HK_GET_TASK_CONTROL 0u
#define HK_GET_TASK_READ    1u
#define HK_GET_TASK_NAME    2u

/* Source-process classification flags (es_process_t-derived). Reported raw; the
 * server applies the platform-binary / allowlist / debugger FP gates. */
#define HK_ESPROC_PLATFORM_BINARY 0x00000001u
#define HK_ESPROC_ALLOWLISTED     0x00000002u
#define HK_ESPROC_DEBUGGER        0x00000004u

/* MMAP baseline classification (signal 111). KNOWN = source is a signed dylib in
 * the per-title manifest; UNKNOWN = unrecognised exec source; ANON_RWX = an
 * anonymous RWX/PROT_EXEC map (no backing file). */
#define HK_MMAP_BASELINE_KNOWN   0u
#define HK_MMAP_BASELINE_UNKNOWN 1u
#define HK_MMAP_BASELINE_ANON_RWX 2u

/* DYLD inject env-var presence bits (signal 112). */
#define HK_DYLD_VAR_INSERT_LIBRARIES 0x00000001u
#define HK_DYLD_VAR_FRAMEWORK_PATH   0x00000002u

/* Thread-origin region classification (signal 114). */
#define HK_REGION_IMAGE          0u  /* entry PC inside a known mach-o image */
#define HK_REGION_ANON           1u  /* entry PC in anonymous/unbacked memory */
#define HK_REGION_JIT_SANCTIONED 2u  /* entry PC in a sanctioned JIT region */

/* -------------------------------------------------------------------------
 * Signals 109/110 — task-port acquisition, with control/name/read flavor.
 * The es_string_token_t team-id / signing-id are copied out (truncated,
 * NUL-padded) before the es_message_t is freed — never retain the message.
 * ------------------------------------------------------------------------- */
typedef struct hk_es_get_task {
    uint32_t source_pid;             /* requester (es_message_t.process) */
    uint32_t target_pid;             /* the game (event.get_task.target) */
    uint32_t flavor;                 /* HK_GET_TASK_CONTROL/READ/NAME */
    uint32_t source_flags;           /* HK_ESPROC_* bitmask */
    uint8_t  source_team_id[16];     /* truncated team-id, NUL-padded */
    uint8_t  source_signing_id[32];  /* truncated signing-id, NUL-padded */
} hk_es_get_task;                    /* 64 bytes */

HK_STATIC_ASSERT(sizeof(hk_es_get_task) == 64, "hk_es_get_task size mismatch");

/* -------------------------------------------------------------------------
 * Signal 111 — non-self executable mmap into the game.
 * ------------------------------------------------------------------------- */
typedef struct hk_es_mmap {
    uint32_t target_pid;
    uint32_t source_pid;
    uint32_t protection;             /* es_event_mmap_t.protection (PROT_EXEC) */
    uint32_t flags;                  /* es_event_mmap_t.flags (MAP_ANON) */
    uint32_t baseline_match;         /* HK_MMAP_BASELINE_* */
    uint32_t reserved;
    uint8_t  source_path_sha256[32]; /* digest of es_event_mmap_t.source path */
} hk_es_mmap;                        /* 56 bytes */

HK_STATIC_ASSERT(sizeof(hk_es_mmap) == 56, "hk_es_mmap size mismatch");

/* -------------------------------------------------------------------------
 * Signal 112 — DYLD_INSERT_LIBRARIES survival past hardened-runtime strip.
 * ------------------------------------------------------------------------- */
typedef struct hk_es_dyld_inject {
    uint32_t pid;
    uint32_t cs_flags;               /* es_process_t.codesigning_flags */
    uint32_t dyld_var_present;       /* HK_DYLD_VAR_* bitmask */
    uint32_t injected_load_seen;     /* 1 if a non-system dylib actually loaded */
    uint8_t  inserted_path_sha256[32];
} hk_es_dyld_inject;                 /* 48 bytes */

HK_STATIC_ASSERT(sizeof(hk_es_dyld_inject) == 48,
    "hk_es_dyld_inject size mismatch");

/* -------------------------------------------------------------------------
 * Signal 115 — proc_info reconnaissance rate/flavor (aggregated per window).
 * ------------------------------------------------------------------------- */
typedef struct hk_es_proc_check {
    uint32_t source_pid;
    uint32_t target_pid;             /* the game */
    uint32_t flavor;                 /* es_proc_check_type_t */
    uint32_t rate_per_window;        /* aggregated count in the sampling window */
    uint32_t flavor_cardinality;     /* distinct flavors seen from this source */
    uint32_t source_flags;           /* HK_ESPROC_* */
} hk_es_proc_check;                  /* 24 bytes */

HK_STATIC_ASSERT(sizeof(hk_es_proc_check) == 24,
    "hk_es_proc_check size mismatch");

/* -------------------------------------------------------------------------
 * Signal 113 — foreign exception-port owner on the game task.
 * ------------------------------------------------------------------------- */
typedef struct hk_es_exc_port {
    uint32_t game_pid;
    uint32_t owner_pid;              /* task owning the new exc port (0=unresolved) */
    uint32_t mask;                   /* exception_mask_t bits that changed */
    uint32_t is_foreign;            /* 1 if owner != game and not Apple diagnostics */
} hk_es_exc_port;                    /* 16 bytes */

HK_STATIC_ASSERT(sizeof(hk_es_exc_port) == 16, "hk_es_exc_port size mismatch");

/* -------------------------------------------------------------------------
 * Signal 114 — thread with non-bundle entry point.
 * ------------------------------------------------------------------------- */
typedef struct hk_es_thread_origin {
    uint32_t game_pid;
    uint32_t thread_id;              /* mach thread id for correlation */
    uint64_t entry_pc;               /* arm64 __pc / x86_64 __rip start address */
    uint32_t region_kind;           /* HK_REGION_* */
    uint32_t reserved;
} hk_es_thread_origin;               /* 24 bytes */

HK_STATIC_ASSERT(sizeof(hk_es_thread_origin) == 24,
    "hk_es_thread_origin size mismatch");

/* -------------------------------------------------------------------------
 * Signal 116 — P_TRACED transition edge.
 * ------------------------------------------------------------------------- */
typedef struct hk_es_ptrace {
    uint32_t game_pid;
    uint32_t tracer_pid;             /* kp_eproc.e_ppid / correlated GET_TASK src */
    uint32_t traced_now;             /* current p_flag & P_TRACED */
    uint32_t cs_release_signed;      /* 1 if release-signed && no get-task-allow */
} hk_es_ptrace;                      /* 16 bytes */

HK_STATIC_ASSERT(sizeof(hk_es_ptrace) == 16, "hk_es_ptrace size mismatch");

/* -------------------------------------------------------------------------
 * Signal 117 — writable / COW-broken page inside signed __TEXT.
 * ------------------------------------------------------------------------- */
typedef struct hk_es_text_wx {
    uint32_t game_pid;
    uint32_t protection;             /* vm_region_submap_info_64.protection */
    uint32_t share_mode;             /* SM_COW / SM_PRIVATE */
    uint32_t csops_valid;            /* csops(CS_OPS_STATUS): 0 if invalidated */
    uint64_t region_addr;            /* start of the offending page */
} hk_es_text_wx;                     /* 24 bytes */

HK_STATIC_ASSERT(sizeof(hk_es_text_wx) == 24, "hk_es_text_wx size mismatch");
