/*
 * kernel/macos/es/EsClient.mm
 * Role: EndpointSecurity client for macOS. Subscribes to ES_EVENT_TYPE_NOTIFY_EXEC
 *       and ES_EVENT_TYPE_AUTH_EXEC; converts NOTIFY events to hk_event_record
 *       payloads and queues them for the userspace daemon. Every AUTH event is
 *       replied to unconditionally (ES_AUTH_RESULT_ALLOW) — Phase 4 is
 *       observation-only; blocking logic lands in Phase 5 under TDD.
 * Target platform: macOS 12+ (EndpointSecurity framework requires macOS 10.15+;
 *                  12 is the minimum for the entitlement path we target).
 * Interface: declares HKEsClientStart() / HKEsClientStop() for the XPC daemon
 *            (daemon/macos/HKDaemon.mm). Implements none of the horkos
 *            kernel-layer interfaces — this is userspace.
 *
 * API references:
 *   - Apple EndpointSecurity API docs (developer.apple.com/documentation/endpointsecurity)
 *   - /usr/include/EndpointSecurity/ESClient.h, ESTypes.h (macOS 12+ SDK)
 *   - TN3137: "On Mac runloops and the EndpointSecurity framework" (reply deadline)
 *
 * Guardrail compliance:
 *   #1  No raw _WIN32/__linux__/__APPLE__ — compilation is controlled entirely
 *       by CMake option HORKOS_MACOS_ES; no preprocessor platform guards needed.
 *   #3  This module comment covers role/platform/interface.
 *   #4  Pure userspace TU — no kernel headers included.
 *   #7  CRITICAL: es_respond_auth_result is called on EVERY ES_ACTION_TYPE_AUTH
 *       event before the handler block returns. Dropping a reply blocks the
 *       originating process indefinitely and eventually hangs the system.
 *   #8  No blocking calls on the ES event-handler queue (it is serial and
 *       time-bounded by the kernel deadline — treat it like an async handler).
 */

#import <Foundation/Foundation.h>
#import <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>   /* audit_token_to_pid */
#include <mach/mach_time.h>
#include <os/log.h>
#include <stdatomic.h>
#include <string.h>   /* memcpy / memset / strncmp for the injection emitters */

#include "horkos/event_schema.h"
#include "horkos/event_schema_macos.h"   /* hk_es_* injection payloads (109-117) */

/* macos-codesign-integrity (signals 121/122/123): EsClient also feeds the
 * code-signing orchestrator's in-process ES-observation tap (Option A — these
 * are NOT wire records, they never hit event_schema*.h). The tap is OPTIONAL and
 * compiled in only when the CS ES-driven probes are built; without it the new
 * NOTIFY_CS_INVALIDATED subscription is the only addition and the observations
 * are simply not forwarded. Guardrail #4 holds: this is a userspace-to-userspace
 * in-process struct, no kernel TU includes it. */
#include "CsScan.h"   /* HkEsObservation, HkCsScanOnEsObservation */

/* The ES framework delivers events on an internal serial queue. The kernel
 * enforces a reply deadline for AUTH events (documented as "within a few
 * seconds" in TN3137; the exact value is private but experimentation with
 * Apple's sample code puts it around 10–60 s depending on the event type).
 * Exceeding the deadline triggers a kernel panic or forces ES to re-deliver.
 * Our handler does no I/O on the fast path — only a mach_continuous_time()
 * read and a ring-write — so the deadline is not at risk here. */

static os_log_t sLog;

/* Forward declaration of the event-sink callback type. The daemon registers
 * this to receive completed hk_event_record structs without coupling EsClient
 * to any specific transport. */
typedef void (*HKEsEventSink)(const hk_event_header *header,
                               const void             *payload,
                               uint32_t                payload_bytes,
                               void                   *ctx);

/* Module-level state. Initialised in HKEsClientStart, cleared in
 * HKEsClientStop. All accesses happen either before the ES client is created
 * (single-threaded init) or from within the ES serial event queue (which
 * serialises them automatically). */
static es_client_t    *sEsClient;
static HKEsEventSink   sSink;
static void           *sSinkCtx;
/* The sink is invoked on this private serial queue, NOT on the ES delivery
 * queue. The ES queue is serial and deadline-bound: a blocking sink (back-
 * pressured ring, stalled XPC peer) would stall every exec on the system. We
 * copy the fixed-size record and hand it off async so the ES queue never waits
 * on transport. */
static dispatch_queue_t sSinkQueue;

/* -------------------------------------------------------------------------
 * Monotonic timestamp helper.
 * mach_continuous_time() counts while asleep (unlike mach_absolute_time()).
 * We convert to ns so the header timestamp is in the same unit as the Linux
 * and Windows paths.
 * ------------------------------------------------------------------------- */
static uint64_t hk_monotonic_ns(void)
{
    static mach_timebase_info_data_t sTbi;
    static atomic_int                sInitDone = 0;

    /* One-time initialisation. Races are benign: the result is idempotent and
     * mach_timebase_info is safe to call redundantly. */
    if (!atomic_load_explicit(&sInitDone, memory_order_acquire)) {
        mach_timebase_info(&sTbi);
        atomic_store_explicit(&sInitDone, 1, memory_order_release);
    }

    uint64_t ticks = mach_continuous_time();
    /* Overflow guard: numer/denom are typically 125/3 on Apple Silicon, safely
     * fitting in uint64_t for any realistic uptime. */
    return (ticks * sTbi.numer) / sTbi.denom;
}

/* -------------------------------------------------------------------------
 * Internal: emit an hk_event_process_create record to the registered sink.
 * Called from the ES notify handler; must not block.
 * ------------------------------------------------------------------------- */
static void emit_process_create(const es_process_t *proc)
{
    /* Snapshot the globals into locals once: HKEsClientStop may null sSinkQueue
     * concurrently, and dispatch_async(nil, ...) crashes. A captured non-nil
     * queue is safe to dispatch on even after the global is nil'd; Stop drains
     * it with a barrier before returning. */
    dispatch_queue_t q    = sSinkQueue;
    HKEsEventSink    sink = sSink;
    void            *ctx  = sSinkCtx;
    if (!sink || !q) {
        return;
    }

    hk_event_header hdr = {
        .version       = HK_EVENT_SCHEMA_VERSION,
        .type          = HK_EVENT_PROCESS_CREATE,
        .timestamp_ns  = hk_monotonic_ns(),
        .payload_bytes = sizeof(hk_event_process_create),
        .reserved      = 0,
    };

    /* audit_token_to_pid() is declared in <bsm/libbsm.h>. */
    hk_event_process_create payload = {
        .pid            = (uint32_t)audit_token_to_pid(proc->audit_token),
        .parent_pid     = (uint32_t)proc->ppid,
        /* create_time_ns is defined by the wire schema as a FILETIME (1601)
         * epoch value. ES does not expose a creation wall-clock here, and
         * emitting a mach-monotonic value into a FILETIME field would be
         * misread by ~400 years — so report 0 (unavailable) rather than a
         * foreign-epoch number. A real start time can be sourced from
         * es_process_t.start_time on newer ES message versions later. */
        .create_time_ns = 0,
    };

    /* Copy by value into the block and transport off the ES queue. */
    dispatch_async(q, ^{
        sink(&hdr, &payload, sizeof(payload), ctx);
    });
}

/* -------------------------------------------------------------------------
 * Injection-sensor emit helpers (signals 109/110/111/112/115).
 *
 * All five ride the SAME bounded-copy-then-dispatch_async discipline as
 * emit_process_create (guardrail #7-adjacent: the ES serial queue is deadline-
 * bound; never hash large buffers or do I/O / manifest lookups here). The
 * es_string_token_t fields (team_id, signing_id) are pointer+len INTO the
 * message, which is freed after the handler returns — we copy the bytes out
 * before dispatching. Never retain the es_message_t.
 *
 * NOTE: client emits raw signals only; ALL false-positive gating (platform-
 * binary / allowlist / debugger / NAME-suppression / rate threshold) is
 * server-side (plan risk #7). Do not add trust decisions to these helpers.
 * ------------------------------------------------------------------------- */

/* Copy a (possibly truncated) es_string_token_t into a fixed NUL-padded buffer. */
static void copy_token(uint8_t *dst, size_t dst_len, const es_string_token_t *tok)
{
    memset(dst, 0, dst_len);
    if (tok == NULL || tok->data == NULL || tok->length == 0) {
        return;
    }
    size_t n = tok->length;
    if (n > dst_len - 1) {       /* always leave room for a terminator */
        n = dst_len - 1;
    }
    memcpy(dst, tok->data, n);
}

/* Translate es_process_t signing attributes into HK_ESPROC_* flags. */
static uint32_t esproc_flags(const es_process_t *proc)
{
    uint32_t flags = 0;
    if (proc == NULL) {
        return flags;
    }
    if (proc->is_platform_binary) {
        flags |= HK_ESPROC_PLATFORM_BINARY;
    }
    /* HK-TODO(allowlist): _ALLOWLISTED is a server-side determination; the
     * client never holds the signed-diagnostics allowlist. Left unset here. */
    /* A non-NULL responsible/debugger relationship is not directly on
     * es_process_t; the debugger gate is applied server-side from the
     * P_TRACED / GET_TASK correlation. */
    return flags;
}

static void emit_to_sink(const hk_event_header *hdr_in,
                         const void *payload, uint32_t payload_bytes)
{
    dispatch_queue_t q    = sSinkQueue;
    HKEsEventSink    sink = sSink;
    void            *ctx  = sSinkCtx;
    if (!sink || !q) {
        return;
    }
    /* Copy header + payload by value into the block (the caller's locals go out
     * of scope). A bare C array cannot be captured by a block, so wrap the
     * fixed-size buffer in a struct — structs ARE captured by value. Payloads
     * are small (<= 64B), so a stack copy is cheap. */
    struct hk_sink_buf { uint8_t bytes[64]; };
    hk_event_header hdr = *hdr_in;
    if (payload_bytes > sizeof(((struct hk_sink_buf *)0)->bytes)) {
        os_log_error(sLog, "HKEsClient: payload %u exceeds sink buffer", payload_bytes);
        return;
    }
    struct hk_sink_buf sbuf;
    memset(&sbuf, 0, sizeof(sbuf));
    memcpy(sbuf.bytes, payload, payload_bytes);
    dispatch_async(q, ^{
        sink(&hdr, sbuf.bytes, payload_bytes, ctx);
    });
}

/* Signals 109/110 — GET_TASK / GET_TASK_NAME / GET_TASK_READ. */
static void emit_get_task(const es_message_t *msg, uint32_t flavor,
                          const es_process_t *target)
{
    hk_event_header hdr = {
        .version       = HK_EVENT_SCHEMA_VERSION,
        .type          = HK_EVENT_ES_GET_TASK,
        .timestamp_ns  = hk_monotonic_ns(),
        .payload_bytes = sizeof(hk_es_get_task),
        .reserved      = 0,
    };
    hk_es_get_task p;
    memset(&p, 0, sizeof(p));
    p.source_pid   = (uint32_t)audit_token_to_pid(msg->process->audit_token);
    p.target_pid   = target ? (uint32_t)audit_token_to_pid(target->audit_token) : 0;
    p.flavor       = flavor;
    p.source_flags = esproc_flags(msg->process);
    copy_token(p.source_team_id,    sizeof(p.source_team_id),    &msg->process->team_id);
    copy_token(p.source_signing_id, sizeof(p.source_signing_id), &msg->process->signing_id);
    emit_to_sink(&hdr, &p, sizeof(p));
}

/* Signal 111 — non-self executable mmap into a target. The PROT_EXEC/MAP_ANON
 * discrimination and the path digest happen here, but the per-title baseline
 * lookup is deferred to the daemon/server (never on the ES queue). */
static void emit_mmap(const es_message_t *msg)
{
    const es_event_mmap_t *mm = &msg->event.mmap;
    hk_event_header hdr = {
        .version       = HK_EVENT_SCHEMA_VERSION,
        .type          = HK_EVENT_ES_MMAP,
        .timestamp_ns  = hk_monotonic_ns(),
        .payload_bytes = sizeof(hk_es_mmap),
        .reserved      = 0,
    };
    hk_es_mmap p;
    memset(&p, 0, sizeof(p));
    p.source_pid = (uint32_t)audit_token_to_pid(msg->process->audit_token);
    p.target_pid = p.source_pid;  /* ES MMAP is the mapping process itself */
    p.protection = (uint32_t)mm->protection;
    p.flags      = (uint32_t)mm->flags;
    /* baseline_match is set later by the daemon/server from HKMmapBaselineMatch;
     * the client leaves it UNKNOWN and ships the (deferred) source-path digest as
     * zero here — hashing a path on the ES serial queue is exactly the I/O the
     * deadline rule forbids. HK-TODO(mmap-digest): the daemon computes
     * source_path_sha256 off-queue from mm->source. */
    p.baseline_match = HK_MMAP_BASELINE_UNKNOWN;
    emit_to_sink(&hdr, &p, sizeof(p));
}

/* Signal 115 — proc_info reconnaissance. Emitted raw per-event here; the daemon
 * aggregates per-source rate/cardinality over a window before the server scores
 * (the plan's flood mitigation). */
static void emit_proc_check(const es_message_t *msg)
{
    const es_event_proc_check_t *pc = &msg->event.proc_check;
    hk_event_header hdr = {
        .version       = HK_EVENT_SCHEMA_VERSION,
        .type          = HK_EVENT_ES_PROC_CHECK,
        .timestamp_ns  = hk_monotonic_ns(),
        .payload_bytes = sizeof(hk_es_proc_check),
        .reserved      = 0,
    };
    hk_es_proc_check p;
    memset(&p, 0, sizeof(p));
    p.source_pid         = (uint32_t)audit_token_to_pid(msg->process->audit_token);
    p.target_pid         = pc->target
                           ? (uint32_t)audit_token_to_pid(pc->target->audit_token) : 0;
    p.flavor             = (uint32_t)pc->type;
    p.rate_per_window    = 1;  /* daemon aggregates; single-event count here */
    p.flavor_cardinality = 1;
    p.source_flags       = esproc_flags(msg->process);
    emit_to_sink(&hdr, &p, sizeof(p));
}

/* Signal 112 — DYLD_INSERT_LIBRARIES survival, derived from the EXEC env. */
static void emit_dyld_inject(const es_message_t *msg)
{
    const es_event_exec_t *ex = &msg->event.exec;
    const es_process_t    *tgt = ex->target;
    uint32_t var_present = 0;

    uint32_t env_count = es_exec_env_count(ex);
    for (uint32_t i = 0; i < env_count; ++i) {
        es_string_token_t e = es_exec_env(ex, i);
        if (e.data == NULL || e.length == 0) {
            continue;
        }
        /* Prefix-match the env var name up to '='. strncmp is bounded by the
         * literal length; e.data is not NUL-terminated, so never strlen it. */
        if (e.length >= 22 && strncmp(e.data, "DYLD_INSERT_LIBRARIES=", 22) == 0) {
            var_present |= HK_DYLD_VAR_INSERT_LIBRARIES;
        } else if (e.length >= 20 && strncmp(e.data, "DYLD_FRAMEWORK_PATH=", 20) == 0) {
            var_present |= HK_DYLD_VAR_FRAMEWORK_PATH;
        }
    }

    if (var_present == 0) {
        return;  /* no DYLD injection vars — nothing to report */
    }

    hk_event_header hdr = {
        .version       = HK_EVENT_SCHEMA_VERSION,
        .type          = HK_EVENT_ES_DYLD_INJECT,
        .timestamp_ns  = hk_monotonic_ns(),
        .payload_bytes = sizeof(hk_es_dyld_inject),
        .reserved      = 0,
    };
    hk_es_dyld_inject p;
    memset(&p, 0, sizeof(p));
    p.pid              = tgt ? (uint32_t)audit_token_to_pid(tgt->audit_token) : 0;
    p.cs_flags         = tgt ? (uint32_t)tgt->codesigning_flags : 0;
    p.dyld_var_present = var_present;
    /* injected_load_seen requires correlating a later non-system image load;
     * the client cannot confirm it inline. Server/daemon sets it from a
     * follow-up image-load event. */
    p.injected_load_seen = 0;
    emit_to_sink(&hdr, &p, sizeof(p));
}

/* -------------------------------------------------------------------------
 * macos-codesign-integrity ES-observation emitters (signals 121/122/123).
 *
 * These hand an in-process HkEsObservation to the CS orchestrator's tap. Like
 * the wire emitters they NEVER run probe logic on the ES serial queue: the
 * orchestrator call is dispatched onto sSinkQueue (the same async hand-off
 * sSinkQueue provides for records) so the deadline-bound ES queue never waits on
 * correlation work. The es_string_token_t signing-id is copied out before the
 * es_message_t is freed — never retain the message.
 *
 * The CS tap is build-gated by HK_MACOS_CS_ES_TAP: it is defined only when the
 * CS ES-driven probes (121/122/123) are compiled into the daemon the ES lib
 * links with. When undefined, the observation is built but not forwarded (the
 * new NOTIFY_CS_INVALIDATED subscription is harmless without a consumer).
 * ------------------------------------------------------------------------- */
static void emit_cs_observation(const HkEsObservation *obs)
{
    dispatch_queue_t q = sSinkQueue;
    if (!q) {
        return;
    }
    HkEsObservation copy = *obs;   /* by-value capture into the block */
    dispatch_async(q, ^{
#ifdef HK_MACOS_CS_ES_TAP
        HkCsScanOnEsObservation(&copy);
#else
        (void)copy;  /* no CS consumer compiled in — drop after the bounded copy */
#endif
    });
}

/* Signal 121 input: a CS_INVALIDATED on a target audit_token. */
static void cs_emit_invalidated(const es_message_t *msg)
{
    HkEsObservation obs;
    memset(&obs, 0, sizeof(obs));
    obs.kind         = HK_ES_OBS_CS_INVALIDATED;
    obs.target_pid   = (uint32_t)audit_token_to_pid(msg->process->audit_token);
    obs.source_pid   = obs.target_pid;
    obs.timestamp_ns = hk_monotonic_ns();
    obs.is_platform_src = msg->process->is_platform_binary ? 1u : 0u;
    copy_token(obs.signing_id, sizeof(obs.signing_id), &msg->process->signing_id);
    emit_cs_observation(&obs);
}

/* Signal 121/122 input: an exec mmap. Reuses es_event_mmap_t (already read for
 * the wire emit_mmap); here we surface the source-FD signing-id + platform bit
 * the correlator/team-id probes need. */
static void cs_emit_mmap(const es_message_t *msg)
{
    const es_event_mmap_t *mm = &msg->event.mmap;
    HkEsObservation obs;
    memset(&obs, 0, sizeof(obs));
    obs.kind         = HK_ES_OBS_MMAP;
    obs.source_pid   = (uint32_t)audit_token_to_pid(msg->process->audit_token);
    obs.target_pid   = obs.source_pid;   /* ES MMAP is the mapping process itself */
    obs.protection   = (uint32_t)mm->protection;
    obs.flags        = (uint32_t)mm->flags;
    /* The source FD's signing attributes (es_file_t.* via mm->source) and whether
     * it is a platform binary identify a non-platform exec page. mm->source is an
     * es_file_t*; the signing-id lives on the mapping PROCESS for team-id, but the
     * FD-level platform bit is the discriminant the correlator wants.
     * HK-UNCERTAIN(es-mmap-source): the exact es_event_mmap_t source signing
     * fields / availability across ES message versions is unverified (plan
     * Risk 4); we conservatively copy the mapping process's platform bit + signing
     * id, which the correlator treats as the non-platform gate input. */
    obs.is_platform_src = msg->process->is_platform_binary ? 1u : 0u;
    obs.timestamp_ns = hk_monotonic_ns();
    copy_token(obs.signing_id, sizeof(obs.signing_id), &msg->process->signing_id);
    emit_cs_observation(&obs);
}

/* Signal 123 input: a get-task on a target (the watch matches amfid by signing-id
 * daemon-side). */
static void cs_emit_get_task(const es_message_t *msg, const es_process_t *target)
{
    HkEsObservation obs;
    memset(&obs, 0, sizeof(obs));
    obs.kind         = HK_ES_OBS_GET_TASK;
    obs.source_pid   = (uint32_t)audit_token_to_pid(msg->process->audit_token);
    obs.target_pid   = target ? (uint32_t)audit_token_to_pid(target->audit_token) : 0;
    obs.is_platform_src = msg->process->is_platform_binary ? 1u : 0u;
    obs.timestamp_ns = hk_monotonic_ns();
    /* The watch keys on the TARGET's signing-id (amfid); copy the target's. */
    if (target) {
        copy_token(obs.signing_id, sizeof(obs.signing_id), &target->signing_id);
    }
    emit_cs_observation(&obs);
}

/* -------------------------------------------------------------------------
 * ES event handler block.
 *
 * GUARDRAIL #7: Every ES_ACTION_TYPE_AUTH event MUST receive an
 * es_respond_auth_result call before this block returns. Failure to reply
 * blocks the originating process until the kernel deadline fires; at that
 * point the kernel may assume an allow (or panic, depending on macOS version).
 * Never add an early return, a goto, or an exception path that skips the reply.
 * ------------------------------------------------------------------------- */
static void handle_es_message(es_client_t *client, const es_message_t *msg)
{
    switch (msg->event_type) {

    case ES_EVENT_TYPE_AUTH_EXEC: {
        /* Phase 4 is observation-only. Allow unconditionally.
         *
         * es_respond_auth_result(client, msg, result, cache):
         *   - client : the es_client_t that received this message
         *   - msg    : the es_message_t being replied to (must not be retained)
         *   - result : ES_AUTH_RESULT_ALLOW / ES_AUTH_RESULT_DENY
         *   - cache  : false — do not cache this decision; re-evaluate every
         *              exec. Phase 5 may flip this to true for allowlisted paths.
         *
         * Reference: developer.apple.com/documentation/endpointsecurity/3228976-es_respond_auth_result
         * Declared in <EndpointSecurity/ESClient.h>. The bool 'cache' param
         * was added in macOS 10.15.4; earlier SDKs take a different signature.
         *
         * CRITICAL: this call is the reply. Do not restructure the switch in a
         * way that lets control reach the bottom of this case without it. */
        es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false);

        /* Also emit a process-create record for the auth exec so the server
         * sees it on the same code path as notify execs. */
        emit_process_create(msg->event.exec.target);
        /* Signal 112: surface DYLD_INSERT_LIBRARIES/FRAMEWORK_PATH in the env. */
        emit_dyld_inject(msg);
        break;
    }

    case ES_EVENT_TYPE_NOTIFY_EXEC: {
        /* Notify events require no reply — they are informational. */
        emit_process_create(msg->event.exec.target);
        emit_dyld_inject(msg);  /* signal 112 */
        break;
    }

    /* Signals 109/110 — task-port acquisition. All NOTIFY (no reply). The three
     * flavors are emitted RAW; the server suppresses NAME (signal 110's
     * "must NOT be flagged") and applies the platform-binary / debugger gates. */
    case ES_EVENT_TYPE_NOTIFY_GET_TASK:
        emit_get_task(msg, HK_GET_TASK_CONTROL, msg->event.get_task.target);
        cs_emit_get_task(msg, msg->event.get_task.target);  /* signal 123 input */
        break;
    case ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME:
        emit_get_task(msg, HK_GET_TASK_NAME, msg->event.get_task_name.target);
        break;
    case ES_EVENT_TYPE_NOTIFY_GET_TASK_READ:
        emit_get_task(msg, HK_GET_TASK_READ, msg->event.get_task_read.target);
        cs_emit_get_task(msg, msg->event.get_task_read.target);  /* signal 123 */
        break;

    /* Signal 111 — executable mmap. Also feeds the CS correlator/team-id probes
     * (signals 121/122) via the in-process observation tap. */
    case ES_EVENT_TYPE_NOTIFY_MMAP:
        emit_mmap(msg);
        cs_emit_mmap(msg);
        break;

    /* Signal 121 — code-signature invalidated. NOTIFY (no reply). Feeds the CS
     * invalidation correlator only (no wire record of its own — Option A). */
    case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED:
        cs_emit_invalidated(msg);
        break;

    /* Signal 115 — proc_info reconnaissance. */
    case ES_EVENT_TYPE_NOTIFY_PROC_CHECK:
        emit_proc_check(msg);
        break;

    default:
        /* Defensive: ES should only deliver subscribed event types. But if a
         * future AUTH subscription is ever added without a matching case here,
         * an AUTH message reaching this branch with no reply would block the
         * originating process and eventually hang the system (guardrail #7).
         * Fail safe: reply ALLOW to ANY auth-type message that reaches default. */
        if (msg->action_type == ES_ACTION_TYPE_AUTH) {
            es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false);
        }
        os_log_error(sLog,
            "HKEsClient: unexpected event type %u — not a subscribed type",
            (unsigned)msg->event_type);
        break;
    }
}

/* -------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

/*
 * HKEsClientStart — create the ES client and subscribe to exec events.
 *
 * sink     : callback invoked for each hk_event_record (called on the ES
 *            internal serial queue; must not block).
 * sink_ctx : opaque pointer forwarded to every sink call.
 *
 * Returns YES on success. On failure, *out_err is set to a localised
 * description of the es_new_client_result_t error.
 *
 * Possible es_new_client_result_t values (from ESClient.h):
 *   ES_NEW_CLIENT_RESULT_SUCCESS
 *   ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED      — missing entitlement
 *   ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED    — not running as root
 *   ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED     — SIP prevents this binary
 *   ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS  — system-wide client limit hit
 *   ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT  — nil handler
 *   ES_NEW_CLIENT_RESULT_ERR_INTERNAL          — unspecified kernel error
 */
BOOL HKEsClientStart(HKEsEventSink sink, void *sink_ctx, NSError **out_err)
{
    if (sEsClient) {
        if (out_err) {
            *out_err = [NSError errorWithDomain:@"HKEsClient"
                                           code:1
                                       userInfo:@{NSLocalizedDescriptionKey:
                                           @"ES client already started"}];
        }
        return NO;
    }

    sLog       = os_log_create("io.horkos.daemon", "es-client");
    sSink      = sink;
    sSinkCtx   = sink_ctx;
    sSinkQueue = dispatch_queue_create("io.horkos.daemon.sink",
                                       DISPATCH_QUEUE_SERIAL);

    /* The event types we subscribe to:
     *   ES_EVENT_TYPE_NOTIFY_EXEC — post-exec notification (no reply needed)
     *   ES_EVENT_TYPE_AUTH_EXEC   — pre-exec authorisation (reply required)
     *
     * Reference: developer.apple.com/documentation/endpointsecurity/3228981-es_subscribe
     * The subscription list is an array of es_event_type_t with a count. */
    es_event_type_t subscriptions[] = {
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_AUTH_EXEC,
        /* Process-inspection / injection sensors (signals 109/110/111/112/115).
         * All NOTIFY (no reply) — guardrail #7 is not triggered by these; the
         * AUTH_EXEC reply invariant and the default: fail-safe ALLOW stay as-is.
         * GET_TASK_READ requires the macOS 11.3+ SDK (es_get_task_type_t); the
         * lib targets 12.0 so it is satisfied — do NOT lower the SDK floor below
         * 11.3 without dropping this subscription. */
        ES_EVENT_TYPE_NOTIFY_GET_TASK,
        ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME,
        ES_EVENT_TYPE_NOTIFY_GET_TASK_READ,
        ES_EVENT_TYPE_NOTIFY_MMAP,
        ES_EVENT_TYPE_NOTIFY_PROC_CHECK,
        /* macos-codesign-integrity (signal 121): code-signature invalidation.
         * NOTIFY (no reply) — the AUTH_EXEC reply invariant and the default:
         * fail-safe ALLOW are unchanged (guardrail #7 not implicated). The
         * GET_TASK{,_READ} and MMAP subscriptions above are reused for signals
         * 122/123; only CS_INVALIDATED is a new subscription here. */
        ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED,
    };

    es_client_t *client = NULL;

    /* es_new_client takes the handler block by copy; the block captures
     * 'client' by reference so it can forward it to handle_es_message, but
     * 'client' is only valid after es_new_client returns. The ES framework
     * does not call the handler during es_new_client, so this is safe. */
    es_new_client_result_t result =
        es_new_client(&client, ^(es_client_t *c, const es_message_t *msg) {
            handle_es_message(c, msg);
        });

    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        NSString *desc = nil;
        switch (result) {
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            desc = @"Missing com.apple.developer.endpoint-security.client "
                   @"entitlement. See docs/macos-es.md for the provisioning "
                   @"flag (HORKOS_MACOS_ES_PROVISIONED).";
            break;
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            desc = @"ES client requires root (UID 0).";
            break;
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            desc = @"SIP prevents this binary from using EndpointSecurity. "
                   @"Disable SIP in recoveryOS or load the System Extension.";
            break;
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
            desc = @"System-wide ES client limit reached.";
            break;
        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
            desc = @"es_new_client called with a nil handler.";
            break;
        case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
            /* fallthrough */
        default:
            desc = [NSString stringWithFormat:
                @"es_new_client internal error (result=%u)", (unsigned)result];
            break;
        }
        os_log_error(sLog, "HKEsClient: es_new_client failed: %{public}@", desc);
        if (out_err) {
            *out_err = [NSError errorWithDomain:@"HKEsClient"
                                           code:(NSInteger)result
                                       userInfo:@{NSLocalizedDescriptionKey: desc}];
        }
        sSink      = NULL;
        sSinkCtx   = NULL;
        sSinkQueue = nil;
        sLog       = NULL;
        return NO;
    }

    es_return_t sub = es_subscribe(client,
                                   subscriptions,
                                   sizeof(subscriptions) / sizeof(subscriptions[0]));
    if (sub != ES_RETURN_SUCCESS) {
        os_log_error(sLog, "HKEsClient: es_subscribe failed (%u)", (unsigned)sub);
        es_delete_client(client);
        if (out_err) {
            *out_err = [NSError errorWithDomain:@"HKEsClient"
                                           code:(NSInteger)sub
                                       userInfo:@{NSLocalizedDescriptionKey:
                                           @"es_subscribe failed"}];
        }
        sSink      = NULL;
        sSinkCtx   = NULL;
        sSinkQueue = nil;
        sLog       = NULL;
        return NO;
    }

    sEsClient = client;
    os_log(sLog, "HKEsClient: started, subscribed to NOTIFY_EXEC + AUTH_EXEC + "
                 "GET_TASK{,_NAME,_READ} + MMAP + PROC_CHECK (signals 109-112,115)");
    return YES;
}

/*
 * HKEsClientStop — unsubscribe and destroy the ES client.
 *
 * MUST be called on the SAME thread that called HKEsClientStart: the ES API
 * requires es_delete_client to run on the thread that called es_new_client.
 * After this returns the event-handler block will not be called again, and
 * es_delete_client blocks until all in-flight handler invocations have returned,
 * so the auth-reply invariant is satisfied before teardown.
 */
void HKEsClientStop(void)
{
    if (!sEsClient) {
        return;
    }
    /* es_unsubscribe_all then es_delete_client is the documented teardown
     * sequence. es_delete_client alone is sufficient per the ES headers, but
     * explicit unsubscribe signals intent clearly. */
    es_unsubscribe_all(sEsClient);
    es_delete_client(sEsClient);
    /* es_delete_client waits only on in-flight ES HANDLERS, not on the
     * dispatch_async sink work those handlers already enqueued. Drain it with a
     * barrier so no block runs sink(...,ctx) after the caller frees ctx. */
    if (sSinkQueue) {
        dispatch_sync(sSinkQueue, ^{});
    }
    sEsClient  = NULL;
    sSink      = NULL;
    sSinkCtx   = NULL;
    sSinkQueue = nil;  /* ARC releases the serial sink queue. */
    os_log(sLog, "HKEsClient: stopped");
}
