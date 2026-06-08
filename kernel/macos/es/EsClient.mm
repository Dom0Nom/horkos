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

#include "horkos/event_schema.h"

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
        break;
    }

    case ES_EVENT_TYPE_NOTIFY_EXEC: {
        /* Notify events require no reply — they are informational. */
        emit_process_create(msg->event.exec.target);
        break;
    }

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
        sSink    = NULL;
        sSinkCtx = NULL;
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
        sSink    = NULL;
        sSinkCtx = NULL;
        return NO;
    }

    sEsClient = client;
    os_log(sLog, "HKEsClient: started, subscribed to NOTIFY_EXEC + AUTH_EXEC");
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
