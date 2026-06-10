/*
 * daemon/macos/horkosd.cpp
 * Role: launchd-managed XPC service daemon bring-up skeleton.
 *       Registers a Mach service under the label "com.horkos.daemon",
 *       accepts client connections, and handles a "ping" command with a
 *       "pong" reply.  No anti-cheat logic yet; this is the verifiable
 *       macOS bring-up path (Phase 4 Step 4.4).
 * Target platforms: macOS only.
 * Interface: standalone executable; no Horkos library headers required at
 *            this stage.  Future phases will include ac.h / Attestation.h.
 *
 * Build:
 *   clang++ -std=c++17 -Wall -Wextra -Werror horkosd.cpp \
 *           -framework Foundation -framework Security -o horkosd
 *   (Foundation pulls in libSystem and the XPC runtime on macOS.)
 *
 * XPC service naming note:
 *   xpc_connection_create_mach_service() with XPC_CONNECTION_MACH_SERVICE_LISTENER
 *   requires either a launchd job that declares the service in MachServices, or
 *   the SandboxExtension entitlement in a sandboxed context.  When launched by
 *   launchd via the plist, launchd registers the Mach service automatically before
 *   exec, so the call here just names an already-registered port.
 *   Reference: man 3 xpc_connection_create_mach_service, WWDC 2012 session 241.
 */

#include <xpc/xpc.h>
#include <dispatch/dispatch.h>
#include <Security/Security.h>
#include <syslog.h>
#include <cstdlib>
#include <cstring>

/* -----------------------------------------------------------------------
 * xpc_connection_get_audit_token is Apple SPI (not in the public SDK
 * headers) but is stable and documented via security research. We declare
 * it guarded so the build fails loudly if the symbol disappears rather
 * than silently calling the wrong address.
 *
 * HK-UNCERTAIN(xpc-audit-token-spi): xpc_connection_get_audit_token is
 * private SPI. Its signature is well-known and the symbol has been stable
 * across OS X 10.10 through macOS 14, but Apple may remove or change it
 * without notice. If the symbol is unavailable the peer-validation path
 * fails closed (connection cancelled). Verify on each major macOS release.
 * ----------------------------------------------------------------------- */
extern "C" void xpc_connection_get_audit_token(xpc_connection_t, audit_token_t *);

/* Allowlisted signing identifiers that may connect to this daemon.
 * A placeholder list; the real list must be reviewed before Phase 5
 * ships to production. */
static const char * const kAllowedSigningIds[] = {
    "com.horkos.game",
    "com.horkos.client",
};
static const size_t kAllowedSigningIdCount =
    sizeof(kAllowedSigningIds) / sizeof(kAllowedSigningIds[0]);

/* ------------------------------------------------------------------
 * Forward declarations
 * ------------------------------------------------------------------ */
static void handle_client_event(xpc_connection_t peer, xpc_object_t event);
static void handle_peer_connection(xpc_connection_t peer);

/* ------------------------------------------------------------------
 * validate_peer_signing_id
 *
 * Obtains the connecting process's audit token via the SPI
 * xpc_connection_get_audit_token, creates a SecTask from it, reads the
 * code-signing identifier, and checks it against the allowlist.
 *
 * Fail-closed contract: any failure in the SPI call, SecTask creation,
 * or identifier retrieval returns false (caller cancels the connection).
 * ------------------------------------------------------------------ */
static bool validate_peer_signing_id(xpc_connection_t peer)
{
    audit_token_t token;
    memset(&token, 0, sizeof(token));

    /* SPI — see HK-UNCERTAIN(xpc-audit-token-spi) above. */
    xpc_connection_get_audit_token(peer, &token);

    SecTaskRef task = SecTaskCreateWithAuditToken(NULL, token);
    if (task == NULL) {
        syslog(LOG_ERR, "horkosd: SecTaskCreateWithAuditToken failed — rejecting peer");
        return false;
    }

    CFErrorRef err = NULL;
    /* Try the application-identifier entitlement first (sandboxed apps). */
    CFTypeRef ent_val = SecTaskCopyValueForEntitlement(
        task, CFSTR("com.apple.application-identifier"), &err);
    CFStringRef signing_id = NULL;
    if (ent_val != NULL && CFGetTypeID(ent_val) == CFStringGetTypeID()) {
        signing_id = (CFStringRef)ent_val;
    } else {
        if (ent_val != NULL) CFRelease(ent_val);
        if (err != NULL) { CFRelease(err); err = NULL; }
        /* Fall back to the bare signing identifier (non-sandboxed daemons). */
        signing_id = SecTaskCopySigningIdentifier(task, &err);
    }
    CFRelease(task);

    if (signing_id == NULL) {
        if (err) CFRelease(err);
        syslog(LOG_ERR, "horkosd: could not read peer signing id — rejecting");
        return false;
    }

    char id_buf[256] = {0};
    CFStringGetCString(signing_id, id_buf, sizeof(id_buf), kCFStringEncodingUTF8);
    CFRelease(signing_id);

    for (size_t i = 0; i < kAllowedSigningIdCount; ++i) {
        if (strcmp(id_buf, kAllowedSigningIds[i]) == 0) {
            return true;
        }
    }

    syslog(LOG_WARNING, "horkosd: rejected peer with signing id '%s'", id_buf);
    return false;
}

/* ------------------------------------------------------------------
 * XPC listener callback — called once per new client connection.
 * ------------------------------------------------------------------ */
static void handle_peer_connection(xpc_connection_t peer)
{
    /* Validate the peer's code-signing identity before processing any
     * messages. Fail closed: if validation is unavailable or fails, the
     * connection is cancelled immediately and the retain is never taken. */
    if (!validate_peer_signing_id(peer)) {
        xpc_connection_cancel(peer);
        return;
    }

    /* Retain the peer; it is released when the connection is cancelled. */
    xpc_retain(peer);

    xpc_connection_set_event_handler(peer, ^(xpc_object_t event) {
        handle_client_event(peer, event);
    });

    /* Resume starts delivering events on the connection's private queue. */
    xpc_connection_resume(peer);
}

/* ------------------------------------------------------------------
 * Per-client event handler.
 * Handles the special XPC_ERROR_* sentinel objects and real messages.
 * ------------------------------------------------------------------ */
static void handle_client_event(xpc_connection_t peer, xpc_object_t event)
{
    xpc_type_t type = xpc_get_type(event);

    if (type == XPC_TYPE_ERROR) {
        if (event == XPC_ERROR_CONNECTION_INVALID) {
            /* Client disconnected cleanly or the connection was cancelled.
               Release the retain taken in handle_peer_connection(). */
            syslog(LOG_INFO, "horkosd: client disconnected");
            xpc_release(peer);
        } else if (event == XPC_ERROR_TERMINATION_IMMINENT) {
            /* launchd is about to force-terminate us (e.g. system shutdown).
               We have a short window — no long-running work here. */
            syslog(LOG_NOTICE, "horkosd: termination imminent");
        }
        return;
    }

    if (type != XPC_TYPE_DICTIONARY) {
        /* Unexpected object type — ignore. */
        return;
    }

    const char *command = xpc_dictionary_get_string(event, "command");
    if (command == nullptr) {
        syslog(LOG_WARNING, "horkosd: received message with no 'command' key");
        return;
    }

    if (__builtin_strcmp(command, "ping") == 0) {
        /* Build and send a pong reply on the same peer connection.
           xpc_dictionary_create_reply() sets the reply's routing information
           so the client's reply handler receives it.
           Reference: man 3 xpc_dictionary_create_reply. */
        xpc_object_t reply = xpc_dictionary_create_reply(event);
        if (reply == nullptr) {
            /* event was not a two-way message (no reply channel).  Skip. */
            syslog(LOG_WARNING, "horkosd: ping with no reply channel");
            return;
        }

        xpc_dictionary_set_string(reply, "response", "pong");
        xpc_connection_send_message(peer, reply);
        xpc_release(reply);

        syslog(LOG_DEBUG, "horkosd: handled ping → pong");
        return;
    }

    syslog(LOG_WARNING, "horkosd: unknown command '%s'", command);
}

/* ------------------------------------------------------------------
 * main — register the XPC listener and enter the run loop.
 * ------------------------------------------------------------------ */
int main(void)
{
    openlog("horkosd", LOG_PID | LOG_CONS, LOG_DAEMON);
    syslog(LOG_INFO, "horkosd: starting");

    /*
     * XPC_CONNECTION_MACH_SERVICE_LISTENER marks this connection as the
     * accepting end of the Mach service registered in the launchd plist.
     * The second argument (targetq) may be NULL to accept the default
     * concurrent queue; we pass NULL here and let XPC dispatch internally.
     *
     * IMPORTANT: XPC_CONNECTION_MACH_SERVICE_LISTENER is only valid for the
     * server side (the daemon).  Clients call xpc_connection_create_mach_service()
     * WITHOUT this flag.
     * Reference: <xpc/connection.h>, man 3 xpc_connection_create_mach_service.
     */
    xpc_connection_t listener = xpc_connection_create_mach_service(
        "com.horkos.daemon",
        /*targetq=*/nullptr,
        XPC_CONNECTION_MACH_SERVICE_LISTENER
    );

    if (listener == nullptr) {
        syslog(LOG_ERR, "horkosd: xpc_connection_create_mach_service failed");
        return EXIT_FAILURE;
    }

    xpc_connection_set_event_handler(listener, ^(xpc_object_t event) {
        xpc_type_t type = xpc_get_type(event);

        if (type == XPC_TYPE_CONNECTION) {
            /* A new client has connected; hand it to per-peer handler. */
            handle_peer_connection(reinterpret_cast<xpc_connection_t>(event));
        } else if (type == XPC_TYPE_ERROR) {
            /* Listener-level error (e.g. launchd invalidated our service port). */
            syslog(LOG_ERR, "horkosd: listener error");
        }
    });

    xpc_connection_resume(listener);

    syslog(LOG_INFO, "horkosd: listener active on com.horkos.daemon");

    /* dispatch_main() never returns.  launchd kills us via SIGTERM when the
       system requires it; KeepAlive in the plist will re-launch us. */
    dispatch_main();

    /* Unreachable, but satisfies non-void return analysis. */
    return EXIT_SUCCESS;
}
