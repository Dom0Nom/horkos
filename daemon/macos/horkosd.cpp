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
 *           -framework Foundation -o horkosd
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
#include <syslog.h>
#include <cstdlib>

/* ------------------------------------------------------------------
 * Forward declarations
 * ------------------------------------------------------------------ */
static void handle_client_event(xpc_connection_t peer, xpc_object_t event);
static void handle_peer_connection(xpc_connection_t peer);

/* ------------------------------------------------------------------
 * XPC listener callback — called once per new client connection.
 * ------------------------------------------------------------------ */
static void handle_peer_connection(xpc_connection_t peer)
{
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
