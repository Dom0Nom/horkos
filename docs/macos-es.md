# macOS EndpointSecurity Client (Phase 4 Step 4.5)

Requires the `com.apple.developer.endpoint-security.client` entitlement at
runtime. All API references are grounded in Apple's public documentation and
the macOS 12 SDK headers.

---

## Overview

`kernel/macos/es/EsClient.mm` is an Objective-C++ userspace client for
Apple's [EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity).
It is **not** kernel code — it runs in the Horkos macOS daemon (userspace
System Extension) and observes process events through the ES API.

Phase 4 is observation-only. The client subscribes to:

| Event | Action | Notes |
|---|---|---|
| `ES_EVENT_TYPE_AUTH_EXEC` | Allow unconditionally | AUTH events **require a reply** (see below) |
| `ES_EVENT_TYPE_NOTIFY_EXEC` | Record only | No reply needed |

Both event types emit an `hk_event_process_create` record to the registered
sink callback. Phase 5 will add policy enforcement on top of this layer.

---

## Build flags

Two independent CMake options control the feature:

### `HORKOS_MACOS_ES` (default: `OFF`)

```
cmake -DHORKOS_MACOS_ES=ON …
```

Compiles `EsClient.mm` and links `EndpointSecurity.framework`. The resulting
binary still requires the entitlement at runtime — building with this flag
does **not** grant the entitlement.

Without this flag the `kernel/macos/es/` directory is entirely skipped and
the daemon builds without any ES dependency. The daemon logs a warning and
operates in a reduced mode (no exec monitoring).

### `HORKOS_MACOS_ES_PROVISIONED` (default: `OFF`, requires `HORKOS_MACOS_ES=ON`)

```
cmake -DHORKOS_MACOS_ES=ON -DHORKOS_MACOS_ES_PROVISIONED=ON …
```

Embeds the `endpoint-security` entitlement plist into the System Extension
bundle's codesign step. Only set this when you have:

1. An Apple Developer account with the **Endpoint Security entitlement** approved
   (requires a separate application to Apple; not automatically available).
2. A provisioning profile that includes the entitlement.
3. The entitlement plist at
   `kernel/macos/es/entitlements/endpoint-security.entitlements`.

Setting `PROVISIONED=ON` without the correct profile will cause notarisation
to fail at submission.

---

## Running in a dev environment (no entitlement)

During bring-up, before the provisioning profile arrives, you can load the ES
client on a dev Mac by:

1. **Disabling SIP** in recoveryOS (`csrutil disable`). This is destructive to
   the host's security posture — use a dedicated VM or a throwaway machine.
2. Running the daemon as **root** (`sudo`). ES requires UID 0 regardless of SIP
   state.

The daemon will call `HKEsClientStart()`; `es_new_client` will succeed on a
SIP-disabled host without the entitlement. On a production Mac with SIP enabled,
`es_new_client` returns `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED` and the daemon
logs an actionable error.

---

## AUTH event reply deadline — CRITICAL

EndpointSecurity delivers `AUTH_EXEC` events to the handler block on a
kernel-managed serial queue. The originating process is **blocked** until the
daemon calls `es_respond_auth_result`. If the reply is never sent:

- The process hangs indefinitely from the user's perspective.
- After Apple's undocumented deadline (empirically 10–60 s per Apple Tech Note
  [TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-runloops-and-the-endpointsecurity-framework))
  the kernel may assume an allow result, panic, or re-deliver.

**Rules enforced in `EsClient.mm`:**

1. `es_respond_auth_result` is called inside the same `case` branch that
   handles `ES_EVENT_TYPE_AUTH_EXEC`, before any early exit.
2. No exceptions (`@throw`, C++ throw) are allowed in the handler block.
3. The handler block does no blocking I/O — only a `mach_continuous_time()`
   read and a sink callback (which must also be non-blocking).
4. Any future phase that adds policy logic must call the respond function
   **first**, then do the policy book-keeping asynchronously if needed.

Violating any of these rules can silently hang arbitrary processes on the
host. Treat it the same way you treat dropping an IRP in the Windows driver.

---

## Entitlement approval process

Apple's Endpoint Security entitlement is gated behind a manual review:

1. File a request at [developer.apple.com/system-extensions/](https://developer.apple.com/system-extensions/).
2. Apple reviews the use case (typically 1–4 weeks).
3. On approval, the entitlement is added to your team's provisioning portal.
4. Generate a provisioning profile that includes it and place the entitlement
   plist at `kernel/macos/es/entitlements/endpoint-security.entitlements`.
5. Re-run CMake with `HORKOS_MACOS_ES_PROVISIONED=ON`.

Until step 4 is complete, the standard dev workflow is SIP-disabled + root
as described above.

---

## File map

| Path | Purpose |
|---|---|
| `kernel/macos/es/EsClient.mm` | ES client implementation |
| `kernel/macos/es/CMakeLists.txt` | Build options and `horkos_es` static lib |
| `kernel/macos/es/entitlements/` | Entitlement plist (not checked in; generated from provisioning profile) |
| `docs/macos-es.md` | This document |
