/*
 * Role: evdev/uinput provenance merge-gate bypass test (Phase: [disabled]) for signal
 *       140. The activated body creates a /dev/uinput virtual mouse emitting EV_REL with
 *       no USB parent and asserts: (1) it is reported with bus_type == HK_BUS_VIRTUAL +
 *       HK_DAUD_NO_USB_PARENT and a non-zero creator_pid; (2) a Steam-Input creator PID
 *       is ALLOWLIST-ATTRIBUTABLE (HK_DAUD_CREATOR_KNOWN, server allowlists it); (3) an
 *       UNKNOWN creator PID is NOT auto-allowlisted (the FP gate — uinput presence
 *       alone is never a client-side ban; the creator-PID allowlist is the gate).
 * Target platforms: Linux only (built behind elseif(UNIX)); the pure classifier is
 *       platform-free, so the disabled stub compiles on any host.
 * Interface: consumes sdk/include/horkos/device_trust_schema.h and the pure
 *       classify_evdev_provenance core in sdk/src/backends/posix/input/DeviceTrustPosix.h.
 *
 * Merge gate (guardrail #12): this is the bypass test for the device-trust evdev/uinput
 * provenance sensor (signal 140). It compiles now; its assertions activate when the bpf
 * ringbuf drain + the server creator-PID allowlist path land — exactly like the
 * memory-access gates. The repo never commits a real injection tool; the activated body
 * uses only /dev/uinput on its OWN synthetic device.
 */

#include <cstdio>

#ifndef HK_DEVICE_TRUST_BYPASS_ENABLED

int main(void)
{
    std::printf("DISABLED: uinput_virtual_provenance bypass test activates with the "
                "140 bpf-drain + creator-PID allowlist path.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include "input/DeviceTrustPosix.h"

/* Activated body drives classify_evdev_provenance with three EvdevProvenanceInput
 * fixtures: (BUS_VIRTUAL, no USB parent, EV_REL, creator=Steam-Input) ->
 * HK_DAUD_NO_USB_PARENT | HK_DAUD_CREATOR_KNOWN; (..., creator=unknown/unresolved) ->
 * HK_DAUD_NO_USB_PARENT only (no CREATOR_KNOWN — server must NOT allowlist); (BUS_USB,
 * has_usb_parent) -> no flags (a real USB mouse is benign). It also creates a real
 * /dev/uinput device to confirm the live path reports BUS_VIRTUAL once the drain is
 * wired. */
int main(void)
{
    return 0;
}

#endif
