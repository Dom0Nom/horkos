/*
 * Role: Linux Proton/Wine bypass-test fixture (merge gate, guardrail #12) for
 *       signal 108 (synthetic uinput/evdev injection). Demonstrates: a mid-session
 *       non-allowlisted process creates a uinput device and injects EV_KEY/EV_ABS
 *       correlated with game keys (no-recoil macro) -> HK_EVENT_SYNTH_INPUT with
 *       HK_SYNTH_UINPUT_CREATE / _MID_SESSION / _OFF_ALLOWLIST; Steam Input's own
 *       uinput device (created pre-focus, allowlisted) does NOT flag (FP gate — the
 *       load-bearing assertion). Catalog marks 108 HIGH-FP: the test asserts the
 *       server treats the record as a LOW-WEIGHT corroborator. uinput_create_device/
 *       input_inject_event kprobe-ability is UNCERTAIN (impl-plan Risks; gated
 *       behind HORKOS_LINUX_EBPF_PROTON_KPROBES), so this also runs in replay mode.
 * Target platforms: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: drives the loader event sink (signal 108) + DeckInputBaseline + the
 *            server linux_proton feature weight.
 */

#include <cstdio>

#ifndef HK_PW_UINPUT_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: bypass_uinput_macro activates once uinput_inject_audit "
                "(uinput/evdev kprobes — UNCERTAIN, confirm kprobe-ability; behind "
                "HORKOS_LINUX_EBPF_PROTON_KPROBES) and DeckInputBaseline land on-box. "
                "Replay mode gates the decode/classify path meanwhile.\n");
    return 0;
}

#else

#include <unistd.h>

int main(void) {
    /* On-box fill-in:
     *   1. Resolve + allowlist Steam Input / hid-steam / gamescope-libinput tgids at
     *      session start; record session_start_ns.
     *   2. Mid-session off-allowlist process creates /dev/uinput device + injects
     *      EV_KEY -> assert HK_EVENT_SYNTH_INPUT / UINPUT_CREATE | MID_SESSION |
     *      OFF_ALLOWLIST.
     *   3. Steam Input's pre-focus allowlisted device -> assert NO off-allowlist.
     *   4. Assert the server feature row has corroborator_only=true (low weight). */
    std::printf("bypass_uinput_macro: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_PW_UINPUT_TEST_ENABLED */
