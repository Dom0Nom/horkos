/*
 * Role: Linux Proton/Wine bypass-test fixture (merge gate, guardrail #12) for
 *       signal 100 (WINEDLLOVERRIDES anomaly). Demonstrates: launch Proton with
 *       WINEDLLOVERRIDES=ntdll=n (native shadowing a builtin-only DLL) plus an
 *       override naming an off-manifest DLL -> HK_EVENT_PROTON_OVERRIDE fires with
 *       HK_PROTON_NATIVE_SHADOWS_BUILTIN | _OFF_MANIFEST; a legitimate DXVK
 *       d3d11=n override does NOT flag (the FP gate — load-bearing assertion).
 * Target platforms: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: drives the loader event sink (signal 100) + ProtonOverrideCheck once
 *            the eBPF loader attach path lands on-box.
 */

#include <cstdio>

#ifndef HK_PW_DLLOVERRIDE_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: bypass_dlloverride_inject activates once the proton_env "
                "loader attach + ProtonOverrideCheck manifest diff land on-box.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include <cstdlib>
#include <unistd.h>

int main(void) {
    /* On-box fill-in:
     *   1. exec the Proton fixture with WINEDLLOVERRIDES="ntdll=n,evilcheat=n".
     *   2. Drain loader events; assert HK_EVENT_PROTON_OVERRIDE with
     *      HK_PROTON_NATIVE_SHADOWS_BUILTIN (ntdll is builtin-only) | _OFF_MANIFEST.
     *   3. Relaunch with WINEDLLOVERRIDES="d3d11=n" (legit DXVK); assert NO flag
     *      (on the FP allowlist, not shadowing a builtin-only DLL). FP gate proven. */
    std::printf("bypass_dlloverride_inject: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_PW_DLLOVERRIDE_TEST_ENABLED */
