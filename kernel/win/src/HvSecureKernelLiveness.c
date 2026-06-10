/*
 * kernel/win/src/HvSecureKernelLiveness.c
 * Role: Signal 41 kernel sensor (observe-only, weak corroborator) — samples
 *       isolated-user-mode / secure-kernel liveness and compares it against the
 *       VBS-running claim; a VBS-on claim with an inert secure-kernel callout path
 *       is the gap. securekernel.exe/skci.dll presence is observed through the
 *       ALREADY-collected PsSetLoadImageNotifyRoutine records (no second image-
 *       notify registration). Emits hk_event_hv_sk_liveness.
 *       READ-ONLY.
 * Target platforms: Windows kernel (KMDF). Builds only with the WDK.
 *
 *       HK-UNCERTAIN (plan UNCERTAINTY FLAG): secure-kernel / HyperGuard internals
 *       are undocumented and version-volatile; SystemIsolatedUserModeInformation
 *       sub-fields and the transition counters are not stable contracts. Do NOT
 *       make a client trust decision on this. Until the counter sources are
 *       confirmed on the box, only the image-presence bit (from the existing
 *       notify record set) is set; the transition bucket stays 0. Observe-only,
 *       default OFF (HK_HV_KERNEL_EXPERIMENTAL).
 * Interface: implements HkHvSecureKernelSample (horkos_kernel.h); emits via HkRingEmit.
 */

#include <ntddk.h>

#include "horkos_kernel.h"
#include "horkos/event_schema.h"

void HkHvSecureKernelSample(void)
{
    hk_event_hv_sk_liveness ev;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    RtlZeroMemory(&ev, sizeof(ev));

    /* HK-UNCERTAIN: IUM running state + secure-kernel transition counters via
     * SystemIsolatedUserModeInformation are not stable across builds. Until
     * confirmed on the box, leave the IUM/transition fields 0 and ship the record
     * as a liveness heartbeat only (records_seen on the usermode side reflects it).
     * The securekernel.exe/skci.dll presence bit is folded usermode from the
     * existing image-load notify set, not re-derived here. */
    ev.flags = 0;
    ev.transition_count_bucket = 0;

    HkRingEmit(HK_EVENT_HV_SK_LIVENESS, &ev, sizeof(ev));
}
