/*
 * kernel/win/src/CanaryProc.c
 * Role: Guard-process canary (win-handle-memory-access, catalog signal 68). Would
 *       spawn a low-cost AC-owned guard process and arm an ObRegisterCallbacks
 *       filter on ITS process object, so that a foreign opener polling the guard at
 *       a fixed sub-second (frame-locked) cadence externalizes a cheat's PID-poll
 *       loop. System enumerators (taskmgr/procexp) are bursty and excluded by the
 *       cadence gate. Read-only telemetry; nothing here blocks.
 * Target platforms: Windows kernel mode (KMDF).
 * Interface: implements HkCanaryStart/HkCanaryStop declared in
 *       kernel/win/include/horkos_kernel.h.
 *
 * HK-UNCERTAIN(canary-spawn): spawning a usermode process FROM the driver is not a
 * thing to code blind. The create path (RtlCreateUserProcess vs ZwCreateUserProcess
 * argument blocks, the section/PEB/initial-thread setup, the session-0 vs
 * interactive-session placement, and — critically — guaranteed teardown on driver
 * unload and on uninstall so no orphan guard process survives) all need on-box
 * verification. The plan itself marks the canary optional/experimental with "its own
 * attack surface and cleanup/uninstall implications". Per guardrail #13 this start
 * installs NOTHING and returns STATUS_NOT_SUPPORTED; the Ob-filter-on-the-guard-object
 * half is trivial once a real guard PEPROCESS exists, but a half-built spawn that
 * leaks a process is worse than an unimplemented feature. Do NOT spawn from the
 * driver without validating the create + teardown sequence on the target build.
 */

#include <ntddk.h>
#include <wdf.h>

#include "horkos_kernel.h"

#if defined(HK_WIN_VMWATCH)

_Use_decl_annotations_
NTSTATUS HkCanaryStart(PHK_DEVICE_CONTEXT Ctx)
{
    if (Ctx == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    InterlockedExchange(&Ctx->CanaryArmed, 0);
    Ctx->CanaryRegistrationHandle = NULL;
    /* See HK-UNCERTAIN(canary-spawn): no process is spawned and no Ob filter is
     * armed until the create + teardown path is verified on-box. */
    return STATUS_NOT_SUPPORTED;
}

_Use_decl_annotations_
void HkCanaryStop(PHK_DEVICE_CONTEXT Ctx)
{
    PVOID handle;
    if (Ctx == NULL) {
        return;
    }
    /* Defensive teardown shape: if a future verified start armed an Ob filter on the
     * guard object, take-and-clear it exactly once (mirrors HkObDisarm). The guard
     * PROCESS teardown itself is part of the unverified create path and is not done
     * here. */
    handle = InterlockedExchangePointer(&Ctx->CanaryRegistrationHandle, NULL);
    if (handle != NULL) {
        ObUnRegisterCallbacks(handle);
    }
    InterlockedExchange(&Ctx->CanaryArmed, 0);
}

#else /* !HK_WIN_VMWATCH — feature OFF: link-safe no-op stubs. */

_Use_decl_annotations_
NTSTATUS HkCanaryStart(PHK_DEVICE_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
    return STATUS_NOT_SUPPORTED;
}

_Use_decl_annotations_
void HkCanaryStop(PHK_DEVICE_CONTEXT Ctx) { UNREFERENCED_PARAMETER(Ctx); }

#endif /* HK_WIN_VMWATCH */
