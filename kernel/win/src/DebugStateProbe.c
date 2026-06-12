/*
 * Role: Signal 33 — kernel-debugger attach-state probe. Reads the exported
 *       KdDebuggerEnabled / KdDebuggerNotPresent globals and corroborates with
 *       SystemKernelDebuggerInformation, distinguishing "boot-debug allowed but
 *       not attached" (low weight) from "a debugger is currently attached" (high
 *       weight). Read-only; lowest-risk sensor (all reads of documented exports).
 * Target platforms: Windows kernel mode (KMDF).
 * Interface: implements HkDebugStateProbe declared in
 *       kernel/win/include/horkos_kernel.h. No-op when HK_WIN_INTEGRITY_DEBUGSTATE
 *       is not defined (build flag OFF). Emits hk_event_integrity_finding.
 */

#include <ntddk.h>
#include <wdf.h>

#include "horkos_kernel.h"

#if defined(HK_WIN_INTEGRITY_DEBUGSTATE)

/* SystemKernelDebuggerInformation == 35. The documented shape is two BOOLEANs:
 * KernelDebuggerEnabled (a debugger session has ever been enabled) and
 * KernelDebuggerNotPresent (no debugger is currently attached). */
#ifndef SystemKernelDebuggerInformation
#  define SystemKernelDebuggerInformation 35
#endif

typedef struct _HK_SYSTEM_KERNEL_DEBUGGER_INFORMATION {
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} HK_SYSTEM_KERNEL_DEBUGGER_INFORMATION;

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Inout_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

/* Exported globals (ntddk). KdDebuggerNotPresent == FALSE => a debugger is
 * present. KdDebuggerEnabled => debugging was enabled at boot (bcdedit /debug). */
extern PBOOLEAN KdDebuggerEnabled;
extern PBOOLEAN KdDebuggerNotPresent;

_Use_decl_annotations_
void HkDebugStateProbe(PHK_DEVICE_CONTEXT Ctx)
{
    NTSTATUS status;
    HK_SYSTEM_KERNEL_DEBUGGER_INFORMATION dbg;
    BOOLEAN  bootEnabled;
    BOOLEAN  currentlyAttached;

    UNREFERENCED_PARAMETER(Ctx);
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    /* The Kd* exports are PBOOLEAN globals; they are always present (linked from
     * ntoskrnl) but read them defensively in case a future build relocates them. */
    bootEnabled = (KdDebuggerEnabled != NULL && *KdDebuggerEnabled != FALSE);

    /* Corroborate "currently attached" with the system-information query, which
     * is more authoritative than the cached KdDebuggerNotPresent global (which can
     * lag until KdRefreshDebuggerNotPresent runs).
     * HK-UNCERTAIN(kd-refresh): KdRefreshDebuggerNotPresent is documented in the
     * WDK (learn.microsoft.com/windows-hardware/drivers/ddi/ntddk/
     * nf-ntddk-kdrefreshdebuggernotpresent) as refreshing the KdDebuggerNotPresent
     * cached flag. However, forcing a refresh can poll the debug transport and its
     * availability across all WDK/build targets must be confirmed on-box. We do NOT
     * call it here; we trust SystemKernelDebuggerInformation (class 35) as the live
     * read and fall back to the cached global only if the query fails.
     * (docs: KdRefreshDebuggerNotPresent documented; still needs on-box: confirm
     * export availability + transport-poll risk on this target build) */
    RtlZeroMemory(&dbg, sizeof(dbg));
    status = ZwQuerySystemInformation(SystemKernelDebuggerInformation,
                                      &dbg, sizeof(dbg), NULL);
    if (NT_SUCCESS(status)) {
        currentlyAttached = (dbg.KernelDebuggerNotPresent == FALSE) ? TRUE : FALSE;
    } else {
        /* Query failed — fall back to the cached global. guardrail #5: checked. */
        currentlyAttached = (KdDebuggerNotPresent != NULL &&
                             *KdDebuggerNotPresent == FALSE) ? TRUE : FALSE;
    }

    if (currentlyAttached) {
        /* High weight: a debugger is attached right now. detail carries no
         * address (no KASLR leak); 1 = corroborated by the live query. */
        HkIntegrityEmit(33u, HK_INTEGRITY_KDBG_ATTACHED,
                        NT_SUCCESS(status) ? 1ull : 0ull);
    } else if (bootEnabled) {
        /* Lower weight: debugging was enabled at boot but nothing is attached. */
        HkIntegrityEmit(33u, HK_INTEGRITY_KDBG_BOOT_ALLOWED, 0ull);
    }
    /* Neither => clean; emit nothing (the orchestrator's OK heartbeat covers
     * "the probe ran"). */
}

#else /* HK_WIN_INTEGRITY_DEBUGSTATE not defined — compile to a no-op. */

_Use_decl_annotations_
void HkDebugStateProbe(PHK_DEVICE_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
}

#endif /* HK_WIN_INTEGRITY_DEBUGSTATE */
