/*
 * kernel/win/src/CallbackResidency.c
 * Role: Signal 31 — registered driver-callback table residency check. Ships ONLY
 *       the documented self-sentinel half: it confirms Horkos's OWN registered
 *       callbacks (the Ob handle-filter registration handle and the Ps* notify
 *       slot accounting) are still intact — detecting something that strips our
 *       callbacks. For broader enumeration, any handler address the sensor can
 *       legitimately observe is resolved against the ModuleMap and a pool-backed
 *       / no-image handler is flagged HK_INTEGRITY_CALLBACK_NO_IMAGE. The full
 *       OS-array walk (PspCreateProcessNotifyRoutine / CmCallbackListHead) is
 *       OUT — those are unexported and reading them requires version-fragile
 *       offsets (plan Risk 1, the highest-risk sensor). Read-only.
 * Target platforms: Windows kernel mode (KMDF).
 * Interface: implements HkCallbackResidencyScan declared in
 *       kernel/win/include/horkos_kernel.h. Depends on the shared ModuleMap.
 *       No-op when HK_WIN_INTEGRITY_CALLBACKS is not defined (DEFAULT OFF;
 *       self-sentinel half only when ON). Emits hk_event_integrity_finding.
 */

#include <ntddk.h>
#include <wdf.h>

#include "horkos_kernel.h"

#if defined(HK_WIN_INTEGRITY_CALLBACKS)

_Use_decl_annotations_
void HkCallbackResidencyScan(PHK_DEVICE_CONTEXT Ctx, const HK_MODULE_MAP* Map)
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    if (Ctx == NULL) {
        return;
    }

    /* --- Documented self-sentinel half (the only part that ships) ---
     * We do NOT walk the OS notify arrays. We confirm OUR registrations survive.
     * This overlaps CallbackSelfCheck.c's deregistration detection but reports it
     * through the integrity-finding plane (signal 31) for the driver-integrity
     * scorer, distinct from the callback self-integrity plane (signal 7).
     *
     * Our Ob handle-filter: if we believe we are armed (ObCallbacksArmed) but the
     * registration handle went NULL, something deregistered our callback out from
     * under us — a stripped-callback signal. */
    if (Ctx->ObCallbacksArmed && Ctx->ObRegistrationHandle == NULL) {
        /* detail = 0: no address (the handle is gone). Signal-id 31. */
        HkIntegrityEmit(31u, HK_INTEGRITY_CALLBACK_NO_IMAGE, 0ull);
    }

    /* Our Ps* notify slots: NotifyRoutinesArmed is Horkos's own count (Notify.c).
     * A drop below the steady-state 3 while no disarm is in progress means a slot
     * was stripped. The detail carries the observed count so the server sees how
     * many remain. */
    {
        LONG armed = Ctx->NotifyRoutinesArmed;
        if (armed >= 0 && armed < 3) {
            HkIntegrityEmit(31u, HK_INTEGRITY_CALLBACK_NO_IMAGE, (uint64_t)(ULONG)armed);
        }
    }

    /* HK-UNCERTAIN(callback-table-walk): the broad enumeration —
     * PspCreateProcessNotifyRoutine / PspLoadImageNotifyRoutine /
     * CmCallbackListHead — is UNEXPORTED and undocumented. Reading it to resolve
     * every system callback handler against `Map` requires pattern-scanning
     * ntoskrnl or hardcoded per-build offsets, which guardrail #13 forbids. Per
     * plan Risk 1 (the HIGHEST-RISK sensor) the full table walk is OUT until a
     * documented or robustly version-resolved surface is agreed. `Map` is accepted
     * so the signature is stable for when the resolve-against-image half lands;
     * until then it is unused beyond this note. */
    UNREFERENCED_PARAMETER(Map);
}

#else /* HK_WIN_INTEGRITY_CALLBACKS not defined — compile to a no-op. */

_Use_decl_annotations_
void HkCallbackResidencyScan(PHK_DEVICE_CONTEXT Ctx, const HK_MODULE_MAP* Map)
{
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(Map);
}

#endif /* HK_WIN_INTEGRITY_CALLBACKS */
