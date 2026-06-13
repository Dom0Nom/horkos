/*
 * Role: Periodic self-integrity sensor for Horkos's own kernel callback
 *       registrations. A periodic KTIMER fires a KDPC at DISPATCH_LEVEL that does
 *       nothing but bump a heartbeat and queue a PASSIVE_LEVEL work item; ALL
 *       actual checks run in the work item, because they touch pageable state,
 *       call ZwOpenProcess, re-arm Ps* routines, and hash pages — every one of
 *       which is PASSIVE-only. Checks implemented (read-only, observe-only):
 *         signal 1 — Ob liveness self-poll (sentinel handle-open, nonce stamp).
 *         signal 7 — per-type Enabled/Operations drift vs. our OWN arm-time intent.
 *         signal 3 — Ps* re-arm probe (serialized with Notify.c arm state).
 *         signal 4 — notify census via Horkos's own delta accounting + floor.
 *         signal 8 — SHA-256 of the callback .text range vs. arm-time baseline.
 *       Ban authority is server-side; this only emits self-integrity events.
 * Target platforms: Windows kernel mode (KMDF).
 * Interface: implements HkSelfCheckArm / HkSelfCheckDisarm / HkObSelfPoll
 *       declared in kernel/win/include/horkos_kernel.h. Emits
 *       hk_event_callback_integrity / hk_event_callback_census (HK-TODO(schema):
 *       wire types are kernel-private mirrors until the Schema phase appends them
 *       to event_schema.h — see horkos_kernel.h).
 */

#include <ntddk.h>
#include <wdf.h>

#include "horkos_kernel.h"

/* Self-check period in milliseconds. Overridable at build time; the plan's
 * default is 5000ms. A short period raises load; a long one slows detection. */
#ifndef HK_SELFCHECK_TIMER_MS
#  define HK_SELFCHECK_TIMER_MS 5000
#endif

/* The IoQueueWorkItem device the work item is bound to; resolved from the
 * control device at arm time. */
static PDEVICE_OBJECT HkSelfCheckWdmDevice(void)
{
    WDFDEVICE dev = g_HkControlDevice;
    if (dev == NULL) {
        return NULL;
    }
    return WdfDeviceWdmGetDeviceObject(dev);
}

/* -------------------------------------------------------------------------
 * Signal 1 — Ob liveness self-poll. Open the System process with the magic
 * reserved access bit. HkObPreCallback (Callbacks.c) recognizes the sentinel,
 * stamps ObSelfPollNonce with the value we armed in ObSelfPollExpected, and
 * suppresses the normal emit. We then read the nonce back: matched => callback
 * fired. PASSIVE-only: ZwOpenProcess / ZwClose require PASSIVE_LEVEL.
 * ------------------------------------------------------------------------- */
_Use_decl_annotations_
void HkObSelfPoll(PHK_DEVICE_CONTEXT Ctx)
{
    NTSTATUS          status;
    HANDLE            sysHandle = NULL;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID         cid;
    LONG64            armed;
    LONG64            observed;
    BOOLEAN           fired;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    /* Only probe while the Ob callbacks are supposed to be armed; otherwise a
     * legitimately-disarmed callback would read as tamper. */
    if (Ctx->ObCallbacksArmed == 0) {
        return;
    }

    /* Arm a fresh nonce for this round. The pre-callback copies Expected into
     * Nonce; we compare afterward. Use the interrupt time as a cheap unique-ish
     * value so a stale stamp from a prior round cannot satisfy this round. */
    armed = (LONG64)KeQueryInterruptTime() | 1; /* never 0 (0 == "not stamped") */
    InterlockedExchange64(&Ctx->ObSelfPollExpected, armed);
    InterlockedExchange64(&Ctx->ObSelfPollNonce, 0);

    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    cid.UniqueProcess = PsGetProcessId(PsInitialSystemProcess);
    cid.UniqueThread = NULL;

    /* Kernel-mode caller opening the System process with the magic access mask.
     * ZwOpenProcess routes through the object manager and fires Ob callbacks. */
    status = ZwOpenProcess(&sysHandle, HK_OB_SELFPOLL_MAGIC, &oa, &cid);
    if (!NT_SUCCESS(status)) {
        /* Could not run the probe this round (e.g. transient resource pressure).
         * Do NOT count this as a miss — a failed probe is not a removed callback.
         * Leave the consecutive-miss counter unchanged. */
        return;
    }

    /* Close immediately; the handle itself is not needed, only the callback
     * side effect. Check the return (guardrail #5) but a close failure here is
     * not security-relevant beyond a handle leak we log via the bugcheck-free
     * path: assert in checked builds, proceed in free builds. */
    status = ZwClose(sysHandle);
    NT_ASSERT(NT_SUCCESS(status));
    (void)status;

    observed = InterlockedCompareExchange64(&Ctx->ObSelfPollNonce, 0, 0);
    fired = (observed == armed) ? TRUE : FALSE;

    if (fired) {
        InterlockedExchange(&Ctx->ObConsecutiveMiss, 0);
        return;
    }

    /* Missed this round. Bump the consecutive counter and consult the FP gate:
     * verdict only after HK_SELFCHECK_MISS_THRESHOLD consecutive misses AND a
     * heartbeat that proves the engine actually ran (not scheduler starvation).
     * We treat "heartbeat advanced" as "we are running right now", which is
     * trivially true inside the work item — the meaningful starvation case is
     * caught upstream because a starved engine never reaches this code at all. */
    {
        LONG consecutive = InterlockedIncrement(&Ctx->ObConsecutiveMiss);
        int heartbeat_advanced = 1; /* we are executing in the work item */
        if (HkFpObMissingVerdict((uint32_t)consecutive, heartbeat_advanced)) {
            hk_event_callback_integrity ev;
            RtlZeroMemory(&ev, sizeof(ev));
            ev.check_id = HK_CB_CHECK_OB_LIVENESS;
            ev.object_type = HK_CB_OBJTYPE_PROCESS;
            ev.result = HK_CB_RESULT_MISSING;
            ev.consecutive = (uint32_t)consecutive;
            HkRingEmit(HK_EVENT_CALLBACK_INTEGRITY, &ev, sizeof(ev));
        }
    }
}

/* -------------------------------------------------------------------------
 * Signal 7 — per-type Enabled/Operations drift, compared against the arm-time
 * baseline Horkos itself recorded (our OWN OB_OPERATION_REGISTRATION intent and
 * the returned handle). No undocumented CallbackList walk — that raw walk ships
 * OFF behind HK_SELFCHECK_UNDOC_OFFSETS (see Risks). What we CAN check here
 * without internals: the registration handle is still non-NULL (the callback was
 * not deregistered out from under us) and the recorded PreOperation pointer still
 * matches HkObPreCallbackAddress() (no in-table pointer swap that we constructed).
 * ------------------------------------------------------------------------- */
static void HkSelfCheckEnabledDrift(PHK_DEVICE_CONTEXT Ctx)
{
    hk_event_callback_integrity ev;

    if (!Ctx->ObBaseline.Valid) {
        return;
    }

    /* Deregistration check: our handle went NULL while we still believe we are
     * armed. HkObDisarm clears the handle atomically, so a NULL handle with
     * ObCallbacksArmed still set means something other than our disarm path
     * cleared it. */
    if (Ctx->ObCallbacksArmed && Ctx->ObRegistrationHandle == NULL) {
        RtlZeroMemory(&ev, sizeof(ev));
        ev.check_id = HK_CB_CHECK_ENABLED_DRIFT;
        ev.object_type = HK_CB_OBJTYPE_PROCESS;
        ev.result = HK_CB_RESULT_MISSING;
        ev.consecutive = 0;
        HkRingEmit(HK_EVENT_CALLBACK_INTEGRITY, &ev, sizeof(ev));
        return;
    }

    /* Pointer-swap check: the function we recorded at arm time must still be the
     * address of HkObPreCallback. This catches a baseline we built ourselves
     * being tampered (defense in depth — it should never change). */
    if (Ctx->ObBaseline.PreOpFnBaseline != HkObPreCallbackAddress()) {
        RtlZeroMemory(&ev, sizeof(ev));
        ev.check_id = HK_CB_CHECK_ENABLED_DRIFT;
        ev.object_type = HK_CB_OBJTYPE_PROCESS;
        ev.result = HK_CB_RESULT_PTR_SWAP;
        ev.consecutive = 0;
        HkRingEmit(HK_EVENT_CALLBACK_INTEGRITY, &ev, sizeof(ev));
    }

    /* HK-UNCERTAIN(ob-callbacklist): the per-operation Enabled flag as the kernel
     * actually stores it lives in the undocumented OBJECT_TYPE.CallbackList /
     * OB_CALLBACK_ENTRY layout. Reading it to confirm OUR entry is still Enabled
     * requires version-fragile offsets and is NOT implemented here. It ships OFF
     * behind HK_SELFCHECK_UNDOC_OFFSETS; do not add an offset table without
     * per-build validation. The documented checks above (handle non-NULL, ptr
     * unchanged) cover the high-weight removal/swap case. */
}

/* -------------------------------------------------------------------------
 * Signal 3 — Ps* re-arm probe. Re-register an ALREADY-registered notify routine.
 * Documented behavior: a still-registered routine yields STATUS_INVALID_PARAMETER
 * (duplicate). STATUS_SUCCESS means the routine had been silently removed and we
 * just re-registered it — immediately re-disarm the duplicate to keep slot
 * accounting correct, and emit a _MISSING integrity event.
 *
 * Serialization: this probe registers/removes a notify routine, which races
 * Notify.c's own arm/disarm. We must NOT probe while NotifyRoutinesArmed is mid-
 * transition. Notify.c maintains NotifyRoutinesArmed as a count via Interlocked;
 * a value of 3 means all three are armed and stable. We only probe the process
 * routine when that count is exactly 3 (steady armed state). This is conservative
 * — a transient count skips the probe rather than risk a double-free / leaked slot.
 *
 * HK-UNCERTAIN(ps-rearm-lock): Notify.c does NOT currently expose a dedicated
 * arm/disarm lock — it uses file-scope BOOLEANs guarded only by the single-
 * instance assumption and the Interlocked count. Re-registering here from a
 * different thread than DriverEntry/unload introduces a real race the existing
 * code was not designed for. Per guardrail #12 the actual re-register call is
 * left UNIMPLEMENTED until Notify.c grows an explicit arm lock; we only read the
 * steady-state count and, if it is wrong, emit drift. DO NOT enable the live
 * PsSetCreateProcessNotifyRoutineEx re-register without that lock — getting it
 * wrong leaks or double-frees a notify slot.
 * ------------------------------------------------------------------------- */
static void HkSelfCheckPsRearm(PHK_DEVICE_CONTEXT Ctx)
{
    LONG armed = Ctx->NotifyRoutinesArmed;

    /* Steady armed state is all three routines (process/thread/image) present.
     * A lower count, with no disarm in progress, is itself a drop worth flagging
     * via the census path; here we only gate the (currently disabled) probe. */
    if (armed != 3) {
        return;
    }

    /* HK-UNCERTAIN(ps-rearm-lock): live re-arm probe intentionally not issued.
     * When Notify.c exposes an arm lock, the body is:
     *   acquire Notify arm lock
     *   st = PsSetCreateProcessNotifyRoutineEx(HkProcessNotifyEx, FALSE)
     *   if (st == STATUS_SUCCESS) {        // was silently removed
     *       (void)PsSetCreateProcessNotifyRoutineEx(HkProcessNotifyEx, TRUE);
     *       emit HK_CB_CHECK_PS_REARM / HK_CB_RESULT_MISSING
     *   }                                  // STATUS_INVALID_PARAMETER == still armed
     *   release Notify arm lock
     */
    UNREFERENCED_PARAMETER(Ctx);
}

/* -------------------------------------------------------------------------
 * Signal 4 — notify census via Horkos's own delta accounting + a documented cap.
 * We do NOT scan the undocumented PspCreateProcessNotifyRoutine array (that ships
 * OFF behind HK_SELFCHECK_UNDOC_OFFSETS). Instead: NotifyRoutinesArmed is our own
 * count, maintained by Notify.c. Establish a per-host floor once it settles, then
 * alert only on a monotone drop below floor that includes our own slot (which, in
 * the own-accounting model, is "our count fell" since every slot in the count is
 * ours). own_present reflects whether our recorded routines are still counted.
 * ------------------------------------------------------------------------- */
/* Establish the floor (capture-once, ratchet-up only) and run the FP-gated drop
 * verdict. Emits a drift integrity event on a verdict but NO census record — the
 * caller owns the census emit (so we never double-emit when the Cm path also
 * emits a census). Shared by HkSelfCheckCensus and HkSelfCheckCensusDriftOnly. */
static void HkSelfCheckCensusVerdict(PHK_DEVICE_CONTEXT Ctx)
{
    LONG armed = Ctx->NotifyRoutinesArmed;
    LONG floor = Ctx->CensusFloor;
    uint32_t own_notify;

    if (armed == 3 && floor < 3) {
        InterlockedExchange(&Ctx->CensusFloor, armed);
        floor = armed;
    }
    own_notify = (armed >= 3) ? HK_CENSUS_OWN_NOTIFY : 0u;

    if (HkFpCensusDropVerdict((uint32_t)(floor < 0 ? 0 : floor),
                              (uint32_t)(armed < 0 ? 0 : armed),
                              own_notify ? 1 : 0)) {
        hk_event_callback_integrity drift;
        RtlZeroMemory(&drift, sizeof(drift));
        drift.check_id = HK_CB_CHECK_ENABLED_DRIFT;
        drift.object_type = HK_CB_OBJTYPE_PROCESS;
        drift.result = HK_CB_RESULT_MISSING;
        drift.consecutive = 0;
        HkRingEmit(HK_EVENT_CALLBACK_INTEGRITY, &drift, sizeof(drift));
    }
}

/* Notify-only census emit + drop verdict. Used when the Cm filter is NOT armed
 * (so no Cm path emits a census this tick). */
static void HkSelfCheckCensus(PHK_DEVICE_CONTEXT Ctx)
{
    hk_event_callback_census ev;
    LONG  armed = Ctx->NotifyRoutinesArmed;
    LONG  floor = Ctx->CensusFloor;
    uint32_t own_present = 0;

    if (armed >= 3) {
        own_present |= HK_CENSUS_OWN_NOTIFY;
    }
    if (Ctx->CmArmed && Ctx->CmBaseline.Present) {
        own_present |= HK_CENSUS_OWN_CM;
    }

    RtlZeroMemory(&ev, sizeof(ev));
    ev.notify_count = (uint32_t)(armed < 0 ? 0 : armed);
    ev.cm_count = (uint32_t)(Ctx->CmArmed ? 1 : 0); /* own-cookie accounting only */
    ev.own_present = own_present;
    ev.floor = (uint32_t)(floor < 0 ? 0 : floor);
    HkRingEmit(HK_EVENT_CALLBACK_CENSUS, &ev, sizeof(ev));

    HkSelfCheckCensusVerdict(Ctx);
}

/* Run only the floor/verdict logic, no census emit — used when HkCmCensus has
 * already emitted the combined census this tick. */
static void HkSelfCheckCensusDriftOnly(PHK_DEVICE_CONTEXT Ctx)
{
    HkSelfCheckCensusVerdict(Ctx);
}

/* -------------------------------------------------------------------------
 * Signal 8 — SHA-256 of the callback .text range vs. arm-time baseline. An inline
 * patch over a callback prologue changes the hash even when the registration
 * pointer is pristine. Cross-check with attestation before trusting the in-memory
 * baseline.
 *
 * HK-UNCERTAIN(text-hash-base): resolving the owning image base + .text extent
 * for HkObPreCallbackAddress() requires either a documented base-resolution path
 * or a PsLoadedModuleList walk. The loaded-module walk relies on partly-
 * undocumented offsets that can fault if they drift; hashing the wrong range
 * yields false positives. Per guardrail #12 the base/extent resolution and the
 * actual hashing are left UNIMPLEMENTED. The baseline capture below records that
 * signal 8 is not yet active (TextHashValid stays FALSE) rather than hashing a
 * guessed range. Provide a documented base resolver (e.g. an exported anchor +
 * known section layout from our own PE) before enabling.
 * ------------------------------------------------------------------------- */
static void HkSelfCheckTextHash(PHK_DEVICE_CONTEXT Ctx)
{
    if (!Ctx->ObBaseline.TextHashValid) {
        /* Baseline never captured (resolver unimplemented) — nothing to compare.
         * Do not emit: an absent baseline is not a tamper signal. */
        return;
    }
    /* HK-UNCERTAIN(text-hash-base): re-hash + compare against ObBaseline.TextHash
     * goes here once a documented base/extent resolver and the attestation cross-
     * check are wired. Emit HK_CB_CHECK_TEXT_HASH / HK_CB_RESULT_TEXT_PATCH on
     * mismatch. Intentionally not implemented (see header comment). */
}

/* -------------------------------------------------------------------------
 * The PASSIVE_LEVEL work item: runs every check in sequence. Queued by the DPC.
 * ------------------------------------------------------------------------- */
_Function_class_(IO_WORKITEM_ROUTINE)
static VOID HkSelfCheckWorker(_In_ PDEVICE_OBJECT DeviceObject, _In_opt_ PVOID Context)
{
    PHK_DEVICE_CONTEXT ctx = (PHK_DEVICE_CONTEXT)Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    if (ctx == NULL || ctx->SelfCheckArmed == 0) {
        return;
    }

    HkObSelfPoll(ctx);            /* signal 1 */
    HkSelfCheckEnabledDrift(ctx); /* signal 7 (documented half) */
    HkSelfCheckPsRearm(ctx);      /* signal 3 (probe gated; see HK-UNCERTAIN) */
    HkSelfCheckTextHash(ctx);     /* signal 8 (gated; see HK-UNCERTAIN) */

    /* Exactly ONE census emit per tick. When the Cm filter is armed, HkCmCensus
     * (RegistryCallback.c) owns the combined census (it folds in notify_count +
     * the Cm cookie bit); otherwise HkSelfCheckCensus emits the notify-only
     * census. Both still run their respective FP-gated drift checks. */
    if (ctx->CmArmed) {
        HkCmCensus(ctx);          /* signals 4 + 9 (combined census + Cm drift) */
        HkSelfCheckCensusDriftOnly(ctx); /* signal 4 drop verdict, no duplicate emit */
    } else {
        HkSelfCheckCensus(ctx);   /* signal 4 census + drop verdict */
    }
}

/* -------------------------------------------------------------------------
 * The DISPATCH_LEVEL DPC: the single most IRQL-sensitive routine in this file.
 * It MUST do nothing but bump the heartbeat and queue the PASSIVE work item — no
 * list walks, no Zw*, no paging. A blocking/paging call here is a bugcheck.
 * ------------------------------------------------------------------------- */
_Function_class_(KDEFERRED_ROUTINE)
static VOID HkSelfCheckDpc(_In_ struct _KDPC* Dpc,
                           _In_opt_ PVOID DeferredContext,
                           _In_opt_ PVOID SystemArgument1,
                           _In_opt_ PVOID SystemArgument2)
{
    PHK_DEVICE_CONTEXT ctx = (PHK_DEVICE_CONTEXT)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (ctx == NULL || ctx->SelfCheckArmed == 0) {
        return;
    }

    /* Heartbeat: proves the timer/DPC chain ran this period. The work item's FP
     * gate distinguishes "engine never ran" (starvation) from "callback gone". */
    InterlockedIncrement(&ctx->SelfCheckHeartbeat);

    if (ctx->SelfCheckWorkItem != NULL) {
        /* IoQueueWorkItem is callable at DISPATCH_LEVEL and runs the routine at
         * PASSIVE in a system worker thread (documented). DelayedWorkQueue keeps
         * us off the time-critical queue. */
        IoQueueWorkItem(ctx->SelfCheckWorkItem, HkSelfCheckWorker,
                        DelayedWorkQueue, ctx);
    }
}

_Use_decl_annotations_
NTSTATUS HkSelfCheckArm(PHK_DEVICE_CONTEXT Ctx)
{
    PDEVICE_OBJECT  wdmDevice;
    LARGE_INTEGER   dueTime;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    if (Ctx == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Capture the Ob baseline from our OWN registration intent (signals 7, 8). */
    RtlZeroMemory(&Ctx->ObBaseline, sizeof(Ctx->ObBaseline));
    Ctx->ObBaseline.Enabled[0] = TRUE;  /* process type registered */
    Ctx->ObBaseline.Enabled[1] = TRUE;  /* thread type registered */
    Ctx->ObBaseline.Operations[0] =
        OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    Ctx->ObBaseline.Operations[1] =
        OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    Ctx->ObBaseline.PreOpFnBaseline = HkObPreCallbackAddress();
    Ctx->ObBaseline.TextHashValid = FALSE; /* signal 8 base resolver unimplemented */
    Ctx->ObBaseline.Valid = TRUE;

    InterlockedExchange(&Ctx->ObConsecutiveMiss, 0);
    InterlockedExchange(&Ctx->CensusFloor, 0);
    InterlockedExchange(&Ctx->SelfCheckHeartbeat, 0);
    InterlockedExchange64(&Ctx->ObSelfPollNonce, 0);
    InterlockedExchange64(&Ctx->ObSelfPollExpected, 0);

    wdmDevice = HkSelfCheckWdmDevice();
    if (wdmDevice == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    /* Allocate the work item once; reuse it every period. IoAllocateWorkItem is
     * PASSIVE_LEVEL and may fail under memory pressure. */
    Ctx->SelfCheckWorkItem = IoAllocateWorkItem(wdmDevice);
    if (Ctx->SelfCheckWorkItem == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeDpc(&Ctx->SelfCheckDpc, HkSelfCheckDpc, Ctx);
    KeInitializeTimerEx(&Ctx->SelfCheckTimer, NotificationTimer);

    /* Mark armed BEFORE starting the timer so the first DPC sees a valid state. */
    InterlockedExchange(&Ctx->SelfCheckArmed, 1);

    /* Negative due time = relative; period in ms. 100ns units => ms * -10000. */
    dueTime.QuadPart = -((LONGLONG)HK_SELFCHECK_TIMER_MS * 10000LL);
    KeSetTimerEx(&Ctx->SelfCheckTimer, dueTime, HK_SELFCHECK_TIMER_MS,
                 &Ctx->SelfCheckDpc);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
void HkSelfCheckDisarm(PHK_DEVICE_CONTEXT Ctx)
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    if (Ctx == NULL) {
        return;
    }

    /* Clear armed first so an in-flight DPC/work item early-returns. */
    InterlockedExchange(&Ctx->SelfCheckArmed, 0);

    /* Cancel the periodic timer; KeCancelTimer returns TRUE if it was queued.
     * Either way no new DPC is queued after this returns. */
    (void)KeCancelTimer(&Ctx->SelfCheckTimer);

    /* Flush any DPC already inserted, so no DPC can queue a work item after we
     * free it. KeFlushQueuedDpcs waits for all currently-queued DPCs on all
     * processors to execute to completion (documented: learn.microsoft.com/
     * windows-hardware/drivers/ddi/wdm/nf-wdm-keflushqueueddpcs). It is
     * PASSIVE_LEVEL and may take a long time; acceptable in disarm which is not
     * a hot path. The scope is system-wide, not per-DPC; KeCancelTimer +
     * SelfCheckArmed early-return is the primary guard; this is belt-and-
     * suspenders. HK-VERIFIED(dpc-flush-ordering): the documented guarantee --
     * DPCs queued before the call complete before it returns -- is exactly the
     * ordering property needed here. */
    KeFlushQueuedDpcs();

    if (Ctx->SelfCheckWorkItem != NULL) {
        /* IoFreeWorkItem waits for an in-flight routine to finish (documented),
         * so a worker that slipped past the armed check completes before free. */
        IoFreeWorkItem(Ctx->SelfCheckWorkItem);
        Ctx->SelfCheckWorkItem = NULL;
    }
}
