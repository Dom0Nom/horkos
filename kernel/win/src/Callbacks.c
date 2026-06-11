/*
 * kernel/win/src/Callbacks.c
 * Role: Registers an ObRegisterCallbacks handle-filter for the protected
 *       process/thread types. Phase 3 is observe-and-log: the pre-callback
 *       records each handle-open into the ring and only strips rights when the
 *       (default-off) policy flag is set. Rights-stripping enforcement and its
 *       bypass tests land in Phase 5.
 * Target platforms: Windows kernel mode (KMDF).
 * Interface: implements HkObArm / HkObDisarm declared in
 *       kernel/win/include/horkos_kernel.h.
 */

#include <ntddk.h>
#include <wdf.h>

#include "horkos_kernel.h"

/* Rights stripped from cross-process handle opens when policy enables it.
 * Observe-only by default (Phase 3); enforcement is gated by Policy. */
#define HK_STRIP_PROCESS_RIGHTS (PROCESS_VM_READ | PROCESS_VM_WRITE | \
                                 PROCESS_VM_OPERATION | PROCESS_TERMINATE)
#define HK_STRIP_THREAD_RIGHTS  (THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | \
                                 THREAD_TERMINATE)

_Function_class_(OB_PRE_OPERATION_CALLBACK)
static OB_PREOP_CALLBACK_STATUS HkObPreCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION Info)
{
    PHK_DEVICE_CONTEXT     ctx;
    hk_event_handle_open   payload;
    ACCESS_MASK*           desired = NULL;
    ACCESS_MASK            original = 0;
    ACCESS_MASK            stripMask = 0;
    HANDLE                 targetPid = NULL;
    BOOLEAN                isProcess;

    UNREFERENCED_PARAMETER(RegistrationContext);

    ctx = HkContext();
    if (ctx == NULL) {
        return OB_PREOP_SUCCESS;
    }

    /* Never filter kernel-mode openers. */
    if (Info->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    isProcess = (Info->ObjectType == *PsProcessType);

    /* Signal 1 — Ob liveness self-poll. The self-check work item opens the
     * System process (PID 4) with a magic reserved access bit. Recognizing that
     * exact (opener == System, target == System, magic bit set) shape, we stamp
     * the nonce the work item armed and suppress the normal emit so the probe
     * never pollutes hk_event_handle_open. A real opener cannot forge this: the
     * opener is the System process and the access bit is reserved. */
    if (isProcess) {
        ACCESS_MASK selfDesired = 0;
        if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
            selfDesired = Info->Parameters->CreateHandleInformation.OriginalDesiredAccess;
        } else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            selfDesired = Info->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
        }
        if ((selfDesired & HK_OB_SELFPOLL_MAGIC) &&
            PsGetCurrentProcessId() == PsGetProcessId(PsInitialSystemProcess) &&
            (PEPROCESS)Info->Object == PsInitialSystemProcess) {
            /* Stamp the expected nonce so the work item sees the callback fired.
             * InterlockedExchange64 publishes the value to the PASSIVE reader. */
            InterlockedExchange64(&ctx->ObSelfPollNonce, ctx->ObSelfPollExpected);
            return OB_PREOP_SUCCESS;
        }
    }

    if (isProcess) {
        targetPid = PsGetProcessId((PEPROCESS)Info->Object);
        stripMask = HK_STRIP_PROCESS_RIGHTS;
    } else {
        targetPid = PsGetThreadProcessId((PETHREAD)Info->Object);
        stripMask = HK_STRIP_THREAD_RIGHTS;
    }

    /* desired points at the MUTABLE access field (what we strip); original is
     * the read-only access the requester actually asked for. A higher-altitude
     * callback may have already reduced DesiredAccess, so we LOG original (true
     * intent) but STRIP desired. */
    if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
        desired = &Info->Parameters->CreateHandleInformation.DesiredAccess;
        original = Info->Parameters->CreateHandleInformation.OriginalDesiredAccess;
    } else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        desired = &Info->Parameters->DuplicateHandleInformation.DesiredAccess;
        original = Info->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
    }

    RtlZeroMemory(&payload, sizeof(payload));
    payload.requesting_pid = (uint32_t)(ULONG_PTR)PsGetCurrentProcessId();
    payload.target_pid = (uint32_t)(ULONG_PTR)targetPid;
    payload.access_mask = (uint32_t)original;
    HkRingEmit(HK_EVENT_HANDLE_OPEN, &payload, sizeof(payload));

#if defined(HK_WIN_VMWATCH)
    /* Handle provenance (#66). DuplicateHandleInformation.SourceProcessId is only
     * present on the PRE-operation parameters (the POST-op duplicate info carries no
     * SourceProcessId), so the dup-laundering check MUST happen here, not in the
     * post-op. For a CREATE we record the requester as a known opener; for a
     * DUPLICATE we look up the dup's SourceProcessId — if that source never appeared
     * as a create-path opener, the chain is "laundered". The granted-access half (#67)
     * is owned by the post-op (granted is not known until then). */
    if (isProcess) {
        if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
            HkObRecordOpener(ctx, (uint32_t)(ULONG_PTR)PsGetCurrentProcessId());
        } else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            hk_event_handle_provenance prov;
            uint32_t source_pid = (uint32_t)(ULONG_PTR)
                Info->Parameters->DuplicateHandleInformation.SourceProcessId;
            RtlZeroMemory(&prov, sizeof(prov));
            prov.requester_pid = (uint32_t)(ULONG_PTR)PsGetCurrentProcessId();
            prov.source_pid = source_pid;
            prov.target_pid = (uint32_t)(ULONG_PTR)targetPid;
            prov.original_desired_access = (uint32_t)original;
            /* granted_access stays 0 on the pre-op dup path; the post-op carries the
             * granted mask for the create/#67 path. */
            if (!HkObRootOpenerSeen(ctx, source_pid)) {
                prov.flags |= HK_HND_DUP_LAUNDERED;
            }
#if defined(HK_VMWATCH_SCHEMA_READY)
            /* 24-byte payload EXCEEDS HK_EVENT_PAYLOAD_MAX (16); captured but not
             * emitted until the Schema phase grows the envelope (truncation guard). */
            HkRingEmit(HK_EVENT_HANDLE_PROVENANCE, &prov, sizeof(prov));
#else
            UNREFERENCED_PARAMETER(prov);
#endif
        }
    }
#endif

    /* Enforcement: strip the dangerous bits only when policy enables it AND the
     * opener is not opening its own process/thread. Default policy is off. */
    if (desired != NULL && ctx->Policy.enable_ob_strip &&
        targetPid != PsGetCurrentProcessId()) {
        *desired &= ~stripMask;
    }

    return OB_PREOP_SUCCESS;
}

#if defined(HK_WIN_VMWATCH)
/* -------------------------------------------------------------------------
 * Provenance ring (#66). HkObRecordOpener pushes a create-path requester PID;
 * HkObRootOpenerSeen answers whether a given PID ever appeared as a create-path
 * opener. Best-effort: the ring is small and wraps, so "not seen" can be a false
 * negative under churn — that is acceptable for a provenance HINT (the server fuses
 * it, it never bans on this alone). Guarded by ProvLock. Both run at <= DISPATCH.
 * ------------------------------------------------------------------------- */
_Use_decl_annotations_
void HkObRecordOpener(PHK_DEVICE_CONTEXT Ctx, uint32_t requester_pid)
{
    KIRQL irql;
    ULONG slots = (ULONG)RTL_NUMBER_OF(Ctx->ProvOpenerPids);
    KeAcquireSpinLock(&Ctx->ProvLock, &irql);
    Ctx->ProvOpenerPids[Ctx->ProvHead & (slots - 1)] = requester_pid;
    Ctx->ProvHead += 1;
    KeReleaseSpinLock(&Ctx->ProvLock, irql);
}

_Use_decl_annotations_
BOOLEAN HkObRootOpenerSeen(PHK_DEVICE_CONTEXT Ctx, uint32_t source_pid)
{
    KIRQL irql;
    ULONG i;
    ULONG slots = (ULONG)RTL_NUMBER_OF(Ctx->ProvOpenerPids);
    BOOLEAN seen = FALSE;
    KeAcquireSpinLock(&Ctx->ProvLock, &irql);
    for (i = 0; i < slots; ++i) {
        if (Ctx->ProvOpenerPids[i] == source_pid) {
            seen = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&Ctx->ProvLock, irql);
    return seen;
}

/* -------------------------------------------------------------------------
 * Ob post-operation callback (#67 granted-access delta). The DUP-laundering half
 * (#66) lives in the PRE callback, where DuplicateHandleInformation.SourceProcessId
 * is available (the POST-op duplicate info struct has NO SourceProcessId).
 *
 * HK-UNCERTAIN(ob-postop-grantedaccess): OB_POST_OPERATION_INFORMATION and the
 * Parameters.CreateHandleInformation.GrantedAccess field are documented (WDK:
 * learn.microsoft.com/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_post_operation_information).
 * Whether it reflects the FINAL mask after all higher-altitude callbacks, and
 * whether registering a PostOperation changes pre-op dispatch, must be confirmed
 * on-box. The per-handle pre/post CallContext keying (needed to compute
 * HK_HND_GRANT_EXCEEDS_PREOP in-kernel) is undocumented — the pre-op already LOGS
 * OriginalDesiredAccess into hk_event_handle_open, and the server diffs
 * granted-vs-requested on its side. HK_HND_GRANT_EXCEEDS_PREOP is NOT set here
 * until the CallContext pairing is confirmed on-box. The post-op never strips and
 * never blocks (post-op cannot). (docs: OB_POST_OPERATION_INFORMATION documented;
 * still needs on-box: final-mask guarantee + CallContext pairing semantics)
 *
 * Emit is guarded by HK_VMWATCH_SCHEMA_READY: hk_event_handle_provenance is 24 bytes,
 * which EXCEEDS the frozen HK_EVENT_PAYLOAD_MAX (16). Until the Schema phase grows the
 * envelope, HkRingEmit would TRUNCATE the record, so we capture-but-do-not-emit. Do
 * NOT emit a truncated provenance record.
 * ------------------------------------------------------------------------- */
_Function_class_(OB_POST_OPERATION_CALLBACK)
static VOID HkObPostCallback(_In_ PVOID RegistrationContext,
                             _In_ POB_POST_OPERATION_INFORMATION Info)
{
    PHK_DEVICE_CONTEXT ctx;
    hk_event_handle_provenance payload;
    ACCESS_MASK granted = 0;
    BOOLEAN isProcess;

    UNREFERENCED_PARAMETER(RegistrationContext);

    ctx = HkContext();
    if (ctx == NULL) {
        return;
    }

    /* Post-op fires only after a successful operation; a failed open carries a
     * non-success ReturnStatus and no meaningful granted mask. */
    if (!NT_SUCCESS(Info->ReturnStatus)) {
        return;
    }

    isProcess = (Info->ObjectType == *PsProcessType);
    if (!isProcess) {
        return; /* provenance is tracked for process handles (#67). */
    }

    if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
        granted = Info->Parameters->CreateHandleInformation.GrantedAccess;
    } else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        granted = Info->Parameters->DuplicateHandleInformation.GrantedAccess;
    }

    RtlZeroMemory(&payload, sizeof(payload));
    payload.requester_pid = (uint32_t)(ULONG_PTR)PsGetCurrentProcessId();
    payload.source_pid = payload.requester_pid; /* post-op has no dup source; see pre-op */
    payload.target_pid = (uint32_t)(ULONG_PTR)PsGetProcessId((PEPROCESS)Info->Object);
    payload.granted_access = (uint32_t)granted;
    /* HK_HND_GRANT_EXCEEDS_PREOP intentionally NOT set here — see HK-UNCERTAIN above. */

#if defined(HK_VMWATCH_SCHEMA_READY)
    /* Only reachable once the Schema phase grows HK_EVENT_PAYLOAD_MAX to >= 24 and
     * assigns HK_EVENT_HANDLE_PROVENANCE a distinct hk_event_type value. Until then
     * the record is captured above but NOT emitted (truncation guard). */
    HkRingEmit(HK_EVENT_HANDLE_PROVENANCE, &payload, sizeof(payload));
#else
    UNREFERENCED_PARAMETER(payload);
#endif
}
#endif /* HK_WIN_VMWATCH */

_Use_decl_annotations_
NTSTATUS HkObArm(PHK_DEVICE_CONTEXT Ctx)
{
    NTSTATUS                  status;
    OB_CALLBACK_REGISTRATION  reg;
    OB_OPERATION_REGISTRATION op[2];
    UNICODE_STRING            altitude;

    RtlInitUnicodeString(&altitude, HK_OB_ALTITUDE);
    RtlZeroMemory(&op, sizeof(op));
    RtlZeroMemory(&reg, sizeof(reg));

    /* OB_OPERATION_REGISTRATION.ObjectType is POBJECT_TYPE* and PsProcessType is
     * already POBJECT_TYPE*, so assign WITHOUT a dereference. (The pre-callback
     * compares Info->ObjectType, a POBJECT_TYPE, against *PsProcessType — that
     * side DOES dereference. Do not "normalize" the two; they are different
     * types and aligning them would silently break callback dispatch.) */
    op[0].ObjectType = PsProcessType;
    op[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    op[0].PreOperation = HkObPreCallback;
#if defined(HK_WIN_VMWATCH)
    /* Granted-access delta + dup provenance (#66/#67). Wired only for the process
     * type; thread handles keep PostOperation NULL. See HkObPostCallback's
     * HK-UNCERTAIN(ob-postop-grantedaccess). The provenance ring lock is initialized
     * here so the pre-op record and post-op lookup can use it. */
    KeInitializeSpinLock(&Ctx->ProvLock);
    op[0].PostOperation = HkObPostCallback;
#else
    op[0].PostOperation = NULL;
#endif

    op[1].ObjectType = PsThreadType;
    op[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    op[1].PreOperation = HkObPreCallback;
    op[1].PostOperation = NULL;

    reg.Version = OB_FLT_REGISTRATION_VERSION;
    reg.OperationRegistrationCount = 2;
    reg.Altitude = altitude;
    reg.RegistrationContext = NULL;
    reg.OperationRegistration = op;

    /* reg/op are on the stack; this is safe because ObRegisterCallbacks copies
     * all registration data before returning (documented WDK contract). */
    status = ObRegisterCallbacks(&reg, &Ctx->ObRegistrationHandle);
    if (!NT_SUCCESS(status)) {
        /* STATUS_ACCESS_DENIED here means the driver image lacks the
         * object-callback signing EKU — bcdedit /set testsigning on does NOT
         * grant it. Store the status so HK_IOCTL_GET_STATUS / a debugger can
         * tell signing-denied from an altitude collision or a real bug. */
        InterlockedExchange(&Ctx->ObLastStatus, (LONG)status);
        Ctx->ObRegistrationHandle = NULL;
        InterlockedExchange(&Ctx->ObCallbacksArmed, 0);
        return status;
    }

    InterlockedExchange(&Ctx->ObLastStatus, (LONG)STATUS_SUCCESS);
    InterlockedExchange(&Ctx->ObCallbacksArmed, 1);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
void HkObDisarm(PHK_DEVICE_CONTEXT Ctx)
{
    /* Atomic take-and-clear so exactly one caller ever unregisters the handle,
     * even if a future IOCTL-triggered disarm races the unload path. */
    PVOID handle = InterlockedExchangePointer(&Ctx->ObRegistrationHandle, NULL);
    if (handle != NULL) {
        ObUnRegisterCallbacks(handle);
    }
    InterlockedExchange(&Ctx->ObCallbacksArmed, 0);
}

PVOID HkObPreCallbackAddress(void)
{
    /* Exposed so CallbackSelfCheck.c can (a) compare the registered PreOperation
     * pointer against this baseline (signal 7 ptr-swap) and (b) locate the
     * owning image's .text for the SHA-256 baseline (signal 8). Taking the
     * address of a static function in its own TU is well-defined. */
    return (PVOID)(ULONG_PTR)&HkObPreCallback;
}
