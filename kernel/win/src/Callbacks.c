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

    /* Enforcement: strip the dangerous bits only when policy enables it AND the
     * opener is not opening its own process/thread. Default policy is off. */
    if (desired != NULL && ctx->Policy.enable_ob_strip &&
        targetPid != PsGetCurrentProcessId()) {
        *desired &= ~stripMask;
    }

    return OB_PREOP_SUCCESS;
}

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
    op[0].PostOperation = NULL;

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
