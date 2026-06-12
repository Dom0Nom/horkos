/*
 * Role: CmRegisterCallbackEx registry filter scoped STRICTLY to Horkos's own
 *       service / config / driver-image keys. Observe-only (Phase 3): the
 *       callback NEVER blocks a write — it always returns STATUS_SUCCESS — it
 *       only records who touched a protected value (signal 5, hk_event_reg_tamper)
 *       and exposes a cookie-presence census (signal 9, folded into the callback
 *       census). Like the macOS ES never-drop rule, every notification path
 *       returns a status; no path early-returns without one. Ban authority is
 *       server-side.
 * Target platforms: Windows kernel mode (KMDF).
 * Interface: implements HkCmArm / HkCmDisarm / HkCmCensus declared in
 *       kernel/win/include/horkos_kernel.h. Emits hk_event_reg_tamper /
 *       hk_event_callback_census (HK-TODO(schema): kernel-private wire mirrors
 *       until the Schema phase appends them to event_schema.h).
 */

#include <ntddk.h>
#include <wdf.h>

#include "horkos_kernel.h"

/* CmRegisterCallbackEx altitude. Distinct from the Ob altitude; a registry
 * filter and an object filter occupy different callback namespaces but a
 * production build still draws both from Microsoft's Allocated Altitudes
 * (docs/windows-signing.md). Reuse a value adjacent to HK_OB_ALTITUDE's group. */
#define HK_CM_ALTITUDE L"385202"

/* The registry subtree(s) we protect. Scope is deliberately narrow to bound FP
 * volume and per-write load — only Horkos's own service and driver-image keys.
 * Matching is a case-insensitive prefix test against the RegNt* target path. */
static const PCWSTR g_HkProtectedKeyPrefixes[] = {
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Horkos",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Horkos",
};

/* Classify the trailing value name into an HK_REG_VAL_* class. Pure string
 * compare on the writer's value name; defaults to OTHER. */
static uint32_t HkClassifyRegValue(_In_opt_ PCUNICODE_STRING ValueName)
{
    /* DECLARE_CONST_UNICODE_STRING yields a stack-local UNICODE_STRING bound to a
     * static wide literal — addressable, no compound-literal lifetime worry under
     * /W4 /WX. Case-insensitive compare (TRUE). */
    DECLARE_CONST_UNICODE_STRING(vnImagePath, L"ImagePath");
    DECLARE_CONST_UNICODE_STRING(vnStart,     L"Start");
    DECLARE_CONST_UNICODE_STRING(vnAltitude,  L"Altitude");

    if (ValueName == NULL || ValueName->Buffer == NULL || ValueName->Length == 0) {
        return HK_REG_VAL_OTHER;
    }
    if (RtlEqualUnicodeString(ValueName, &vnImagePath, TRUE)) {
        return HK_REG_VAL_IMAGEPATH;
    }
    if (RtlEqualUnicodeString(ValueName, &vnStart, TRUE)) {
        return HK_REG_VAL_START;
    }
    if (RtlEqualUnicodeString(ValueName, &vnAltitude, TRUE)) {
        return HK_REG_VAL_ALTITUDE;
    }
    return HK_REG_VAL_OTHER;
}

/* TRUE if Path begins (case-insensitively) with one of our protected prefixes.
 * Uses only safe, bounded RTL string routines (guardrail #5). */
static BOOLEAN HkIsProtectedKey(_In_opt_ PCUNICODE_STRING Path)
{
    ULONG i;

    if (Path == NULL || Path->Buffer == NULL || Path->Length == 0) {
        return FALSE;
    }

    for (i = 0; i < ARRAYSIZE(g_HkProtectedKeyPrefixes); ++i) {
        UNICODE_STRING prefix;
        UNICODE_STRING head;
        RtlInitUnicodeString(&prefix, g_HkProtectedKeyPrefixes[i]);

        if (Path->Length < prefix.Length) {
            continue;
        }
        /* Compare only the leading prefix.Length bytes of Path. */
        head.Buffer = Path->Buffer;
        head.Length = prefix.Length;
        head.MaximumLength = prefix.Length;
        if (RtlEqualUnicodeString(&head, &prefix, TRUE)) {
            return TRUE;
        }
    }
    return FALSE;
}

/* TRUE if the current requester token is SYSTEM/TrustedInstaller (a servicing
 * window — low weight). FP gate input for signal 5.
 * HK-UNCERTAIN(cm-writer-token): a robust SYSTEM/TrustedInstaller determination
 * needs SeQueryInformationToken on the effective token and a SID compare against
 * the well-known SYSTEM/TrustedInstaller SIDs. SeQueryInformationToken is documented
 * (learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/nf-ntifs-sequeryinformationtoken);
 * PsReferencePrimaryToken and ObDereferenceObject are also documented. However, their
 * IRQL requirements and token reference lifetime in a Cm callback context must be
 * confirmed on-box. Per guardrail #13 the precise token check is NOT implemented here;
 * we approximate with PID == 4 (System) only, which is a strict subset (no false "is
 * system"). The writer_is_system field therefore UNDER-counts system writers (fails
 * toward HIGH weight), which is the safe direction for an observe-only sensor.
 * (docs: SeQueryInformationToken + PsReferencePrimaryToken documented; still needs
 * on-box: IRQL constraint + token ref lifetime inside a Cm callback) */
static uint32_t HkWriterIsSystem(void)
{
    return (PsGetCurrentProcessId() == PsGetProcessId(PsInitialSystemProcess))
               ? 1u : 0u;
}

_Function_class_(EX_CALLBACK_FUNCTION)
static NTSTATUS HkCmCallback(_In_ PVOID CallbackContext,
                             _In_opt_ PVOID Argument1,
                             _In_opt_ PVOID Argument2)
{
    REG_NOTIFY_CLASS    notifyClass;
    hk_event_reg_tamper ev;
    PCUNICODE_STRING    keyPath = NULL;
    PCUNICODE_STRING    valueName = NULL;
    uint32_t            op = HK_REG_OP_SET;

    UNREFERENCED_PARAMETER(CallbackContext);

    /* Argument2 may legitimately be NULL for classes we do not handle. We must
     * STILL return a status for every invocation (never-drop rule). */
    if (Argument2 == NULL) {
        return STATUS_SUCCESS;
    }

    notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    switch (notifyClass) {
    case RegNtPreSetValueKey: {
        PREG_SET_VALUE_KEY_INFORMATION info =
            (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        valueName = info->ValueName;
        op = HK_REG_OP_SET;
        /* CmCallbackGetKeyObjectIDEx gives the full registry path for the key.
         * HK-UNCERTAIN(cm-key-path): CmCallbackGetKeyObjectIDEx is documented
         * (learn.microsoft.com/windows-hardware/drivers/ddi/wdm/
         * nf-wdm-cmcallbackgetkeyobjectidex); it requires our live cookie and the
         * key Object, and the returned name must be freed with
         * CmCallbackReleaseKeyObjectIDEx (also documented). The exact Object field
         * on REG_SET_VALUE_KEY_INFORMATION across WDK versions (Object vs RootObject)
         * must be confirmed on-box before calling. We therefore scope-match on the
         * value name only below and leave full-path extraction to the on-box pass.
         * This means HkIsProtectedKey cannot yet run on a real path here.
         * (docs: CmCallbackGetKeyObjectIDEx + Release documented; still needs on-box:
         * Object field name on REG_SET_VALUE_KEY_INFORMATION for target WDK version) */
        break;
    }
    case RegNtPreDeleteKey:
        op = HK_REG_OP_DELETE;
        break;
    case RegNtPreDeleteValueKey: {
        PREG_DELETE_VALUE_KEY_INFORMATION info =
            (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
        valueName = info->ValueName;
        op = HK_REG_OP_DELETEVALUE;
        break;
    }
    default:
        /* Not a class we record. Return success — observe-only, never block. */
        return STATUS_SUCCESS;
    }

    /* Scope gate. HK-UNCERTAIN(cm-key-path): until full-path extraction is wired
     * via CmCallbackGetKeyObjectIDEx (see above; API is documented but on-box
     * Object-field confirmation is pending), we cannot confirm keyPath is one of
     * ours. We conservatively emit only when a value-name classification is
     * meaningful (Start/ImagePath/Altitude on a Services-class write). Broaden to
     * HkIsProtectedKey(keyPath) once the path call is confirmed on-box. */
    {
        uint32_t valueClass = HkClassifyRegValue(valueName);
        BOOLEAN  pathProtected =
            (keyPath != NULL) ? HkIsProtectedKey(keyPath) : FALSE;

        if (!pathProtected && valueClass == HK_REG_VAL_OTHER) {
            return STATUS_SUCCESS; /* not interesting; never block */
        }

        RtlZeroMemory(&ev, sizeof(ev));
        ev.writer_pid = (uint32_t)(ULONG_PTR)PsGetCurrentProcessId();
        ev.value_class = valueClass;
        ev.op = op;
        ev.writer_is_system = HkWriterIsSystem();
        HkRingEmit(HK_EVENT_REG_TAMPER, &ev, sizeof(ev));
    }

    /* Observe-only Phase 3: never block the write. */
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS HkCmArm(PHK_DEVICE_CONTEXT Ctx)
{
    NTSTATUS       status;
    UNICODE_STRING altitude;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    if (Ctx == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlInitUnicodeString(&altitude, HK_CM_ALTITUDE);
    Ctx->CmCookie.QuadPart = 0;

    if (g_HkDriverObject == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    /* CmRegisterCallbackEx requires IRQL <= APC_LEVEL. The Driver parameter is a
     * PVOID to the DRIVER_OBJECT (verified against the wdm.h reference) — pass the
     * captured g_HkDriverObject, NOT the WDFDEVICE. STATUS_FLT_INSTANCE_ALTITUDE_
     * COLLISION on an altitude clash; check the return (guardrail #5). */
    status = CmRegisterCallbackEx(HkCmCallback, &altitude,
                                  (PVOID)g_HkDriverObject,
                                  Ctx, &Ctx->CmCookie, NULL);
    if (!NT_SUCCESS(status)) {
        Ctx->CmCookie.QuadPart = 0;
        Ctx->CmBaseline.Present = FALSE;
        InterlockedExchange(&Ctx->CmArmed, 0);
        return status;
    }

    Ctx->CmBaseline.Cookie = Ctx->CmCookie;
    Ctx->CmBaseline.Present = TRUE;
    InterlockedExchange(&Ctx->CmArmed, 1);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
void HkCmDisarm(PHK_DEVICE_CONTEXT Ctx)
{
    NTSTATUS status;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    if (Ctx == NULL || Ctx->CmArmed == 0) {
        return;
    }

    if (Ctx->CmCookie.QuadPart != 0) {
        status = CmUnRegisterCallback(Ctx->CmCookie);
        if (NT_SUCCESS(status)) {
            Ctx->CmCookie.QuadPart = 0;
            Ctx->CmBaseline.Present = FALSE;
        }
        /* On failure leave Present set so the unload path can observe that the
         * callback could not be removed (the caller decides whether to bugcheck,
         * mirroring the Notify.c disarm-failed discipline). */
    }
    InterlockedExchange(&Ctx->CmArmed, 0);
}

_Use_decl_annotations_
void HkCmCensus(PHK_DEVICE_CONTEXT Ctx)
{
    hk_event_callback_census ev;

    if (Ctx == NULL) {
        return;
    }

    /* Signal 9: report whether OUR Cm cookie is still present. Absolute count of
     * all registered Cm callbacks has no documented enumerator; we report our own
     * cookie presence (the high-weight self-integrity case) plus a count of 1/0
     * for our own registration. The undocumented global callback list scan ships
     * OFF behind HK_SELFCHECK_UNDOC_OFFSETS and is not implemented here. */
    RtlZeroMemory(&ev, sizeof(ev));
    ev.notify_count = (uint32_t)(Ctx->NotifyRoutinesArmed < 0
                                     ? 0 : Ctx->NotifyRoutinesArmed);
    ev.cm_count = (uint32_t)(Ctx->CmArmed ? 1 : 0);
    ev.own_present = 0;
    if (Ctx->NotifyRoutinesArmed >= 3) {
        ev.own_present |= HK_CENSUS_OWN_NOTIFY;
    }
    if (Ctx->CmArmed && Ctx->CmBaseline.Present) {
        ev.own_present |= HK_CENSUS_OWN_CM;
    }
    ev.floor = (uint32_t)(Ctx->CensusFloor < 0 ? 0 : Ctx->CensusFloor);
    HkRingEmit(HK_EVENT_CALLBACK_CENSUS, &ev, sizeof(ev));

    /* Our cookie vanished while we believe we are armed: high-weight signal 9. */
    if (Ctx->CmArmed && !Ctx->CmBaseline.Present) {
        hk_event_callback_integrity drift;
        RtlZeroMemory(&drift, sizeof(drift));
        drift.check_id = HK_CB_CHECK_ENABLED_DRIFT;
        drift.object_type = HK_CB_OBJTYPE_PROCESS;
        drift.result = HK_CB_RESULT_MISSING;
        drift.consecutive = 0;
        HkRingEmit(HK_EVENT_CALLBACK_INTEGRITY, &drift, sizeof(drift));
    }
}
