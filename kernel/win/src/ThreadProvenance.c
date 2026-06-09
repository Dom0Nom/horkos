/*
 * kernel/win/src/ThreadProvenance.c
 * Role: Kernel-side thread-create provenance capture (win-kernel-thread-injection,
 *       catalog signals 19/22/23/26 capture half). Arms the *Ex* create-thread
 *       notify and, per thread-create event, captures the new TID/PID, the
 *       owning-process session id, and a WOW64-target flag, emitting an
 *       hk_event_thread_create record into the ring. Capture-only; all scoring
 *       and ban authority is server-side.
 * Target platforms: Windows kernel mode (KMDF).
 * Interface: implements HkThreadProvenanceArm / HkThreadProvenanceDisarm /
 *       HkThreadProvenanceDisarmFailed declared in
 *       kernel/win/include/horkos_kernel.h. Emits hk_event_thread_create
 *       (HK-TODO(schema): wire type is a kernel-private mirror until the Schema
 *       phase appends it to event_schema.h and grows HK_EVENT_PAYLOAD_MAX — see
 *       horkos_kernel.h). Guardrail #4: kernel TU only, no userspace headers.
 *
 * ============================================================================
 * HK-UNCERTAIN(ex-thread-notify-startaddress): VERIFIED-FALSE PLAN ASSUMPTION.
 * The plan (docs/impl-plans/win-kernel-thread-injection.md §"Kernel plane") is
 * built on PsSetCreateThreadNotifyRoutineEx delivering a
 * PPS_CREATE_THREAD_NOTIFY_INFO whose StartAddress is the spoof-resistant kernel
 * ETHREAD start (the load-bearing source for signal 23). That is INCORRECT per
 * the WDK DDI:
 *   - PsSetCreateThreadNotifyRoutineEx(PSCREATETHREADNOTIFYTYPE NotifyType,
 *       PVOID NotifyInformation): for PsCreateThreadNotifyNonSystem,
 *       NotifyInformation is a PCREATE_THREAD_NOTIFY_ROUTINE — the SAME 3-arg
 *       callback as the non-Ex variant: VOID(HANDLE ProcessId, HANDLE ThreadId,
 *       BOOLEAN Create). There is NO PS_CREATE_THREAD_NOTIFY_INFO and NO
 *       StartAddress parameter.
 *   - The ONLY documented difference vs PsSetCreateThreadNotifyRoutine is the
 *       execution context: the Ex/NonSystem callback runs on the NEWLY CREATED
 *       thread; the legacy callback runs on the CREATOR thread.
 *   refs: ntddk.h PsSetCreateThreadNotifyRoutineEx /
 *         PCREATE_THREAD_NOTIFY_ROUTINE (both fetched & quoted in the task log).
 *
 * Consequence: there is NO sanctioned kernel-callback source for the thread
 * start address at create time. Signal 23's "spoof-resistant kernel start" must
 * come from a different mechanism (e.g. ZwQueryInformationThread under the
 * userspace enrichment plane, with its known spoofability, or an undocumented
 * ETHREAD->StartAddress / Win32StartAddress field read which is exactly the kind
 * of version-gated internals the CLAUDE.md guardrails forbid guessing). Per
 * guardrail #13 this file does NOT fabricate a start-address source: it captures
 * kernel_start_address = 0 and sets it to be resolved by the userspace plane,
 * and the design owner must revisit signal 23 before this ships. STOP/confirm.
 * ============================================================================
 */

#include <ntddk.h>
#include <wdf.h>

#include "horkos_kernel.h"

/* Armed-state + disarm-failure tracking mirrors Notify.c's discipline: a failed
 * remove must block unload rather than leave a live callback pointer into freed
 * image pages. */
static BOOLEAN g_ThreadExArmed   = FALSE;
static BOOLEAN g_ThreadExDisarmFailed = FALSE;

BOOLEAN HkThreadProvenanceDisarmFailed(void)
{
    return g_ThreadExDisarmFailed;
}

/*
 * HK_TI_SCHEMA_READY gates the actual ring emit. hk_event_thread_create is 48
 * bytes and EXCEEDS the frozen HK_EVENT_PAYLOAD_MAX (16) until the Schema phase
 * grows it (see horkos_kernel.h). HkRingEmit would TRUNCATE a 48-byte payload to
 * 16 today, silently corrupting the record. Until the grown payload lands we
 * capture the provenance but DO NOT push a truncated record (guardrail: no
 * faithless serialization). Defined by the Schema phase build once the record
 * is re-pinned to 80 bytes. */
#ifndef HK_TI_SCHEMA_READY
#  define HK_TI_SCHEMA_READY 0
#endif

/* -------------------------------------------------------------------------
 * WOW64 / session accessors.
 *
 * HK-UNCERTAIN(wow64-session-accessors): PsGetProcessWow64Process and
 * PsGetProcessSessionId are commonly used by AV/EDR drivers but are NOT cleanly
 * published on the ntddk public DDI surface the way PsGetThreadId is (the ntifs
 * PsGetProcessSessionId reference page 404s as of this writing). Their exact
 * header (ntifs.h vs ntddk.h), availability per target build, and IRQL contract
 * must be confirmed against the target WDK before relying on them. They are
 * called behind HK_TI_PROC_ACCESSORS so the build does not pull an unresolved
 * import until that confirmation lands; until then the WOW64 and cross-session
 * flags are reported as "unknown" (cleared), which the server treats as no
 * evidence rather than negative evidence. Do NOT assume these resolve. */
#ifndef HK_TI_PROC_ACCESSORS
#  define HK_TI_PROC_ACCESSORS 0
#endif

#if HK_TI_PROC_ACCESSORS
/* These prototypes intentionally mirror the documented-but-unverified shapes.
 * They are compiled only when HK_TI_PROC_ACCESSORS is set by a build that has
 * confirmed the exports exist on the target WDK. */
NTKERNELAPI ULONG    PsGetProcessSessionId(_In_ PEPROCESS Process);
NTKERNELAPI PVOID    PsGetProcessWow64Process(_In_ PEPROCESS Process);
#endif

/*
 * The Ex/NonSystem thread-create notify. Runs ON THE NEW THREAD at
 * IRQL <= APC_LEVEL (verified DDI). Capture-only.
 *
 * What is actually available here (verified):
 *   - ProcessId : owning process of the new thread.
 *   - ThreadId  : the new thread's TID.
 *   - Create    : TRUE on create, FALSE on delete.
 *   - PsGetCurrentThreadId() == the NEW thread (Ex runs on the new thread), so
 *     it is NOT a creator-TID source. Creator lineage (signal 19) therefore has
 *     no kernel-callback source either and is left to the userspace plane, which
 *     the plan already routes there for the region/VAD work.
 */
_Function_class_(PCREATE_THREAD_NOTIFY_ROUTINE)
static VOID NTAPI HkThreadNotifyEx(_In_ HANDLE ProcessId,
                                   _In_ HANDLE ThreadId,
                                   _In_ BOOLEAN Create)
{
    hk_event_thread_create payload;

    /* Only create events carry provenance; deletions are covered by the
     * process/thread lifecycle elsewhere and need no thread-origin record. */
    if (!Create) {
        return;
    }

    RtlZeroMemory(&payload, sizeof(payload));
    payload.tid = (uint32_t)(ULONG_PTR)ThreadId;
    payload.pid = (uint32_t)(ULONG_PTR)ProcessId;

    /* HK-UNCERTAIN(ex-thread-notify-startaddress) — see file header. No
     * sanctioned kernel start-address source at create time; resolved by the
     * userspace enrichment plane (hk_event_thread_provenance). Left zero. */
    payload.kernel_start_address = 0;

    /* HK-UNCERTAIN(creator-lineage): the Ex callback runs on the new thread, so
     * the current thread is NOT the creator. Neither notify variant yields a
     * reliable creator TID without ETHREAD internals. Left zero; creator
     * provenance (signal 19) is resolved server/userspace-side. */
    payload.creator_tid = 0;
    payload.creator_pid = 0;

    payload.flags = 0;
    payload.creator_session_id = 0;
    payload.target_session_id = 0;

#if HK_TI_PROC_ACCESSORS
    {
        /* Resolve the owning EPROCESS to read session id + WOW64 state. Behind
         * HK_TI_PROC_ACCESSORS because the accessor exports are unverified. */
        PEPROCESS targetProc = NULL;
        NTSTATUS  st = PsLookupProcessByProcessId(ProcessId, &targetProc);
        if (NT_SUCCESS(st) && targetProc != NULL) {
            payload.target_session_id =
                (uint32_t)PsGetProcessSessionId(targetProc);
            if (PsGetProcessWow64Process(targetProc) != NULL) {
                payload.flags |= HK_THREAD_FLAG_WOW64_TARGET;
            }
            ObDereferenceObject(targetProc);
        }
        /* Cross-session (signal 26) needs the creator's session id, which has no
         * creator handle in the Ex-on-new-thread context; left unresolved here
         * and computed server-side from the creator the userspace plane reports.
         * HK_THREAD_FLAG_CROSS_SESSION is therefore NOT set in the kernel. */
    }
#endif

    /* Boot/interrupt-epoch ns; same epoch as header.timestamp_ns (NOT FILETIME). */
    payload.create_time_ns = (uint64_t)KeQueryInterruptTime() * 100ull;

#if HK_TI_SCHEMA_READY
    HkRingEmit(HK_EVENT_THREAD_CREATE, &payload, sizeof(payload));
#else
    /* Provenance captured but not emitted: hk_event_thread_create (48B) exceeds
     * the frozen 16B HK_EVENT_PAYLOAD_MAX; emitting would truncate. The Schema
     * phase enables HK_TI_SCHEMA_READY once the record is re-pinned to 80B. */
    UNREFERENCED_PARAMETER(payload);
#endif
}

_Use_decl_annotations_
NTSTATUS HkThreadProvenanceArm(void)
{
    NTSTATUS status;

    /* PsSetCreateThreadNotifyRoutineEx(PsCreateThreadNotifyNonSystem, routine):
     * PASSIVE_LEVEL (verified DDI). Returns STATUS_SUCCESS or
     * STATUS_INSUFFICIENT_RESOURCES. Like the process Ex notify it requires the
     * driver image to carry IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY
     * (/INTEGRITYCHECK) or registration is refused. */
    status = PsSetCreateThreadNotifyRoutineEx(
        PsCreateThreadNotifyNonSystem,
        (PVOID)(PCREATE_THREAD_NOTIFY_ROUTINE)HkThreadNotifyEx);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    g_ThreadExArmed = TRUE;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
void HkThreadProvenanceDisarm(void)
{
    NTSTATUS status;

    if (!g_ThreadExArmed) {
        return;
    }

    /* PsRemoveCreateThreadNotifyRoutine removes a routine registered via either
     * Set variant. Remove waits for in-flight callbacks to drain before
     * returning, so no callback can be running into freed pages after success. */
    status = PsRemoveCreateThreadNotifyRoutine(
        (PCREATE_THREAD_NOTIFY_ROUTINE)HkThreadNotifyEx);
    if (NT_SUCCESS(status)) {
        g_ThreadExArmed = FALSE;
    } else {
        g_ThreadExDisarmFailed = TRUE;
    }
}
