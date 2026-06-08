/*
 * kernel/win/src/Notify.c
 * Role: Registers the process/thread/image-load notify routines for early-bird
 *       visibility and funnels each event into the ring buffer. Phase 3 is
 *       capture-only; evidence collection and real BYOVD blocking land later.
 * Target platforms: Windows kernel mode (KMDF).
 * Interface: implements HkNotifyArm / HkNotifyDisarm declared in
 *       kernel/win/include/horkos_kernel.h.
 */

#include <ntddk.h>
#include <wdf.h>

#include "horkos_kernel.h"

/* Track which routines were successfully armed so disarm removes exactly those
 * (single driver instance, so file-scope state is safe). */
static BOOLEAN g_ProcessArmed = FALSE;
static BOOLEAN g_ThreadArmed  = FALSE;
static BOOLEAN g_ImageArmed   = FALSE;

/* Set if any Ps*Remove* call failed during disarm. The unload path bugchecks
 * rather than unload with a live callback pointer into freed image pages. */
static BOOLEAN g_DisarmFailed = FALSE;

BOOLEAN HkNotifyDisarmFailed(void)
{
    return g_DisarmFailed;
}

static void HkBumpArmed(LONG delta)
{
    PHK_DEVICE_CONTEXT ctx = HkContext();
    if (ctx != NULL) {
        InterlockedAdd(&ctx->NotifyRoutinesArmed, delta);
    }
}

_Function_class_(PCREATE_PROCESS_NOTIFY_ROUTINE_EX)
static VOID NTAPI HkProcessNotifyEx(_Inout_ PEPROCESS Process,
                                    _In_ HANDLE ProcessId,
                                    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    if (CreateInfo != NULL) {
        hk_event_process_create payload;
        RtlZeroMemory(&payload, sizeof(payload));
        payload.pid = (uint32_t)(ULONG_PTR)ProcessId;
        payload.parent_pid = (uint32_t)(ULONG_PTR)CreateInfo->ParentProcessId;
        /* True creation time (1601/FILETIME epoch, 100ns units). Distinct from
         * header.timestamp_ns (boot/interrupt epoch) — do not compare directly. */
        payload.create_time_ns =
            (uint64_t)PsGetProcessCreateTimeQuadPart(Process) * 100ull;
        HkRingEmit(HK_EVENT_PROCESS_CREATE, &payload, sizeof(payload));
    } else {
        hk_event_process_exit payload;
        RtlZeroMemory(&payload, sizeof(payload));
        payload.pid = (uint32_t)(ULONG_PTR)ProcessId;
        payload.exit_time_ns = (uint64_t)KeQueryInterruptTime() * 100ull;
        HkRingEmit(HK_EVENT_PROCESS_EXIT, &payload, sizeof(payload));
    }
}

_Function_class_(PCREATE_THREAD_NOTIFY_ROUTINE)
static VOID NTAPI HkThreadNotify(_In_ HANDLE ProcessId,
                                 _In_ HANDLE ThreadId,
                                 _In_ BOOLEAN Create)
{
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ThreadId);
    UNREFERENCED_PARAMETER(Create);
    /* The shared event schema has no thread record yet (event_schema.h is the
     * source of truth; adding a type bumps the schema version). The routine is
     * armed so the path is live; a thread event type is added when the schema
     * gains one. */
}

_Function_class_(PLOAD_IMAGE_NOTIFY_ROUTINE)
static VOID NTAPI HkImageNotify(_In_opt_ PUNICODE_STRING FullImageName,
                                _In_ HANDLE ProcessId,
                                _In_ PIMAGE_INFO ImageInfo)
{
    hk_event_image_load payload;
    PHK_DEVICE_CONTEXT  ctx = HkContext();

    NT_ASSERT(ImageInfo != NULL);  /* WDK contract: ImageInfo is never NULL. */

    RtlZeroMemory(&payload, sizeof(payload));
    payload.pid = (uint32_t)(ULONG_PTR)ProcessId;
    payload.image_base = (uint64_t)(ULONG_PTR)ImageInfo->ImageBase;

    /* BYOVD detection. The load-image notify callback CANNOT abort a load that
     * is already mapping; it can only detect and flag. True blocking requires
     * a minifilter pre-create or a boot-time blocklist and is deferred to a
     * later phase (CLAUDE.md #13: do not pretend an API does more than it can).
     * Tag the single record so the server-side ban path can distinguish it from
     * a normal load — one emit, no duplicate ring noise. */
    if (ctx != NULL && ctx->Policy.enable_byovd_block &&
        HkWhitelistIsBlockedImage(FullImageName)) {
        payload.flags |= HK_IMAGE_FLAG_BYOVD_SUSPECT;
    }

    HkRingEmit(HK_EVENT_IMAGE_LOAD, &payload, sizeof(payload));
}

_Use_decl_annotations_
NTSTATUS HkNotifyArm(void)
{
    NTSTATUS status;

    /* PsSetCreateProcessNotifyRoutineEx returns STATUS_ACCESS_DENIED if the
     * driver image lacks IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY. The CMake and
     * vcxproj builds both pass /INTEGRITYCHECK; a load failure here on a fresh
     * build almost always means that flag was dropped from the link. */
    status = PsSetCreateProcessNotifyRoutineEx(HkProcessNotifyEx, FALSE);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    g_ProcessArmed = TRUE;
    HkBumpArmed(1);

    status = PsSetCreateThreadNotifyRoutine(HkThreadNotify);
    if (!NT_SUCCESS(status)) {
        HkNotifyDisarm();
        return status;
    }
    g_ThreadArmed = TRUE;
    HkBumpArmed(1);

    status = PsSetLoadImageNotifyRoutine(HkImageNotify);
    if (!NT_SUCCESS(status)) {
        HkNotifyDisarm();
        return status;
    }
    g_ImageArmed = TRUE;
    HkBumpArmed(1);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
void HkNotifyDisarm(void)
{
    NTSTATUS status;

    if (g_ImageArmed) {
        status = PsRemoveLoadImageNotifyRoutine(HkImageNotify);
        if (NT_SUCCESS(status)) {
            g_ImageArmed = FALSE;
            HkBumpArmed(-1);
        } else {
            g_DisarmFailed = TRUE;
        }
    }

    if (g_ThreadArmed) {
        status = PsRemoveCreateThreadNotifyRoutine(HkThreadNotify);
        if (NT_SUCCESS(status)) {
            g_ThreadArmed = FALSE;
            HkBumpArmed(-1);
        } else {
            g_DisarmFailed = TRUE;
        }
    }

    if (g_ProcessArmed) {
        /* The Ex variant is removed with the same function and TRUE. */
        status = PsSetCreateProcessNotifyRoutineEx(HkProcessNotifyEx, TRUE);
        if (NT_SUCCESS(status)) {
            g_ProcessArmed = FALSE;
            HkBumpArmed(-1);
        } else {
            g_DisarmFailed = TRUE;
        }
    }
}
