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

/* ETW-TI consumer keepalive bump (signal 212, version-independent half). The
 * intended caller is Horkos's ETW-TI consumer: on each Threat-Intelligence event
 * (ReadVm/WriteVm/etc.) it calls this so HkEtwTiLiveness can confirm the TI feed
 * is alive without reading any unexported global.
 *
 * HK-UNCERTAIN(etw-ti-consumer): Microsoft-Windows-Threat-Intelligence is a
 * PROTECTED provider — an ordinary KMDF driver CANNOT consume it; only a
 * PPL/ELAM-signed user-mode process may open a real-time session on it (the kernel
 * emits to it via EtwRegister). Horkos holds no anti-malware/ELAM cert today, so
 * there is NO in-kernel TI consumer and this bump has no caller yet. Notify.c is a
 * plausible home only if the consumption ends up being a kernel surface, which it
 * is not under current signing. The function is provided so the keepalive contract
 * is visible and a future PPL user-mode consumer can bump through an IOCTL into
 * this counter; until then EtwKeepaliveArmed stays 0 and the keepalive check is
 * UNVERIFIABLE-gated. Do NOT enable EtwKeepaliveArmed without a real consumer. */
void HkEtwTiKeepaliveBump(void)
{
    PHK_DEVICE_CONTEXT ctx = HkContext();
    if (ctx != NULL) {
        (void)InterlockedIncrement64(&ctx->EtwTiKeepalive);
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

/* The thread-create notify is now the Ex/NonSystem variant implemented in
 * ThreadProvenance.c (win-kernel-thread-injection). The non-Ex HkThreadNotify
 * stub that used to live here is removed; HkNotifyArm/Disarm delegate to
 * HkThreadProvenanceArm/Disarm below. */

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

    /* Thread-create provenance via the Ex/NonSystem notify (ThreadProvenance.c).
     * Like the process Ex notify it needs /INTEGRITYCHECK; a STATUS_ACCESS_DENIED
     * here on a fresh build usually means that flag was dropped from the link. */
    status = HkThreadProvenanceArm();
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
        /* Delegate to ThreadProvenance.c, which owns the Ex notify registration.
         * It records its own disarm-failure; fold that into g_DisarmFailed so the
         * unload path's bugcheck-on-failure discipline still covers it. */
        HkThreadProvenanceDisarm();
        if (HkThreadProvenanceDisarmFailed()) {
            g_DisarmFailed = TRUE;
        } else {
            g_ThreadArmed = FALSE;
            HkBumpArmed(-1);
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
