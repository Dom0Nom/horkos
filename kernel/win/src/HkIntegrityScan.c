/*
 * kernel/win/src/HkIntegrityScan.c
 * Role: Integrity-scan orchestrator + work-item scheduling for the driver/module
 *       trust sensors (win-kernel-driver-integrity, signals 28-36). Owns the
 *       single periodic PASSIVE_LEVEL work item: a KTIMER fires a DISPATCH_LEVEL
 *       DPC that does nothing but queue the work item; the work item builds the
 *       shared ModuleMap ONCE, fans out to each enabled sensor, then frees the
 *       map. Read-only throughout — sensors sample and emit
 *       HK_EVENT_INTEGRITY_FINDING; the server scores and bans. Also provides
 *       HkIntegrityEmit, the helper every sensor uses to push one finding.
 * Target platforms: Windows kernel mode (KMDF).
 * Interface: implements HkIntegrityScanInit / HkIntegrityScanStop /
 *       HkIntegrityScanAll / HkIntegrityRequestRescan / HkIntegrityEmit declared
 *       in kernel/win/include/horkos_kernel.h. Emits hk_event_integrity_finding
 *       (HK-TODO(schema): kernel-private mirror until the Schema phase appends
 *       HK_EVENT_INTEGRITY_FINDING to event_schema.h — see horkos_kernel.h).
 */

#include <ntddk.h>
#include <wdf.h>

#include "horkos_kernel.h"

/* Scan period in milliseconds. The integrity scan is heavier than the callback
 * self-check (it builds a module map and hashes/walks tables), so it runs less
 * often. Overridable at build time. */
#ifndef HK_INTEGRITY_TIMER_MS
#  define HK_INTEGRITY_TIMER_MS 30000
#endif

void HkIntegrityEmit(_In_ uint32_t signal_id, _In_ uint32_t finding,
                     _In_ uint64_t detail_masked)
{
    hk_event_integrity_finding ev;

    RtlZeroMemory(&ev, sizeof(ev));
    ev.signal_id = signal_id;
    ev.finding = finding;
    /* detail_masked is the caller's responsibility to mask (image-relative or
     * base-subtracted). We do NOT mask here because only the sensor knows the
     * correct base to subtract; the plan's KASLR-leak gate (Risk 7) lives at the
     * call sites, asserted in review. */
    ev.detail = detail_masked;
    HkRingEmit(HK_EVENT_INTEGRITY_FINDING, &ev, sizeof(ev));
}

static PDEVICE_OBJECT HkIntegrityWdmDevice(void)
{
    WDFDEVICE dev = g_HkControlDevice;
    if (dev == NULL) {
        return NULL;
    }
    return WdfDeviceWdmGetDeviceObject(dev);
}

_Use_decl_annotations_
void HkIntegrityScanAll(PHK_DEVICE_CONTEXT Ctx)
{
    HK_MODULE_MAP* map;
    NTSTATUS       status;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    if (Ctx == NULL || Ctx->IntegrityArmed == 0) {
        return;
    }

    /* The ModuleMap is large (HK_MODULEMAP_MAX * 24 bytes ~= 24KB) — too big for
     * the stack. Allocate it from paged pool for the duration of the scan. */
    map = (HK_MODULE_MAP*)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*map), HK_POOL_TAG);
    if (map == NULL) {
        InterlockedExchange(&Ctx->IntegrityScanFaulted, 1);
        return;
    }

    status = HkModuleMapBuild(map);
    if (!NT_SUCCESS(status)) {
        /* Map build failed — the address-resolving sensors (29/31/32/34/35) would
         * have no map. Mark faulted, but still run the sensors that do NOT need
         * the map (30/33/36) so a transient module-query failure does not blind
         * the low-FP probes. guardrail #5: checked, degrade cleanly. */
        InterlockedExchange(&Ctx->IntegrityScanFaulted, 1);
        HkCodeIntegrityRescan(Ctx);   /* 30 */
        HkDebugStateProbe(Ctx);       /* 33 */
        HkBootLoadAudit(Ctx);         /* 36 */
        HkMinifilterAudit(Ctx);       /* 28 (does not consume the map) */
        ExFreePoolWithTag(map, HK_POOL_TAG);
        return;
    }

    /* Map-consuming sensors first (they share the one build). */
    HkImageHashAudit(Ctx, map);       /* 29 */
    HkCallbackResidencyScan(Ctx, map);/* 31 */
    HkNonImageScan(Ctx, map);         /* 32 */
    HkDriverObjectAudit(Ctx, map);    /* 34 */
    HkSsdtIntegrityScan(Ctx, map);    /* 35 */

    /* Syscall/ETW surface-integrity sensors (208..216). They bounds-check against
     * the ntoskrnl/hal image cache, derived from the same ModuleMap build. The
     * cache is small (a few ranges) so it lives on the stack. If it cannot be
     * built (ntoskrnl unresolved), the address-checking sensors get Img->Valid
     * FALSE and emit nothing/UNVERIFIABLE; the non-map ETW sensors still run. */
    {
        HK_KERNEL_IMAGE img;
        (void)HkKernelImageMapBuild(map, &img);

        HkSsdtValidate(Ctx, &img);        /* 208 */
        HkSsdtBaselineCheck(Ctx, &img);   /* 216 */
        HkLstarValidate(Ctx, &img);       /* 210 */
        HkIdtValidate(Ctx, &img);         /* 214 */
        HkSyscallPrologueScan(Ctx, &img); /* 213 */
        HkShadowSsdtValidate(Ctx, &img);  /* 209 (default-OFF) */
        HkInfinityHookProbe(Ctx, &img);   /* 211 (default-OFF) */

        HkKernelImageMapFree(&img);
    }

    /* Non-map sensors. */
    HkMinifilterAudit(Ctx);           /* 28 */
    HkCodeIntegrityRescan(Ctx);       /* 30 */
    HkDebugStateProbe(Ctx);           /* 33 */
    HkBootLoadAudit(Ctx);             /* 36 */
    HkEtwTiLiveness(Ctx);             /* 212 */
    HkEtwSessionCensus(Ctx);          /* 215 (default-OFF) */

    HkModuleMapFree(map);
    ExFreePoolWithTag(map, HK_POOL_TAG);

    /* Heartbeat: a completed scan emits an OK finding so userspace/server can
     * confirm the engine ran without growing hk_status (plan §IOCTL decision). */
    HkIntegrityEmit(0u, HK_INTEGRITY_OK, 0ull);
}

/* Guards against double-queueing the single shared IO_WORKITEM from both the
 * timer DPC and HkIntegrityRequestRescan.  A double-queue of one IO_WORKITEM
 * is undefined behavior per WDK documentation.  Both call sites CAS 0->1
 * before calling IoQueueWorkItem; the worker resets to 0 on exit so the next
 * fire or rescan can re-arm. */
static volatile LONG g_ScanQueued;

_Function_class_(IO_WORKITEM_ROUTINE)
static VOID HkIntegrityWorker(_In_ PDEVICE_OBJECT DeviceObject, _In_opt_ PVOID Context)
{
    PHK_DEVICE_CONTEXT ctx = (PHK_DEVICE_CONTEXT)Context;

    UNREFERENCED_PARAMETER(DeviceObject);
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    if (ctx == NULL || ctx->IntegrityArmed == 0) {
        InterlockedExchange(&g_ScanQueued, 0);
        return;
    }
    HkIntegrityScanAll(ctx);
    InterlockedExchange(&g_ScanQueued, 0);
}

_Function_class_(KDEFERRED_ROUTINE)
static VOID HkIntegrityDpc(_In_ struct _KDPC* Dpc,
                           _In_opt_ PVOID DeferredContext,
                           _In_opt_ PVOID SystemArgument1,
                           _In_opt_ PVOID SystemArgument2)
{
    PHK_DEVICE_CONTEXT ctx = (PHK_DEVICE_CONTEXT)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (ctx == NULL || ctx->IntegrityArmed == 0 || ctx->IntegrityWorkItem == NULL) {
        return;
    }
    /* DISPATCH_LEVEL: queue only, never walk lists here.  The CAS ensures the
     * shared work item is not queued while already in flight (double-queue is
     * undefined behavior per WDK). */
    if (InterlockedCompareExchange(&g_ScanQueued, 1, 0) == 0) {
        IoQueueWorkItem(ctx->IntegrityWorkItem, HkIntegrityWorker, DelayedWorkQueue, ctx);
    }
}

_Use_decl_annotations_
NTSTATUS HkIntegrityScanInit(PHK_DEVICE_CONTEXT Ctx)
{
    PDEVICE_OBJECT wdmDevice;
    LARGE_INTEGER  dueTime;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    if (Ctx == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    InterlockedExchange(&Ctx->IntegrityScanFaulted, 0);
    InterlockedExchange(&Ctx->CiBaselineValid, 0);
    Ctx->CiBaselineOptions = 0;

    /* Capture the signal-30 CodeIntegrity baseline at init (PASSIVE) so the
     * rescan can emit only on a post-boot flip. */
    HkCodeIntegrityBaseline(Ctx);

    /* Capture the syscall/ETW surface baselines at init (PASSIVE): the SSDT
     * descriptor base/limit (208/216) and the ETW provider census (215). Done
     * before any sensor runs so a post-arm tamper is caught against a clean
     * snapshot. The unexported-global halves it cannot resolve leave Valid==FALSE
     * and the matching sensors fall back to UNVERIFIABLE. */
    HkSyscallEtwArm(Ctx);

    wdmDevice = HkIntegrityWdmDevice();
    if (wdmDevice == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    Ctx->IntegrityWorkItem = IoAllocateWorkItem(wdmDevice);
    if (Ctx->IntegrityWorkItem == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeDpc(&Ctx->IntegrityDpc, HkIntegrityDpc, Ctx);
    KeInitializeTimerEx(&Ctx->IntegrityTimer, NotificationTimer);

    InterlockedExchange(&Ctx->IntegrityArmed, 1);

    dueTime.QuadPart = -((LONGLONG)HK_INTEGRITY_TIMER_MS * 10000LL);
    KeSetTimerEx(&Ctx->IntegrityTimer, dueTime, HK_INTEGRITY_TIMER_MS,
                 &Ctx->IntegrityDpc);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
void HkIntegrityScanStop(PHK_DEVICE_CONTEXT Ctx)
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    if (Ctx == NULL) {
        return;
    }

    /* Clear armed first so an in-flight DPC/worker early-returns. */
    InterlockedExchange(&Ctx->IntegrityArmed, 0);
    (void)KeCancelTimer(&Ctx->IntegrityTimer);
    /* HK-UNCERTAIN(dpc-flush-ordering): same belt-and-suspenders pattern as
     * CallbackSelfCheck.c — KeFlushQueuedDpcs waits for ALL DPCs system-wide, not
     * just ours; the narrow correctness comes from KeCancelTimer +
     * IntegrityArmed early-return. Confirm on-box that no work item is queued
     * after this point before freeing the work item. */
    KeFlushQueuedDpcs();

    if (Ctx->IntegrityWorkItem != NULL) {
        /* IoFreeWorkItem waits for an in-flight routine to finish (documented). */
        IoFreeWorkItem(Ctx->IntegrityWorkItem);
        Ctx->IntegrityWorkItem = NULL;
    }
}

_Use_decl_annotations_
NTSTATUS HkIntegrityRequestRescan(PHK_DEVICE_CONTEXT Ctx)
{
    if (Ctx == NULL || Ctx->IntegrityArmed == 0 || Ctx->IntegrityWorkItem == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }
    /* Queue the same worker the timer DPC uses.  The CAS prevents double-queueing
     * the shared work item when the periodic fire and an IOCTL rescan race. */
    if (InterlockedCompareExchange(&g_ScanQueued, 1, 0) != 0) {
        return STATUS_SUCCESS; /* scan already queued or in flight — no-op. */
    }
    IoQueueWorkItem(Ctx->IntegrityWorkItem, HkIntegrityWorker, DelayedWorkQueue, Ctx);
    return STATUS_SUCCESS;
}
