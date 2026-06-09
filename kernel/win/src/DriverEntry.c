/*
 * kernel/win/src/DriverEntry.c
 * Role: KMDF driver entry point and teardown. Creates the control device used
 *       for the userspace IOCTL bridge, initializes the event ring, and arms
 *       the Ps* notify routines and the Ob handle-filter callback.
 * Target platforms: Windows kernel mode (KMDF, non-PnP control driver).
 * Interface: implements DriverEntry; declares no public interface. Internal
 *       routines are declared in kernel/win/include/horkos_kernel.h.
 */

#include <ntddk.h>
#include <wdf.h>
#include <wdmsec.h>   /* SDDL_DEVOBJ_* and WdfControlDeviceInitAllocate SDDL. */

#include "horkos_kernel.h"

/* Single global control-device handle (declared extern in horkos_kernel.h). */
WDFDEVICE g_HkControlDevice = NULL;

/* WDM driver object, captured at DriverEntry for CmRegisterCallbackEx (declared
 * extern in horkos_kernel.h). */
PDRIVER_OBJECT g_HkDriverObject = NULL;

PHK_DEVICE_CONTEXT HkContext(void)
{
    WDFDEVICE dev = g_HkControlDevice;
    if (dev == NULL) {
        return NULL;
    }
    return HkGetDeviceContext(dev);
}

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD HkEvtDriverUnload;

/* Forward declaration so _Use_decl_annotations_ on the definition has a prior
 * declaration to inherit the SAL contract from (without it the inline _In_ is
 * silently dropped and PREfast skips the WDFDRIVER null check). */
static NTSTATUS HkCreateControlDevice(_In_ WDFDRIVER Driver);

_Use_decl_annotations_
static NTSTATUS HkCreateControlDevice(_In_ WDFDRIVER Driver)
{
    NTSTATUS              status;
    PWDFDEVICE_INIT       deviceInit = NULL;
    WDFDEVICE             controlDevice = NULL;
    WDF_OBJECT_ATTRIBUTES deviceAttr;
    WDF_IO_QUEUE_CONFIG   queueConfig;
    WDFQUEUE              queue;
    PHK_DEVICE_CONTEXT    ctx;

    DECLARE_CONST_UNICODE_STRING(deviceName, HK_DEVICE_NAME_KERNEL);
    DECLARE_CONST_UNICODE_STRING(symlinkName, HK_DEVICE_SYMLINK);

    /* SYSTEM + Administrators full access; nothing for anyone else. */
    deviceInit = WdfControlDeviceInitAllocate(Driver, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
    if (deviceInit == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = WdfDeviceInitAssignName(deviceInit, &deviceName);
    if (!NT_SUCCESS(status)) {
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    WdfDeviceInitSetDeviceType(deviceInit, FILE_DEVICE_UNKNOWN);
    WdfDeviceInitSetIoType(deviceInit, WdfDeviceIoBuffered);
    WdfDeviceInitSetExclusive(deviceInit, FALSE);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttr, HK_DEVICE_CONTEXT);

    status = WdfDeviceCreate(&deviceInit, &deviceAttr, &controlDevice);
    if (!NT_SUCCESS(status)) {
        /* For a WdfControlDeviceInitAllocate'd init, WdfDeviceCreate does NOT
         * free deviceInit on failure (it NULLs *deviceInit only on success), so
         * the driver must free it here. Matches the WDK nonpnp sample. */
        if (deviceInit != NULL) {
            WdfDeviceInitFree(deviceInit);
        }
        return status;
    }

    ctx = HkGetDeviceContext(controlDevice);
    RtlZeroMemory(ctx, sizeof(*ctx));
    HkRingInit(&ctx->Ring);
    /* Policy defaults to all-off (detect/observe only). */
    ctx->Policy.enable_byovd_block = 0;
    ctx->Policy.enable_ob_strip = 0;

    status = WdfDeviceCreateSymbolicLink(controlDevice, &symlinkName);
    if (!NT_SUCCESS(status)) {
        WdfObjectDelete(controlDevice);
        return status;
    }

    /* Sequential dispatch serializes IOCTLs (notably PUSH_POLICY); throughput
     * is not a requirement on this control channel. */
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = HkEvtIoDeviceControl;
    /* No create/close handlers needed; framework completes them with success. */

    status = WdfIoQueueCreate(controlDevice, &queueConfig,
                              WDF_NO_OBJECT_ATTRIBUTES, &queue);
    if (!NT_SUCCESS(status)) {
        WdfObjectDelete(controlDevice);
        return status;
    }

    /* Publish the device to the global before arming producers, since the
     * notify callbacks reach the ring through HkContext(). */
    g_HkControlDevice = controlDevice;

    WdfControlFinishInitializing(controlDevice);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS           status;
    WDF_DRIVER_CONFIG  config;
    WDFDRIVER          driver;
    PHK_DEVICE_CONTEXT ctx;

    /* Capture the WDM driver object for CmRegisterCallbackEx (Driver param is a
     * PDRIVER_OBJECT, not a WDFDEVICE). Set before any callback is armed. */
    g_HkDriverObject = DriverObject;

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = HkEvtDriverUnload;

    status = WdfDriverCreate(DriverObject, RegistryPath,
                             WDF_NO_OBJECT_ATTRIBUTES, &config, &driver);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = HkCreateControlDevice(driver);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ctx = HkContext();
    if (ctx == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    /* Arm process/thread/image notify routines. Failure here is fatal: tear
     * down so we do not run half-blind. HkNotifyArm self-disarms on partial
     * failure. KMDF does NOT call EvtDriverUnload when DriverEntry fails, so
     * clear the global ourselves to keep the "set iff operational" invariant;
     * the framework deletes the WDFDEVICE as a child of the failing WDFDRIVER. */
    status = HkNotifyArm();
    if (!NT_SUCCESS(status)) {
        g_HkControlDevice = NULL;
        return status;
    }

    /* Arm the Ob handle-filter callback. Non-fatal: the driver still provides
     * notify-routine visibility without it (status flag reflects the gap). */
    status = HkObArm(ctx);
    if (!NT_SUCCESS(status)) {
        /* Leave ObCallbacksArmed at 0; continue in reduced mode. */
        status = STATUS_SUCCESS;
    }

    /* Arm the registry-tamper filter on Horkos's own keys (signals 5, 9).
     * Non-fatal: an altitude collision or denied registration degrades the
     * registry sensor but the rest of the driver runs. */
    status = HkCmArm(ctx);
    if (!NT_SUCCESS(status)) {
        status = STATUS_SUCCESS;
    }

    /* Arm the self-integrity self-check timer (signals 1,3,4,7,8 + Cm census).
     * Non-fatal: without it the callbacks still run, we just lose the self-poll.
     * Arm LAST so the baselines it captures reflect the final armed state. */
    status = HkSelfCheckArm(ctx);
    if (!NT_SUCCESS(status)) {
        status = STATUS_SUCCESS;
    }

    /* Init the driver/module-integrity scan engine (signals 28-36). Non-fatal:
     * without it the rest of the driver runs, we just lose the periodic integrity
     * sweep. Init captures the signal-30 CodeIntegrity baseline at DriverEntry
     * (PASSIVE), so it must run after the device/context are live. */
    status = HkIntegrityScanInit(ctx);
    if (!NT_SUCCESS(status)) {
        status = STATUS_SUCCESS;
    }

    return STATUS_SUCCESS;
}

/* Bugcheck code used when we cannot guarantee a clean unload. A controlled
 * crash is strictly safer than letting the image unload with a live kernel
 * callback pointer into freed pages. */
#define HK_BUGCHECK_DISARM_FAILED 0xE2  /* MANUALLY_INITIATED_CRASH. */

_Use_decl_annotations_
void HkEvtDriverUnload(_In_ WDFDRIVER Driver)
{
    PHK_DEVICE_CONTEXT ctx = HkContext();
    WDFDEVICE          dev = g_HkControlDevice;

    UNREFERENCED_PARAMETER(Driver);

    /* Stop the periodic engines FIRST: cancel timers, flush DPCs, free work
     * items, so no worker can touch Ob/Cm/ring/module-map state after we start
     * tearing those down. Both Disarm/Stop wait for an in-flight worker to finish
     * before returning. */
    if (ctx != NULL) {
        HkIntegrityScanStop(ctx);
        HkSelfCheckDisarm(ctx);
    }

    /* Disarm in reverse order of arming, BEFORE deleting the control device,
     * so no callback can touch a freed ring. */
    HkNotifyDisarm();

    /* If a Ps* callback could not be removed, the kernel still holds a live
     * pointer into our image. Unloading now would jump into freed pages on the
     * next event. Bugcheck deliberately rather than proceed. */
    if (HkNotifyDisarmFailed()) {
        KeBugCheckEx(HK_BUGCHECK_DISARM_FAILED, 0, 0, 0, 0);
    }

    if (ctx != NULL) {
        HkObDisarm(ctx);
        HkCmDisarm(ctx);
    }

    /* Control devices are NOT auto-deleted by the framework; delete explicitly
     * or the \Device\Horkos name leaks and a reload hits STATUS_OBJECT_NAME_
     * COLLISION. */
    g_HkControlDevice = NULL;
    if (dev != NULL) {
        WdfObjectDelete(dev);
    }
}
