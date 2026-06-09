/*
 * kernel/win/src/IrpDispatch.c
 * Role: WDF IOCTL handler for the control device. Implements the three IOCTL
 *       codes from sdk/include/horkos/ioctl.h: drain the event ring, report
 *       status, and push a (Phase 3: minimal) policy.
 * Target platforms: Windows kernel mode (KMDF).
 * Interface: implements HkEvtIoDeviceControl declared in
 *       kernel/win/include/horkos_kernel.h.
 */

#include <ntddk.h>
#include <wdf.h>

#include "horkos_kernel.h"

static NTSTATUS HkHandleDrain(_In_ WDFREQUEST Request,
                              _In_ PHK_DEVICE_CONTEXT Ctx,
                              _In_ size_t OutputBufferLength,
                              _Out_ size_t* BytesReturned)
{
    NTSTATUS         status;
    PVOID            outBuf = NULL;
    hk_drain_header* hdr;
    hk_event_record* records;
    ULONG            capacity;
    ULONG            written;
    ULONG            remaining = 0;

    *BytesReturned = 0;

    if (OutputBufferLength < sizeof(hk_drain_header)) {
        *BytesReturned = sizeof(hk_drain_header); /* tell caller the minimum */
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(hk_drain_header),
                                            &outBuf, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    hdr = (hk_drain_header*)outBuf;
    records = (hk_event_record*)(hdr + 1);

    capacity = (ULONG)((OutputBufferLength - sizeof(hk_drain_header)) /
                       sizeof(hk_event_record));

    {
        LONG64 total = 0;
        LONG64 dropped = 0;

        /* Pass NULL when no record fits so we never hand HkRingDrain a
         * one-past-the-end Out pointer; it still reports Remaining + counters. */
        written = HkRingDrain(&Ctx->Ring, capacity > 0 ? records : NULL,
                              capacity, &remaining, &total, &dropped);

        RtlZeroMemory(hdr, sizeof(*hdr));
        hdr->records_written = written;
        hdr->records_remaining = remaining;
        /* Saturate the 64-bit drop counter into the 32-bit wire field so it
         * never wraps and disagrees with the 64-bit GET_STATUS value. */
        hdr->records_dropped = (dropped > 0xFFFFFFFFll) ? 0xFFFFFFFFu
                                                        : (uint32_t)dropped;
    }

    *BytesReturned = sizeof(hk_drain_header) +
                     (size_t)written * sizeof(hk_event_record);
    return STATUS_SUCCESS;
}

static NTSTATUS HkHandleStatus(_In_ WDFREQUEST Request,
                               _In_ PHK_DEVICE_CONTEXT Ctx,
                               _In_ size_t OutputBufferLength,
                               _Out_ size_t* BytesReturned)
{
    NTSTATUS   status;
    PVOID      outBuf = NULL;
    hk_status* st;

    *BytesReturned = 0;

    if (OutputBufferLength < sizeof(hk_status)) {
        *BytesReturned = sizeof(hk_status); /* tell caller the minimum */
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(hk_status),
                                            &outBuf, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    {
        LONG64 total = 0;
        LONG64 dropped = 0;

        HkRingReadCounters(&Ctx->Ring, &total, &dropped);

        st = (hk_status*)outBuf;
        RtlZeroMemory(st, sizeof(*st));
        st->driver_version = HK_DRIVER_VERSION;
        st->events_total = (uint64_t)total;
        st->events_dropped = (uint64_t)dropped;
        st->notify_routines_armed = (uint32_t)Ctx->NotifyRoutinesArmed;
        st->ob_callbacks_armed = (uint32_t)Ctx->ObCallbacksArmed;

        if (Ctx->ObCallbacksArmed) {
            st->flags |= HK_STATUS_FLAG_OB_ACTIVE;
        }
        if (dropped > 0) {
            st->flags |= HK_STATUS_FLAG_RING_OVERFLOW;
        }
    }
    if (Ctx->Policy.enable_byovd_block) {
        st->flags |= HK_STATUS_FLAG_BYOVD_ARMED;
    }

    /* Reflect the driver/module-integrity scan health through the existing flags
     * field (the plan's decision: do NOT grow hk_status; surface scan health via
     * status flags + the HK_INTEGRITY_OK heartbeat finding). These flag bits are
     * kernel-private mirrors until the Schema phase moves them to ioctl.h. */
    if (Ctx->IntegrityArmed) {
        st->flags |= HK_STATUS_FLAG_INTEGRITY_SCAN_ACTIVE;
    }
    if (Ctx->IntegrityScanFaulted) {
        st->flags |= HK_STATUS_FLAG_INTEGRITY_SCAN_FAULTED;
    }

    *BytesReturned = sizeof(hk_status);
    return STATUS_SUCCESS;
}

static NTSTATUS HkHandlePolicy(_In_ WDFREQUEST Request,
                               _In_ PHK_DEVICE_CONTEXT Ctx,
                               _In_ size_t InputBufferLength)
{
    NTSTATUS         status;
    PVOID            inBuf = NULL;
    const hk_policy* in;

    if (InputBufferLength < sizeof(hk_policy)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(hk_policy),
                                           &inBuf, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    in = (const hk_policy*)inBuf;
    /* Interlocked writes so the callback-side readers (Ob pre-callback, image
     * notify) see fully-ordered updates even on weakly-ordered targets; the
     * default queue is sequential so two PUSH_POLICY requests cannot interleave. */
    InterlockedExchange((volatile LONG*)&Ctx->Policy.enable_byovd_block,
                        in->enable_byovd_block ? 1 : 0);
    InterlockedExchange((volatile LONG*)&Ctx->Policy.enable_ob_strip,
                        in->enable_ob_strip ? 1 : 0);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
void HkEvtIoDeviceControl(WDFQUEUE Queue, WDFREQUEST Request,
                          size_t OutputBufferLength, size_t InputBufferLength,
                          ULONG IoControlCode)
{
    NTSTATUS           status;
    PHK_DEVICE_CONTEXT ctx;
    size_t             bytesReturned = 0;

    ctx = HkGetDeviceContext(WdfIoQueueGetDevice(Queue));
    if (ctx == NULL) {
        WdfRequestComplete(Request, STATUS_DEVICE_NOT_READY);
        return;
    }

    switch (IoControlCode) {
    case HK_IOCTL_DRAIN_EVENTS:
        status = HkHandleDrain(Request, ctx, OutputBufferLength, &bytesReturned);
        break;
    case HK_IOCTL_GET_STATUS:
        status = HkHandleStatus(Request, ctx, OutputBufferLength, &bytesReturned);
        break;
    case HK_IOCTL_PUSH_POLICY:
        status = HkHandlePolicy(Request, ctx, InputBufferLength);
        break;
    case HK_IOCTL_INTEGRITY_RESCAN:
        /* Empty input/output: queue a manual integrity rescan. Findings still
         * flow out through HK_IOCTL_DRAIN_EVENTS as HK_EVENT_INTEGRITY_FINDING
         * records (no new output envelope). Returns STATUS_DEVICE_NOT_READY if the
         * scan engine is not armed. HK-TODO(schema): HK_IOCTL_INTEGRITY_RESCAN is a
         * kernel-private mirror until the Schema phase adds it to ioctl.h. */
        status = HkIntegrityRequestRescan(ctx);
        break;
    case HK_IOCTL_SELF_READ_VA:
        /* memory-integrity-selfcheck self-read (signals 145/146/148/151/152): the AC
         * asks the kernel to foreign-read ITS OWN image. Refuses by default — the
         * caller-identity binding is UNCERTAIN and the reply plane is pre-Schema (see
         * selfcheck_read.c). HK-TODO(schema): HK_IOCTL_SELF_READ_VA is a kernel-private
         * mirror until the Schema phase adds it to ioctl.h. */
        status = HkHandleSelfRead(Request, ctx, InputBufferLength,
                                  OutputBufferLength, &bytesReturned);
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    WdfRequestCompleteWithInformation(Request, status, bytesReturned);
}
