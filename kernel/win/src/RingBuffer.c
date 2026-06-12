/*
 * Role: Single-producer / single-consumer event ring for the Horkos driver.
 *       Producers are the Ps* notify callbacks and the Ob pre-callback;
 *       the consumer is the HK_IOCTL_DRAIN_EVENTS handler. Access is serialized
 *       by a KSPIN_LOCK. Also provides HkRingEmit, the helper producers call to
 *       stamp and enqueue a record.
 * Target platforms: Windows kernel mode (KMDF).
 * Interface: implements the RingBuffer.c routines declared in
 *       kernel/win/include/horkos_kernel.h.
 */

#include <ntddk.h>
#include <wdf.h>

#include "horkos_kernel.h"

#define HK_RING_MASK (HK_RING_CAPACITY - 1u)

void HkRingInit(_Out_ PHK_RING Ring)
{
    RtlZeroMemory(Ring, sizeof(*Ring));
    KeInitializeSpinLock(&Ring->Lock);
    Ring->Head = 0;
    Ring->Tail = 0;
    Ring->Total = 0;
    Ring->Dropped = 0;
}

_Use_decl_annotations_
BOOLEAN HkRingPush(PHK_RING Ring, const hk_event_record* Record)
{
    KIRQL   oldIrql;
    ULONG   next;
    BOOLEAN accepted;

    KeAcquireSpinLock(&Ring->Lock, &oldIrql);

    next = (Ring->Head + 1u) & HK_RING_MASK;
    if (next == Ring->Tail) {
        /* Full: drop the newest. Counter is updated under the lock. */
        Ring->Dropped++;
        accepted = FALSE;
    } else {
        Ring->Slots[Ring->Head] = *Record;
        Ring->Head = next;
        Ring->Total++;
        accepted = TRUE;
    }

    KeReleaseSpinLock(&Ring->Lock, oldIrql);
    return accepted;
}

_Use_decl_annotations_
ULONG HkRingDrain(PHK_RING Ring, hk_event_record* Out, ULONG MaxRecords,
                  ULONG* Remaining, LONG64* TotalOut, LONG64* DroppedOut)
{
    KIRQL oldIrql;
    ULONG count = 0;

    KeAcquireSpinLock(&Ring->Lock, &oldIrql);

    while (count < MaxRecords && Out != NULL && Ring->Tail != Ring->Head) {
        Out[count] = Ring->Slots[Ring->Tail];
        Ring->Tail = (Ring->Tail + 1u) & HK_RING_MASK;
        count++;
    }

    /* Records still queued after this drain. */
    if (Ring->Head >= Ring->Tail) {
        *Remaining = Ring->Head - Ring->Tail;
    } else {
        *Remaining = HK_RING_CAPACITY - (Ring->Tail - Ring->Head);
    }

    /* Snapshot the counters under the same lock so the drain header is coherent
     * with what we just consumed (no producer can slip between drain and read). */
    *TotalOut = Ring->Total;
    *DroppedOut = Ring->Dropped;

    KeReleaseSpinLock(&Ring->Lock, oldIrql);
    return count;
}

_Use_decl_annotations_
void HkRingReadCounters(PHK_RING Ring, LONG64* TotalOut, LONG64* DroppedOut)
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&Ring->Lock, &oldIrql);
    *TotalOut = Ring->Total;
    *DroppedOut = Ring->Dropped;
    KeReleaseSpinLock(&Ring->Lock, oldIrql);
}

void HkRingEmit(_In_ uint32_t type,
                _In_reads_bytes_opt_(payload_bytes) const void* payload,
                _In_ uint32_t payload_bytes)
{
    PHK_DEVICE_CONTEXT ctx;
    hk_event_record    rec;
    ULONG64            now100ns;

    ctx = HkContext();
    if (ctx == NULL) {
        return;
    }

    if (payload_bytes > HK_EVENT_PAYLOAD_MAX) {
        payload_bytes = HK_EVENT_PAYLOAD_MAX;
    }

    RtlZeroMemory(&rec, sizeof(rec));

    /* InterruptTime is monotonic and runs at all IRQLs; 100ns units -> ns. */
    now100ns = KeQueryInterruptTime();

    rec.header.version = HK_EVENT_SCHEMA_VERSION;
    rec.header.type = type;
    rec.header.timestamp_ns = (uint64_t)now100ns * 100ull;
    rec.header.payload_bytes = payload_bytes;
    rec.header.reserved = 0;

    if (payload != NULL && payload_bytes > 0) {
        RtlCopyMemory(rec.payload, payload, payload_bytes);
    }

    (void)HkRingPush(&ctx->Ring, &rec);
}
