/*
 * Role: Orchestrator for the memory-scan plane (signals 10-18). Owns a
 *       PASSIVE_LEVEL system worker thread, a non-blocking pending-target queue
 *       (pushed from the notify routines / HK_IOCTL_SCAN_PROCESS), and the
 *       large-record (344-byte) mem ring drained by HK_IOCTL_DRAIN_MEM_EVENTS.
 *       Per target the worker takes an EPROCESS reference, confirms the process
 *       is not exiting, attaches with KeStackAttachProcess (IRQL < DISPATCH; the
 *       attached window is kept minimal per the documented caution), runs the
 *       VAD-based scanners, detaches, then runs the file-mapping scanner
 *       (ModuleStomp) in its own context. Attach/detach + reference are strictly
 *       paired on every exit path (guardrail #5).
 *       READ-ONLY: samples target state; mutates nothing.
 * Target platforms: Windows kernel (KMDF). Builds only with the WDK.
 * Interface: implements HkMemScanArm/Disarm/EnqueueTarget, HkMemRingEmit,
 *       HkMemRingDrain, HkMemScanWorker (mem_scan.h).
 */

#include "mem_scan.h"

/* ---- mem ring: a self-contained SPSC-ish ring under a spinlock ----
 * Kept local to this TU (not in the device context) to avoid resizing the shared
 * context; IrpDispatch reaches it via HkMemRingDrain. */
typedef struct _HK_MEM_RING {
    KSPIN_LOCK         Lock;
    ULONG              Head;       /* next write (mod capacity). */
    ULONG              Tail;       /* next read. */
    ULONG              Count;
    ULONG              Dropped;
    hk_event_mem_record Slots[HK_MEM_RING_CAPACITY];
} HK_MEM_RING;

static HK_MEM_RING g_MemRing;

/* ---- pending-target queue ---- */
#define HK_MEM_PENDING_CAP 64u
typedef struct _HK_MEM_PENDING {
    KSPIN_LOCK         Lock;
    ULONG              Head, Tail, Count;
    HK_MEM_SCAN_TARGET Slots[HK_MEM_PENDING_CAP];
} HK_MEM_PENDING;

static HK_MEM_PENDING g_Pending;

/* ---- worker control ---- */
static PETHREAD          g_WorkerThread;
static KEVENT            g_WorkSignal;      /* set when a target is enqueued or on stop. */
static KEVENT            g_WorkerDone;      /* signalled by worker as its very last action. */
static volatile LONG     g_Stop;
static volatile BOOLEAN  g_Armed;

void HkMemRingEmit(uint32_t type, const void* payload, uint32_t payload_bytes)
{
    KIRQL irql;
    hk_event_mem_record rec;
    LARGE_INTEGER now;

    if (payload_bytes > HK_EVENT_MEM_PAYLOAD_MAX) {
        payload_bytes = HK_EVENT_MEM_PAYLOAD_MAX; /* never overflow the slot. */
    }
    RtlZeroMemory(&rec, sizeof(rec));
    rec.header.version = HK_EVENT_SCHEMA_VERSION;
    rec.header.type = type;
    KeQuerySystemTimePrecise(&now);
    rec.header.timestamp_ns = (uint64_t)now.QuadPart * 100ull; /* 100ns ticks -> ns. */
    rec.header.payload_bytes = payload_bytes;
    if (payload != NULL && payload_bytes > 0) {
        RtlCopyMemory(rec.payload, payload, payload_bytes);
    }

    KeAcquireSpinLock(&g_MemRing.Lock, &irql);
    if (g_MemRing.Count >= HK_MEM_RING_CAPACITY) {
        ++g_MemRing.Dropped; /* overflow: drop newest, keep the ring bounded. */
    } else {
        g_MemRing.Slots[g_MemRing.Head] = rec;
        g_MemRing.Head = (g_MemRing.Head + 1u) & (HK_MEM_RING_CAPACITY - 1u);
        ++g_MemRing.Count;
    }
    KeReleaseSpinLock(&g_MemRing.Lock, irql);
}

ULONG HkMemRingDrain(hk_event_mem_record* Out, ULONG MaxRecords,
                     ULONG* Remaining, ULONG* Dropped)
{
    KIRQL irql;
    ULONG written = 0;

    KeAcquireSpinLock(&g_MemRing.Lock, &irql);
    while (written < MaxRecords && g_MemRing.Count > 0) {
        if (Out != NULL) {
            Out[written] = g_MemRing.Slots[g_MemRing.Tail];
        }
        g_MemRing.Tail = (g_MemRing.Tail + 1u) & (HK_MEM_RING_CAPACITY - 1u);
        --g_MemRing.Count;
        ++written;
    }
    if (Remaining != NULL) {
        *Remaining = g_MemRing.Count;
    }
    if (Dropped != NULL) {
        *Dropped = g_MemRing.Dropped;
    }
    KeReleaseSpinLock(&g_MemRing.Lock, irql);
    return written;
}

NTSTATUS HkMemScanEnqueueTarget(HANDLE Pid, ULONG SignalMask)
{
    KIRQL irql;
    NTSTATUS status = STATUS_SUCCESS;

    if (!g_Armed) {
        return STATUS_DEVICE_NOT_READY;
    }
    KeAcquireSpinLock(&g_Pending.Lock, &irql);
    if (g_Pending.Count >= HK_MEM_PENDING_CAP) {
        status = STATUS_INSUFFICIENT_RESOURCES; /* drop: the worker is behind. */
    } else {
        HK_MEM_SCAN_TARGET* t = &g_Pending.Slots[g_Pending.Head];
        RtlZeroMemory(t, sizeof(*t));
        t->Pid = Pid;
        t->SignalMask = SignalMask;
        g_Pending.Head = (g_Pending.Head + 1u) % HK_MEM_PENDING_CAP;
        ++g_Pending.Count;
    }
    KeReleaseSpinLock(&g_Pending.Lock, irql);
    if (NT_SUCCESS(status)) {
        KeSetEvent(&g_WorkSignal, IO_NO_INCREMENT, FALSE);
    }
    return status;
}

static BOOLEAN HkPendingPop(HK_MEM_SCAN_TARGET* out)
{
    KIRQL irql;
    BOOLEAN got = FALSE;
    KeAcquireSpinLock(&g_Pending.Lock, &irql);
    if (g_Pending.Count > 0) {
        *out = g_Pending.Slots[g_Pending.Tail];
        g_Pending.Tail = (g_Pending.Tail + 1u) % HK_MEM_PENDING_CAP;
        --g_Pending.Count;
        got = TRUE;
    }
    KeReleaseSpinLock(&g_Pending.Lock, irql);
    return got;
}

/* Scan one target. Attach/detach + EPROCESS reference strictly paired on every
 * exit path. The VAD-based scanners run while attached; ModuleStomp runs after
 * detach (it maps on-disk files, which must not happen in the attached window). */
static void HkScanOneTarget(const HK_MEM_SCAN_TARGET* target)
{
    PEPROCESS proc = NULL;
    NTSTATUS status;
    PHK_MEM_SCAN_CTX ctx;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    status = PsLookupProcessByProcessId(target->Pid, &proc);
    if (!NT_SUCCESS(status) || proc == NULL) {
        return;
    }
    /* Skip processes that are exiting — VAD/loader teardown races (guardrail #13,
     * the plan's mandate). PsGetProcessExitProcessCalled is documented. */
    if (PsGetProcessExitProcessCalled(proc)) {
        ObDereferenceObject(proc);
        return;
    }

    ctx = (PHK_MEM_SCAN_CTX)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*ctx), 'cSmH');
    if (ctx == NULL) {
        ObDereferenceObject(proc);
        return;
    }
    RtlZeroMemory(ctx, sizeof(*ctx));
    ctx->Process = proc;
    ctx->Pid = target->Pid;
    ctx->Layout = HkVadLayoutForCurrentBuild(); /* NULL => scanners fail closed. */

    KeStackAttachProcess(proc, &ctx->ApcState);
    ctx->Attached = TRUE;
    __try {
        (void)HkVadEnumerate(ctx);   /* fills ctx->Nodes while attached. */
        HkMemScanVad(ctx);           /* 10/14/15 */
        HkLdrCrosscheck(ctx);        /* 13 (reads PEB Ldr while attached). */
        HkHollowDetect(ctx);         /* 16 */
        HkExecOrigin(ctx);           /* 17 */
        HkMemScanPte(ctx);           /* 11 */
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* A torn structure faulted past an inner guard — abandon this target's
         * scan; the detach below still runs. */
    }
    KeUnstackDetachProcess(&ctx->ApcState);
    ctx->Attached = FALSE;

    /* File-mapping scanner runs detached (KeStackAttachProcess caution). */
    HkModuleStomp(ctx);

    ExFreePoolWithTag(ctx, 'cSmH');
    ObDereferenceObject(proc);
}

static void HkMemScanWorker(PVOID context)
{
    UNREFERENCED_PARAMETER(context);
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    for (;;) {
        HK_MEM_SCAN_TARGET target;
        KeWaitForSingleObject(&g_WorkSignal, Executive, KernelMode, FALSE, NULL);
        if (InterlockedCompareExchange(&g_Stop, 0, 0) != 0) {
            break;
        }
        while (HkPendingPop(&target)) {
            if (InterlockedCompareExchange(&g_Stop, 0, 0) != 0) {
                break;
            }
            HkScanOneTarget(&target);
        }
    }
    KeSetEvent(&g_WorkerDone, IO_NO_INCREMENT, FALSE);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS HkMemScanArm(void)
{
    HANDLE h = NULL;
    NTSTATUS status;
    OBJECT_ATTRIBUTES oa;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (g_Armed) {
        return STATUS_SUCCESS;
    }
    RtlZeroMemory(&g_MemRing, sizeof(g_MemRing));
    KeInitializeSpinLock(&g_MemRing.Lock);
    RtlZeroMemory(&g_Pending, sizeof(g_Pending));
    KeInitializeSpinLock(&g_Pending.Lock);
    KeInitializeEvent(&g_WorkSignal, SynchronizationEvent, FALSE);
    KeInitializeEvent(&g_WorkerDone, NotificationEvent, FALSE);
    g_Stop = 0;

    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = PsCreateSystemThread(&h, THREAD_ALL_ACCESS, &oa, NULL, NULL,
                                  HkMemScanWorker, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = ObReferenceObjectByHandle(h, THREAD_ALL_ACCESS, *PsThreadType,
                                       KernelMode, (PVOID*)&g_WorkerThread, NULL);
    ZwClose(h);
    if (!NT_SUCCESS(status)) {
        /* Cannot obtain a thread reference to wait on at disarm time.  Drive the
         * worker to exit via the stop flag + wake event, then wait on g_WorkerDone
         * (the worker signals it as its last action before PsTerminateSystemThread).
         * Do NOT set g_Armed: callers must not enqueue targets into a partially-armed
         * state, and HkMemScanDisarm must still run to drain g_WorkerDone. */
        InterlockedExchange(&g_Stop, 1);
        KeSetEvent(&g_WorkSignal, IO_NO_INCREMENT, FALSE);
        KeWaitForSingleObject(&g_WorkerDone, Executive, KernelMode, FALSE, NULL);
        g_WorkerThread = NULL;
        return status;
    }
    g_Armed = TRUE;
    return STATUS_SUCCESS;
}

void HkMemScanDisarm(void)
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (!g_Armed) {
        return;
    }
    InterlockedExchange(&g_Stop, 1);
    KeSetEvent(&g_WorkSignal, IO_NO_INCREMENT, FALSE);
    if (g_WorkerThread != NULL) {
        KeWaitForSingleObject(g_WorkerThread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(g_WorkerThread);
        g_WorkerThread = NULL;
    } else {
        /* g_WorkerThread == NULL only if ObReferenceObjectByHandle failed in arm,
         * but g_Armed was never set in that path so we cannot reach here normally.
         * Belt-and-suspenders: wait on the done event in case a future code path
         * changes that invariant. */
        KeWaitForSingleObject(&g_WorkerDone, Executive, KernelMode, FALSE, NULL);
    }
    g_Armed = FALSE;
}
