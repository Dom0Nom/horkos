/*
 * kernel/win/include/mem_scan.h
 * Role: Kernel-private interface for the memory-scan plane (win-kernel-memory-
 *       injection, signals 10-18). Read-only sampling of a target process's
 *       address space (VAD tree, PEB loader lists, on-disk image backing) from a
 *       PASSIVE_LEVEL system worker thread that attaches per-target with
 *       KeStackAttachProcess. Declares the worker lifetime, the shared read-only
 *       VAD walk, the per-signal scanners, and the large-record emit path. NOT
 *       userspace-visible (guardrail #4: kernel/userspace never share a TU); the
 *       structural decision logic is in the host-tested pure cores
 *       (kernel/win/include/mem_logic_*.h), which this plane feeds.
 * Target platforms: Windows kernel (KMDF).
 * Interface: implemented by VadWalk.c / MemScanWorker.c / MemScan*.c; the worker
 *       is enqueued from HK_IOCTL_SCAN_PROCESS (IrpDispatch.c) and from the
 *       process/thread/image notify routines.
 */

#pragma once

#include <ntddk.h>

#include "horkos/event_schema.h"
#include "mem_types.h"     /* HK_VAD_NODE (host-safe normalized leaf). */
#include "vad_layout.h"    /* per-build offsets, fail-closed allow-list. */

/* Bounded per-scan buffers. A scan tick walks at most this many VAD leaves so a
 * 10k-VAD process cannot monopolise the worker (the plan's budget mandate). */
#define HK_MEM_MAX_VAD_NODES   2048u
#define HK_MEM_MAX_LDR_BASES    1024u

/* One target enqueued for the worker. Keyed by PID + create-time to survive PID
 * reuse between enqueue and attach. */
typedef struct _HK_MEM_SCAN_TARGET {
    HANDLE   Pid;
    LARGE_INTEGER CreateTime; /* PsGetProcessCreateTimeQuadPart at enqueue. */
    ULONG    SignalMask;      /* bit per signal 10..18; 0 = all. */
} HK_MEM_SCAN_TARGET, *PHK_MEM_SCAN_TARGET;

/* Shared scan state for one attached target. Lives on the worker stack / a
 * per-scan pool allocation; never on the wire. */
typedef struct _HK_MEM_SCAN_CTX {
    PEPROCESS              Process;     /* referenced EPROCESS, held across attach. */
    HANDLE                 Pid;
    const HK_VAD_LAYOUT*   Layout;      /* NULL => fail closed, emit nothing. */
    KAPC_STATE             ApcState;    /* for KeStackAttachProcess pairing. */
    BOOLEAN                Attached;
    ULONG                  NodeCount;
    HK_VAD_NODE            Nodes[HK_MEM_MAX_VAD_NODES];
    ULONG                  LdrBaseCount;
    ULONG64                LdrBases[HK_MEM_MAX_LDR_BASES];
} HK_MEM_SCAN_CTX, *PHK_MEM_SCAN_CTX;

/* ---- worker lifetime (MemScanWorker.c) ---- */
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS HkMemScanArm(void);
_IRQL_requires_max_(PASSIVE_LEVEL) void     HkMemScanDisarm(void);
/* Non-blocking: pushes a target PID onto the pending ring; the worker attaches.
 * Safe to call from the notify routines (<= DISPATCH_LEVEL via a lookaside push). */
_IRQL_requires_max_(DISPATCH_LEVEL) NTSTATUS HkMemScanEnqueueTarget(_In_ HANDLE Pid,
                                                                    _In_ ULONG SignalMask);

/* ---- large-record emit (MemScanWorker.c) ---- */
/* Stamp + push one hk_event_mem_record onto the mem ring. PASSIVE/ DISPATCH-safe
 * (brief spinlock), mirroring HkRingEmit but for the 344-byte record. `type` is
 * the hk_event_type discriminant (HK_EVENT_MEM_*); `payload` is the matching
 * hk_event_mem_* struct; payload_bytes <= HK_EVENT_MEM_PAYLOAD_MAX. */
void HkMemRingEmit(_In_ uint32_t type,
                   _In_reads_bytes_(payload_bytes) const void* payload,
                   _In_ uint32_t payload_bytes);

/* Drain up to MaxRecords from the mem ring into Out; reports how many remain.
 * Called by HK_IOCTL_DRAIN_MEM_EVENTS (IrpDispatch.c). Brief spinlock. */
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG HkMemRingDrain(_Out_writes_to_opt_(MaxRecords, return) hk_event_mem_record* Out,
                     _In_ ULONG MaxRecords,
                     _Out_ ULONG* Remaining,
                     _Out_ ULONG* Dropped);

/* ---- shared read-only VAD walk (VadWalk.c) ----
 * Walks Process->VadRoot (the RTL_AVL_TREE at Layout->Eprocess_VadRoot) while the
 * worker is ATTACHED to the target, normalising each leaf into ctx->Nodes[]. All
 * reads are SEH-guarded; a torn node degrades to "skip", never a bugcheck.
 * Returns the node count (also stored in ctx->NodeCount). Requires ctx->Layout
 * non-NULL and ctx->Attached; otherwise returns 0 (fail closed). */
_IRQL_requires_max_(APC_LEVEL) ULONG HkVadEnumerate(_Inout_ PHK_MEM_SCAN_CTX Ctx);

/* Collect the DllBase of every loaded module from the three PEB.Ldr lists into
 * Ctx->LdrBases (deduplicated, bounded). Runs while ATTACHED; SEH-guarded; uses
 * the fail-closed layout offsets. Returns the base count. Shared by signals
 * 13/16/17. */
_IRQL_requires_max_(APC_LEVEL) ULONG HkCollectLdrBases(_Inout_ PHK_MEM_SCAN_CTX Ctx);

/* ---- per-signal scanners (each emits raw evidence; server classifies) ---- */
_IRQL_requires_max_(APC_LEVEL) void HkMemScanVad(_Inout_ PHK_MEM_SCAN_CTX Ctx);   /* 10/14/15 */
_IRQL_requires_max_(APC_LEVEL) void HkLdrCrosscheck(_Inout_ PHK_MEM_SCAN_CTX Ctx);/* 13 */
_IRQL_requires_max_(APC_LEVEL) void HkHollowDetect(_Inout_ PHK_MEM_SCAN_CTX Ctx); /* 16 */
_IRQL_requires_max_(APC_LEVEL) void HkExecOrigin(_Inout_ PHK_MEM_SCAN_CTX Ctx);   /* 17 */
/* ModuleStomp + Pte read on-disk files / physical pages: they capture target
 * bytes while attached, then do the file map + hash/PTE work AFTER detach (the
 * KeStackAttachProcess docs require the attached window stay minimal). */
_IRQL_requires_max_(PASSIVE_LEVEL) void HkModuleStomp(_Inout_ PHK_MEM_SCAN_CTX Ctx);/* 12 (+ stages 18) */
_IRQL_requires_max_(APC_LEVEL) void HkMemScanPte(_Inout_ PHK_MEM_SCAN_CTX Ctx);   /* 11 */
