/*
 * kernel/win/include/horkos_kernel.h
 * Role: Internal kernel-mode header for the Horkos KMDF driver. Declares the
 *       device context, the SPSC event ring buffer, and every internal
 *       routine across DriverEntry / IrpDispatch / Notify / RingBuffer /
 *       Callbacks / Whitelist. NOT exposed to userspace.
 * Target platforms: Windows kernel mode (KMDF).
 * Interface: kernel-private. The userspace-facing wire contract is
 *       sdk/include/horkos/ioctl.h, which this header includes for the
 *       shared record/status/policy structs (guardrail #4: kernel and
 *       userspace never share a TU, but they MAY share this pure-C99 wire
 *       header because it pulls in no platform headers).
 */

#pragma once

#include <ntddk.h>
#include <wdf.h>

#include "horkos/ioctl.h"

/* Pool tag for all Horkos kernel allocations: 'hkOS' shown reversed in tools. */
#define HK_POOL_TAG 'SOkh'

/* ObRegisterCallbacks altitude. Must be a unique, registered-range string.
 * 360000-389999 is the FSFilter "Activity Monitor" load-order group range used
 * by HIPS/AV-class minifilters; an anti-cheat handle-filter sits here. A
 * production build uses an Allocated Altitude from Microsoft (see
 * docs/windows-signing.md). */
#define HK_OB_ALTITUDE L"385201"

/* -------------------------------------------------------------------------
 * Event ring buffer — multi-producer / single-consumer, serialized by Lock.
 * Producers: the three Ps* notify callbacks and the Ob pre-callback, which
 * write Head concurrently — correctness comes ENTIRELY from Lock, so do not
 * "optimize away" the lock on the strength of a single-producer assumption.
 * Consumer:  the HK_IOCTL_DRAIN_EVENTS handler. All access (Head, Tail, Total,
 * Dropped) is under Lock; the brief critical section runs at DISPATCH_LEVEL.
 * Capacity is a power of two so the modulo is a mask.
 * ------------------------------------------------------------------------- */
#define HK_RING_CAPACITY 4096u  /* Must be a power of two. */

typedef struct _HK_RING {
    KSPIN_LOCK        Lock;
    ULONG             Head;      /* Next write index. */
    ULONG             Tail;      /* Next read index.  */
    LONG64            Total;     /* Cumulative events accepted (under Lock). */
    LONG64            Dropped;   /* Cumulative events dropped, full (under Lock). */
    hk_event_record   Slots[HK_RING_CAPACITY];
} HK_RING, *PHK_RING;

/* -------------------------------------------------------------------------
 * Control-device context. One instance, attached to the WDFDEVICE created in
 * DriverEntry. Holds the ring and the live policy/status flags.
 * ------------------------------------------------------------------------- */
typedef struct _HK_DEVICE_CONTEXT {
    HK_RING          Ring;
    hk_policy        Policy;            /* Live policy; flags written via Interlocked. */
    volatile LONG    NotifyRoutinesArmed;
    volatile LONG    ObCallbacksArmed;  /* 0/1. */
    volatile LONG    ObLastStatus;      /* NTSTATUS from the last HkObArm attempt;
                                           STATUS_ACCESS_DENIED here means the image
                                           lacks the object-callback signing EKU. */
    PVOID            ObRegistrationHandle; /* From ObRegisterCallbacks. */
} HK_DEVICE_CONTEXT, *PHK_DEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(HK_DEVICE_CONTEXT, HkGetDeviceContext)

/* Single global handle to the control device, set in DriverEntry. The notify
 * callbacks have no per-call context argument, so they reach the ring through
 * this. Set once before any routine is armed; cleared after all are disarmed. */
extern WDFDEVICE g_HkControlDevice;

/* Convenience: the device context of g_HkControlDevice, or NULL if not ready. */
PHK_DEVICE_CONTEXT HkContext(void);

/* ---- RingBuffer.c ---- */
void    HkRingInit(_Out_ PHK_RING Ring);
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN HkRingPush(_Inout_ PHK_RING Ring, _In_ const hk_event_record* Record);
/* Drains up to MaxRecords and snapshots the Total/Dropped counters under the
 * same lock so the returned counts are coherent with the drained state. */
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG   HkRingDrain(_Inout_ PHK_RING Ring,
                    _Out_writes_to_opt_(MaxRecords, return) hk_event_record* Out,
                    _In_ ULONG MaxRecords,
                    _Out_ ULONG* Remaining,
                    _Out_ LONG64* TotalOut,
                    _Out_ LONG64* DroppedOut);
/* Reads the Total/Dropped counters under the lock (for the status IOCTL). */
_IRQL_requires_max_(DISPATCH_LEVEL)
void    HkRingReadCounters(_Inout_ PHK_RING Ring,
                           _Out_ LONG64* TotalOut, _Out_ LONG64* DroppedOut);

/* Helper used by producers to stamp a record from a type + payload. */
void HkRingEmit(_In_ uint32_t type,
                _In_reads_bytes_opt_(payload_bytes) const void* payload,
                _In_ uint32_t payload_bytes);

/* ---- Notify.c ---- */
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS HkNotifyArm(void);
_IRQL_requires_max_(PASSIVE_LEVEL) void     HkNotifyDisarm(void);
/* TRUE if any Ps* routine could not be removed during disarm (unload must not
 * complete — the caller bugchecks). */
BOOLEAN HkNotifyDisarmFailed(void);

/* ---- Callbacks.c ---- */
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS HkObArm(_In_ PHK_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL) void     HkObDisarm(_In_ PHK_DEVICE_CONTEXT Ctx);

/* ---- Whitelist.c ---- */
/* Returns TRUE if the image at FullImageName matches a known-bad (BYOVD) hash
 * and BYOVD blocking is enabled. Phase 3 list is empty (always FALSE); the
 * load-image hook in Notify.c consults this. */
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN HkWhitelistIsBlockedImage(_In_opt_ PUNICODE_STRING FullImageName);

/* ---- IrpDispatch.c ---- */
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL HkEvtIoDeviceControl;
