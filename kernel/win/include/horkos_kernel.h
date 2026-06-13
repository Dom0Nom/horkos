/*
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
#include "selfcheck_fpgate.h"
#include "module_map_resolve.h"  /* pure address-range resolver (signals 29/31/32/34/35) */
#include "ssdt_decode.h"         /* pure x64 SSDT entry decoder (signal 35, 208) */
#include "syscall_etw_logic.h"   /* pure syscall/ETW decode + FP-gate math (208..216) */

/* Pool tag for all Horkos kernel allocations: 'hkOS' shown reversed in tools. */
#define HK_POOL_TAG 'SOkh'

/* -------------------------------------------------------------------------
 * HK-TODO(schema): self-integrity wire types are NOT YET in the frozen schema
 * headers (sdk/include/horkos/event_schema.h, sdk/include/horkos/ioctl.h). The
 * Schema phase specifies bumping HK_EVENT_SCHEMA_VERSION 2->3 and appending:
 *     HK_EVENT_CALLBACK_INTEGRITY = 5, HK_EVENT_CALLBACK_CENSUS = 6,
 *     HK_EVENT_REG_TAMPER = 7
 * plus the three 16-byte payload structs and two hk_status flags. That edit is
 * owned by the Schema phase and must NOT be made from this domain TU. Until it
 * lands, the kernel sensors below compile against these kernel-PRIVATE mirrors,
 * declared only when the real symbols are absent so there is no collision once
 * the Schema phase appends them. The sizes are pinned identically (== 16) so a
 * future divergence breaks the kernel build, not just the wire side.
 *
 * The emit paths that use these types are written and reachable, but the records
 * they produce cannot cross the IOCTL drain envelope as DISTINCT types until the
 * frozen enum gains the values — they would today serialize with a type the
 * userspace/server side does not yet decode. That is the intended, flagged gap.
 * ------------------------------------------------------------------------- */
#ifndef HK_EVENT_CALLBACK_INTEGRITY
#  define HK_EVENT_CALLBACK_INTEGRITY 5u  /* HK-TODO(schema): move to hk_event_type */
#  define HK_EVENT_CALLBACK_CENSUS    6u  /* HK-TODO(schema): move to hk_event_type */
#  define HK_EVENT_REG_TAMPER         7u  /* HK-TODO(schema): move to hk_event_type */

typedef struct hk_event_callback_integrity {
    uint32_t check_id;     /* HK_CB_CHECK_* */
    uint32_t object_type;  /* 0=process 1=thread 2=image */
    uint32_t result;       /* HK_CB_RESULT_* */
    uint32_t consecutive;  /* consecutive-miss counter (FP gate) */
} hk_event_callback_integrity;
HK_STATIC_ASSERT(sizeof(hk_event_callback_integrity) == 16,
    "hk_event_callback_integrity size mismatch (HK-TODO schema mirror)");

typedef struct hk_event_callback_census {
    uint32_t notify_count; /* populated Ps* notify slots (cap HK_PSP_MAX_NOTIFY) */
    uint32_t cm_count;     /* registered Cm callbacks (cap 100) */
    uint32_t own_present;  /* bit0 = our notify slot present, bit1 = our Cm cookie */
    uint32_t floor;        /* per-host post-boot floor (FP gate) */
} hk_event_callback_census;
HK_STATIC_ASSERT(sizeof(hk_event_callback_census) == 16,
    "hk_event_callback_census size mismatch (HK-TODO schema mirror)");

typedef struct hk_event_reg_tamper {
    uint32_t writer_pid;       /* PsGetCurrentProcessId of the RegNt* requester */
    uint32_t value_class;      /* HK_REG_VAL_* */
    uint32_t op;               /* HK_REG_OP_* */
    uint32_t writer_is_system; /* 1 if requester token is SYSTEM/TrustedInstaller */
} hk_event_reg_tamper;
HK_STATIC_ASSERT(sizeof(hk_event_reg_tamper) == 16,
    "hk_event_reg_tamper size mismatch (HK-TODO schema mirror)");
#endif /* HK_EVENT_CALLBACK_INTEGRITY */

/* HK-TODO(schema): the Schema phase adds these two hk_status flags to ioctl.h.
 * Defined kernel-private until then; the IrpDispatch status handler is NOT edited
 * here (schema-frozen), so these are reserved for the Schema-phase wiring. */
#ifndef HK_STATUS_FLAG_SELFCHECK_OK
#  define HK_STATUS_FLAG_SELFCHECK_OK   0x00000008u
#  define HK_STATUS_FLAG_CB_TAMPER_SEEN 0x00000010u
#endif

/* -------------------------------------------------------------------------
 * HK-TODO(schema): thread-origin wire types (win-kernel-thread-injection) are
 * NOT YET in the frozen schema headers (event_schema.h / ioctl.h). The
 * Schema phase specifies bumping HK_EVENT_SCHEMA_VERSION 2->3, appending:
 *     HK_EVENT_THREAD_CREATE = 5, HK_EVENT_THREAD_INJECT = 6,
 *     HK_EVENT_APC_INJECT = 7, HK_EVENT_THREAD_PROVENANCE = 8
 * and — critically — growing HK_EVENT_PAYLOAD_MAX 16 -> 56 (re-pinning
 * hk_event_record 40 -> 80 bytes). Those edits are owned by the Schema phase and
 * MUST NOT be made from this domain TU. Until they land, the sensor below
 * compiles against these kernel-PRIVATE mirrors, declared only when the real
 * symbols are absent so there is no collision once the Schema phase appends them.
 *
 * FLAGGED GAP (same shape as the callback-integrity mirror above): the
 * thread-create emit path is written and reachable, but hk_event_thread_create
 * is 48 bytes — it EXCEEDS the current frozen HK_EVENT_PAYLOAD_MAX (16), so it
 * CANNOT cross the existing 40-byte HK_IOCTL_DRAIN_EVENTS envelope as a distinct
 * record until the Schema phase grows the payload max and re-pins the record.
 * HkRingEmit would today TRUNCATE this payload to 16 bytes. The emit call below
 * is therefore guarded by HK_TI_SCHEMA_READY (defined only once the frozen
 * schema carries the grown record); until then the kernel captures and would
 * push, but the value cannot be faithfully serialized. This is the intended,
 * flagged blocker — do NOT work around it by emitting a truncated record.
 * ------------------------------------------------------------------------- */
#ifndef HK_EVENT_THREAD_CREATE
#  define HK_EVENT_THREAD_CREATE     5u  /* HK-TODO(schema): move to hk_event_type */
#  define HK_EVENT_THREAD_INJECT     6u  /* HK-TODO(schema): move to hk_event_type */
#  define HK_EVENT_APC_INJECT        7u  /* HK-TODO(schema): move to hk_event_type */
#  define HK_EVENT_THREAD_PROVENANCE 8u  /* HK-TODO(schema): move to hk_event_type */

/* HK_EVENT_THREAD_CREATE — 48 bytes. Captured at PsSetCreateThreadNotifyRoutineEx. */
typedef struct hk_event_thread_create {
    uint32_t tid;                  /* new thread TID                              */
    uint32_t pid;                  /* target (owning) PID                         */
    uint32_t creator_tid;          /* PsGetCurrentThreadId at callback            */
    uint32_t creator_pid;          /* PsGetThreadProcessId(creator)               */
    uint64_t kernel_start_address; /* PS_CREATE_THREAD_NOTIFY_INFO.StartAddress   */
    uint32_t target_session_id;    /* PsGetProcessSessionId(target)               */
    uint32_t creator_session_id;   /* PsGetProcessSessionId(creator)              */
    uint32_t flags;                /* HK_THREAD_FLAG_* (wow64 target, etc.)       */
    uint32_t reserved;             /* zero                                        */
    uint64_t create_time_ns;       /* KeQueryInterruptTime*100; boot epoch        */
} hk_event_thread_create;
HK_STATIC_ASSERT(sizeof(hk_event_thread_create) == 48,
    "hk_event_thread_create size mismatch (HK-TODO schema mirror)");

/* HK_EVENT_THREAD_INJECT — 56 bytes. ETW-TI alloc/setcontext/resume causality. */
typedef struct hk_event_thread_inject {
    uint32_t source_pid;           /* SETTHREADCONTEXT/RESUMETHREAD source        */
    uint32_t target_pid;
    uint32_t target_tid;
    uint32_t chain_flags;          /* HK_INJECT_CHAIN_* bits seen for this TID    */
    uint64_t alloc_base;           /* ALLOCVM_REMOTE base, 0 if not seen          */
    uint64_t alloc_size;
    uint64_t window_ns;            /* span first->last event in the chain         */
    uint64_t context_rip;          /* SETTHREADCONTEXT new RIP/EIP, 0 if none     */
    uint32_t source_session_id;
    uint32_t flags;                /* debugger-source / overlay-allowlisted bits  */
} hk_event_thread_inject;
HK_STATIC_ASSERT(sizeof(hk_event_thread_inject) == 56,
    "hk_event_thread_inject size mismatch (HK-TODO schema mirror)");

/* HK_EVENT_APC_INJECT — 40 bytes. ETW-TI QUEUEUSERAPC_REMOTE. */
typedef struct hk_event_apc_inject {
    uint32_t source_pid;
    uint32_t target_pid;
    uint32_t target_tid;
    uint32_t apc_flags;            /* special-user-APC bit, etc.                  */
    uint64_t apc_routine;          /* ApcRoutine address                          */
    uint32_t routine_region_type;  /* HK_REGION_* (image/private/mapped) resolved */
    uint32_t reserved;
    uint64_t event_time_ns;
} hk_event_apc_inject;
HK_STATIC_ASSERT(sizeof(hk_event_apc_inject) == 40,
    "hk_event_apc_inject size mismatch (HK-TODO schema mirror)");

/* HK_EVENT_THREAD_PROVENANCE — 48 bytes. Userspace enrichment result. */
typedef struct hk_event_thread_provenance {
    uint32_t tid;
    uint32_t pid;
    uint64_t user_start_address;   /* ThreadQuerySetWin32StartAddress (spoofable) */
    uint64_t entry_region_base;    /* MemoryBasicInformation base of start page   */
    uint32_t entry_region_type;    /* HK_REGION_IMAGE/PRIVATE/MAPPED              */
    uint32_t prov_flags;           /* HK_PROV_* (start mismatch, stomped, hidden) */
    uint64_t entry_page_disk_delta;/* #mismatching bytes vs on-disk RVA, MEM_IMAGE*/
    uint32_t backing_module_hash32;/* truncated hash id of backing module path    */
    uint32_t reserved;
} hk_event_thread_provenance;
HK_STATIC_ASSERT(sizeof(hk_event_thread_provenance) == 48,
    "hk_event_thread_provenance size mismatch (HK-TODO schema mirror)");

/* Thread-origin flag/enum constants (appended, never renumbered). */
#  define HK_THREAD_FLAG_WOW64_TARGET    0x00000001u
#  define HK_THREAD_FLAG_CROSS_SESSION   0x00000002u  /* creator/target session differ */
#  define HK_INJECT_CHAIN_ALLOCVM        0x00000001u
#  define HK_INJECT_CHAIN_SETCONTEXT     0x00000002u
#  define HK_INJECT_CHAIN_RESUME         0x00000004u
#  define HK_INJECT_FLAG_SOURCE_DEBUGGER 0x00000008u  /* gate: registered debugger src */
#  define HK_INJECT_FLAG_SOURCE_OVERLAY  0x00000010u  /* gate: signed-overlay allowlist */
#  define HK_REGION_IMAGE                1u
#  define HK_REGION_PRIVATE              2u
#  define HK_REGION_MAPPED               3u
#  define HK_PROV_START_MISMATCH         0x00000001u  /* kernel start unbacked, user in-module (23) */
#  define HK_PROV_ENTRY_STOMPED          0x00000002u  /* MEM_IMAGE but bytes != on-disk (24) */
#  define HK_PROV_ENTRY_PRIVATE          0x00000004u  /* manual-map private RX (24) */
#  define HK_PROV_HIDE_FROM_DEBUGGER     0x00000008u  /* ThreadHideFromDebugger (25) */
#  define HK_PROV_WOW64_64BIT_START      0x00000010u  /* start > 4GB in wow64 proc (22) */
#  define HK_PROV_JIT_ALLOWLISTED        0x00000020u  /* signed JIT host — FP suppressor */
#endif /* HK_EVENT_THREAD_CREATE */

/* -------------------------------------------------------------------------
 * HK-TODO(schema): driver/module-integrity wire types (win-kernel-driver-
 * integrity) are NOT YET in the frozen schema headers (event_schema.h /
 * ioctl.h). The Schema phase specifies bumping HK_EVENT_SCHEMA_VERSION 2->3 and
 * appending:
 *     HK_EVENT_INTEGRITY_FINDING = 5,
 * plus one 16-byte payload struct, the HK_INTEGRITY_* finding codes, two
 * hk_status flags, and HK_IOCTL_INTEGRITY_RESCAN. Those edits are owned by the
 * Schema phase and MUST NOT be made from this domain TU (guardrail #11). Until
 * they land, the integrity sensors compile against these kernel-PRIVATE mirrors,
 * declared only when the real symbols are absent so there is no collision once
 * the Schema phase appends them. The payload is pinned at 16 bytes — equal to the
 * current frozen HK_EVENT_PAYLOAD_MAX — so it crosses the existing 40-byte
 * HK_IOCTL_DRAIN_EVENTS envelope WITHOUT a ring resize. The records are emitted
 * with the kernel-private discriminant value (5u) and cannot be decoded as a
 * DISTINCT type by userspace/server until the frozen enum gains the value; that
 * is the intended, flagged gap shared with the callback-integrity mirror above.
 *
 * NOTE the discriminant collision: HK_EVENT_INTEGRITY_FINDING, HK_EVENT_CALLBACK_
 * INTEGRITY, and HK_EVENT_THREAD_CREATE are all the kernel-private value 5u here
 * because each domain plan independently reserves "the next free type" pre-Schema.
 * Only ONE of these domains' types can ultimately take value 5; the Schema phase
 * resolves the final numbering. The sensors below therefore must NOT be enabled in
 * the same build as a conflicting domain until the Schema phase assigns distinct
 * values — see the build-flag defaults (all integrity sensors default OFF except
 * the four low-FP ones, and the wire records remain undecodable until Schema).
 * ------------------------------------------------------------------------- */
#ifndef HK_EVENT_INTEGRITY_FINDING
#  define HK_EVENT_INTEGRITY_FINDING 5u  /* HK-TODO(schema): move to hk_event_type */

typedef struct hk_event_integrity_finding {
    uint32_t signal_id;   /* Catalog number 28..36, or the sensor that completed
                             on a HK_INTEGRITY_OK heartbeat. */
    uint32_t finding;     /* HK_INTEGRITY_* code below. */
    uint64_t detail;      /* Signal-specific: image-relative offset, altitude,
                             CodeIntegrityOptions bitfield, or a MASKED handler
                             address. NEVER a raw kernel pointer — KASLR-leak
                             hygiene: detail is image-relative or
                             base-subtracted before emit. */
} hk_event_integrity_finding;
HK_STATIC_ASSERT(sizeof(hk_event_integrity_finding) == 16,
    "hk_event_integrity_finding size mismatch (HK-TODO schema mirror)");

/* Finding-code constants. */
#  define HK_INTEGRITY_OK                 0x00u
#  define HK_INTEGRITY_FLT_OUT_OF_IMAGE   0x01u  /* signal 28 */
#  define HK_INTEGRITY_TEXT_HASH_DELTA    0x02u  /* signal 29 */
#  define HK_INTEGRITY_CI_STATE_DELTA     0x03u  /* signal 30 */
#  define HK_INTEGRITY_CALLBACK_NO_IMAGE  0x04u  /* signal 31 */
#  define HK_INTEGRITY_NONIMAGE_EXEC      0x05u  /* signal 32 */
#  define HK_INTEGRITY_KDBG_ATTACHED      0x06u  /* signal 33 (attach > boot-flag) */
#  define HK_INTEGRITY_KDBG_BOOT_ALLOWED  0x07u  /* signal 33 (lower weight) */
#  define HK_INTEGRITY_DRVOBJ_DIVERGENCE  0x08u  /* signal 34 */
#  define HK_INTEGRITY_SSDT_OUT_OF_IMAGE  0x09u  /* signal 35 */
#  define HK_INTEGRITY_BOOTLOAD_SUPPRESS  0x0Au  /* signal 36 */

/* Syscall / ETW / PatchGuard surface integrity (win-kernel-syscall-etw-integrity,
 * signals 208..216). Disjoint 0x20..0x2F range from the 0x01..0x0A driver-
 * integrity codes above, both inside the same hk_event_integrity_finding wire
 * type (no new event type, no payload widening). HK-TODO(schema): these belong in
 * the frozen sdk/include/horkos/event_schema.h alongside the 0x01..0x0A codes; the
 * Schema phase owns that edit. Defined kernel-private here so the sensors below
 * compile; the server mirror (server/telemetry/src/driver_integrity.rs) carries
 * the matching constants. */
#  define HK_INTEGRITY_SSDT_ENTRY_OOI     0x20u  /* 208 native SSDT entry out-of-image */
#  define HK_INTEGRITY_SHADOW_SSDT_OOI    0x21u  /* 209 shadow SSDT entry out-of-image */
#  define HK_INTEGRITY_LSTAR_MISMATCH     0x22u  /* 210 IA32_LSTAR != KiSystemCall64[Shadow] */
#  define HK_INTEGRITY_LSTAR_CPU_DIVERGE  0x23u  /* 210 per-CPU LSTAR divergence */
#  define HK_INTEGRITY_INFINITY_HOOK      0x24u  /* 211 perf-trace callback out-of-image */
#  define HK_INTEGRITY_ETWTI_DOWN         0x25u  /* 212 ETW-TI handle nulled / disabled */
#  define HK_INTEGRITY_ETWTI_NO_KEEPALIVE 0x26u  /* 212 consumer keepalive stale (version-indep) */
#  define HK_INTEGRITY_SYSCALL_PROLOGUE   0x27u  /* 213 KiSystemCall64 prologue byte delta */
#  define HK_INTEGRITY_IDT_OOI            0x28u  /* 214 IDT gate handler out-of-image */
#  define HK_INTEGRITY_ETW_SESSION_SUPPR  0x29u  /* 215 security provider/session disabled vs baseline */
#  define HK_INTEGRITY_SSDT_BASE_SWAP     0x2Au  /* 216 ServiceTableBase/Limit changed from baseline */
/* Build-fragility outcome: any signal above can resolve to "unverifiable" on an
 * unknown build rather than false-positive. The server weights it as no-signal. */
#  define HK_INTEGRITY_UNVERIFIABLE       0x2Fu
#endif /* HK_EVENT_INTEGRITY_FINDING */

/* HK-TODO(schema): the Schema phase adds these two hk_status flags to ioctl.h.
 * Defined kernel-private until then; the IrpDispatch status handler reflects them
 * through the integrity scan state below (schema-frozen flag field is not re-edited). */
#ifndef HK_STATUS_FLAG_INTEGRITY_SCAN_ACTIVE
#  define HK_STATUS_FLAG_INTEGRITY_SCAN_ACTIVE  0x00000020u
#  define HK_STATUS_FLAG_INTEGRITY_SCAN_FAULTED 0x00000040u
#endif

/* HK-TODO(schema): the Schema phase adds HK_IOCTL_INTEGRITY_RESCAN (function
 * 0x803) to ioctl.h. Defined kernel-private until then so IrpDispatch can route it; the
 * value reproduces HK_CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, BUFFERED, ANY). */
#ifndef HK_IOCTL_INTEGRITY_RESCAN
#  define HK_IOCTL_INTEGRITY_RESCAN \
      HK_CTL_CODE(HK_FILE_DEVICE_UNKNOWN, 0x803, HK_METHOD_BUFFERED, HK_FILE_ANY_ACCESS)
#endif

/* -------------------------------------------------------------------------
 * HK-TODO(schema): client self-integrity self-read IOCTL (memory-integrity-
 * selfcheck, signals 145/146/148/151/152) is NOT YET in the frozen ioctl.h. The
 * Schema phase specifies appending HK_IOCTL_SELF_READ_VA (function 0x805) +
 * hk_self_read_request to ioctl.h and the hk_event_self_* payloads + the
 * large-record drain plane (HK_EVENT_MEM_PAYLOAD_MAX / HK_IOCTL_DRAIN_MEM_EVENTS)
 * to event_schema.h. Those edits are owned by the
 * Schema phase and MUST NOT be made from this domain TU. Defined kernel-private
 * here so IrpDispatch can route the IOCTL and selfcheck_read.c can compile. The
 * value reproduces HK_CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, BUFFERED, ANY) — distinct
 * from any other domain's function code.
 *
 * FLAGGED GAP: even when routed, the reply payloads (hk_event_self_crossview is 120
 * bytes) EXCEED the frozen HK_EVENT_PAYLOAD_MAX (16) and require the large-record
 * drain plane, which is itself pre-Schema. So HK_IOCTL_SELF_READ_VA
 * is wired but its replies cannot cross the existing 40-byte envelope as distinct
 * records until the Schema phase lands that plane. The handler is therefore a
 * documented, default-refused stub (see the caller-identity uncertainty in
 * selfcheck_read.c). Do NOT widen the frozen ring from this domain. */
#ifndef HK_IOCTL_SELF_READ_VA
#  define HK_IOCTL_SELF_READ_VA \
      HK_CTL_CODE(HK_FILE_DEVICE_UNKNOWN, 0x805, HK_METHOD_BUFFERED, HK_FILE_ANY_ACCESS)

typedef enum hk_self_read_kind {
    HK_SELF_READ_BYTES      = 0,  /* 145: raw bytes of our .text range.        */
    HK_SELF_READ_PAGE_SHARE = 1,  /* 146: per-page share/CoW/dirty state.      */
    HK_SELF_READ_PTE_PROT   = 2,  /* 152: per-page kernel PTE write/NX bits.   */
    HK_SELF_READ_DEBUG_REGS = 3,  /* 148: per-thread DR0-DR7 + DR7.            */
    HK_SELF_READ_IMAGE_FILE = 4,  /* 151: kernel section-object FILE name.     */
} hk_self_read_kind;

typedef struct hk_self_read_request {
    uint32_t kind;        /* hk_self_read_kind. */
    uint32_t flags;       /* reserved. */
    uint64_t va_base;     /* start VA in the caller's own image. */
    uint64_t va_len;      /* length; bounded server-/kernel-side. */
} hk_self_read_request;
HK_STATIC_ASSERT(sizeof(hk_self_read_request) == 24,
    "hk_self_read_request wire size drift (HK-TODO schema mirror)");
#endif /* HK_IOCTL_SELF_READ_VA */

/* ---- selfcheck_read.c (memory-integrity-selfcheck self-read handler) ----
 * Handles HK_IOCTL_SELF_READ_VA: foreign-read the CALLING AC process's own VA
 * range / page-share state / PTE bits / per-thread DRs / image-file name. Reads
 * ONLY the verified AC caller's own address space; refuses out-of-image VAs and
 * non-AC callers. PASSIVE_LEVEL (pageable reads + file I/O). Returns a refusal
 * NTSTATUS today — the caller-identity binding is UNCERTAIN (see the TU). */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS HkHandleSelfRead(_In_ WDFREQUEST Request,
                          _In_ PHK_DEVICE_CONTEXT Ctx,
                          _In_ size_t InputBufferLength,
                          _In_ size_t OutputBufferLength,
                          _Out_ size_t* BytesReturned);

/* -------------------------------------------------------------------------
 * HK-TODO(schema): external-memory-access wire types (win-handle-memory-access,
 * signals 64-72) are NOT YET in the frozen schema headers (event_schema.h /
 * ioctl.h). The Schema phase specifies bumping HK_EVENT_SCHEMA_VERSION
 * 2->3 and appending:
 *     HK_EVENT_VM_ACCESS = 5, HK_EVENT_HANDLE_PROVENANCE = 6,
 *     HK_EVENT_FOREIGN_HOLDER = 7, HK_EVENT_PROTECT_DRIFT = 8
 * plus the four payload structs below. Those edits are owned by the Schema phase
 * and MUST NOT be made from this domain TU (guardrail #11). Until they land, the
 * sensors compile against these kernel-PRIVATE mirrors, declared only when the
 * real symbols are absent so there is no collision once the Schema phase appends
 * them. The sizes are pinned (32/24/12/24 — see the per-struct notes on the
 * explicit tail-pad that the u64 alignment forces) so a future divergence breaks
 * the kernel build, not just the wire side.
 *
 * FLAGGED GAP (same shape as the thread-origin mirror above): hk_event_vm_access
 * is 32 bytes and hk_event_handle_provenance is 24 bytes — both EXCEED the current
 * frozen HK_EVENT_PAYLOAD_MAX (16), so they CANNOT cross the existing 40-byte
 * HK_IOCTL_DRAIN_EVENTS envelope as distinct records until the Schema phase grows
 * the payload max and re-pins hk_event_record. HkRingEmit would today TRUNCATE
 * these payloads to 16 bytes. Every emit site below is therefore guarded by
 * HK_VMWATCH_SCHEMA_READY (defined only once the frozen schema carries the grown
 * record); until then the kernel captures and would push, but the value cannot be
 * faithfully serialized. This is the intended, flagged blocker — do NOT work
 * around it by emitting a truncated record.
 *
 * Discriminant collision: HK_EVENT_VM_ACCESS reuses the kernel-private value 5u,
 * exactly like HK_EVENT_INTEGRITY_FINDING / HK_EVENT_CALLBACK_INTEGRITY /
 * HK_EVENT_THREAD_CREATE — each domain reserves "the next free type" pre-Schema.
 * Only ONE can ultimately take 5; the Schema phase resolves the final numbering.
 * The VMWATCH sensors default OFF (HK_WIN_VMWATCH) and the wire records remain
 * undecodable until Schema, so the collision is inert in any shippable build.
 * ------------------------------------------------------------------------- */
#ifndef HK_EVENT_VM_ACCESS
#  define HK_EVENT_VM_ACCESS         5u  /* HK-TODO(schema): move to hk_event_type */
#  define HK_EVENT_HANDLE_PROVENANCE 6u  /* HK-TODO(schema): move to hk_event_type */
#  define HK_EVENT_FOREIGN_HOLDER    7u  /* HK-TODO(schema): move to hk_event_type */
#  define HK_EVENT_PROTECT_DRIFT     8u  /* HK-TODO(schema): move to hk_event_type */

/* HK_EVENT_VM_ACCESS — 32 bytes. ETW-TI ReadVm/WriteVm/AllocVm/ProtectVm against
 * the protected pid (#64, #69, #72). EXCEEDS HK_EVENT_PAYLOAD_MAX (16) — see the
 * HK_VMWATCH_SCHEMA_READY gate above. The field list (source/target pid,
 * target_va, access_kind, section_flags, flags) sums to 28, but the u64 target_va
 * forces 8-byte struct alignment, so a trailing 'reserved' u32 is made EXPLICIT to
 * pin the real on-wire size at 32 rather than relying on silent tail padding (which
 * the kernel and server mirrors could disagree on). */
typedef struct hk_event_vm_access {
    uint32_t source_pid;
    uint32_t target_pid;            /* == protected game pid */
    uint64_t target_va;
    uint32_t access_kind;           /* HK_VM_READ|WRITE|ALLOC|PROTECT bitmask */
    uint32_t target_section_flags;  /* IMAGE_SCN_* of resolved VA, 0 if not in a module */
    uint32_t flags;                 /* HK_VM_REMOTE | HK_VM_STAGING_SEQ | HK_VM_ETWTI_SILENT */
    uint32_t reserved;              /* explicit tail pad (u64 alignment); must be zero */
} hk_event_vm_access;
HK_STATIC_ASSERT(sizeof(hk_event_vm_access) == 32,
    "hk_event_vm_access size mismatch (HK-TODO schema mirror)");

/* HK_EVENT_HANDLE_PROVENANCE — 24 bytes. Ob post-op granted-access delta (#67) and
 * DuplicateHandle source provenance (#66). EXCEEDS HK_EVENT_PAYLOAD_MAX (16). */
typedef struct hk_event_handle_provenance {
    uint32_t requester_pid;
    uint32_t source_pid;            /* DuplicateHandle source; == requester for direct create */
    uint32_t target_pid;
    uint32_t original_desired_access;
    uint32_t granted_access;        /* post-op; 0 on create path */
    uint32_t flags;                 /* HK_HND_DUP_LAUNDERED | HK_HND_GRANT_EXCEEDS_PREOP */
} hk_event_handle_provenance;
HK_STATIC_ASSERT(sizeof(hk_event_handle_provenance) == 24,
    "hk_event_handle_provenance size mismatch (HK-TODO schema mirror)");

/* HK_EVENT_FOREIGN_HOLDER — 12 bytes. Userspace handle-table audit (#70). Fits the
 * current 16-byte payload max, but its event type is still pre-Schema. */
typedef struct hk_event_foreign_holder {
    uint32_t owner_pid;
    uint32_t granted_access;
    uint32_t flags;                 /* HK_HND_DANGEROUS_RIGHTS | HK_HND_UNSIGNED_OWNER */
} hk_event_foreign_holder;
HK_STATIC_ASSERT(sizeof(hk_event_foreign_holder) == 12,
    "hk_event_foreign_holder size mismatch (HK-TODO schema mirror)");

/* HK_EVENT_PROTECT_DRIFT — 24 bytes. Userspace page-protection drift on shipped
 * code (#71). EXCEEDS HK_EVENT_PAYLOAD_MAX (16). The field list sums to 20,
 * but the leading u64 region_base forces 8-byte alignment, so a trailing 'reserved'
 * u32 is EXPLICIT to pin the on-wire size at 24 rather than relying on tail padding. */
typedef struct hk_event_protect_drift {
    uint64_t region_base;
    uint32_t live_protect;          /* MEMORY_BASIC_INFORMATION.Protect */
    uint32_t expected_protect;      /* from PE section characteristics */
    uint32_t flags;                 /* HK_PROT_WX_ON_SHIPPED | HK_PROT_FOREIGN_INITIATED */
    uint32_t reserved;              /* explicit tail pad (u64 alignment); must be zero */
} hk_event_protect_drift;
HK_STATIC_ASSERT(sizeof(hk_event_protect_drift) == 24,
    "hk_event_protect_drift size mismatch (HK-TODO schema mirror)");

/* access_kind bits for hk_event_vm_access.access_kind. */
#  define HK_VM_READ    0x00000001u
#  define HK_VM_WRITE   0x00000002u
#  define HK_VM_ALLOC   0x00000004u
#  define HK_VM_PROTECT 0x00000008u

/* flags bits for hk_event_vm_access.flags. */
#  define HK_VM_REMOTE       0x00000001u  /* cross-process (remote) operation */
#  define HK_VM_STAGING_SEQ  0x00000002u  /* completed alloc->protect->write triad (#72) */
#  define HK_VM_ETWTI_SILENT 0x00000004u  /* working-set page-in with no matching ReadVm (#69) */

/* flags bits for hk_event_handle_provenance.flags. */
#  define HK_HND_DUP_LAUNDERED      0x00000001u  /* dup chain whose root opener never appeared (#66) */
#  define HK_HND_GRANT_EXCEEDS_PREOP 0x00000002u /* post-op granted > pre-op recorded mask (#67) */

/* flags bits for hk_event_foreign_holder.flags. */
#  define HK_HND_DANGEROUS_RIGHTS 0x00000001u  /* holder has VM_READ/WRITE/OPERATION */
#  define HK_HND_UNSIGNED_OWNER   0x00000002u  /* holder image is unsigned/unknown */

/* flags bits for hk_event_protect_drift.flags. */
#  define HK_PROT_WX_ON_SHIPPED      0x00000001u /* live RWX on a shipped +X section */
#  define HK_PROT_FOREIGN_INITIATED  0x00000002u /* drift correlated to a foreign ProtectVm (#71) */
#endif /* HK_EVENT_VM_ACCESS */

/* -------------------------------------------------------------------------
 * VM-access section-flag cache (EtwTiVmWatch.c). Per-module [base,size)+section
 * IMAGE_SCN_* ranges for the PROTECTED process, populated at PsSetLoadImage time so
 * a runtime VA from an ETW-TI ReadVm/WriteVm/ProtectVm event can be classified back
 * to its section characteristics (#64/#71 input) without a per-event VAD walk. The
 * pure range->flags lookup is HkVmSectionResolve; the userspace mirror of the same
 * logic is hk::sdk::vmaccess::classify_target_section (host-tested).
 *
 * HK-UNCERTAIN(section-cache-lifetime): the cache must survive image unload/reload
 * races. The fill/evict hooks below are
 * declared but the actual PsSetLoadImageNotifyRoutine wiring into Notify.c's
 * load-image handler is left for on-box verification — a stale range that outlives an
 * unloaded module would mis-classify a later allocation at the same VA. Do NOT wire
 * the evict path blind; confirm the unload-notify ordering on the target build first.
 * ------------------------------------------------------------------------- */
#define HK_VM_SECTION_CACHE_MAX 256u  /* cap on tracked sections; oversized truncates. */

typedef struct _HK_VM_SECTION_RANGE {
    uint64_t Base;            /* runtime VA of the section start */
    uint64_t Size;           /* section virtual size in bytes   */
    uint32_t Characteristics;/* IMAGE_SCN_* of this section      */
    uint32_t OwnerPid;       /* protected-process PID this range belongs to */
} HK_VM_SECTION_RANGE, *PHK_VM_SECTION_RANGE;

typedef struct _HK_VM_SECTION_CACHE {
    HK_VM_SECTION_RANGE Ranges[HK_VM_SECTION_CACHE_MAX];
    ULONG               Count;
    BOOLEAN             Truncated;
    KSPIN_LOCK          Lock;     /* fill (PASSIVE) vs lookup (PASSIVE ETW callback) */
} HK_VM_SECTION_CACHE, *PHK_VM_SECTION_CACHE;

/* -------------------------------------------------------------------------
 * Loaded-module map (ModuleMap.c). Built once per integrity scan from
 * ZwQuerySystemInformation(SystemModuleInformation); the sensors range-lookup
 * addresses against it via the pure HkModuleRange* helpers in
 * module_map_resolve.h. Allocated from paged pool in the PASSIVE work item.
 * ------------------------------------------------------------------------- */
#define HK_MODULEMAP_MAX 1024u  /* cap on tracked modules; oversized lists truncate. */

typedef struct _HK_MODULE_MAP {
    hk_module_range Ranges[HK_MODULEMAP_MAX]; /* base/size/index/flags per module. */
    ULONG           Count;                    /* populated entries (<= HK_MODULEMAP_MAX). */
    BOOLEAN         Truncated;                /* TRUE if the live list exceeded the cap. */
} HK_MODULE_MAP, *PHK_MODULE_MAP;

/* -------------------------------------------------------------------------
 * Syscall / ETW surface-integrity baselines (SyscallIntegrity.c / EtwIntegrity.c,
 * win-kernel-syscall-etw-integrity, signals 208..216). Snapshots taken at arm
 * time and re-read on each scan; NOT wire-visible. Captured from documented/
 * exported reads where possible; the unexported-global halves are offset-gated and
 * fall back to Valid==FALSE => HK_INTEGRITY_UNVERIFIABLE (never a false positive).
 * ------------------------------------------------------------------------- */
#define HK_SYSCALL_PROLOGUE_WINDOW 32u  /* stable-window byte count captured (213). */

typedef struct _HK_SSDT_BASELINE {
    PVOID   ServiceTableBase;        /* KeServiceDescriptorTable.Base at arm time (216). */
    ULONG   ServiceLimit;            /* KeServiceDescriptorTable.Limit at arm time (216). */
    PVOID   ShadowServiceTableBase;  /* shadow descriptor base (209; OFF by default). */
    ULONG   ShadowServiceLimit;
    PVOID   ExpectedLstar;           /* &KiSystemCall64 or ...Shadow under KVA-shadow (210). */
    UCHAR   PrologueBytes[HK_SYSCALL_PROLOGUE_WINDOW]; /* stable-window bytes of KiSystemCall64 (213). */
    ULONG   PrologueLen;             /* bytes captured; 0 => prologue check unverifiable. */
    BOOLEAN Valid;                   /* FALSE => emit HK_INTEGRITY_UNVERIFIABLE, not a hook. */
} HK_SSDT_BASELINE;

typedef struct _HK_ETW_BASELINE {
    /* Boot-time enabled-provider census for the security-relevant providers Horkos
     * depends on (NT Kernel Logger, ETW-TI). Keyed by provider GUID -> a stable bit
     * (HK_ETW_PROVIDER_* below), not by an unexported global, so the baseline half
     * is version-independent. */
    ULONG   SecurityProviderMask;    /* bit per tracked provider, enabled at boot (215). */
    BOOLEAN EtwTiHandlePresent;      /* EtwThreatIntProvRegHandle non-null at arm (212; offset-resolved). */
    BOOLEAN Valid;
} HK_ETW_BASELINE;

/* Provider-GUID bits for HK_ETW_BASELINE.SecurityProviderMask (signal 215). The
 * GUIDs themselves live in EtwIntegrity.c; these are the version-independent bit
 * positions the pure HkEtwProviderSuppressed diff operates on. */
#define HK_ETW_PROVIDER_NT_KERNEL_LOGGER 0x00000001u
#define HK_ETW_PROVIDER_THREAT_INTEL     0x00000002u
/* Dependency set Horkos relies on (a disable of any of these is a signal-215
 * finding; a disable of a provider OUTSIDE this set is a no-op, the FP gate). */
#define HK_ETW_DEPENDENCY_MASK \
    (HK_ETW_PROVIDER_NT_KERNEL_LOGGER | HK_ETW_PROVIDER_THREAT_INTEL)

/* Per-CPU IPI result buffer for signals 210 (LSTAR) and 214 (IDT). Filled inside
 * KeIpiGenericCall (IPI level — read + store ONLY, no alloc/lock) and consumed at
 * PASSIVE_LEVEL. Stack/pool, never wire. 64 caps current x64 processor count;
 * HK_IDT_GATES_CHECKED is the first N gates we bounds-check per CPU. */
#define HK_PERCPU_MAX_CPUS  64u
#define HK_IDT_GATES_CHECKED 20u

typedef struct _HK_PERCPU_READ {
    ULONG64 Lstar[HK_PERCPU_MAX_CPUS];                      /* IA32_LSTAR per CPU (210). */
    ULONG64 IdtHandler[HK_PERCPU_MAX_CPUS][HK_IDT_GATES_CHECKED]; /* reconstructed gate VAs (214). */
    ULONG   ProcessorCount;
    volatile LONG Faulted;  /* set if an IPI read guard tripped (defensive). */
} HK_PERCPU_READ, *PHK_PERCPU_READ;

/* check_id values for hk_event_callback_integrity.check_id. */
#define HK_CB_CHECK_OB_LIVENESS   1u  /* signal 1: Ob pre-callback self-poll */
#define HK_CB_CHECK_ENABLED_DRIFT 2u  /* signal 7: per-type Enabled/Operations drift */
#define HK_CB_CHECK_PS_REARM      3u  /* signal 3: Ps* re-arm probe */
#define HK_CB_CHECK_TEXT_HASH     4u  /* signal 8: callback .text SHA-256 drift */

/* result values for hk_event_callback_integrity.result. */
#define HK_CB_RESULT_OK         0u
#define HK_CB_RESULT_MISSING    1u
#define HK_CB_RESULT_DISABLED   2u
#define HK_CB_RESULT_PTR_SWAP   3u
#define HK_CB_RESULT_TEXT_PATCH 4u

/* object_type values (callback_integrity.object_type). */
#define HK_CB_OBJTYPE_PROCESS 0u
#define HK_CB_OBJTYPE_THREAD  1u
#define HK_CB_OBJTYPE_IMAGE   2u

/* own_present bits for hk_event_callback_census.own_present. */
#define HK_CENSUS_OWN_NOTIFY 0x1u  /* our Ps* notify slot accounted for */
#define HK_CENSUS_OWN_CM     0x2u  /* our Cm cookie present */

/* value_class values for hk_event_reg_tamper.value_class. */
#define HK_REG_VAL_IMAGEPATH 0u
#define HK_REG_VAL_START     1u
#define HK_REG_VAL_ALTITUDE  2u
#define HK_REG_VAL_POLICY    3u
#define HK_REG_VAL_OTHER     4u

/* op values for hk_event_reg_tamper.op. */
#define HK_REG_OP_SET         0u
#define HK_REG_OP_DELETE      1u
#define HK_REG_OP_DELETEVALUE 2u

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
/* -------------------------------------------------------------------------
 * Self-integrity baselines (CallbackSelfCheck.c). Captured at arm time from
 * Horkos's OWN registration intent — never by parsing undocumented kernel
 * internals. signals 2/7 (documented half), 8.
 * ------------------------------------------------------------------------- */
typedef struct _HK_OB_BASELINE {
    BOOLEAN  Enabled[2];      /* [0]=PsProcessType, [1]=PsThreadType */
    ULONG    Operations[2];   /* CREATE|DUPLICATE bitmask we registered per type */
    PVOID    PreOpFnBaseline; /* expected &HkObPreCallback */
    UCHAR    TextHash[32];    /* SHA-256 of callback .text range (signal 8) */
    BOOLEAN  TextHashValid;   /* TRUE iff TextHash was captured (signal 8 gated) */
    BOOLEAN  Valid;
} HK_OB_BASELINE;

typedef struct _HK_CM_BASELINE {            /* signal 9 */
    LARGE_INTEGER Cookie;     /* our CmRegisterCallbackEx cookie at arm time */
    BOOLEAN       Present;
} HK_CM_BASELINE;

typedef struct _HK_DEVICE_CONTEXT {
    HK_RING          Ring;
    hk_policy        Policy;            /* Live policy; flags written via Interlocked. */
    volatile LONG    NotifyRoutinesArmed;
    volatile LONG    ObCallbacksArmed;  /* 0/1. */
    volatile LONG    ObLastStatus;      /* NTSTATUS from the last HkObArm attempt;
                                           STATUS_ACCESS_DENIED here means the image
                                           lacks the object-callback signing EKU. */
    PVOID            ObRegistrationHandle; /* From ObRegisterCallbacks. */

    /* ---- Self-check substrate (CallbackSelfCheck.c) ---- */
    HK_OB_BASELINE   ObBaseline;
    HK_CM_BASELINE   CmBaseline;
    KTIMER           SelfCheckTimer;
    KDPC             SelfCheckDpc;
    PIO_WORKITEM     SelfCheckWorkItem;
    volatile LONG    SelfCheckArmed;       /* 0/1: timer running, work item valid. */
    volatile LONG    SelfCheckHeartbeat;   /* DPC-incremented; FP gate for signal 1
                                              (scheduler starvation vs removal). */
    volatile LONG64  ObSelfPollNonce;      /* stamped by HkObPreCallback on the
                                              sentinel self-open, read by the poll. */
    volatile LONG64  ObSelfPollExpected;   /* nonce the work item armed this round. */
    volatile LONG    ObConsecutiveMiss;    /* consecutive missed liveness polls. */
    volatile LONG    CensusFloor;          /* per-host post-boot notify-slot floor. */

    /* ---- Registry callback (RegistryCallback.c) ---- */
    LARGE_INTEGER    CmCookie;             /* live cookie, separate from baseline. */
    volatile LONG    CmArmed;              /* 0/1. */

    /* ---- Driver/module-integrity scan (HkIntegrityScan.c, signals 28-36) ---- */
    KTIMER           IntegrityTimer;       /* periodic scan trigger. */
    KDPC             IntegrityDpc;          /* DPC that queues the scan work item. */
    PIO_WORKITEM     IntegrityWorkItem;     /* runs HkIntegrityScanAll at PASSIVE. */
    volatile LONG    IntegrityArmed;        /* 0/1: timer running, work item valid. */
    volatile LONG    IntegrityScanFaulted;  /* 0/1: a scan aborted on a checked error. */
    /* CodeIntegrity (signal 30) baseline snapshot, captured at scan init. The
     * sensor compares the live read against this and emits only on a flag flip. */
    volatile LONG    CiBaselineValid;       /* 0/1. */
    ULONG            CiBaselineOptions;      /* SYSTEM_CODEINTEGRITY_INFORMATION bits. */

    /* ---- Syscall/ETW surface integrity (SyscallIntegrity.c / EtwIntegrity.c,
     * win-kernel-syscall-etw-integrity, signals 208..216). Baselines captured at
     * HkSyscallEtwArm time; re-read each scan. ---- */
    HK_SSDT_BASELINE SsdtBaseline;          /* 208/213/216 arm-time snapshot. */
    HK_ETW_BASELINE  EtwBaseline;           /* 212/215 arm-time snapshot. */
    /* ETW-TI consumer keepalive (signal 212, version-independent half). Bumped by
     * Horkos's ETW-TI consumer on each TI event; HkEtwTiLiveness checks it
     * advanced since the previous scan. HK-VERIFIED(etw-ti-consumer): ETW-TI is a
     * PROTECTED provider; no in-kernel consumer is possible (see Notify.c note).
     * Where the bump occurs depends on the (unresolved) PPL consumer architecture.
     * Until a PPL consumer exists this stays 0 and the keepalive check is correctly
     * UNVERIFIABLE-gated by EtwKeepaliveArmed. */
    volatile LONG64  EtwTiKeepalive;        /* monotonic; bumped per TI event. */
    LONG64           EtwTiKeepalivePrev;    /* counter at the previous scan (PASSIVE only). */
    volatile LONG    EtwKeepaliveArmed;     /* 0/1: a consumer exists and bumps the counter. */

    /* ---- External-memory-access watch (EtwTiVmWatch.c / CanaryProc.c,
     * win-handle-memory-access, signals 64-72). All default-OFF (HK_WIN_VMWATCH)
     * and the wire records are pre-Schema undecodable; see the mirror block above. ---- */
    HK_VM_SECTION_CACHE VmSectionCache;     /* protected-process section ranges (#64/#71). */
    volatile LONG       VmWatchArmed;       /* 0/1: ETW-TI VM consumer arm state (stub). */
    volatile LONG       ProtectedPid;       /* the protected game PID ETW-TI filters to. */
    /* Ob "who opened us" provenance ring (#66): a small ring of recent create-path
     * openers so a later DuplicateHandle whose root opener never appeared can be
     * flagged HK_HND_DUP_LAUNDERED. Indices wrap; correctness is best-effort
     * (provenance, not enforcement), guarded by ProvLock. */
    KSPIN_LOCK          ProvLock;
    uint32_t            ProvOpenerPids[64];  /* recent create-path requester PIDs. */
    ULONG               ProvHead;            /* next write index (mask 63). */
    PVOID               CanaryRegistrationHandle; /* Ob filter on the canary proc object (#68). */
    volatile LONG       CanaryArmed;         /* 0/1. */
} HK_DEVICE_CONTEXT, *PHK_DEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(HK_DEVICE_CONTEXT, HkGetDeviceContext)

/* Single global handle to the control device, set in DriverEntry. The notify
 * callbacks have no per-call context argument, so they reach the ring through
 * this. Set once before any routine is armed; cleared after all are disarmed. */
extern WDFDEVICE g_HkControlDevice;

/* The WDM driver object, captured in DriverEntry. CmRegisterCallbackEx's Driver
 * parameter is a PVOID to the DRIVER_OBJECT (NOT a WDFDEVICE) — RegistryCallback.c
 * needs this. Set once in DriverEntry before HkCmArm; never cleared (the driver
 * object outlives all our callbacks). */
extern PDRIVER_OBJECT g_HkDriverObject;

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

/* ---- win-hypervisor-detection kernel sensors (signals 39/41/42/44) ----
 * Each samples at PASSIVE_LEVEL and emits a 16-byte hk_event_hv_* record via
 * HkRingEmit. HkHvKernelSample() drives the enabled subset per the build flags
 * (42 default ON; 39 default OFF-until-reviewed; 41/44 behind
 * HK_HV_KERNEL_EXPERIMENTAL). The periodic call site is wired on the target box. */
_IRQL_requires_max_(PASSIVE_LEVEL) void HkHvSyntheticMsrSample(void);   /* 42 */
_IRQL_requires_max_(PASSIVE_LEVEL) void HkHvEptProbeSample(void);       /* 39 */
_IRQL_requires_max_(PASSIVE_LEVEL) void HkHvSecureKernelSample(void);   /* 41 */
_IRQL_requires_max_(PASSIVE_LEVEL) void HkHvApicIdtSample(void);        /* 44 */
_IRQL_requires_max_(PASSIVE_LEVEL) void HkHvKernelSample(void);

/* ---- process-genealogy kernel sensors (signals 199/200/202) ----
 * Called from the create-process / image-load notify routines. Read-only;
 * emit via HkRingEmit (the 199 path uses the v5 24-byte create-ex record). */
_IRQL_requires_max_(PASSIVE_LEVEL)
void HkGenealogyClassify(_In_ HANDLE ProcessId, _In_ HANDLE ParentProcessId,
                         _In_ LONG64 CreateTimeNs);                       /* 199 */
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS HkLaunchTimingArm(void);
_IRQL_requires_max_(PASSIVE_LEVEL) void     HkLaunchTimingDisarm(void);
_IRQL_requires_max_(PASSIVE_LEVEL)
void HkLaunchTimingOnImage(_In_ HANDLE ProcessId, _In_ PVOID ImageBase);  /* 200 */
_IRQL_requires_max_(PASSIVE_LEVEL)
void HkModuleReconcileOnImage(_In_ HANDLE ProcessId, _In_ PVOID ImageBase,
                              _In_ SIZE_T ImageSize, _In_ BOOLEAN HasBackingFile); /* 202 */

/* ---- Notify.c ---- */
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS HkNotifyArm(void);
_IRQL_requires_max_(PASSIVE_LEVEL) void     HkNotifyDisarm(void);
/* TRUE if any Ps* routine could not be removed during disarm (unload must not
 * complete — the caller bugchecks). */
BOOLEAN HkNotifyDisarmFailed(void);
/* ETW-TI consumer keepalive bump (signal 212). Bumped by the (future) PPL ETW-TI
 * consumer on each TI event; read by HkEtwTiLiveness. HK-VERIFIED(etw-ti-consumer):
 * no kernel TI consumer exists under current signing (ETW-TI is a PROTECTED provider
 * requiring PPL/ELAM) — see the bump-site note in Notify.c. */
void HkEtwTiKeepaliveBump(void);

/* ---- ThreadProvenance.c (win-kernel-thread-injection) ---- */
/* Arms/disarms the Ex thread-create notify (HkThreadNotifyEx) that captures the
 * spoof-resistant kernel ETHREAD StartAddress + creator/session provenance.
 * Called from HkNotifyArm/Disarm in Notify.c (which no longer arms the non-Ex
 * stub). Arm is PASSIVE_LEVEL (PsSetCreateThreadNotifyRoutineEx requirement);
 * the disarm Remove=TRUE path waits for in-flight callbacks before returning. */
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS HkThreadProvenanceArm(void);
_IRQL_requires_max_(PASSIVE_LEVEL) void     HkThreadProvenanceDisarm(void);
/* TRUE if the Ex notify could not be removed during disarm (unload must not
 * complete — folded into HkNotifyDisarmFailed by Notify.c). */
BOOLEAN HkThreadProvenanceDisarmFailed(void);

/* ---- Callbacks.c ---- */
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS HkObArm(_In_ PHK_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL) void     HkObDisarm(_In_ PHK_DEVICE_CONTEXT Ctx);
/* The magic DesiredAccess bit pattern the self-poll uses on its sentinel open so
 * HkObPreCallback can recognize the probe, stamp the nonce, and suppress the
 * normal HK_EVENT_HANDLE_OPEN emit (signal 1). Picked from reserved access bits
 * unlikely to be requested by a real opener; the poll target is the System
 * process so even if a real opener set it, the self-open is additionally keyed
 * on opener==target==System (see CallbackSelfCheck.c). */
/* HK-UNCERTAIN(selfpoll-access-bit): 0x08000000 is ACCESS_SYSTEM_SECURITY (documented
 * in WinNT.h / learn.microsoft.com/windows/win32/secauthz/access-mask), which a
 * legitimate System-context opener of the System process CAN request (SACL access).
 * When that rare coincidence happens, the pre-callback stamps the nonce for a foreign
 * open and suppresses that one hk_event_handle_open. The nonce comparison keeps the
 * liveness verdict correct, but the access bit should be a truly-unused reserved bit
 * validated on-box before relying on it; do not assume 0x08000000 is collision-free.
 * (docs: ACCESS_SYSTEM_SECURITY value 0x08000000 documented; still needs on-box:
 * confirm no legitimate System-self-open uses this bit in practice) */
#define HK_OB_SELFPOLL_MAGIC ((ACCESS_MASK)0x08000000u)
/* Address of the Ob pre-callback, exported so the self-check can baseline its
 * .text range and compare the registered PreOperation pointer (signals 7, 8). */
PVOID HkObPreCallbackAddress(void);

/* ---- Callbacks.c Ob post-op + provenance (win-handle-memory-access #66/#67) ----
 * HkObPostCallback is wired into op[].PostOperation by HkObArm when HK_WIN_VMWATCH
 * is built; it diffs the post-op GrantedAccess against the pre-op-recorded mask and
 * emits HK_EVENT_HANDLE_PROVENANCE on grant>preop (#67). HkObRecordOpener pushes a
 * create-path requester PID into the provenance ring; HkObRootOpenerSeen answers
 * whether a DuplicateHandle's root opener ever appeared there (#66). The provenance
 * ring + post-op emit are pre-Schema undecodable (28/24-byte payloads), so the emit
 * is guarded by HK_VMWATCH_SCHEMA_READY (see the mirror block). */
void    HkObRecordOpener(_In_ PHK_DEVICE_CONTEXT Ctx, _In_ uint32_t requester_pid);
BOOLEAN HkObRootOpenerSeen(_In_ PHK_DEVICE_CONTEXT Ctx, _In_ uint32_t source_pid);

/* ---- EtwTiVmWatch.c (win-handle-memory-access #64/#69/#72/#71-input) ----
 * The ETW-TI consumer surface for ReadVm/WriteVm/AllocVm/ProtectVm against the
 * protected pid, plus the per-module section-flag cache the classifier resolves a
 * target VA against. HK-VERIFIED(etw-ti): under current signing there is NO
 * in-kernel TI consumer (Microsoft-Windows-Threat-Intelligence is a PROTECTED
 * event provider; only a PPL/ELAM user-mode process can open a consumer session
 * — documented: learn.microsoft.com/windows/win32/etw/consuming-events
 * "Protected Event Providers"). HkEtwTiArm/Disarm therefore install NOTHING today
 * and return STATUS_NOT_SUPPORTED; the section cache + classifier are the real,
 * compilable substrate. Do NOT write a kernel ETW-TI consumer. */
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS HkEtwTiArm(_In_ PHK_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL) void     HkEtwTiDisarm(_In_ PHK_DEVICE_CONTEXT Ctx);
/* Section-flag cache maintenance. Fill is called from the load-image notify for the
 * protected process; reset clears it (e.g. on protected-process exit). Both
 * PASSIVE_LEVEL; serialized by HK_VM_SECTION_CACHE.Lock. */
_IRQL_requires_max_(PASSIVE_LEVEL)
void HkVmSectionCacheReset(_Inout_ PHK_VM_SECTION_CACHE Cache);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS HkVmSectionCacheAdd(_Inout_ PHK_VM_SECTION_CACHE Cache,
                             _In_ uint32_t owner_pid, _In_ uint64_t base,
                             _In_ uint64_t size, _In_ uint32_t characteristics);
/* Pure range->IMAGE_SCN_* lookup over the cache; 0 if the VA is in no tracked
 * section. Mirrors hk::sdk::vmaccess::classify_target_section. Safe at <=DISPATCH
 * (it only takes the cache spin lock and scans). */
_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t HkVmSectionResolve(_Inout_ PHK_VM_SECTION_CACHE Cache, _In_ uint64_t target_va);

/* ---- CanaryProc.c (win-handle-memory-access #68) ----
 * Spawns + tracks a low-cost guard process and arms an Ob filter on ITS process
 * object to externalize foreign PID-poll cadence. HK-UNCERTAIN(canary-spawn): a
 * driver spawning a usermode guard process (RtlCreateUserProcess/ZwCreateUserProcess
 * arguments, session/desktop placement, and cleanup on uninstall) is not verified
 * blind; HkCanaryStart therefore installs NOTHING today and returns
 * STATUS_NOT_SUPPORTED (canary is optional/experimental). Do NOT spawn
 * a process from the driver without on-box validation of the create path + teardown. */
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS HkCanaryStart(_In_ PHK_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL) void     HkCanaryStop(_In_ PHK_DEVICE_CONTEXT Ctx);

/* ---- CallbackSelfCheck.c ---- */
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS HkSelfCheckArm(_In_ PHK_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL) void     HkSelfCheckDisarm(_In_ PHK_DEVICE_CONTEXT Ctx);
/* The Ob liveness self-poll target (signal 1): runs the sentinel open and reads
 * back the nonce. PASSIVE-only (it calls ZwOpenProcess/ZwClose). */
_IRQL_requires_max_(PASSIVE_LEVEL) void HkObSelfPoll(_In_ PHK_DEVICE_CONTEXT Ctx);

/* ---- RegistryCallback.c ---- */
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS HkCmArm(_In_ PHK_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL) void     HkCmDisarm(_In_ PHK_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL) void     HkCmCensus(_In_ PHK_DEVICE_CONTEXT Ctx);

/* ---- Whitelist.c ---- */
/* Returns TRUE if the image at FullImageName matches a known-bad (BYOVD) hash
 * and BYOVD blocking is enabled. Phase 3 list is empty (always FALSE); the
 * load-image hook in Notify.c consults this. */
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN HkWhitelistIsBlockedImage(_In_opt_ PUNICODE_STRING FullImageName);

/* -------------------------------------------------------------------------
 * Driver/module-integrity sensors (win-kernel-driver-integrity, signals 28-36).
 * All read-only: they sample and emit HK_EVENT_INTEGRITY_FINDING; the server
 * scores and bans. Every sensor runs from the single PASSIVE_LEVEL work item
 * owned by HkIntegrityScan.c. Each sensor `.c` compiles to a no-op stub when its
 * HK_WIN_INTEGRITY_* build flag is OFF (see kernel/win/CMakeLists.txt), so the
 * orchestrator fans out only to enabled sensors and the driver links with any
 * subset. Helper to emit one finding with KASLR-masked detail (RingBuffer.c-
 * backed) is HkIntegrityEmit. detail MUST already be image-relative/masked.
 * ------------------------------------------------------------------------- */
void HkIntegrityEmit(_In_ uint32_t signal_id, _In_ uint32_t finding,
                     _In_ uint64_t detail_masked);

/* ---- ModuleMap.c (shared scan substrate; always compiled) ---- */
/* Builds Map from SystemModuleInformation. PASSIVE_LEVEL only (ZwQuery...).
 * Returns STATUS_SUCCESS and a populated Map, or a failure NTSTATUS with
 * Map->Count == 0 (a sensor that gets an empty map emits nothing — guardrail #5
 * "emit nothing rather than garbage"). */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS HkModuleMapBuild(_Out_ PHK_MODULE_MAP Map);
/* Resolve an address to a module index via the pure resolver, or
 * HK_MODRANGE_NONE. Thin wrapper over HkModuleRangeResolve for call-site clarity. */
size_t   HkModuleMapResolve(_In_ const HK_MODULE_MAP* Map, _In_ uint64_t Addr);
/* No-op today (the map is a fixed-size context-embedded struct, not heap), kept
 * so the build/free lifecycle is explicit and a future heap map can hook here. */
void     HkModuleMapFree(_Inout_ PHK_MODULE_MAP Map);

/* ---- HkIntegrityScan.c (orchestrator; always compiled) ---- */
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS HkIntegrityScanInit(_In_ PHK_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL) void     HkIntegrityScanStop(_In_ PHK_DEVICE_CONTEXT Ctx);
/* Runs one full scan: builds the ModuleMap once, fans out to every enabled
 * sensor, frees the map. PASSIVE_LEVEL (called from the work item or a rescan
 * IOCTL that queues the work item). */
_IRQL_requires_max_(PASSIVE_LEVEL) void     HkIntegrityScanAll(_In_ PHK_DEVICE_CONTEXT Ctx);
/* Triggered by HK_IOCTL_INTEGRITY_RESCAN: queues the scan work item if armed.
 * Safe at DISPATCH_LEVEL (only queues a work item). Returns STATUS_SUCCESS if a
 * scan was queued, STATUS_DEVICE_NOT_READY if the scan engine is not armed. */
NTSTATUS HkIntegrityRequestRescan(_In_ PHK_DEVICE_CONTEXT Ctx);

/* ---- Per-signal sensors. Each is a no-op when its build flag is OFF. The
 * signature takes the shared, already-built ModuleMap where the sensor needs it
 * (29/31/32/34/35); 28/30/33/36 take only the context. ---- */
_IRQL_requires_max_(PASSIVE_LEVEL) void HkMinifilterAudit(_In_ PHK_DEVICE_CONTEXT Ctx);                                  /* 28 */
_IRQL_requires_max_(PASSIVE_LEVEL) void HkImageHashAudit(_In_ PHK_DEVICE_CONTEXT Ctx, _In_ const HK_MODULE_MAP* Map);   /* 29 */
_IRQL_requires_max_(PASSIVE_LEVEL) void HkCodeIntegrityBaseline(_In_ PHK_DEVICE_CONTEXT Ctx);                           /* 30 */
_IRQL_requires_max_(PASSIVE_LEVEL) void HkCodeIntegrityRescan(_In_ PHK_DEVICE_CONTEXT Ctx);                             /* 30 */
_IRQL_requires_max_(PASSIVE_LEVEL) void HkCallbackResidencyScan(_In_ PHK_DEVICE_CONTEXT Ctx, _In_ const HK_MODULE_MAP* Map); /* 31 */
_IRQL_requires_max_(PASSIVE_LEVEL) void HkNonImageScan(_In_ PHK_DEVICE_CONTEXT Ctx, _In_ const HK_MODULE_MAP* Map);     /* 32 */
_IRQL_requires_max_(PASSIVE_LEVEL) void HkDebugStateProbe(_In_ PHK_DEVICE_CONTEXT Ctx);                                 /* 33 */
_IRQL_requires_max_(PASSIVE_LEVEL) void HkDriverObjectAudit(_In_ PHK_DEVICE_CONTEXT Ctx, _In_ const HK_MODULE_MAP* Map);/* 34 */
_IRQL_requires_max_(PASSIVE_LEVEL) void HkSsdtIntegrityScan(_In_ PHK_DEVICE_CONTEXT Ctx, _In_ const HK_MODULE_MAP* Map);/* 35 */
_IRQL_requires_max_(PASSIVE_LEVEL) void HkBootLoadAudit(_In_ PHK_DEVICE_CONTEXT Ctx);                                   /* 36 */

/* -------------------------------------------------------------------------
 * Syscall / ETW / PatchGuard surface-integrity sensors (win-kernel-syscall-etw-
 * integrity, signals 208..216). All READ-ONLY: they sample and bounds-check the
 * x64 dispatch/ETW surface, then emit HK_EVENT_INTEGRITY_FINDING; the server
 * scores. They register as additional fan-out targets of the SAME PASSIVE_LEVEL
 * work item owned by HkIntegrityScan.c (no second work item). The per-CPU reads
 * (210 LSTAR, 214 IDT) are dispatched via KeIpiGenericCall, which raises to IPI
 * level ONLY for the brief read. Each .c compiles to a no-op stub when its
 * HK_WIN_SYSCALL_*/HK_WIN_ETW_* build flag is OFF.
 * ------------------------------------------------------------------------- */

/* ---- KernelImageMap.c (shared scan cache for 208/209/211/213/214; always
 * compiled). Maps ntoskrnl/hal/win32k image ranges and the on-disk ntoskrnl
 * .text view. If the sibling ModuleMap.c is present (it is), this is a thin
 * adapter over it for the range half; the on-disk .text view is the only new
 * substrate. ---- */
typedef struct _HK_KERNEL_IMAGE {
    uint64_t NtoskrnlBase;   /* ntoskrnl image base, 0 if unresolved. */
    uint64_t NtoskrnlSize;   /* ntoskrnl SizeOfImage. */
    uint64_t HalBase;        /* hal image base, 0 if unresolved. */
    uint64_t HalSize;
    BOOLEAN  Valid;          /* FALSE => sensors emit nothing / UNVERIFIABLE. */
} HK_KERNEL_IMAGE, *PHK_KERNEL_IMAGE;

/* Build the kernel-image cache from the already-built ModuleMap (resolves
 * ntoskrnl/hal by name). PASSIVE_LEVEL. Returns STATUS_SUCCESS with Img->Valid
 * set, or a failure NTSTATUS with Img->Valid == FALSE. */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS HkKernelImageMapBuild(_In_ const HK_MODULE_MAP* Map, _Out_ PHK_KERNEL_IMAGE Img);
/* TRUE iff Addr lands inside ntoskrnl OR hal. Pure range test over the cache. */
int      HkKernelImageContains(_In_ const HK_KERNEL_IMAGE* Img, _In_ uint64_t Addr);
void     HkKernelImageMapFree(_Inout_ PHK_KERNEL_IMAGE Img);

/* ---- Arm-time baseline capture (called from HkIntegrityScanInit). Snapshots the
 * SSDT/ETW baselines into the context. PASSIVE_LEVEL. Always compiled; the
 * unexported-global halves it cannot resolve leave Valid==FALSE. ---- */
_IRQL_requires_max_(PASSIVE_LEVEL) void HkSyscallEtwArm(_In_ PHK_DEVICE_CONTEXT Ctx);

/* ---- Per-signal sensors. Each is a no-op when its build flag is OFF. They take
 * the shared HK_KERNEL_IMAGE cache where they range-check addresses. ---- */
_IRQL_requires_max_(PASSIVE_LEVEL) void HkSsdtValidate(_In_ PHK_DEVICE_CONTEXT Ctx, _In_ const HK_KERNEL_IMAGE* Img);      /* 208 */
_IRQL_requires_max_(PASSIVE_LEVEL) void HkShadowSsdtValidate(_In_ PHK_DEVICE_CONTEXT Ctx, _In_ const HK_KERNEL_IMAGE* Img);/* 209 */
_IRQL_requires_max_(PASSIVE_LEVEL) void HkLstarValidate(_In_ PHK_DEVICE_CONTEXT Ctx, _In_ const HK_KERNEL_IMAGE* Img);     /* 210 */
_IRQL_requires_max_(PASSIVE_LEVEL) void HkInfinityHookProbe(_In_ PHK_DEVICE_CONTEXT Ctx, _In_ const HK_KERNEL_IMAGE* Img); /* 211 */
_IRQL_requires_max_(PASSIVE_LEVEL) void HkEtwTiLiveness(_In_ PHK_DEVICE_CONTEXT Ctx);                                      /* 212 */
_IRQL_requires_max_(PASSIVE_LEVEL) void HkSyscallPrologueScan(_In_ PHK_DEVICE_CONTEXT Ctx, _In_ const HK_KERNEL_IMAGE* Img);/* 213 */
_IRQL_requires_max_(PASSIVE_LEVEL) void HkIdtValidate(_In_ PHK_DEVICE_CONTEXT Ctx, _In_ const HK_KERNEL_IMAGE* Img);       /* 214 */
_IRQL_requires_max_(PASSIVE_LEVEL) void HkEtwSessionCensus(_In_ PHK_DEVICE_CONTEXT Ctx);                                   /* 215 */
_IRQL_requires_max_(PASSIVE_LEVEL) void HkSsdtBaselineCheck(_In_ PHK_DEVICE_CONTEXT Ctx, _In_ const HK_KERNEL_IMAGE* Img); /* 216 */

/* ---- IrpDispatch.c ---- */
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL HkEvtIoDeviceControl;
