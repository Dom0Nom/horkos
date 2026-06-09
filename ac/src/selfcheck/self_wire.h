/*
 * ac/src/selfcheck/self_wire.h
 * Role: Userspace-private wire mirrors for the client self-integrity events
 *       (memory-integrity-selfcheck, catalog signals 145-153) and the self-read
 *       IOCTL request. The Schema phase has NOT yet landed these in the frozen
 *       headers (sdk/include/horkos/event_schema.h, sdk/include/horkos/ioctl.h),
 *       and the large-record drain plane (hk_event_mem_record /
 *       HK_IOCTL_DRAIN_MEM_EVENTS) the plan reuses is likewise absent. Per the
 *       task constraint we do NOT add wire types to the frozen schema TUs; these
 *       mirrors compile the sensors now and are pinned by HK_STATIC_ASSERT so any
 *       future divergence from the eventual frozen types breaks THIS build, not
 *       just the server side.
 * Target platforms: all (plain C99-shaped structs over <stdint.h>; this is a
 *       userspace-only mirror — guardrail #4: never #included by a kernel TU).
 * Interface: consumed by the ac/src/selfcheck TUs and tests; mirrored on the server
 *       by server/telemetry/src/self_events.rs (same field order/sizes).
 *
 * HK-TODO(schema): every symbol below moves to the frozen schema when the Schema
 * phase lands. The event-type discriminants continue the numbering the plan
 * sketches (14..22); they are LOCAL consts here exactly as
 * server/telemetry/src/vm_access.rs mirrors its 5..8 block pre-Schema. Until the
 * frozen enum gains these values the records cannot cross the existing 40-byte
 * HK_IOCTL_DRAIN_EVENTS envelope as DISTINCT decodable types — the large-record
 * plane they need (HK_EVENT_MEM_PAYLOAD_MAX) is itself pre-Schema. This is the
 * intended, flagged gap; do NOT widen the frozen 40-byte ring from this domain.
 */

#pragma once

#include <stdint.h>

#include "horkos/event_schema.h"  /* HK_STATIC_ASSERT only (no field reuse). */

/* -------------------------------------------------------------------------
 * Event-type discriminants (continue after the memory-injection block which the
 * plan ends at 13). LOCAL until the Schema phase appends them to hk_event_type.
 * ------------------------------------------------------------------------- */
#ifndef HK_EVENT_SELF_CROSSVIEW
#  define HK_EVENT_SELF_CROSSVIEW   14u
#  define HK_EVENT_SELF_PAGE_COW    15u
#  define HK_EVENT_SELF_RETADDR     16u
#  define HK_EVENT_SELF_HWBP        17u
#  define HK_EVENT_SELF_IAT_TARGET  18u
#  define HK_EVENT_SELF_VEH_UNWIND  19u
#  define HK_EVENT_SELF_LOADER      20u
#  define HK_EVENT_SELF_WX_DRIFT    21u
#  define HK_EVENT_SELF_TLS_INIT    22u
#endif

/* The shared self-check frame cap (must match selfcheck.h HK_SELF_MAX_FRAMES). */
#ifndef HK_SELF_MAX_FRAMES
#  define HK_SELF_MAX_FRAMES 16u
#endif

/* -------------------------------------------------------------------------
 * Payload structs. Each begins pid + image_base so the server correlates across
 * signals. Sizes pinned. The largest (crossview, 120 bytes) sets the floor for
 * the shared HK_EVENT_MEM_PAYLOAD_MAX the plan reconciles with the memory-
 * injection domain. HK-TODO(schema): take max(this domain, mem-injection) once
 * both land; do NOT pick a value from this TU.
 * ------------------------------------------------------------------------- */

/* 145 — cross-view hashes. Largest self payload -> pins the shared max. */
typedef struct hk_event_self_crossview {
    uint32_t pid;
    uint32_t section_rva;       /* RVA of the .text range hashed. */
    uint64_t image_base;
    uint8_t  hash_inproc[32];   /* SHA-256 via our own VA read (spoofable view). */
    uint8_t  hash_kernel[32];   /* SHA-256 via kernel foreign read (authoritative). */
    uint8_t  hash_disk[32];     /* SHA-256 of relocated on-disk bytes. */
    uint32_t match_matrix;      /* HK_SELF_MATCH_* bits. */
    uint32_t first_diff_rva;    /* first byte where the diverging pair differs, else 0. */
} hk_event_self_crossview;
HK_STATIC_ASSERT(sizeof(hk_event_self_crossview) == 120,
    "hk_event_self_crossview size drift (HK-TODO schema mirror)");

/* 146 — page CoW/share audit. */
typedef struct hk_event_self_page_cow {
    uint32_t pid;
    uint32_t page_count;        /* pages covered by this report. */
    uint64_t image_base;
    uint64_t region_base;       /* first page VA. */
    uint32_t private_pages;     /* pages that became private/CoW (share-count dropped). */
    uint32_t dirty_pages;       /* soft-dirty / Private_Dirty (Linux) / SM_PRIVATE (mac). */
} hk_event_self_page_cow;
HK_STATIC_ASSERT(sizeof(hk_event_self_page_cow) == 32,
    "hk_event_self_page_cow size drift (HK-TODO schema mirror)");

/* 147 — return-address provenance. Bounded frame array. */
typedef struct hk_event_self_retaddr {
    uint32_t pid;
    uint32_t guarded_fn_id;     /* which HK_GUARD_ENTRY site fired. */
    uint64_t frames[HK_SELF_MAX_FRAMES];  /* captured return addresses. */
    uint16_t frame_count;
    uint16_t unsigned_frame_idx;/* index of first unsigned/private frame, 0xFFFF if none. */
    uint32_t shadow_stack_mismatch; /* 0/1 from CET SSP cross-check when CET active. */
} hk_event_self_retaddr;
HK_STATIC_ASSERT(sizeof(hk_event_self_retaddr) == 144,
    "hk_event_self_retaddr size drift (HK-TODO schema mirror)");

/* 148 — hardware-breakpoint audit (kernel-context DR read). */
typedef struct hk_event_self_hwbp {
    uint32_t pid;
    uint32_t thread_id;
    uint64_t dr[4];             /* DR0-DR3 linear addresses. */
    uint32_t dr7;               /* enable bits. */
    uint32_t dr_in_text_mask;   /* bit i set if DRi lands inside our .text. */
} hk_event_self_hwbp;
HK_STATIC_ASSERT(sizeof(hk_event_self_hwbp) == 48,
    "hk_event_self_hwbp size drift (HK-TODO schema mirror)");

/* 149 — IAT/GOT target audit (one flagged slot per record). */
typedef struct hk_event_self_iat_target {
    uint32_t pid;
    uint32_t slot_rva;          /* RVA of the IAT/GOT slot. */
    uint64_t slot_target_va;    /* where the slot currently points. */
    uint64_t expected_va;       /* recomputed expected export VA. */
    uint32_t target_flags;      /* HK_SELF_TGT_* */
    uint32_t import_class;      /* HK_SELF_IMPCLASS_* (scoped imports only). */
} hk_event_self_iat_target;
HK_STATIC_ASSERT(sizeof(hk_event_self_iat_target) == 32,
    "hk_event_self_iat_target size drift (HK-TODO schema mirror)");

/* 150/151/152/153 — compact {pid, image_base, table_rva, expected, actual, flags}
 * shapes. Each pinned; the meaning of expected/actual/flags is per-signal (see the
 * field comments). All 40 bytes so they share a stride. */
typedef struct hk_event_self_compat {
    uint32_t pid;
    uint32_t signal_id;         /* 150/151/152/153 — disambiguates which sensor. */
    uint64_t image_base;
    uint64_t table_rva;         /* VEH handler PC RVA / loader xref / page RVA / TLS idx. */
    uint64_t expected_va;       /* expected handler/pointer/prot; meaning per signal_id. */
    uint64_t actual_va;         /* live handler/pointer/prot. */
    uint32_t flags;             /* per-signal bitmask (ordering / xref-broken / prot-split). */
    uint32_t reserved;          /* zero. */
} hk_event_self_compat;
HK_STATIC_ASSERT(sizeof(hk_event_self_compat) == 48,
    "hk_event_self_compat size drift (HK-TODO schema mirror)");

/* 151 loader xref-broken flag bits (hk_event_self_compat.flags when signal_id==151). */
#ifndef HK_SELF_LOADER_BASE_MISMATCH
#  define HK_SELF_LOADER_BASE_MISMATCH   0x00000001u /* LDR base != header/kernel/disk */
#  define HK_SELF_LOADER_SIZE_MISMATCH   0x00000002u
#  define HK_SELF_LOADER_ENTRY_MISMATCH  0x00000004u
#  define HK_SELF_LOADER_LIST_INCONSIST  0x00000008u /* InLoad/InMemory/InInit disagree (unlink) */
#  define HK_SELF_LOADER_PATH_MISMATCH   0x00000010u /* canonical path drift (low weight) */
#endif

/* 152 wx-drift flag bits (signal_id==152): kernel-says-writable vs usermode-RX. */
#ifndef HK_SELF_WX_KERNEL_WRITABLE
#  define HK_SELF_WX_KERNEL_WRITABLE     0x00000001u /* leaf PTE write bit set on a +X page */
#  define HK_SELF_WX_KERNEL_NX_CLEARED   0x00000002u /* NX cleared where image expects NX  */
#  define HK_SELF_WX_USERMODE_RX         0x00000004u /* usermode view still reports R-X     */
#endif

/* -------------------------------------------------------------------------
 * Self-read IOCTL request (the AC asks the kernel to read ITS OWN address
 * space). Mirror of the plan's HK_IOCTL_SELF_READ_VA payload. HK-TODO(schema):
 * the IOCTL code + this struct move to sdk/include/horkos/ioctl.h.
 * ------------------------------------------------------------------------- */
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
