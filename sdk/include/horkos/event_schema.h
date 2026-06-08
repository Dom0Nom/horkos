/*
 * sdk/include/horkos/event_schema.h
 * Role: Wire-format source of truth for all Horkos events.
 *       Phase 2 Rust serde structs mirror these field names and sizes.
 *       Phase 3 IOCTL header includes this file directly.
 *       Any field addition bumps HK_EVENT_SCHEMA_VERSION; no field renames;
 *       deprecated fields stay as reserved padding (see docs/event-schema.md).
 * Target platforms: all (plain C99, no platform headers, no compiler extensions).
 * Interface: included by both kernel TUs and userspace TUs — never in the same
 *            translation unit (guardrail #4).
 */

#pragma once

#include <stdint.h>

/* -------------------------------------------------------------------------
 * HK_STATIC_ASSERT — portable compile-time assert.
 * Bare `static_assert` is C++/C11 only; an MSVC kernel C build targeting an
 * older C dialect rejects it, which would break the kernel build before any
 * driver code compiles. Pick the strongest form the current dialect supports
 * and fall back to the negative-array typedef trick on plain C99.
 * ------------------------------------------------------------------------- */
#if defined(__cplusplus)
#  define HK_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#  define HK_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#else
#  define HK_SA_CAT_(a, b) a##b
#  define HK_SA_CAT(a, b) HK_SA_CAT_(a, b)
/* Keyed on __COUNTER__ (not __LINE__) so two asserts at the same line in
 * different headers within one TU cannot collide into a duplicate typedef. */
#  define HK_STATIC_ASSERT(cond, msg) \
      typedef char HK_SA_CAT(hk_static_assert_, __COUNTER__)[(cond) ? 1 : -1]
#endif

/* Schema version. Bumped on every additive field change. Mirrored by the
 * Phase 2 server in lockstep. v2 added hk_event_process_exit and the image
 * flags field. */
#define HK_EVENT_SCHEMA_VERSION 2u

/* -------------------------------------------------------------------------
 * Event type enumeration.
 * New types are appended; existing values never change.
 * ------------------------------------------------------------------------- */
typedef enum hk_event_type {
    HK_EVENT_UNKNOWN         = 0,
    HK_EVENT_PROCESS_CREATE  = 1,
    HK_EVENT_PROCESS_EXIT    = 2,
    HK_EVENT_IMAGE_LOAD      = 3,
    HK_EVENT_HANDLE_OPEN     = 4,
} hk_event_type;

/* -------------------------------------------------------------------------
 * Common event header — present at the start of every event payload.
 * Fixed size: 24 bytes. Verified by HK_STATIC_ASSERT below.
 * ------------------------------------------------------------------------- */
typedef struct hk_event_header {
    uint32_t version;        /* HK_EVENT_SCHEMA_VERSION at emit time. */
    uint32_t type;           /* One of hk_event_type. */
    uint64_t timestamp_ns;   /* Monotonic ns (boot/interrupt epoch) at emit. */
    uint32_t payload_bytes;  /* Size of the payload struct that follows. */
    uint32_t reserved;       /* Padding to 24 bytes; must be zero. */
} hk_event_header;

HK_STATIC_ASSERT(sizeof(hk_event_header) == 24,
    "hk_event_header size mismatch — update the kernel-event serde mirror when "
    "it lands (not yet present in server/)");

/* -------------------------------------------------------------------------
 * Payload: HK_EVENT_PROCESS_CREATE
 * Fixed size: 16 bytes.
 * ------------------------------------------------------------------------- */
typedef struct hk_event_process_create {
    uint32_t pid;            /* New process PID. */
    uint32_t parent_pid;     /* Parent process PID. */
    uint64_t create_time_ns; /* Process creation time, 1601/FILETIME epoch ns.
                                NOTE: different epoch from header.timestamp_ns;
                                the server must not compare the two directly. */
} hk_event_process_create;

HK_STATIC_ASSERT(sizeof(hk_event_process_create) == 16,
    "hk_event_process_create size mismatch");

/* -------------------------------------------------------------------------
 * Payload: HK_EVENT_PROCESS_EXIT
 * Fixed size: 16 bytes. Added in schema v2.
 * ------------------------------------------------------------------------- */
typedef struct hk_event_process_exit {
    uint32_t pid;            /* Exiting process PID. */
    uint32_t reserved;       /* Padding; must be zero. */
    uint64_t exit_time_ns;   /* Exit time, monotonic ns (boot/interrupt epoch). */
} hk_event_process_exit;

HK_STATIC_ASSERT(sizeof(hk_event_process_exit) == 16,
    "hk_event_process_exit size mismatch");

/* -------------------------------------------------------------------------
 * Payload: HK_EVENT_IMAGE_LOAD
 * Fixed size: 16 bytes. The former 'reserved' word became 'flags' in v2
 * (size unchanged; old readers saw zero there, which is HK_IMAGE_FLAG none).
 * ------------------------------------------------------------------------- */
typedef struct hk_event_image_load {
    uint32_t pid;            /* PID of the loading process. */
    uint32_t flags;          /* HK_IMAGE_FLAG_* bitmask (0 = normal load). */
    uint64_t image_base;     /* Virtual base address where the image was mapped. */
} hk_event_image_load;

HK_STATIC_ASSERT(sizeof(hk_event_image_load) == 16,
    "hk_event_image_load size mismatch");

/* Image-load flags. */
#define HK_IMAGE_FLAG_BYOVD_SUSPECT 0x00000001u

/* -------------------------------------------------------------------------
 * Payload: HK_EVENT_HANDLE_OPEN
 * Fixed size: 16 bytes.
 * ------------------------------------------------------------------------- */
typedef struct hk_event_handle_open {
    uint32_t requesting_pid; /* PID that opened the handle. */
    uint32_t target_pid;     /* PID of the process whose handle was opened. */
    uint32_t access_mask;    /* OriginalDesiredAccess the requester asked for. */
    uint32_t reserved;       /* Padding; must be zero. */
} hk_event_handle_open;

HK_STATIC_ASSERT(sizeof(hk_event_handle_open) == 16,
    "hk_event_handle_open size mismatch");
