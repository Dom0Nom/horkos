/*
 * sdk/include/horkos/event_schema.h
 * Role: Wire-format source of truth for all Horkos events.
 *       Phase 2 Rust serde structs mirror these field names and sizes.
 *       Phase 3 IOCTL header includes this file directly.
 *       Any field addition bumps the version field; no field renames;
 *       deprecated fields stay as reserved padding (see docs/event-schema.md).
 * Target platforms: all (plain C99, no platform headers, no compiler extensions).
 * Interface: included by both kernel TUs and userspace TUs — never in the same
 *            translation unit (guardrail #4).
 */

#pragma once

#include <stdint.h>

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
 * Fixed size: 24 bytes. Verified by static_assert below.
 * ------------------------------------------------------------------------- */
typedef struct hk_event_header {
    uint32_t version;        /* Schema version; bumped on every field addition. */
    uint32_t type;           /* One of hk_event_type. */
    uint64_t timestamp_ns;   /* Monotonic nanoseconds since process start. */
    uint32_t payload_bytes;  /* Size of the payload struct that follows. */
    uint32_t reserved;       /* Padding to 24 bytes; must be zero. */
} hk_event_header;

static_assert(sizeof(hk_event_header) == 24,
    "hk_event_header size mismatch — update Phase 2 serde mirror");

/* -------------------------------------------------------------------------
 * Payload: HK_EVENT_PROCESS_CREATE
 * Fixed size: 16 bytes. Verified by static_assert below.
 * ------------------------------------------------------------------------- */
typedef struct hk_event_process_create {
    uint32_t pid;            /* New process PID. */
    uint32_t parent_pid;     /* Parent process PID. */
    uint64_t create_time_ns; /* Process creation time (monotonic ns). */
} hk_event_process_create;

static_assert(sizeof(hk_event_process_create) == 16,
    "hk_event_process_create size mismatch");

/* -------------------------------------------------------------------------
 * Payload: HK_EVENT_IMAGE_LOAD
 * Fixed size: 16 bytes. Verified by static_assert below.
 * ------------------------------------------------------------------------- */
typedef struct hk_event_image_load {
    uint32_t pid;            /* PID of the loading process. */
    uint32_t reserved;       /* Padding; must be zero. */
    uint64_t image_base;     /* Virtual base address where the image was mapped. */
} hk_event_image_load;

static_assert(sizeof(hk_event_image_load) == 16,
    "hk_event_image_load size mismatch");

/* -------------------------------------------------------------------------
 * Payload: HK_EVENT_HANDLE_OPEN
 * Fixed size: 16 bytes. Verified by static_assert below.
 * ------------------------------------------------------------------------- */
typedef struct hk_event_handle_open {
    uint32_t requesting_pid; /* PID that opened the handle. */
    uint32_t target_pid;     /* PID of the process whose handle was opened. */
    uint32_t access_mask;    /* Requested access rights. */
    uint32_t reserved;       /* Padding; must be zero. */
} hk_event_handle_open;

static_assert(sizeof(hk_event_handle_open) == 16,
    "hk_event_handle_open size mismatch");
