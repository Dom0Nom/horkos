/*
 * sdk/include/horkos/ioctl.h
 * Role: Userspace <-> kernel IOCTL contract for the Horkos Windows driver.
 *       Defines the IOCTL control codes and the DRAIN buffer envelope that
 *       wraps the shared event records from event_schema.h.
 * Target platforms: Windows (the IOCTL codes are Windows CTL_CODE values),
 *       but the header is plain C99 and includes NO platform headers, so it
 *       is includable from a kernel TU and a userspace TU alike (never the
 *       same TU — guardrail #4).
 * Interface: kernel/win/src/IrpDispatch.c handles each code; the SDK
 *       (sdk/src/sdk.cpp) and tests/integration/win/ioctl_smoke.cpp issue them.
 *
 * Wire-format note: every field is a fixed-width <stdint.h> type. The Windows
 * CTL_CODE macro is reproduced here verbatim from the public WDK definition so
 * that this header needs no <winioctl.h> include and stays platform-clean.
 */

#pragma once

#include <stdint.h>

#include "horkos/event_schema.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * CTL_CODE reproduction.
 * Identical to the macro in <winioctl.h>:
 *   (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
 * Reproduced (not included) to keep this header free of platform headers.
 * ------------------------------------------------------------------------- */
#ifndef HK_CTL_CODE
#  define HK_CTL_CODE(DeviceType, Function, Method, Access) \
      (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif

/* METHOD_BUFFERED == 0; FILE_DEVICE_UNKNOWN == 0x22; FILE_ANY_ACCESS == 0. */
#define HK_METHOD_BUFFERED      0u
#define HK_FILE_DEVICE_UNKNOWN  0x22u
#define HK_FILE_ANY_ACCESS      0u

/* Custom function codes must be >= 0x800 (vendor range) per WDK guidance. */
#define HK_IOCTL_DRAIN_EVENTS \
    HK_CTL_CODE(HK_FILE_DEVICE_UNKNOWN, 0x800, HK_METHOD_BUFFERED, HK_FILE_ANY_ACCESS)
#define HK_IOCTL_GET_STATUS \
    HK_CTL_CODE(HK_FILE_DEVICE_UNKNOWN, 0x801, HK_METHOD_BUFFERED, HK_FILE_ANY_ACCESS)
#define HK_IOCTL_PUSH_POLICY \
    HK_CTL_CODE(HK_FILE_DEVICE_UNKNOWN, 0x802, HK_METHOD_BUFFERED, HK_FILE_ANY_ACCESS)
/* Memory-scan plane (schema v3). DRAIN_MEM_EVENTS strides the large
 * hk_event_mem_record; SCAN_PROCESS enqueues a target PID for the scan worker. */
#define HK_IOCTL_DRAIN_MEM_EVENTS \
    HK_CTL_CODE(HK_FILE_DEVICE_UNKNOWN, 0x803, HK_METHOD_BUFFERED, HK_FILE_ANY_ACCESS)
#define HK_IOCTL_SCAN_PROCESS \
    HK_CTL_CODE(HK_FILE_DEVICE_UNKNOWN, 0x804, HK_METHOD_BUFFERED, HK_FILE_ANY_ACCESS)

/* User-visible device name. Kernel creates \Device\Horkos with a symlink at
 * \DosDevices\Horkos; userspace opens \\.\Horkos. */
#define HK_DEVICE_NAME_KERNEL   L"\\Device\\Horkos"
#define HK_DEVICE_SYMLINK       L"\\DosDevices\\Horkos"
#define HK_DEVICE_PATH_USER     "\\\\.\\Horkos"

/* -------------------------------------------------------------------------
 * One serialized event record: the common header followed by the largest
 * payload the schema defines. Fixed size so the ring buffer is an array of
 * these and the DRAIN envelope can be a flat copy.
 * ------------------------------------------------------------------------- */
#define HK_EVENT_PAYLOAD_MAX 16u  /* Largest payload struct in event_schema.h. */

typedef struct hk_event_record {
    hk_event_header header;                 /* 24 bytes. */
    uint8_t         payload[HK_EVENT_PAYLOAD_MAX]; /* 16 bytes. */
} hk_event_record;                          /* 40 bytes total. */

/* -------------------------------------------------------------------------
 * HK_IOCTL_DRAIN_EVENTS output envelope.
 * Userspace supplies a buffer of (header + N records). The kernel fills as
 * many records as fit and reports how many it wrote and how many remain.
 * ------------------------------------------------------------------------- */
typedef struct hk_drain_header {
    uint32_t records_written;   /* Records the kernel copied into this buffer. */
    uint32_t records_remaining; /* Records still queued after this drain.      */
    uint32_t records_dropped;   /* Cumulative records dropped on overflow.     */
    uint32_t reserved;          /* Must be zero. */
} hk_drain_header;

/* -------------------------------------------------------------------------
 * HK_IOCTL_GET_STATUS output.
 * ------------------------------------------------------------------------- */
typedef struct hk_status {
    uint32_t driver_version;        /* HK_DRIVER_VERSION below. */
    uint32_t flags;                 /* HK_STATUS_FLAG_* bitmask. */
    uint64_t events_total;          /* Total events captured since load. */
    uint64_t events_dropped;        /* Total events dropped on ring overflow. */
    uint32_t notify_routines_armed; /* Count of registered notify routines. */
    uint32_t ob_callbacks_armed;    /* 1 if ObRegisterCallbacks succeeded. */
} hk_status;

#define HK_DRIVER_VERSION            0x00010000u /* 1.0.0 */
#define HK_STATUS_FLAG_RING_OVERFLOW 0x00000001u
#define HK_STATUS_FLAG_OB_ACTIVE     0x00000002u
#define HK_STATUS_FLAG_BYOVD_ARMED   0x00000004u

/* -------------------------------------------------------------------------
 * HK_IOCTL_PUSH_POLICY input.
 * Phase 3 carries only the BYOVD enforcement toggle and the Ob rights-strip
 * toggle; both default OFF. Real policy plumbing (signed bundles) lands later.
 * ------------------------------------------------------------------------- */
typedef struct hk_policy {
    uint32_t enable_byovd_block;   /* 0/1: block known-bad driver image loads. */
    uint32_t enable_ob_strip;      /* 0/1: strip rights in the Ob pre-callback. */
    uint32_t reserved0;
    uint32_t reserved1;
} hk_policy;

/* -------------------------------------------------------------------------
 * Wire-format size pins. Both the kernel TU and every userspace TU that
 * includes this header compile these; any struct-layout drift breaks the
 * build on both sides (Step 3.5). Uses HK_STATIC_ASSERT from event_schema.h so
 * it compiles on a plain-C99 kernel build, not only C11/C++.
 * ------------------------------------------------------------------------- */
HK_STATIC_ASSERT(sizeof(hk_event_record) == 40, "hk_event_record wire size drift");
HK_STATIC_ASSERT(sizeof(hk_drain_header) == 16, "hk_drain_header wire size drift");
HK_STATIC_ASSERT(sizeof(hk_status) == 32,       "hk_status wire size drift");
HK_STATIC_ASSERT(sizeof(hk_policy) == 16,       "hk_policy wire size drift");

/* -------------------------------------------------------------------------
 * Memory-scan large-record plane (schema v3).
 * Memory/image-anomaly payloads (event_schema.h types 5..13) exceed the
 * 16-byte hk_event_record payload. Rather than widen HK_EVENT_PAYLOAD_MAX
 * (which would bloat the main 4096-slot ring 8-16x), a SECOND fixed-size record
 * type sized to the largest memory payload (hk_event_mem_module_stomp, 304B)
 * is drained via HK_IOCTL_DRAIN_MEM_EVENTS. Both record families share
 * hk_event_header so the server demuxes on header.type.
 * ------------------------------------------------------------------------- */
#define HK_EVENT_MEM_PAYLOAD_MAX 320u /* >= sizeof(hk_event_mem_module_stomp). */
#define HK_MEM_RING_CAPACITY     256u /* power of two; big slots stay bounded. */

typedef struct hk_event_mem_record {
    hk_event_header header;                          /* 24 bytes (shared). */
    uint8_t         payload[HK_EVENT_MEM_PAYLOAD_MAX]; /* 320 bytes. */
} hk_event_mem_record;                               /* 344 bytes total. */

/* HK_IOCTL_SCAN_PROCESS input: enqueue a target for the scan worker. */
typedef struct hk_scan_request {
    uint32_t target_pid;
    uint32_t signal_mask;   /* bit per signal 10..18; 0 = all enabled. */
    uint32_t flags;         /* reserved (e.g. force-resample). */
    uint32_t reserved;      /* must be zero. */
} hk_scan_request;

/* HK_IOCTL_DRAIN_MEM_EVENTS reuses hk_drain_header as its envelope but strides
 * hk_event_mem_record. The largest memory payload must fit the record. */
HK_STATIC_ASSERT(sizeof(hk_event_mem_record) == 344, "hk_event_mem_record wire size drift");
HK_STATIC_ASSERT(sizeof(hk_scan_request) == 16,      "hk_scan_request wire size drift");
HK_STATIC_ASSERT(sizeof(hk_event_mem_module_stomp) <= HK_EVENT_MEM_PAYLOAD_MAX,
    "hk_event_mem_module_stomp exceeds HK_EVENT_MEM_PAYLOAD_MAX");
HK_STATIC_ASSERT(sizeof(hk_event_mem_unsigned_image) <= HK_EVENT_MEM_PAYLOAD_MAX,
    "hk_event_mem_unsigned_image exceeds HK_EVENT_MEM_PAYLOAD_MAX");
HK_STATIC_ASSERT(sizeof(hk_event_mem_image_anomaly) <= HK_EVENT_MEM_PAYLOAD_MAX,
    "hk_event_mem_image_anomaly exceeds HK_EVENT_MEM_PAYLOAD_MAX");

#ifdef __cplusplus
} /* extern "C" */
#endif
