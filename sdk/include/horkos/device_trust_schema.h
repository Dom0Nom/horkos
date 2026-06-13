/*
 * Role: Wire-format source of truth for the USB/HID device-trust sensor findings
 *       (hardware-input-devices domain, catalog signals 136-144). Defines four
 *       fixed-size records: the hk_device_descriptor_audit detail block
 *       (descriptor-coherence / topology, 137/140/141/143), the
 *       hk_event_hid_descriptor structural fingerprint (136), the
 *       hk_pointer_cadence_features block (139 poll-interval ceiling + 144
 *       arrival/lifetime, FEATURES ONLY), and the hk_event_pointer_features ML
 *       feature vector (142, FEATURES ONLY). EXTENDS, does not replace,
 *       input_prov_schema.h — it reuses hk_input_verdict (incl. the additive
 *       HK_INPUT_SRC_DESCRIPTOR_INCOHERENT = 7) for descriptor-audit verdicts so a
 *       third verdict enum is not forked. The pointer-ML / cadence records carry
 *       float feature vectors and therefore have NO verdict field (catalog mandate:
 *       ship features to the server model, never a client-side ban). The opaque
 *       hdevice_token / container_token are per-session salted pseudonyms, never the
 *       raw device path / serial / location-id (privacy; see data-categories §5).
 * Target platforms: all (plain C99, no platform headers, no compiler extensions —
 *       compiles on a C99 kernel-warning build, a C++ usermode build, and an
 *       Objective-C++ daemon build alike via HK_STATIC_ASSERT from event_schema.h).
 * Interface: mirrored by server/telemetry/src/device_trust.rs (audit + HID
 *       fingerprint), server/telemetry/src/input_cadence.rs (cadence features), and
 *       server/telemetry/src/pointer_model.rs (pointer feature vector). Included by
 *       the SDK usermode input TUs (sdk/src/backends/{win,posix}/input/), the macOS
 *       daemon input TUs (daemon/macos/input/), and the eBPF USERSPACE loader TU only
 *       — NEVER a kernel-driver / eBPF .bpf.c TU (guardrail #4). The eBPF kernel-side
 *       provenance record (hk_input_prov_bpf) is a SEPARATE packed struct in
 *       kernel/linux/bpf/include/, not this header. These records ride the HTTP/JSON
 *       telemetry plane, never the HK_IOCTL_DRAIN_EVENTS kernel ring.
 */

#pragma once

#include <stdint.h>

/* Pulls HK_STATIC_ASSERT (and the <stdint.h> width types) plus the hk_input_verdict
 * enum extended with HK_INPUT_SRC_DESCRIPTOR_INCOHERENT. The device-trust plane reuses
 * that verdict enum for descriptor-audit findings; it never reuses the kernel event
 * types (guardrail #4 — no kernel TU includes this header). */
#include "horkos/input_prov_schema.h"

/* Device-trust JSON plane schema version. Independent of HK_EVENT_SCHEMA_VERSION,
 * HK_INPUT_SCHEMA_VERSION, and HK_RENDER_SCHEMA_VERSION; the three server mirrors
 * (DEVICE_TRUST_SCHEMA_VERSION) track this in lockstep. Every additive field bumps
 * it; no field renames. */
#define HK_DEVICE_TRUST_SCHEMA_VERSION 1u

/* ---- Bus type (hk_device_descriptor_audit.bus_type) ----------------------- */
#define HK_BUS_UNKNOWN   0u
#define HK_BUS_USB       1u
#define HK_BUS_BLUETOOTH 2u
#define HK_BUS_VIRTUAL   3u /* BUS_VIRTUAL / uinput / IOHIDUserDevice / DriverKit virtual */

/* ---- Interface-class bitmask (hk_device_descriptor_audit.iface_class_mask) - */
#define HK_IFACE_HID    0x01u /* bInterfaceClass 0x03 present */
#define HK_IFACE_CDC    0x02u /* bInterfaceClass 0x02/0x0A (CDC-ACM) present */
#define HK_IFACE_VENDOR 0x04u /* bInterfaceClass 0xFF (vendor-specific) present */
#define HK_IFACE_HUB    0x08u /* bInterfaceClass 0x09 (hub) present */

/* ---- Descriptor-audit flags (hk_device_descriptor_audit.audit_flags) ------- */
#define HK_DAUD_NULL_SERIAL        0x01u /* iSerialNumber == 0 where the VID class expects one */
#define HK_DAUD_CONTAINER_MISMATCH 0x02u /* HID + CDC/vendor co-resident under one ContainerID (143) */
#define HK_DAUD_BRIDGE_SIGNATURE   0x04u /* bcdDevice/bMaxPacketSize0 matches a known bridge chip (137) */
#define HK_DAUD_NO_USB_PARENT      0x08u /* evdev/IOHID device with no USB parent in the topology (140/141) */
#define HK_DAUD_CREATOR_KNOWN      0x10u /* creator_pid resolved (uinput/dext); server allowlists it */
#define HK_DAUD_INCONCLUSIVE       0x20u /* a descriptor/topology query failed; report, never an anomaly */

/* ---- HID-fingerprint flags (hk_event_hid_descriptor.flags) ----------------- */
#define HK_HIDFP_HAS_REPORT_IDS    0x0001u /* descriptor uses report IDs */
#define HK_HIDFP_MULTI_USAGE_PAGE  0x0002u /* > 1 distinct usage page */
#define HK_HIDFP_VENDOR_USAGE      0x0004u /* a vendor-defined usage page (0xFF00..0xFFFF) present */
#define HK_HIDFP_CAPS_TRUNCATED    0x0008u /* HidP_Get*Caps returned more than the canonical buffer held */
#define HK_HIDFP_PREPARSED_FAILED  0x0010u /* HidD_GetPreparsedData/HidP_GetCaps failed -> inconclusive */

/* ---- Cadence-feature flags (hk_pointer_cadence_features.flags) ------------- */
#define HK_CAD_WIRELESS_EXEMPT 0x01u /* receiver re-clocks (dongle/RF); ceiling comparison suppressed */
#define HK_CAD_HOTPLUG         0x02u /* device arrived mid-session (144) */
#define HK_CAD_PRIOR_IDLE      0x04u /* a prior input source went idle as this one became active (144) */
#define HK_CAD_INCONCLUSIVE    0x08u /* the bInterval/endpoint descriptor was not resolvable */

/* -------------------------------------------------------------------------
 * HID descriptor structural fingerprint (catalog 136). The fingerprint is the
 * SHA-256 of the CANONICALIZED preparsed structure (usage pages sorted, report IDs
 * + field counts + per-report byte lengths folded deterministically), NOT the device
 * serial — it is a structure identity the server clusters (QMK/ZMK vs Arduino-HID /
 * V-USB / LUFA template clusters). Never a client verdict.
 * ------------------------------------------------------------------------- */
typedef struct hk_event_hid_descriptor {
    uint32_t schema_version;   /* HK_DEVICE_TRUST_SCHEMA_VERSION at emit. */
    uint16_t vendor_id;        /* claimed VID. */
    uint16_t product_id;       /* claimed PID. */
    uint8_t  fingerprint[32];  /* SHA-256 of the canonicalized preparsed structure. */
    uint16_t usage_page_count; /* distinct usage pages in the descriptor. */
    uint16_t field_count;      /* total HID fields (button + value caps). */
    uint16_t report_id_count;  /* distinct report IDs. */
    uint16_t flags;            /* HK_HIDFP_* bitmask. */
} hk_event_hid_descriptor;
/* 4 + 2 + 2 + 32 + 2 + 2 + 2 + 2 = 48; max member align is 4 (no 64-bit member), so
 * there is no tail padding. */
HK_STATIC_ASSERT(sizeof(hk_event_hid_descriptor) == 48,
    "hk_event_hid_descriptor size mismatch — update server/telemetry/src/device_trust.rs "
    "HidDescriptor in lockstep");

/* -------------------------------------------------------------------------
 * Descriptor-coherence / topology audit detail (catalog 137/140/141/143). The
 * verdict reuses hk_input_verdict (usually HK_INPUT_SRC_DESCRIPTOR_INCOHERENT). The
 * client only ships the tuple + the resolved verdict bucket; the known-hardware
 * corpus / allowlist correlation is server-side (catalog mandate). container_token is
 * an opaque per-session hash of the ContainerID / IORegistry location-id, never the
 * raw id. creator_pid is the uinput/dext creator (140/141), else 0.
 * ------------------------------------------------------------------------- */
typedef struct hk_device_descriptor_audit {
    uint32_t schema_version;   /* HK_DEVICE_TRUST_SCHEMA_VERSION at emit. */
    uint32_t verdict;          /* hk_input_verdict (often _DESCRIPTOR_INCOHERENT). */
    uint16_t vendor_id;        /* claimed VID. */
    uint16_t product_id;       /* claimed PID. */
    uint16_t bcd_usb;          /* bcdUSB. */
    uint16_t bcd_device;       /* bcdDevice. */
    uint8_t  max_packet_size0; /* bMaxPacketSize0. */
    uint8_t  bus_type;         /* HK_BUS_*. */
    uint8_t  iface_class_mask; /* HK_IFACE_* bitmask. */
    uint8_t  audit_flags;      /* HK_DAUD_* bitmask. */
    uint64_t container_token;  /* opaque per-session ContainerID/location-id hash. */
    uint32_t creator_pid;      /* uinput/dext creator PID (140/141), else 0. */
    uint32_t reserved;         /* must be zero. */
} hk_device_descriptor_audit;
/* Layout: 4+4 (8) + 2+2+2+2 (8) = 16, then 1+1+1+1 (4) = 20; container_token is a
 * 64-bit member so it is 8-byte aligned — 4 bytes of padding push it to offset 24,
 * +8 = 32; creator_pid (4) + reserved (4) = 40. Max align 8, 40 % 8 == 0, no tail
 * pad. NOTE: an earlier draft asserted == 32, which omitted the 4-byte pre-u64
 * alignment pad and the two trailing u32s; the correct fixed size is 40. The server
 * mirror must use 40. */
HK_STATIC_ASSERT(sizeof(hk_device_descriptor_audit) == 40,
    "hk_device_descriptor_audit size mismatch — update server/telemetry/src/device_trust.rs "
    "DescriptorAudit in lockstep (correct size is 40)");

/* -------------------------------------------------------------------------
 * Cadence feature block (catalog 139 descriptor ceiling + 144 arrival/lifetime).
 * FEATURES ONLY — no client verdict (catalog mandate; the server thresholds
 * ceiling_violation_ratio and weighs the low-weight 144 lifetime/correlation
 * features). A ceiling_violation_ratio > 1.0 is the "physically impossible for a
 * compliant endpoint" region; the server, not the client, decides.
 * ------------------------------------------------------------------------- */
typedef struct hk_pointer_cadence_features {
    uint32_t schema_version;          /* HK_DEVICE_TRUST_SCHEMA_VERSION at emit. */
    uint32_t reserved0;               /* must be zero (keeps the f32 block 8-aligned). */
    uint64_t hdevice_token;           /* opaque per-session id, same space as input_prov. */
    float    declared_interval_ms;    /* bInterval-derived permitted period (ms). */
    float    observed_rate_hz;        /* sustained observed report rate (Hz). */
    float    ceiling_violation_ratio; /* observed_rate / descriptor-permitted ceiling. */
    float    device_lifetime_s;       /* arrival -> now (144). */
    float    activity_burst_corr;     /* corr(new-source activity, gameplay bursts) (144). */
    uint32_t flags;                   /* HK_CAD_* bitmask. */
    uint32_t reserved1;               /* must be zero. */
} hk_pointer_cadence_features;
/* 4+4 (8) + 8 (16) + 5*4 (36) + 4 + 4 (44)? Recount: schema(4)+reserved0(4)=8;
 * hdevice_token at 8 (+8)=16; five f32 (20)=36; flags(4)=40; reserved1(4)=44. Max
 * align 8 -> tail pad to 48. The two reserved words keep the documented 48-byte size
 * stable and 8-aligned. */
HK_STATIC_ASSERT(sizeof(hk_pointer_cadence_features) == 48,
    "hk_pointer_cadence_features size mismatch — update server/telemetry/src/input_cadence.rs "
    "in lockstep");

/* -------------------------------------------------------------------------
 * Pointer-motion ML feature vector (catalog 142). Aggregate moments / autocorr /
 * GCD-lattice statistics ONLY — never raw lLastX/lLastY / REL_X/REL_Y / IOHIDValue
 * movement (privacy invariant; data-categories §5). hid_usage_class conditions the
 * server-side ONNX model (only score against the matching sensor-class baseline:
 * mouse/trackball/tablet/touchpad). FEATURES ONLY — no client verdict.
 * ------------------------------------------------------------------------- */
#define HK_POINTER_FEAT_DIM 24u
typedef struct hk_event_pointer_features {
    uint32_t schema_version;             /* HK_DEVICE_TRUST_SCHEMA_VERSION at emit. */
    uint32_t hid_usage_class;            /* HK_PCLASS_* for model conditioning. */
    uint64_t hdevice_token;              /* opaque per-session id. */
    float    feat[HK_POINTER_FEAT_DIM];  /* moments / autocorr / GCD-lattice stats. */
} hk_event_pointer_features;
/* 4+4 (8) + 8 (16) + 24*4 (96) = 112. Max align 8, 112 % 8 == 0, no tail pad. */
HK_STATIC_ASSERT(sizeof(hk_event_pointer_features) == 16 + HK_POINTER_FEAT_DIM * 4,
    "hk_event_pointer_features size mismatch — update server/telemetry/src/pointer_model.rs "
    "in lockstep (== 112)");

/* ---- Pointer HID usage class (hk_event_pointer_features.hid_usage_class) ---
 * Server conditions the model per class so a trackball/tablet/touchpad is never
 * scored against the mouse baseline (catalog high-FP gate). HK_PCLASS_UNKNOWN means
 * the sensor could not resolve the top-level usage; the server skips ML scoring. */
#define HK_PCLASS_UNKNOWN  0u
#define HK_PCLASS_MOUSE    1u /* usage page 0x01, usage 0x02 */
#define HK_PCLASS_TRACKBALL 2u
#define HK_PCLASS_TABLET   3u /* digitizer */
#define HK_PCLASS_TOUCHPAD 4u
