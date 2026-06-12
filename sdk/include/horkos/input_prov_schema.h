/*
 * Role: Wire-format source of truth for the Windows usermode input-provenance
 *       sensor findings (catalog signals 55-63, win-input-automation). Defines the
 *       signal enum, the provenance verdict enum, the per-event source/mode flag
 *       bitmask, the fixed-size numeric finding record (hk_input_finding), and a
 *       fixed-size timing-feature block (hk_input_timing_features) for the
 *       features-only timing signals (58/62). This is a SEPARATE report plane from
 *       both the kernel event schema (event_schema.h) and the render plane
 *       (render_hook_schema.h): input findings carry variable-length strings
 *       (RIDI_DEVICENAME device paths, class-filter service names, Authenticode
 *       signer subjects, HID VID/PID) and a per-device timing histogram that do NOT
 *       fit the 16-byte HK_EVENT_PAYLOAD_MAX kernel ring record, so they ride a JSON
 *       envelope keyed by record index — never the HK_IOCTL_DRAIN_EVENTS path. Any
 *       field addition bumps HK_INPUT_SCHEMA_VERSION.
 * Target platforms: all (plain C99, no platform headers; reuses HK_STATIC_ASSERT
 *       and <stdint.h> from event_schema.h so it stays kernel-includable in
 *       principle, though no kernel TU includes it — guardrail #4).
 * Interface: mirrored by server/telemetry/src/input_prov.rs; included by the SDK
 *       usermode input-sensor TUs under sdk/src/backends/win/ only.
 */

#pragma once

#include <stdint.h>

/* HK_STATIC_ASSERT (and the <stdint.h> width types) come from the existing event
 * schema header so the static size pin uses the same portable macro. No event
 * types are pulled into the input plane; the planes stay independent. */
#include "horkos/event_schema.h"

/* Input-plane schema version. Independent of HK_EVENT_SCHEMA_VERSION and
 * HK_RENDER_SCHEMA_VERSION; the server mirror (INPUT_SCHEMA_VERSION) tracks this in
 * lockstep. */
#define HK_INPUT_SCHEMA_VERSION 1u

/* Catalog signal id, stable. The numeric value IS the catalog signal number so a
 * finding is self-describing on the wire. */
typedef enum hk_input_signal {
    HK_INPUT_SIG_RAWINPUT_PROVENANCE = 55,
    HK_INPUT_SIG_CLASS_FILTER        = 56,
    HK_INPUT_SIG_HID_TRANSPORT       = 57,
    HK_INPUT_SIG_TIMING_ENTROPY      = 58,
    HK_INPUT_SIG_LLHOOK_CHAIN        = 59,
    HK_INPUT_SIG_RAWMOUSE_MODE       = 60,
    HK_INPUT_SIG_QUEUE_ATTACH        = 61,
    HK_INPUT_SIG_HID_POLLRATE        = 62,
    HK_INPUT_SIG_SYNTHETIC_ARTIFACT  = 63
} hk_input_signal;

/* Provenance verdict for the device/source backing an input (55/56/57). The client
 * only RESOLVES and reports the classification; the server alone decides on a ban.
 * "unsigned/unknown filter or emulator bridge" is the anomaly, not mere presence
 * (catalog FP gates). HK_INPUT_SRC_UNRESOLVED is the conservative default whenever a
 * SetupAPI/HID query fails — never a fabricated anomaly. */
typedef enum hk_input_verdict {
    HK_INPUT_SRC_PHYSICAL_KNOWN        = 0, /* enumerated, signed/allowlisted device */
    HK_INPUT_SRC_ACCESSIBILITY_GATED   = 1, /* NULL hDevice but approved remote/accessibility set */
    HK_INPUT_SRC_FILTER_FOREIGN_SIGNED = 2, /* class filter present, signed, not vendor-allowlisted */
    HK_INPUT_SRC_FILTER_UNSIGNED       = 3, /* class filter unsigned / hash-unknown */
    HK_INPUT_SRC_EMULATOR_BRIDGE       = 4, /* HID descriptor over serial/CDC/generic-bridge parent */
    HK_INPUT_SRC_SYNTHETIC             = 5, /* NULL/unknown hDevice or synthetic artifact, no gate */
    HK_INPUT_SRC_UNRESOLVED            = 6, /* enumeration/query failed; sensor inconclusive */
    HK_INPUT_SRC_DESCRIPTOR_INCOHERENT = 7  /* descriptor numerics/strings/topology contradict the
                                               claimed VID/PID; see hk_device_descriptor_audit in
                                               device_trust_schema.h (hardware-input-devices domain,
                                               catalog 137/140/141/143). Additive: keeps 0..6. */
} hk_input_verdict;

/* Source/mode flag bitmask (55/60/61/63). */
#define HK_INFLAG_HDEVICE_NULL       0x0001u /* WM_INPUT with hDevice == NULL */
#define HK_INFLAG_HDEVICE_UNKNOWN    0x0002u /* hDevice not in GetRawInputDeviceList inventory */
#define HK_INFLAG_REMOTE_SESSION     0x0004u /* SM_REMOTESESSION true */
#define HK_INFLAG_ACCESSIBILITY      0x0008u /* approved accessibility/remote flag set */
#define HK_INFLAG_MOUSE_ABSOLUTE     0x0010u /* RAWMOUSE.usFlags MOUSE_MOVE_ABSOLUTE */
#define HK_INFLAG_MOUSE_VIRTDESKTOP  0x0020u /* MOUSE_VIRTUAL_DESKTOP */
#define HK_INFLAG_MODE_OSCILLATION   0x0040u /* hDevice flipped relative<->absolute in window */
#define HK_INFLAG_QUEUE_ATTACHED     0x0080u /* foreign thread shares game GUI input queue */
#define HK_INFLAG_NO_SCANCODE        0x0100u /* keyboard event, scanCode == 0 / KEYEVENTF_UNICODE */
#define HK_INFLAG_EXTRAINFO_UNKNOWN  0x0200u /* GetMessageExtraInfo matches no known driver stamp */
#define HK_INFLAG_LLMHF_INJECTED     0x0400u /* MSLLHOOKSTRUCT/KBDLLHOOKSTRUCT injected-flag baseline */
#define HK_INFLAG_GAMEPLAY_CONTEXT   0x0800u /* sampled during in-combat/gameplay (text not expected) */

/* Fixed-size numeric core of one finding. The variable strings (device_path,
 * filter_service, signer_subject, vidpid, owning_image) travel in the JSON envelope
 * keyed by record index, NEVER inline, so this struct stays fixed-size and paths are
 * not length-bounded. Every "else 0" field is zero when the emitting signal does not
 * populate it. */
typedef struct hk_input_finding {
    uint32_t schema_version;    /* HK_INPUT_SCHEMA_VERSION at emit. */
    uint32_t signal;            /* hk_input_signal. */
    uint32_t verdict;           /* hk_input_verdict, or 0 when N/A. */
    uint32_t flags;             /* HK_INFLAG_* bitmask. */
    uint32_t owning_pid;        /* foreign PID for queue-attach / hook-owner signals, else 0. */
    uint32_t event_count;       /* events observed in the window (ratio denominator). */
    uint32_t anomaly_count;     /* events matching the anomaly (ratio numerator). */
    uint32_t filter_count;      /* ordered class-filter count (56), else 0. */
    uint64_t hdevice_token;     /* opaque per-session hDevice id (NOT the raw HANDLE), else 0. */
    int64_t  llhook_latency_ns; /* measured CallNextHookEx call-out delay (59), else 0. */
} hk_input_finding;

/* 8 x uint32 (32) + 2 x 64-bit (16) = 48 bytes; the two 64-bit members are 8-byte
 * aligned after the eight 4-byte members, so there is no implicit padding. */
HK_STATIC_ASSERT(sizeof(hk_input_finding) == 48,
    "hk_input_finding size mismatch — update server/telemetry/src/input_prov.rs "
    "InputFinding numeric fields in lockstep");

/* Timing-feature block for signals 58 (inter-report entropy) and 62 (poll-rate
 * contradiction). FEATURES ONLY — no client verdict (catalog: "ship features to the
 * server model, never a client-side ban"). Fixed-size histogram so the record stays
 * flat; the server runs the regularity/mismatch model. */
#define HK_INPUT_TIMING_BUCKETS 16u

typedef struct hk_input_timing_features {
    uint32_t schema_version;    /* HK_INPUT_SCHEMA_VERSION at emit. */
    uint32_t signal;            /* 58 or 62. */
    uint64_t hdevice_token;     /* same opaque per-session id as hk_input_finding. */
    uint32_t sample_count;      /* deltas summarized. */
    uint32_t declared_hz;       /* HID/USB bInterval-derived declared rate (62), else 0. */
    uint32_t observed_hz_x100;  /* measured WM_INPUT rate * 100 (fixed-point), else 0. */
    uint32_t transport_flags;   /* HK_INTRANSPORT_* (Bluetooth/wireless exemption for 62). */
    uint32_t cov_x10000;        /* coefficient of variation of inter-arrival deltas, *1e4. */
    uint32_t regularity_x10000; /* chi-square/autocorrelation regularity score, *1e4. */
    uint32_t period_hist[HK_INPUT_TIMING_BUCKETS]; /* inter-arrival delta histogram. */
} hk_input_timing_features;

/* 2 x uint32 (8) + 1 x uint64 (8) + 7 x uint32 (28) + 16 x uint32 (64) = 108? No:
 * after the leading 8 bytes the uint64 is 8-byte aligned (offset 8), then 7 uint32
 * scalars (28) + period_hist[16] (64) = 40+64 = 104, no tail padding (max align 8,
 * 104 % 8 == 0). */
HK_STATIC_ASSERT(sizeof(hk_input_timing_features) == 104,
    "hk_input_timing_features size mismatch — update server/telemetry/src/input_prov.rs "
    "InputTimingFeatures fields (including period_hist[16]) in lockstep");

/* Transport flags for the 62 poll-rate exemption (catalog: exempt BT/wireless). */
#define HK_INTRANSPORT_USB        0x01u
#define HK_INTRANSPORT_BLUETOOTH  0x02u  /* connection-interval != HID bInterval legitimately */
#define HK_INTRANSPORT_WIRELESS   0x04u  /* dongle/proprietary RF */
#define HK_INTRANSPORT_VIRTUAL    0x08u  /* no physical endpoint resolvable */
