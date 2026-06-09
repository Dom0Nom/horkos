# Implementation Plan — USB / HID Device Trust (`hardware-input-devices`)

Scope: read-only sensors that establish the **device-trust** of the USB/HID
peripherals attached to the machine — descriptor structure, descriptor self-
consistency, USB topology, endpoint/poll-interval coherence, virtual-device
provenance, and pointer-motion physicality — and ship typed findings (and, for
the ML signals, feature vectors) to the server, which holds all ban authority.
No descriptor rewriting, no device control, no injection: every sensor only
*reads* descriptors via the OS enumeration/HID APIs and observes input the game
already receives. Sample-and-report only.

Catalog signals covered: **136, 137, 138, 139, 140, 141, 142, 143, 144** (the
nine "USB / HID Device Trust" designs in `docs/detection-catalog.md`,
lines 1417–1507).

Platform split: 136, 137, 139, 143, 144 are `windows-user`; 138 is `windows-user`;
140 is `linux-ebpf` + posix userspace; 141 is `macos` userspace daemon; 142 is
`cross` userspace. All userspace sensors live under `sdk/src/backends/<platform>/input/`
or the macOS daemon tree — guardrail #1 (platform API only inside a `backends/`
folder, `HK_PLATFORM_*`-gated, never raw `_WIN32`/`__linux__`/`__APPLE__`). The
single eBPF object (140) lives in `kernel/linux/bpf/` and shares **no**
translation unit with any userspace `.cpp` (guardrail #4).

## Relationship to `win-input-automation` (signals 55–63)

This domain is the **descriptor/topology** layer; `win-input-automation` is the
**raw-input/timing-hook provenance** layer. They overlap on three signals and
MUST reuse, not fork, the shared schema:

- **138 (Raw Input source-handle reconciliation) ≈ 55** (`HK_INPUT_SIG_RAWINPUT_PROVENANCE`).
  138 is the device-trust framing of the same `hDevice`→`GetRawInputDeviceList`
  gap. It reuses `RawInputInventoryWin.cpp` (built by the sibling plan) and the
  `hk_input_finding` / `hk_input_verdict` enum from `sdk/include/horkos/input_prov_schema.h`.
  If `win-input-automation` lands first, 138 is a thin consumer; if this plan
  lands first, it must introduce `input_prov_schema.h` (see Sequencing).
- **139 (bInterval vs cadence) ≈ 62** (`HK_INPUT_SIG_HID_POLLRATE`). 139 adds the
  *descriptor ceiling* (observed rate vs `bInterval`-permitted rate) on top of
  62's report-rate-vs-declared-poll feature. Both ship a **feature**, never a
  verdict, and both target `server/telemetry/src/input_cadence.rs`. The two
  plans must agree on one `input_cadence.rs`; this plan owns the descriptor-
  ceiling field, the sibling owns the poll-rate field. Coordinate in one PR or
  sequence them.
- **142 (pointer-delta stats)** has no sibling equivalent; it introduces a new
  ML feature plane (`hk_event_pointer_features`).

To avoid a third schema header, all per-device descriptor-audit findings reuse
`hk_input_finding` + `hk_input_verdict`, extended with one new enum
`hk_input_verdict::HK_INPUT_SRC_DESCRIPTOR_INCOHERENT` and a small
`hk_device_descriptor_audit` detail block. The pointer-ML and cadence signals
get their own fixed records because they carry float feature vectors, not
verdicts.

---

## 1. New files

| Path | Role | Module-comment summary |
|---|---|---|
| `sdk/include/horkos/device_trust_schema.h` | Public C99 typed report schema for USB/HID device-trust findings: the `hk_device_descriptor_audit` detail block (fixed-size), the `hk_event_hid_descriptor` fingerprint record (catalog 136), the `hk_event_pointer_features` ML feature record (catalog 142), and the descriptor-ceiling cadence field (catalog 139). Extends, does not replace, `input_prov_schema.h`. | Role: wire-format source of truth for USB/HID device-trust sensor findings; fixed-size descriptor-audit / HID-fingerprint / pointer-feature / cadence records. Target: all (plain C99, no platform headers, no compiler extensions). Interface: mirrored by `server/telemetry/src/device_trust.rs`; included by SDK usermode TUs and the eBPF userspace loader TU only, never a kernel-driver TU (guardrail #4). |
| `sdk/src/backends/win/input/DeviceTrustWin.h` | Internal Windows façade declaring the descriptor-audit sensor entry points + the shared USB-node snapshot type used by 137/139/143. | Role: internal Windows device-trust sensor interface; declarations only. Target: Windows. Interface: implemented by the `*Win.cpp` files below; consumed by the `sdk.cpp` AC tick. |
| `sdk/src/backends/win/input/UsbTopologyWin.cpp` | Shared USB-hub topology + node-descriptor reader: opens `GUID_DEVINTERFACE_USB_HUB` / `\\.\HCDx`, walks node connections, pulls the raw 18-byte device descriptor, config descriptor, and string descriptors via `IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION` / `IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX`. Shared by 137, 139, 143. | Role: USB hub/node descriptor snapshot provider (raw device/config/string descriptors keyed by hub+port). Target: Windows. Interface: implements `hk::sdk::win::build_usb_topology` from `DeviceTrustWin.h`. Guardrail #1: the one place these sensors touch the USB hub IOCTL surface. |
| `sdk/src/backends/win/input/HidDescriptorFingerprintWin.cpp` | Signal 136: canonicalize the HID preparsed structure and hash it. | Role: HID report-descriptor structural-fingerprint sensor (`HidD_GetPreparsedData`+`HidP_GetCaps` over `GUID_DEVINTERFACE_HID`). Target: Windows. Interface: implements `sense_hid_descriptor`; emits `hk_event_hid_descriptor`. Catalog slot 136. |
| `sdk/src/backends/win/input/UsbDescriptorAuditWin.cpp` | Signal 137: bcdUSB/bcdDevice/bMaxPacketSize0/serial-string self-consistency vs claimed VID/PID. | Role: USB device-descriptor self-consistency sensor (bridge-chip signature vs major-vendor VID). Target: Windows. Interface: implements `sense_usb_descriptor_audit`; emits `hk_device_descriptor_audit`. Catalog slot 137. |
| `sdk/src/backends/win/input/RawInputSourceReconcileWin.cpp` | Signal 138: `WM_INPUT` `hDevice`→`GetRawInputDeviceList` reconciliation gap (device-trust framing of sibling signal 55). | Role: raw-input source-handle reconciliation sensor (NULL/unknown `hDevice` vs enumerated USB endpoint set, remote/accessibility-session gated). Target: Windows. Interface: implements `sense_rawinput_reconcile`; reuses `RawInputInventoryWin` + `hk_input_finding`. Catalog slot 138 (pairs with `win-input-automation` 55). |
| `sdk/src/backends/win/input/PollIntervalCoherenceWin.cpp` | Signal 139: observed report cadence vs endpoint `bInterval` descriptor ceiling. | Role: USB interrupt-endpoint poll-interval-coherence sensor (observed QPC cadence vs descriptor-permitted ceiling; wireless-dongle exempt). Target: Windows. Computes a **feature**, never a verdict. Interface: implements `sense_poll_interval`; emits `hk_pointer_cadence_features`. Catalog slot 139. |
| `sdk/src/backends/win/input/CompositeInterfaceAuditWin.cpp` | Signal 143: composite-device IAD / ContainerID irregularity (HID co-resident with CDC-ACM). | Role: composite-interface-collection sensor (`DEVPKEY_Device_ContainerId` + config-descriptor IAD parse; HID+CDC-on-one-ContainerID flag). Target: Windows. Interface: implements `sense_composite_interface`; emits `hk_device_descriptor_audit`. Catalog slot 143. |
| `sdk/src/backends/win/input/DeviceArrivalCorrelationWin.cpp` | Signal 144: hot-plug arrival timing vs bursty combat-correlated activity. | Role: device-arrival/activity-correlation sensor (`RegisterDeviceNotification` arrivals joined to per-`hDevice` activity windows). Target: Windows. Computes a low-weight **feature**, never a verdict. Interface: implements `sense_device_arrival`; emits `hk_pointer_cadence_features` (lifetime fields). Catalog slot 144. |
| `sdk/src/backends/win/input/PointerDeltaStatsWin.cpp` | Signal 142 (Windows half): accumulate `RAWMOUSE.lLastX/lLastY`, compute distribution/autocorrelation/GCD-of-deltas, emit aggregate feature vector only. | Role: Windows pointer-delta statistical-feature extractor (CPI-lattice / noise-profile moments). Target: Windows. Emits `hk_event_pointer_features`; never raw movement. Interface: implements `sense_pointer_stats`. Catalog slot 142. |
| `kernel/linux/bpf/input_provenance.bpf.c` | Signal 140 (kernel half): CO-RE tracepoint/kprobe on `input_event`/`input_handle_event` + `input_register_device` reading `input_dev->id.bustype/name/phys`; pushes a compact provenance record into the shared CO-RE ringbuf. | Role: evdev/uinput virtual-device provenance eBPF sensor. Target: Linux (eBPF, CO-RE). Interface: emits a packed `hk_input_prov_bpf` record into the shared ringbuf; consumed by `EvdevProvenanceLinux.cpp`. Guardrail #4: never linked with userspace; guardrail #6: builds `-Wall -Wextra -Werror`. |
| `sdk/src/backends/posix/input/EvdevProvenanceLinux.cpp` | Signal 140 (userspace half): drain the bpf ringbuf record, supplement with an `EVIOCGID`/`EVIOCGPHYS` poll over `/dev/input/event*`, attach the uinput-creator PID, and emit a finding. | Role: evdev provenance correlator (BUS_VIRTUAL vs BUS_USB; uinput creator PID attribution for Steam-Input allowlisting). Target: Linux. Interface: implements `sense_evdev_provenance`; emits `hk_device_descriptor_audit`. Catalog slot 140. |
| `sdk/src/backends/posix/input/PointerDeltaStatsPosix.cpp` | Signal 142 (Linux half): accumulate `EV_REL REL_X/REL_Y`, same moments as the Windows extractor. | Role: Linux pointer-delta statistical-feature extractor. Target: Linux. Emits `hk_event_pointer_features`; never raw movement. Interface: implements `sense_pointer_stats`. Catalog slot 142. |
| `daemon/macos/input/IOHIDTransportAuditMac.mm` | Signal 141: `IOHIDManager`/`IOHIDDeviceGetProperty` transport/conformance audit; reports providing dext bundle id + transport key. | Role: macOS IOHIDDevice transport/conformance-audit sensor (USB/Bluetooth transport + location-id vs `IOHIDUserDevice`/DriverKit virtual). Target: macOS. Interface: implements `sense_iohid_transport`; emits `hk_device_descriptor_audit`. Catalog slot 141. Pairs with the ES exec record of the dext loader. |
| `daemon/macos/input/PointerDeltaStatsMac.mm` | Signal 142 (macOS half): accumulate `IOHIDValueGetIntegerValue` deltas, same moments. | Role: macOS pointer-delta statistical-feature extractor. Target: macOS. Emits `hk_event_pointer_features`; never raw movement. Interface: implements `sense_pointer_stats`. Catalog slot 142. |
| `server/telemetry/src/device_trust.rs` | Serde mirror of `device_trust_schema.h` + `POST /api/device-trust` ingest route (descriptor-audit findings + HID fingerprints). Phase-2 stub parity with `TickPayload`: validate, log, drop. | Role: device-trust finding ingest plane. Target: server. Interface: mirrors `hk_device_descriptor_audit` / `hk_event_hid_descriptor`; mounted by `telemetry::router()`. No `unwrap()` (guardrail #8); `thiserror`. |
| `server/telemetry/src/input_cadence.rs` | Serde mirror of `hk_pointer_cadence_features` + `POST /api/input-cadence`. Shared with `win-input-automation` (poll-rate 62 / arrival 144 / ceiling 139). | Role: input-cadence feature ingest plane (poll-interval ceiling, device lifetime/arrival). Target: server. Interface: mirrors `hk_pointer_cadence_features`; mounted by `telemetry::router()`. No `unwrap()`. |
| `server/telemetry/src/pointer_model.rs` | Serde mirror of `hk_event_pointer_features` + `POST /api/pointer-features`. ONNX scoring stub: validates feature vector shape, logs, drops (no model load in Phase 2; `ort` already wired in `lib.rs`). | Role: pointer-feature ML ingest plane (sensor-class-conditioned scorer entry, model load deferred). Target: server. Interface: mirrors `hk_event_pointer_features`; mounted by `telemetry::router()`. No `unwrap()`; `thiserror`. |
| `bypass-tests/win/hid_descriptor_template_clone.cpp` | Bypass-test fixture (disabled stub): an Arduino-HID-library / V-USB / LUFA template descriptor must produce a fingerprint that the server corpus flags as template-class, while a QMK/ZMK and a genuine-vendor descriptor produce distinguishable non-template fingerprints. | Role: HID-fingerprint merge-gate bypass test. Target: Windows. Interface: consumes `device_trust_schema.h`. Guardrail #12. |
| `bypass-tests/win/usb_bridge_descriptor_spoof.cpp` | Bypass-test fixture (disabled stub): a CH340/CP2102/FTDI bridge descriptor claiming a major-vendor VID must surface as `HK_INPUT_SRC_DESCRIPTOR_INCOHERENT` (137) and, if it also exposes HID+CDC under one ContainerID, fire 143; a genuine vendor composite (HID+CDC RGB channel) must be reported-but-benign. | Role: USB descriptor-coherence + composite-interface merge-gate bypass test. Target: Windows. Interface: consumes `device_trust_schema.h`. Guardrail #12. |
| `bypass-tests/linux/uinput_virtual_provenance.cpp` | Bypass-test fixture (disabled stub): a `/dev/uinput` virtual mouse emitting `EV_REL` with no USB parent must be reported with `BUS_VIRTUAL` + creator PID; a Steam-Input creator PID must be allowlist-attributable, an unknown creator must not be. | Role: evdev/uinput provenance merge-gate bypass test. Target: Linux. Interface: consumes `device_trust_schema.h`. Guardrail #12. |
| `bypass-tests/cross/pointer_lattice_synthetic.cpp` | Bypass-test fixture (disabled stub): a synthetic delta stream (uniform / integer-perfect curve / single fixed step) must produce a feature vector the model flags as non-physical *even when inter-arrival timing is jittered*, while a captured real-sensor stream conditioned on the same HID usage class does not. | Role: pointer-lattice physicality merge-gate bypass test. Target: cross. Interface: consumes `device_trust_schema.h`. Guardrail #12. |

---

## 2. Interfaces & data structures

### 2.1 `sdk/include/horkos/device_trust_schema.h`

Plain C99, no platform headers; uses `HK_STATIC_ASSERT` from `event_schema.h`
so it compiles on a C99 kernel-warning build and a C++/Objective-C++ usermode
build alike. It `#include "horkos/input_prov_schema.h"` to reuse the
`hk_input_verdict` enum and adds one enumerator (additive, keeps existing
values — same discipline as `event_schema.h`):

```c
/* Added to hk_input_verdict in input_prov_schema.h (additive, value 7): */
/* HK_INPUT_SRC_DESCRIPTOR_INCOHERENT = 7  -- descriptor numerics/strings/
   topology contradict the claimed VID/PID; see hk_device_descriptor_audit. */

#define HK_DEVICE_TRUST_SCHEMA_VERSION 1u   /* independent of HK_EVENT_SCHEMA_VERSION
                                               and HK_INPUT_SCHEMA_VERSION. */

/* HID descriptor structural fingerprint (catalog 136). */
typedef struct hk_event_hid_descriptor {
    uint32_t schema_version;     /* HK_DEVICE_TRUST_SCHEMA_VERSION at emit. */
    uint16_t vendor_id;          /* claimed VID. */
    uint16_t product_id;         /* claimed PID. */
    uint8_t  fingerprint[32];    /* SHA-256 of canonicalized preparsed structure. */
    uint16_t usage_page_count;   /* distinct usage pages in the descriptor. */
    uint16_t field_count;        /* total HID fields. */
    uint16_t report_id_count;    /* distinct report IDs. */
    uint16_t flags;              /* HK_HIDFP_* bitmask. */
} hk_event_hid_descriptor;
HK_STATIC_ASSERT(sizeof(hk_event_hid_descriptor) == 48,
    "hk_event_hid_descriptor size mismatch");

/* Descriptor-coherence / topology audit detail (catalog 137/140/141/143). */
typedef struct hk_device_descriptor_audit {
    uint32_t schema_version;     /* HK_DEVICE_TRUST_SCHEMA_VERSION at emit. */
    uint32_t verdict;            /* hk_input_verdict (often _DESCRIPTOR_INCOHERENT). */
    uint16_t vendor_id;          /* claimed VID. */
    uint16_t product_id;         /* claimed PID. */
    uint16_t bcd_usb;            /* bcdUSB. */
    uint16_t bcd_device;         /* bcdDevice. */
    uint8_t  max_packet_size0;   /* bMaxPacketSize0. */
    uint8_t  bus_type;           /* HK_BUS_USB/_BLUETOOTH/_VIRTUAL/_UNKNOWN. */
    uint8_t  iface_class_mask;   /* bit0 HID present, bit1 CDC present, ... */
    uint8_t  audit_flags;        /* HK_DAUD_* (null-serial, container-mismatch, ...). */
    uint64_t container_token;    /* opaque per-session ContainerID/location-id hash. */
    uint32_t creator_pid;        /* uinput/dext creator PID (140/141), else 0. */
    uint32_t reserved;           /* must be zero. */
} hk_device_descriptor_audit;
HK_STATIC_ASSERT(sizeof(hk_device_descriptor_audit) == 32,
    "hk_device_descriptor_audit size mismatch");

/* Cadence feature block (catalog 139 ceiling + 144 arrival/lifetime). FEATURES
   ONLY — no client verdict (catalog mandate). */
typedef struct hk_pointer_cadence_features {
    uint32_t schema_version;
    uint32_t reserved0;
    uint64_t hdevice_token;          /* opaque per-session id, same as input_prov. */
    float    declared_interval_ms;   /* bInterval-derived permitted period. */
    float    observed_rate_hz;       /* sustained observed report rate. */
    float    ceiling_violation_ratio;/* observed_rate / descriptor-permitted ceiling. */
    float    device_lifetime_s;      /* arrival→now (144). */
    float    activity_burst_corr;    /* corr(new-source activity, gameplay bursts) (144). */
    uint32_t flags;                  /* HK_CAD_WIRELESS_EXEMPT, HK_CAD_HOTPLUG, ... */
    uint32_t reserved1;
} hk_pointer_cadence_features;
HK_STATIC_ASSERT(sizeof(hk_pointer_cadence_features) == 48,
    "hk_pointer_cadence_features size mismatch");

/* Pointer-motion ML feature vector (catalog 142). Aggregate moments only. */
#define HK_POINTER_FEAT_DIM 24u
typedef struct hk_event_pointer_features {
    uint32_t schema_version;
    uint32_t hid_usage_class;        /* mouse/trackball/tablet/touchpad class for
                                        server-side model conditioning. */
    uint64_t hdevice_token;
    float    feat[HK_POINTER_FEAT_DIM]; /* moments / autocorr / GCD-lattice stats. */
} hk_event_pointer_features;
HK_STATIC_ASSERT(sizeof(hk_event_pointer_features) == 16 + HK_POINTER_FEAT_DIM * 4,
    "hk_event_pointer_features size mismatch");  /* == 112 */
```

`HK_BUS_*`, `HK_HIDFP_*`, `HK_DAUD_*`, `HK_CAD_*` are `#define` bitmasks/enums
in the same header. The opaque `hdevice_token`/`container_token` are per-session
salted hashes, never the real device path/serial (privacy; see §2.4).

### 2.2 eBPF ringbuf record (140) — `kernel/linux/bpf/input_provenance.bpf.c`

A separate **packed** kernel-side record (NOT `device_trust_schema.h`, which is
userspace-only) pushed into the existing shared CO-RE ringbuf:

```c
struct hk_input_prov_bpf {
    __u64 ts_ns;
    __u32 input_dev_id;     /* stable per-device cookie within the session. */
    __u32 creator_pid;      /* PID that called input_register_device (uinput). */
    __u16 bustype;          /* input_dev->id.bustype (BUS_USB/BUS_VIRTUAL/...). */
    __u16 vendor;
    __u16 product;
    __u8  has_usb_parent;   /* walked parent chain found a usb_device. */
    __u8  evbit_rel_key;    /* emits EV_REL/EV_KEY (pointer/keyboard). */
} __attribute__((packed));
```

The userspace half (`EvdevProvenanceLinux.cpp`) consumes this, supplements with
`EVIOCGID`/`EVIOCGPHYS`, and converts to `hk_device_descriptor_audit` for the
wire. The kernel record never reaches the server directly — guardrail #4 keeps
the kernel struct and the userspace wire struct in different TUs/headers.

### 2.3 Server mirrors (Rust)

`device_trust.rs`, `input_cadence.rs`, `pointer_model.rs` each define a
`#[derive(Serialize, Deserialize)]` mirror with identical field names/order to
the C structs, a `thiserror` error enum, and an axum route that validates the
schema version then logs-and-drops (Phase-2 parity with `TickPayload`). Field-
to-struct mapping:

| Wire field | Signal(s) | Rust type |
|---|---|---|
| `fingerprint` (32B) | 136 | `[u8; 32]` (serde as hex string in JSON plane) |
| `verdict` | 137/140/141/143 | enum mirroring `hk_input_verdict` |
| `bus_type` / `iface_class_mask` | 137/140/141/143 | `u8` |
| `creator_pid` | 140/141 | `u32` (server allowlist lookup: Steam Input / known dext) |
| `ceiling_violation_ratio` | 139 | `f32` (server thresholds; >1.0 = physically impossible) |
| `device_lifetime_s` / `activity_burst_corr` | 144 | `f32` (low-weight feature) |
| `feat[24]` | 142 | `[f32; 24]`, scored only against the matching `hid_usage_class` baseline |

`telemetry::router()` in `lib.rs` is extended to `.merge(device_trust::router())`,
`.merge(input_cadence::router())`, `.merge(pointer_model::router())`.

### 2.4 IOCTL additions

**None required.** Every signal in this domain is `windows-user`, `macos`
userspace, or `linux-ebpf`+userspace; none flow through the Windows KMDF driver,
so `sdk/include/horkos/ioctl.h` and `HK_EVENT_PAYLOAD_MAX` are untouched. The
Linux path uses the existing eBPF shared ringbuf, not the Windows IOCTL bridge.
The new wire records travel on the HTTP/JSON telemetry plane, not the C99
kernel-event plane.

### 2.5 Guardrail #11 — `server/api/data-categories.md` (same PR)

A new section **`### 5. Input-device trust`** must be added declaring every new
telemetry field. Required rows (each with Source / Retention / Legal basis /
Operator-of-record, matching the existing table format):

- `vendor_id`, `product_id`, `bcd_usb`, `bcd_device`, `max_packet_size0`, `bus_type`,
  `iface_class_mask`, `container_token` — descriptor audit (137/143).
- `fingerprint`, `usage_page_count`, `field_count`, `report_id_count` — HID
  fingerprint (136). Note: hash of descriptor structure, not device serial.
- `creator_pid` — uinput/dext creator (140/141); cross-reference the existing
  process-information category.
- `declared_interval_ms`, `observed_rate_hz`, `ceiling_violation_ratio`,
  `device_lifetime_s`, `activity_burst_corr` — cadence features (139/144).
- `hid_usage_class`, `feat[24]` (pointer feature vector) — 142. **Explicitly
  declare** that only an aggregate feature vector is retained, never raw
  `lLastX/lLastY` / `REL_X/REL_Y` / `IOHIDValue` movement content.

`hdevice_token`/`container_token` are declared as per-session salted pseudonyms
(not stable hardware identifiers) so they fall outside category 4 (attestation
hardware ids). The reviewer rejects the PR if any field above is absent.

---

## 3. Mechanism implementation notes

### 136 — HID report-descriptor fingerprint (Windows, IRQL PASSIVE_LEVEL, usermode)
`SetupDiGetClassDevs(GUID_DEVINTERFACE_HID)` → open each device path →
`HidD_GetPreparsedData` → `HidP_GetCaps` / `HidP_GetButtonCaps` /
`HidP_GetValueCaps`. Canonicalize (usage pages sorted, report IDs, field count,
per-report byte lengths) into a stable byte buffer and SHA-256 it. Always
`HidD_FreePreparsedData` on every path including error paths (handle leak
otherwise). Exclusively-opened devices fail `CreateFile`; treat as
inconclusive, never an anomaly. The fingerprint is **never** a local verdict —
server does the corpus/reputation lookup (catalog FP gate: QMK/ZMK vs Arduino-
HID clusters).

### 137 — USB device-descriptor self-consistency (Windows, usermode)
Via the shared `UsbTopologyWin` snapshot: `IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX`
+ `IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION` (over `GUID_DEVINTERFACE_USB_HUB`)
for the raw 18-byte device descriptor + string descriptors. Cross-check
`(VID,PID,bcdDevice,bMaxPacketSize0,iSerialNumber-presence)` coherence locally,
classify `HK_INPUT_SRC_DESCRIPTOR_INCOHERENT` only on the catalog's narrow
condition (major-vendor VID + bridge-chip descriptor signature). The known-
hardware corpus correlation is **server-side**; the client only ships the tuple.

### 138 — Raw Input source reconciliation (Windows, usermode)
Reuses `RawInputInventoryWin` (sibling plan). For each `WM_INPUT`, compare
`RAWINPUTHEADER.hDevice` against `GetRawInputDeviceList` +
`GetRawInputDeviceInfo(RIDI_DEVICENAME)`. NULL/unknown source → gate by
`WTSGetActiveConsoleSessionId` + remote-session flag + process-context tag
before classifying (`HK_INPUT_SRC_ACCESSIBILITY_GATED` vs `_SYNTHETIC`).
RDP/Parsec/Moonlight/on-screen-keyboard must resolve to the gated verdict.

### 139 — bInterval vs cadence (Windows, usermode; ships feature)
Read the interrupt-IN endpoint descriptor (`USB_ENDPOINT_DESCRIPTOR.bInterval`,
`wMaxPacketSize`, speed) via `IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION`;
timestamp each report with `QueryPerformanceCounter` in the `WM_INPUT` path;
compute `observed_rate / descriptor-permitted ceiling`. Require a **sustained**
violation (observed rate exceeding the physically-impossible-for-compliant
ceiling), not mild jitter. Set `HK_CAD_WIRELESS_EXEMPT` when the receiver re-
clocks (dongle). Feature only → `input_cadence.rs`; server decides.

### 140 — evdev/uinput provenance (Linux eBPF + userspace)
eBPF CO-RE tracepoint/kprobe on `input_event`/`input_handle_event` and a kprobe
on `input_register_device` (uinput path). Read `input_dev->id.bustype`, `->name`,
`->phys` via CO-RE `BPF_CORE_READ` (never fixed offsets — `-Werror` + CO-RE
relocations). Walk the parent chain for a `usb_device` to set `has_usb_parent`.
Userspace correlates `BUS_VIRTUAL` + no USB parent emitting `EV_REL`/`EV_KEY`,
attaches the `creator_pid`, and supplements with `EVIOCGID`/`EVIOCGPHYS`. FP gate
is **high**: Steam Input, Deck back-button/gyro remap, antimicro, accessibility
remappers all use uinput — report the creator PID and let the server allowlist
via the existing exec/process-provenance pipeline. On Game Mode, Steam's virtual
devices are the dominant benign baseline.

### 141 — IOHIDDevice transport audit (macOS daemon, userspace)
`IOHIDManagerCreate` → `IOHIDManagerCopyDevices` → `IOHIDDeviceGetProperty` for
`kIOHIDTransportKey`, `kIOHIDLocationIDKey`, `kIOHIDVendorIDKey`/`ProductIDKey`,
`kIOHIDPhysicalDeviceUniqueIDKey`, `kIOHIDReportDescriptorKey`. Cross-check
transport against a USB location id in the IORegistry. Report the providing
dext/driver bundle id + transport key for server allowlisting (Karabiner,
BetterTouchTool, remote-control apps create legitimate virtual HID). This runs
in the **userspace daemon** (`daemon/macos/`), NOT in the ES auth path — there
is no ES event to reply to here, so guardrail #7's reply-deadline does not
apply. Pair the finding with the ES exec record of the dext loader (correlated
server-side, not in the ES callback).

### 142 — Pointer-delta statistics (cross, usermode; ships feature vector)
Per platform accumulate raw deltas (`RAWMOUSE.lLastX/lLastY` /
`EV_REL REL_X/REL_Y` / `IOHIDValueGetIntegerValue`) into a bounded window,
compute distribution moments, autocorrelation, and GCD-of-deltas (CPI-lattice)
client-side, emit only `feat[24]` + `hid_usage_class`. **Never** ship raw
movement. Server conditions the ONNX model on `hid_usage_class` (only score
against the sensor-class baseline matching the reported HID usage) — trackballs/
tablets/touchpads have their own baselines (FP gate high).

### 143 — Composite-interface audit (Windows, usermode)
`SetupDiGetDeviceProperty(DEVPKEY_Device_ContainerId)` + config-descriptor IAD
parse via the shared `UsbTopologyWin` snapshot
(`USB_INTERFACE_ASSOCIATION_DESCRIPTOR`, `bInterfaceClass` HID=0x03 / CDC=0x0A).
Flag an input device co-resident with a CDC-ACM/vendor-serial interface under one
ContainerID (`HK_DAUD_CONTAINER_MISMATCH`). FP gate low; known vendor composite
layouts allowlisted server-side.

### 144 — Arrival/activity correlation (Windows, usermode; ships feature)
`RegisterDeviceNotification(GUID_DEVINTERFACE_HID)` to timestamp
`DBT_DEVICEARRIVAL`/`DBT_DEVICEREMOVECOMPLETE`; join against per-`hDevice`
activity windows from the raw-input path. Emit `device_lifetime_s` +
`activity_burst_corr` only when the **joint** condition holds (new HID source +
bursty combat-correlated activity + simultaneous idling of the prior device).
Low-weight feature, never a standalone verdict — KVM/dongle re-pair/hub power/
mid-session mouse swap all generate arrivals.

### Server (all signals)
Every route is `async fn`, `thiserror` error enum, no `unwrap()`/`expect()`/
`anyhow` in library code (guardrail #8; `anyhow` binary-only). `ort` stays the
compile-time marker in Phase 2 — `pointer_model.rs` validates shape and drops;
no `Session` is constructed until the `/tdd` inference phase. No blocking calls
on async threads (corpus/allowlist lookups, when they land, go through
`spawn_blocking` or an async store).

---

## 4. Build wiring

- **Windows (136/137/138/139/143/144/142-win):** add the `*Win.cpp` +
  `UsbTopologyWin.cpp` + `DeviceTrustWin.h` to the existing
  `sdk/src/backends/win/` target (same CMake list the sibling input-automation
  sensors join). New link deps: `hid.lib`, `setupapi.lib`, `cfgmgr32.lib`
  (already pulled by `win-input-automation` for SetupAPI), `winusb.lib`/`wtsapi32.lib`.
  Toolchain: WDK/MSVC usermode (NOT the kernel build); guardrail #1/#4 — these
  TUs never compile into `kernel/win/`. Default **ON** for Windows AC builds.
- **Linux eBPF (140):** `kernel/linux/bpf/input_provenance.bpf.c` added to the
  eBPF object list in `kernel/linux/CMakeLists.txt`, gated by the existing eBPF
  option (default **OFF**; required-ON for Steam Deck Game Mode profile).
  clang-19 `-target bpf`, CO-RE, `-Wall -Wextra -Werror` (guardrail #6). The
  userspace `EvdevProvenanceLinux.cpp` + `PointerDeltaStatsPosix.cpp` go in the
  `sdk/src/backends/posix/` target, libbpf for the ringbuf consume. LKM path not
  used for this signal (eBPF-only per locked decision 3).
- **macOS (141/142-mac):** `IOHIDTransportAuditMac.mm` + `PointerDeltaStatsMac.mm`
  added to the `daemon/macos/` target. Frameworks: `IOKit`, `CoreFoundation`.
  Xcode/clang. Default **ON** for the macOS daemon bring-up path (no entitlement
  needed — IOHIDManager is userspace; ES not involved). SysExt swap unaffected.
- **Server:** three new modules registered in `server/telemetry/src/lib.rs`;
  no new workspace member, no new crate deps beyond the pinned `serde`/`thiserror`.
- **Tests/bypass-tests:** `bypass-tests/{win,linux,cross}/…` added to the bypass-
  test target, compiled but disabled-by-default stubs (merge-gate presence, not
  execution, in Phase 2).

---

## 5. Test strategy

### Unit tests (land under `/tdd`, testable logic only)
- **Descriptor canonicalization (136):** fixed preparsed-caps fixtures →
  deterministic, stable SHA-256; reordering usage pages yields the same hash
  (canonicalization correctness). Pure function, no Win32.
- **Coherence classifier (137/143):** table-driven `(VID,PID,bcdDevice,
  bMaxPacketSize0,serial-presence,iface_class_mask)` tuples → expected verdict /
  `audit_flags`; bridge-chip-VID-vs-major-vendor and HID+CDC-ContainerID cases.
- **Cadence ratio (139):** synthetic QPC timestamp series + `bInterval` →
  `ceiling_violation_ratio`; assert wireless-exempt path suppresses; assert mild
  jitter stays < 1.0.
- **Pointer features (142):** captured real-sensor stream → in-distribution
  vector; synthetic uniform/integer-curve stream → out-of-distribution; assert
  no raw delta is present in the emitted struct (privacy invariant).
- **Wire-size pins:** the `HK_STATIC_ASSERT`s in `device_trust_schema.h` compile
  on both a C99 build and a C++ build; a Rust test asserts each serde mirror
  round-trips and matches the documented byte size.
- **Server routes:** axum unit tests — valid payload → `202 ACCEPTED`, wrong
  `schema_version` → `InvalidPayload`; assert no `unwrap()` panics on malformed
  JSON.

### Bypass-tests (merge gate, guardrail #12 — one per security folder touched)
- `bypass-tests/win/hid_descriptor_template_clone.cpp` — must demonstrate an
  Arduino-HID/V-USB/LUFA template descriptor is fingerprinted into a server-
  flaggable template cluster, **and** that a QMK/ZMK and a genuine vendor
  descriptor are distinguishable from it (FP-gate proof, not just detection).
- `bypass-tests/win/usb_bridge_descriptor_spoof.cpp` — a CH340/CP2102/FTDI
  bridge descriptor claiming a major-vendor VID surfaces as
  `HK_INPUT_SRC_DESCRIPTOR_INCOHERENT` (137); HID+CDC under one ContainerID
  additionally fires 143; a genuine vendor HID+CDC composite is reported-benign.
- `bypass-tests/linux/uinput_virtual_provenance.cpp` — a `/dev/uinput` virtual
  mouse with no USB parent is reported `BUS_VIRTUAL` + creator PID; a Steam-Input
  creator PID is allowlist-attributable, an unknown creator is not.
- `bypass-tests/cross/pointer_lattice_synthetic.cpp` — a synthetic delta stream
  is flagged non-physical by the model **even with jittered inter-arrival
  timing**, while a real-sensor stream of the same HID usage class is not.

(138/144 are covered by the sibling `win-input-automation` bypass tests for 55/62
plus the 144 join-condition assertion folded into the unit suite; if this plan
lands first, add `bypass-tests/win/rawinput_source_gap.cpp` mirroring sibling 55.)

---

## 6. Sequencing

1. **`device_trust_schema.h` + server mirrors + data-categories.md §5** (one PR;
   guardrail #11 binds the schema and the doc together). If `win-input-automation`
   has NOT landed, this PR also introduces `input_prov_schema.h` with the
   `hk_input_verdict` enum (and the new `_DESCRIPTOR_INCOHERENT` value); if it
   HAS landed, this PR only adds the enumerator + the new structs. Resolve the
   `input_cadence.rs` ownership with the sibling plan in this PR.
2. **Shared readers:** `UsbTopologyWin.cpp` (137/139/143 depend on it) and the
   reuse hook into `RawInputInventoryWin` (138). No sensor logic yet — snapshot
   provider + façade only.
3. **Windows descriptor sensors:** 136 (standalone, no topology dep) in parallel
   with 137/143 (need step 2). Then 139/144 (need raw-input cadence join).
4. **Pointer-feature plane (142):** all three platform extractors + `pointer_model.rs`;
   independent of the descriptor sensors, can proceed in parallel with step 3.
5. **Linux (140):** `input_provenance.bpf.c` + `EvdevProvenanceLinux.cpp`; depends
   only on step 1's schema. Gate ON for the Deck profile.
6. **macOS (141):** `IOHIDTransportAuditMac.mm`; depends only on step 1.
7. **Bypass-tests** land with their corresponding sensor PR (merge gate — a sensor
   PR without its bypass test is rejected). Logic/unit tests land under `/tdd`
   after the scaffolding PRs (guardrail #14).

---

## 7. Risks & UNCERTAINTY FLAGS

- **FLAG — `IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION` access requirements
  (137/139/143).** I am not certain a non-elevated usermode process can open the
  USB hub interface (`\\.\HCDx` / `GUID_DEVINTERFACE_USB_HUB`) and issue these
  IOCTLs on all Windows 11 builds, or whether it needs the Horkos service's
  SYSTEM context. The exact privilege/handle-share semantics must be verified on
  the Phase-3 Win11 25H2 box before relying on them; if blocked, fall back to
  `SetupDiGetDeviceProperty` / `cfgmgr32` properties for the subset of fields
  exposed there. **Verify before building 137/139/143.**
- **FLAG — `bInterval` → physical-rate ceiling math (139).** The mapping from
  `bInterval` + endpoint speed (full/high/super) to a "physically impossible"
  report-rate ceiling differs across USB speeds and is re-clocked by hubs/
  wireless receivers. I am not certain of the exact ceiling formula for every
  speed class; the threshold must be validated against real high-poll mice
  (1000Hz/8000Hz) before any server weight, else FP risk. Treat as feature-only.
- **FLAG — eBPF `input_dev` parent-chain walk for `has_usb_parent` (140).**
  Walking `struct input_dev` → `dev.parent` → `usb_device` inside eBPF with CO-RE
  across kernel versions (and the Steam Deck kernel specifically) is non-trivial;
  the pointer chain and struct shapes may not be CO-RE-relocatable on all
  targets, and a wrong read is a verifier reject or a bad signal. **Stop and
  verify the exact `BPF_CORE_READ` chain on the Deck kernel** before relying on
  `has_usb_parent`; if unstable, fall back to the userspace `EVIOCGPHYS`/sysfs
  parent check and have eBPF report only `bustype` + `creator_pid`.
- **FLAG — `input_register_device` kprobe stability (140).** Whether
  `input_register_device` (vs a uinput-specific symbol) is the right, stable
  attach point for capturing the uinput creator PID across kernels is uncertain;
  the creator-PID attribution (the entire FP gate for Steam Input) depends on it.
  Verify the symbol and that `bpf_get_current_pid_tgid()` in that context is the
  creator, not a worker thread.
- **FP-risk concentration (140, 142, 144 are high/medium FP):** all three MUST
  remain server-side features with the documented gates (creator-PID allowlist,
  HID-usage-class conditioning, joint-condition for 144). No client verdict. A
  regression that promotes any of these to a local verdict is a correctness bug,
  not just a tuning issue.
- **macOS (141):** low API risk (IOHIDManager is stable, userspace, no ES auth
  deadline), but `kIOHIDPhysicalDeviceUniqueIDKey` availability/population varies
  by device and macOS version — treat a missing key as inconclusive, not as a
  synthetic-device signal.
- **Privacy invariant (142):** the no-raw-movement guarantee is load-bearing for
  the data-categories declaration. A bypass/unit test must assert the emitted
  struct contains no `lLastX/lLastY`-derived raw sample, only aggregates.
