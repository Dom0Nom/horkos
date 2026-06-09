# Implementation Plan — Windows: Input Provenance & Automation (`win-input-automation`)

Scope: read-only Windows usermode sensors that establish the **provenance** of
keyboard/mouse/HID input reaching the game (real physical device vs. synthetic /
emulated / hooked / attached injection) and report typed findings to the server,
which holds all ban authority. No input hooking *of other processes*, no
unhooking, no injection — the sensors only observe input the game itself
receives (its own `WM_INPUT`/LL-hook callbacks), enumerate device topology, and
read device/driver metadata. Sample-and-report only.

Catalog signals covered: **55, 56, 57, 58, 59, 60, 61, 62, 63** (the nine
"Windows — Input Provenance & Automation" designs in `docs/detection-catalog.md`,
lines 571–661).

All nine are `windows-user / userspace` sensors. They live under
`sdk/src/backends/win/` (guardrail #1: platform API only inside a `backends/`
folder, and only `HK_PLATFORM_WINDOWS`-gated, never raw `_WIN32`). None run in
the kernel; the kernel/userspace TU split (guardrail #4) is preserved because
these sensors share **no** translation unit with `kernel/win/`. Timing signals
(58, 62) compute features client-side and ship features — never a verdict — to
the server, matching the catalog's explicit "ship features to the server model,
never a client-side ban" mandate.

---

## 1. New files

| Path | Role | Module-comment summary |
|---|---|---|
| `sdk/include/horkos/input_prov_schema.h` | Public C99 typed report schema for input-provenance findings (verdict enums, source/flag bitmasks, fixed-size record + a fixed-size timing-feature block). Separate plane from `event_schema.h`. | Role: wire-format source of truth for usermode input-provenance sensor findings; verdict enums + fixed-size `hk_input_finding` and `hk_input_timing_features` records. Target: all (plain C99, no platform headers). Interface: mirrored by `server/telemetry/src/input_prov.rs`; included by SDK usermode TUs only, never a kernel TU (guardrail #4). |
| `sdk/src/backends/win/InputSensorWin.h` | Internal façade declaring the nine sensor entry points + the shared raw-input device-inventory snapshot type. | Role: internal Windows input-provenance sensor interface; declarations only. Target: Windows. Interface: implemented by the `*Win.cpp` files below; consumed by `sdk.cpp` AC tick. |
| `sdk/src/backends/win/RawInputInventoryWin.cpp` | Builds + maintains the per-session raw-input device inventory (`GetRawInputDeviceList` + `GetRawInputDeviceInfoW(RIDI_DEVICENAME)` keyed by `hDevice`, updated from `WM_INPUT_DEVICE_CHANGE`) shared by signals 55, 58, 60, 62. | Role: raw-input `hDevice`→device-path/transport snapshot provider. Target: Windows. Interface: implements `hk::sdk::win::build_rawinput_inventory` from `InputSensorWin.h`. Guardrail #1: one of the few places these sensors touch the raw-input Win32 API. |
| `sdk/src/backends/win/RawInputProvenanceWin.cpp` | Signal 55: `WM_INPUT` `hDevice`→device-list reconciliation gap. | Role: raw-input source-handle correlation-gap sensor (NULL/unknown `hDevice` ratio, accessibility/remote-session gating). Target: Windows. Interface: implements `sense_rawinput_provenance` from `InputSensorWin.h`. Catalog slot 55. |
| `sdk/src/backends/win/InputClassFilterWin.cpp` | Signal 56: keyboard/pointer device-stack upper/lower-filter interloper scan. | Role: `KeyboardClass`/`PointerClass` class-filter enumeration + signer sensor. Target: Windows. Interface: implements `sense_input_class_filters`. Catalog slot 56. |
| `sdk/src/backends/win/HidTransportProvenanceWin.cpp` | Signal 57: HID descriptor (mouse/kbd) vs. underlying transport/parent-bus mismatch. | Role: HID-collection-vs-transport provenance sensor (serial-bridge / emulator detection). Target: Windows. Interface: implements `sense_hid_transport`. Catalog slot 57. |
| `sdk/src/backends/win/InputTimingFeaturesWin.cpp` | Signal 58: inter-report timing-entropy feature extraction (per `hDevice`). | Role: `WM_INPUT` inter-arrival timing-feature extractor (QPC histogram / CoV / regularity score). Target: Windows. Computes **features only**, never a verdict (catalog mandate). Interface: implements `sense_input_timing`. Catalog slot 58. |
| `sdk/src/backends/win/LowLevelHookChainWin.cpp` | Signal 59: own-`WH_*_LL`-hook chain-depth/latency + foreign hook-callback owner. | Role: low-level-hook chain-participation sensor (own hook install + `CallNextHookEx` latency + injected-flag baseline). Target: Windows. Interface: implements `sense_llhook_chain`. Catalog slot 59. Observes only the game's own input stream. |
| `sdk/src/backends/win/RawMouseModeWin.cpp` | Signal 60: `RAWMOUSE.usFlags` absolute/virtual-desktop on a previously-relative pointer. | Role: raw-mouse coordinate-mode-transition sensor (absolute/virtual-desktop on a relative `hDevice`, local-console gating). Target: Windows. Interface: implements `sense_rawmouse_mode`. Catalog slot 60. |
| `sdk/src/backends/win/InputQueueAttachWin.cpp` | Signal 61: foreign `AttachThreadInput` interloper on the game GUI thread. | Role: GUI-thread input-queue-attach sensor (`GetGUIThreadInfo` shared-state + foreign-thread/PID attribution). Target: Windows. Interface: implements `sense_input_queue_attach`. Catalog slot 61. |
| `sdk/src/backends/win/HidPollRateWin.cpp` | Signal 62: observed report rate vs. declared USB `bInterval`/HID poll interval. | Role: HID report-rate-vs-declared-poll-interval contradiction sensor. Target: Windows. Computes a sustained-mismatch feature; Bluetooth/wireless exempted. Interface: implements `sense_hid_pollrate`. Catalog slot 62. |
| `sdk/src/backends/win/SyntheticInputArtifactWin.cpp` | Signal 63: scan-code-less / `KEYEVENTF_UNICODE` / unrecognized `GetMessageExtraInfo` injection artifact. | Role: synthetic-input desktop/journal-artifact sensor (own LL-hook scan-code + extra-info gap, gameplay-context gated). Target: Windows. Interface: implements `sense_synthetic_artifact`. Catalog slot 63. |
| `server/telemetry/src/input_prov.rs` | Serde mirror of `input_prov_schema.h` + `POST /api/input-findings` ingest route. | Role: input-provenance finding ingest plane; validates schema, logs, drops (Phase-2 stub parity with `TickPayload`). Target: server. Interface: mirrors `hk_input_finding`/`hk_input_timing_features`; mounted by `telemetry::router()`. No `unwrap()` (guardrail #8). |
| `bypass-tests/win/synthetic_input_provenance.cpp` | Bypass-test fixture: benign self-issued `SendInput` (incl. `KEYEVENTF_UNICODE`) and a simulated NULL-`hDevice` injection must be *reported* by signals 55/63, never silently missed and never auto-banned client-side. | Role: input-provenance merge-gate bypass test (disabled until enforcement TDD phase). Target: Windows. Interface: consumes `input_prov_schema.h`. Guardrail #12. |
| `bypass-tests/win/input_filter_interloper.cpp` | Bypass-test fixture: an unsigned/unknown class upper-filter (simulated registry/inventory entry) must surface in signal-56 findings with the filter service name + signer verdict, while a vendor-allowlisted filter is reported-but-benign. | Role: input-class-filter merge-gate bypass test (disabled stub). Target: Windows. Interface: consumes `input_prov_schema.h`. Guardrail #12. |

Module comment on every file above satisfies guardrail #3.

---

## 2. Interfaces & data structures

### 2.1 New report plane: `sdk/include/horkos/input_prov_schema.h`

These findings carry **variable-length strings** (`RIDI_DEVICENAME` device-interface
paths, filter service names, Authenticode signer subjects, HID VID/PID strings) and
**per-device timing histograms** that do not fit the fixed 16-byte
`HK_EVENT_PAYLOAD_MAX` kernel ring record. They are **not** kernel events and must not
be forced through the `HK_IOCTL_DRAIN_EVENTS` envelope. Mirroring the existing two-plane
split (kernel `event_schema.h` vs JSON `TickPayload`), input-provenance findings get
their **own JSON plane** to the server. `input_prov_schema.h` defines the *typed numeric*
core (enums, bitmasks, fixed-size record + a fixed-size timing-feature block) as the
source of truth; string fields ride alongside in the JSON envelope, not in the C struct.

```c
#pragma once
#include <stdint.h>
#include "horkos/event_schema.h"   /* HK_STATIC_ASSERT + <stdint.h> only; no platform headers */

#define HK_INPUT_SCHEMA_VERSION 1u   /* independent of HK_EVENT_SCHEMA_VERSION */

typedef enum hk_input_signal {       /* catalog signal id, stable */
    HK_INPUT_SIG_RAWINPUT_PROVENANCE = 55,
    HK_INPUT_SIG_CLASS_FILTER        = 56,
    HK_INPUT_SIG_HID_TRANSPORT       = 57,
    HK_INPUT_SIG_TIMING_ENTROPY      = 58,
    HK_INPUT_SIG_LLHOOK_CHAIN        = 59,
    HK_INPUT_SIG_RAWMOUSE_MODE       = 60,
    HK_INPUT_SIG_QUEUE_ATTACH        = 61,
    HK_INPUT_SIG_HID_POLLRATE        = 62,
    HK_INPUT_SIG_SYNTHETIC_ARTIFACT  = 63,
} hk_input_signal;

/* Provenance verdict for the device/source backing an input (55/56/57). The
 * client reports the resolved classification; the server alone decides on a
 * ban. "unsigned/unknown filter or emulator bridge" is the anomaly, not mere
 * presence (catalog FP gates). */
typedef enum hk_input_verdict {
    HK_INPUT_SRC_PHYSICAL_KNOWN       = 0, /* resolves to an enumerated, signed/allowlisted device */
    HK_INPUT_SRC_ACCESSIBILITY_GATED  = 1, /* NULL hDevice but approved remote/accessibility session set */
    HK_INPUT_SRC_FILTER_FOREIGN_SIGNED= 2, /* class filter present, signed, not vendor-allowlisted */
    HK_INPUT_SRC_FILTER_UNSIGNED      = 3, /* class filter unsigned / hash-unknown */
    HK_INPUT_SRC_EMULATOR_BRIDGE      = 4, /* HID descriptor over serial/CDC/generic-bridge parent */
    HK_INPUT_SRC_SYNTHETIC            = 5, /* NULL/unknown hDevice or synthetic artifact, no gate */
    HK_INPUT_SRC_UNRESOLVED           = 6, /* enumeration/query failed; sensor inconclusive */
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

/* Fixed-size numeric core of one finding. Strings (device_path, filter_service,
 * signer_subject, vidpid, owning_image) travel in the JSON envelope keyed by record
 * index, never inline, so this struct stays fixed-size and paths are not length-bounded. */
typedef struct hk_input_finding {
    uint32_t schema_version;   /* HK_INPUT_SCHEMA_VERSION at emit. */
    uint32_t signal;           /* hk_input_signal. */
    uint32_t verdict;          /* hk_input_verdict, or 0 when N/A. */
    uint32_t flags;            /* HK_INFLAG_* bitmask. */
    uint32_t owning_pid;       /* foreign PID for queue-attach / hook-owner signals, else 0. */
    uint32_t event_count;      /* events observed in the window (denominator for the ratio). */
    uint32_t anomaly_count;    /* events matching the anomaly (numerator), e.g. NULL-hDevice count. */
    uint32_t filter_count;     /* ordered class-filter count (56), else 0. */
    uint64_t hdevice_token;    /* opaque per-session hDevice id (NOT the raw HANDLE), else 0. */
    int64_t  llhook_latency_ns;/* measured CallNextHookEx call-out delay (59), else 0. */
} hk_input_finding;

HK_STATIC_ASSERT(sizeof(hk_input_finding) == 48, "hk_input_finding size mismatch");

/* Timing-feature block for signals 58 (inter-report entropy) and 62 (poll-rate
 * contradiction). FEATURES ONLY — no client verdict (catalog: "ship features to the
 * server model, never a client-side ban"). Fixed-size histogram so the record stays
 * flat; the server runs the regularity/mismatch model. */
#define HK_INPUT_TIMING_BUCKETS 16u

typedef struct hk_input_timing_features {
    uint32_t schema_version;   /* HK_INPUT_SCHEMA_VERSION at emit. */
    uint32_t signal;           /* 58 or 62. */
    uint64_t hdevice_token;    /* same opaque per-session id as hk_input_finding. */
    uint32_t sample_count;     /* deltas summarized. */
    uint32_t declared_hz;      /* HID/USB bInterval-derived declared rate (62), else 0. */
    uint32_t observed_hz_x100; /* measured WM_INPUT rate * 100 (fixed-point), else 0. */
    uint32_t transport_flags;  /* HK_INTRANSPORT_* (Bluetooth/wireless exemption for 62). */
    uint32_t cov_x10000;       /* coefficient of variation of inter-arrival deltas, *1e4. */
    uint32_t regularity_x10000;/* chi-square/autocorrelation regularity score, *1e4. */
    uint32_t period_hist[HK_INPUT_TIMING_BUCKETS]; /* inter-arrival delta histogram. */
} hk_input_timing_features;

HK_STATIC_ASSERT(sizeof(hk_input_timing_features) == 104,
    "hk_input_timing_features size mismatch");

/* Transport flags for the 62 poll-rate exemption (catalog: exempt BT/wireless). */
#define HK_INTRANSPORT_USB        0x01u
#define HK_INTRANSPORT_BLUETOOTH  0x02u  /* connection-interval != HID bInterval legitimately */
#define HK_INTRANSPORT_WIRELESS   0x04u  /* dongle/proprietary RF */
#define HK_INTRANSPORT_VIRTUAL    0x08u  /* no physical endpoint resolvable */
```

Sizes (`48` for the finding, `104` for the timing block) are computed from the field
layout above (no implicit padding on either struct: all members are 4/8-byte aligned and
the histogram is `16 * uint32_t = 64`, giving `40 + 64 = 104`). The `HK_STATIC_ASSERT`
pins both; any layout drift breaks the SDK build, and the Rust `#[test]` mirror (§5)
breaks the server build.

### 2.2 No new IOCTL codes

`ioctl.h` is **not** modified. These are usermode sensors reporting over HTTP/JSON, not
kernel records. Adding an IOCTL would imply kernel involvement and violate the plane
separation. `HK_IOCTL_DRAIN_EVENTS`, `HK_EVENT_PAYLOAD_MAX`, and the 40-byte
`hk_event_record` stay untouched — forcing the 48/104-byte input records through the
40-byte ring would corrupt it (see risk R1).

### 2.3 Server mirror: `server/telemetry/src/input_prov.rs`

```rust
pub const INPUT_SCHEMA_VERSION: u32 = 1;
pub const INPUT_TIMING_BUCKETS: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InputFinding {
    pub schema_version: u32,
    pub signal: u32,
    pub verdict: u32,
    pub flags: u32,
    pub owning_pid: u32,
    pub event_count: u32,
    pub anomaly_count: u32,
    pub filter_count: u32,
    pub hdevice_token: u64,
    pub llhook_latency_ns: i64,
    // String side-channel — not in the C struct; declared in data-categories.md.
    #[serde(default)] pub device_path: Option<String>,
    #[serde(default)] pub filter_service: Option<String>,
    #[serde(default)] pub signer_subject: Option<String>,
    #[serde(default)] pub vidpid: Option<String>,
    #[serde(default)] pub owning_image: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InputTimingFeatures {
    pub schema_version: u32,
    pub signal: u32,
    pub hdevice_token: u64,
    pub sample_count: u32,
    pub declared_hz: u32,
    pub observed_hz_x100: u32,
    pub transport_flags: u32,
    pub cov_x10000: u32,
    pub regularity_x10000: u32,
    pub period_hist: [u32; INPUT_TIMING_BUCKETS],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputFindingBatch {
    pub schema_version: u32,
    pub player_id: u64,
    #[serde(default)] pub findings: Vec<InputFinding>,
    #[serde(default)] pub timing: Vec<InputTimingFeatures>,
}
```

Route `POST /api/input-findings` validates `schema_version == INPUT_SCHEMA_VERSION`,
records a tracing span, then drops (Phase-2 stub, exactly like `telemetry::ingest`). No
`unwrap()`/`expect()` outside `#[cfg(test)]` (guardrail #8); errors via the existing
`telemetry::error::TelemetryError` (extend with an `InputSchema` variant through
`thiserror`, mirroring how the render plan extends it). Fully async axum handler on
tokio — no blocking calls (guardrail #8).

### 2.4 `data-categories.md` additions (guardrail #11 — same PR)

Every new telemetry field above must be declared. Add a new section **"6. Input
provenance & automation findings (Windows usermode)"** to `server/api/data-categories.md`:

| Field | Source | Notes |
|---|---|---|
| `signal` | input sensor | catalog signal id (55–63) |
| `verdict` | provenance classifier (55/56/57) | enum `hk_input_verdict` |
| `flags` | per-event source/mode bits | `HK_INFLAG_*` (NULL/unknown hDevice, absolute mode, queue-attach, no-scancode, injected baseline) |
| `owning_pid` | queue-attach / foreign LL-hook owner attribution | `GetWindowThreadProcessId` / module-map owner |
| `event_count` / `anomaly_count` | ratio numerator/denominator | catalog mandate: report the **ratio**, not single events |
| `filter_count` | class-filter stack depth (56) | ordered upper/lower filter count |
| `hdevice_token` | opaque per-session id derived from `hDevice` | **not** the raw OS handle; stable within a session only |
| `llhook_latency_ns` | own-hook `CallNextHookEx` call-out delay (59) | chain-participation timing |
| `declared_hz` / `observed_hz_x100` / `transport_flags` | HID poll-rate contradiction (62) | declared vs observed rate + BT/wireless exemption |
| `cov_x10000` / `regularity_x10000` / `period_hist[16]` | inter-report timing features (58) | **features only**, server model decides; no raw input content |
| `device_path` | `GetRawInputDeviceInfoW(RIDI_DEVICENAME)` | device-interface path string |
| `filter_service` | `SPDRP_UPPERFILTERS`/`LOWERFILTERS` | class-filter driver service name |
| `signer_subject` | Authenticode signer (`wintrust`/`crypt32`) | publisher subject the server allow-lists against |
| `vidpid` | `HidD_GetAttributes` | VID/PID of the implicated HID collection |
| `owning_image` | foreign queue-attach / hook-owner image path | on-disk path of the implicated module/process |

Reviewer rejects the PR if any field above lands without its row here. Note: the
sensors record **input provenance/timing metadata only** — never keystroke content,
never typed text, never aim coordinates (those live on the separate `TickPayload`
plane). The timing histogram is inter-arrival *deltas*, not the input values.

---

## 3. Mechanism implementation notes

All sensors are **read-only and observe only the game's own input + system device
topology**: they register the game's *own* `RIDEV_INPUTSINK` raw-input sink, install the
game's *own* `WH_*_LL` hooks, enumerate devices/filters via SetupAPI, and read device
metadata. No `WriteProcessMemory`, no foreign-process input hooking, no unhooking. They
run on the SDK AC tick thread / the game's input thread, **not** in the kernel — none of
the IRQL/IRP/`ObRegisterCallbacks`/ES-reply concerns apply (those are kernel/macOS and
out of scope here). The relevant safety axis is **usermode robustness**: every Win32
call's failure path is handled, no exceptions cross the C ABI boundary, and a sensor that
cannot resolve a source emits `HK_INPUT_SRC_UNRESOLVED` rather than a false anomaly.

**Shared (`RawInputInventoryWin.cpp`).** On AC start, register the game's raw-input sink:
`RegisterRawInputDevices` with `RIDEV_INPUTSINK | RIDEV_DEVNOTIFY` for the generic mouse
(usage page 0x01 usage 0x02) and keyboard (0x01/0x06) top-level collections, so the game
receives `WM_INPUT` even when not foreground and gets `WM_INPUT_DEVICE_CHANGE`
arrive/remove notifications. Build the inventory map `hDevice → { RIDI_DEVICENAME,
RID_DEVICE_INFO, derived transport }` from `GetRawInputDeviceList` +
`GetRawInputDeviceInfoW(RIDI_DEVICENAME / RIDI_DEVICEINFO)`, refreshed on every
`WM_INPUT_DEVICE_CHANGE`. The map assigns each `hDevice` an opaque stable
`hdevice_token` (a per-session counter), so the raw OS `HANDLE` value is never shipped.
Signals 55/58/60/62 consume this map. *Concern:* the `WM_INPUT` handler must
`GetRawInputData` with a correctly-sized buffer (call once for size, once for data) and
must never block the input thread — feature accumulation is O(1) per message.

**55 — Raw-input source-handle correlation gap.** For each `WM_INPUT`, read
`RAWINPUTHEADER.hDevice` and reconcile against the inventory. Count
`HK_INFLAG_HDEVICE_NULL` (synthetic `SendInput`/`keybd_event`/`mouse_event` typically
yields `hDevice == NULL`) and `HK_INFLAG_HDEVICE_UNKNOWN` (a path never seen enumerate).
**Report the ratio** (`anomaly_count`/`event_count`) over a window, never a single event
(catalog FP gate). Gate NULL-`hDevice` as benign only when an approved accessibility/
remote flag is set: `GetSystemMetrics(SM_REMOTESESSION)` and
`WTSGetActiveConsoleSessionId`/`ProcessIdToSessionId` comparison → set
`HK_INFLAG_REMOTE_SESSION`/`HK_INFLAG_ACCESSIBILITY` and verdict
`HK_INPUT_SRC_ACCESSIBILITY_GATED`. On-screen keyboards, Steam Input virtual gamepads,
AHK remappers legitimately produce NULL `hDevice` — the gating + ratio handles them.

**56 — Keyboard/Pointer device-stack filter interloper.** Enumerate via
`SetupDiGetClassDevs(GUID_DEVCLASS_KEYBOARD / GUID_DEVCLASS_MOUSE)`, read
`SPDRP_UPPERFILTERS`/`SPDRP_LOWERFILTERS` with `SetupDiGetDeviceRegistryProperty`, and
cross-read the **class** UpperFilters/LowerFilters under
`HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96b-...}` (keyboard) and `{4d36e96f-...}`
(mouse). Report the **full ordered filter list** (`filter_count` + per-filter
`filter_service`) and each filter image's signing chain via `WinVerifyTrust`. Verdict:
unsigned/hash-unknown → `HK_INPUT_SRC_FILTER_UNSIGNED`; signed-but-not-vendor-allowlisted →
`HK_INPUT_SRC_FILTER_FOREIGN_SIGNED`. The vendor allow-list (kbdclass/mouclass/i8042prt/HID
stack, Synaptics/ELAN/Logitech/Razer/Corsair/Wacom/KVM/HASP) is **server-side signed-rule
plumbing** — the client reports signer + service name, never decides. *Concern:*
`WinVerifyTrust` is expensive and may hit revocation network; cache per image per session,
run off the hot path, map timeout → `HK_INPUT_SRC_UNRESOLVED`, never a false "unsigned".

**57 — HID descriptor vs. transport mismatch.** For each HID mouse/keyboard collection,
`CreateFileW` the HID interface path, `HidD_GetPreparsedData` + `HidP_GetCaps` for
`UsagePage`/`Usage`, `HidD_GetAttributes` for VID/PID, then walk
`SetupDiGetDevicePropertyW(DEVPKEY_Device_EnumeratorName / DEVPKEY_Device_Parent /
DEVPKEY_Device_BusTypeGuid)` to confirm the underlying transport. A pointer/keyboard usage
on a USB-CDC/serial or generic-bridge parent → `HK_INPUT_SRC_EMULATOR_BRIDGE`
(Arduino/Pi Pico/KMBox-style serial-to-HID). Gate on the **combination** of
generic/known-emulator VID/PID *plus* absence of a vendor HID report-descriptor signature
(catalog FP gate: composite gaming keyboards + serial config interfaces, DACs, KVM
adapters legitimately pair HID with CDC) — never flag VID/PID against an allow-list alone.
The allow-list is server-side; the client reports `vidpid` + parent-bus + descriptor
presence. *Concern:* `CreateFileW` on a HID path can fail with sharing/access errors for
exclusively-opened devices — handle and emit `HK_INPUT_SRC_UNRESOLVED`, do not crash.

**58 — Inter-report timing entropy.** Timestamp each `WM_INPUT` at receipt with
`QueryPerformanceCounter`, bucket inter-arrival deltas per `hDevice`, and over a sliding
window compute the `period_hist` histogram, `cov_x10000`, and a chi-square/autocorrelation
`regularity_x10000`. **Ship `hk_input_timing_features` — never a verdict** (catalog:
"timing alone is too noisy ... ship features to the server model, never a client-side ban").
The server combines regularity with the device's reported polling rate and requires
persistence across context switches / aim phases. *Concern:* 1000–8000 Hz mice genuinely
produce regular deltas and frame-locked input aliases to fixed periods — that disambiguation
is **server-side** and explicitly out of scope for the client; the client must not threshold.
*Robustness:* histogram accumulation is O(1) per message on the input thread; the per-tick
serialize/ship runs on the AC tick thread, never the input thread.

**59 — Low-level hook ownership and chain depth.** Install the game's own
`SetWindowsHookEx(WH_MOUSE_LL / WH_KEYBOARD_LL)` and measure the call-out delay around
`CallNextHookEx` (`QueryPerformanceCounter` before/after) → `llhook_latency_ns`; a foreign
hook earlier in the chain adds measurable per-event latency. Read
`MSLLHOOKSTRUCT.flags`/`KBDLLHOOKSTRUCT.flags` (`LLMHF_INJECTED` /
`LLMHF_LOWER_IL_INJECTED`) for the `HK_INFLAG_LLMHF_INJECTED` baseline. Correlate the
foreign hook-callback owner with the module inventory from the **already-implemented**
`PsSetLoadImageNotifyRoutine` kernel path (read via the existing AC module surface — no new
kernel coupling, just consuming the existing event stream). Verdict only when the owner is
unsigned/unknown — Discord/Steam/GeForce overlays, OBS, push-to-talk, AHK legitimately
install LL hooks; the signed-module allow-list join is server-side. *Concern:* the LL hook
callback runs on the thread that installed it with a system timeout (≈ `LowLevelHooksTimeout`,
default ~300 ms); the callback must do only O(1) work and `CallNextHookEx` promptly, or
Windows silently removes the hook. **Flagged in R3.**

**60 — RAWMOUSE absolute/virtual-desktop flag on a relative pointer.** Inspect
`RAWMOUSE.usFlags` on each `WM_INPUT` for `MOUSE_MOVE_ABSOLUTE` / `MOUSE_VIRTUAL_DESKTOP` /
`MOUSE_MOVE_RELATIVE` transitions per `hDevice`; a device that reported relative then emits
absolute, or oscillates, sets `HK_INFLAG_MODE_OSCILLATION`. Read `lLastX`/`lLastY` range to
confirm absolute-coordinate semantics. Gate on local-console (`SM_REMOTESESSION` false) and
on whether an absolute-capable HID (digitizer/touch class) actually enumerated — flag
absolute reports only when **no corresponding absolute-class device is present** (catalog FP:
Wacom, touchscreens, RDP/VNC, VM guest-tools legitimately report absolute). Report
`HK_INFLAG_MOUSE_ABSOLUTE`/`HK_INFLAG_MOUSE_VIRTDESKTOP` + the device path; the server scores.

**61 — GUI-thread input queue attach.** Read `GetGUIThreadInfo` for the game's input
thread and compare active/focus/capture window ownership + the queue-shared state against
expectation. Detect cross-process queue attachment by correlating
`GetWindowThreadProcessId` of the foreground/focus windows against the game's own thread,
surfacing threads sharing input state via `AttachThreadInput`. Report `owning_pid` +
`owning_image` of the attaching process with `HK_INFLAG_QUEUE_ATTACHED`. Gate by
attaching-process signer allow-list (server-side) and flag only when the attacher is also
unsigned or already flagged by the process/handle sensors. *Concern:* `GUITHREADINFO.cbSize`
must be set before the call; IMEs/screen-readers/UI-automation legitimately attach — the
benign filter is server-side.

**62 — HID report-rate vs. declared polling-interval contradiction.** Read the device's
configured report cadence via `SetupDiGetDevicePropertyW` and the USB endpoint `bInterval`
through `IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION` on the parent hub (parse
`USB_ENDPOINT_DESCRIPTOR.bInterval` for the interrupt-IN endpoint), derive `declared_hz`,
and compare against the measured `WM_INPUT` arrival rate per `hDevice` (`observed_hz_x100`).
Emit `hk_input_timing_features` with both rates + `transport_flags`. Require a **large,
sustained** mismatch (server-side threshold) and set `HK_INTRANSPORT_BLUETOOTH`/`WIRELESS`
so the server exempts transports where connection-interval legitimately differs from HID
`bInterval` (catalog FP: variable-rate mice, OS rate overrides, BLE connection-interval
variance). *Concern:* walking the USB topology to the parent hub + node-connection IOCTL is
intricate and can fail for non-USB (BT/virtual) devices — handle, set
`HK_INTRANSPORT_VIRTUAL`, and emit `declared_hz == 0` (unknown), never a false contradiction.
**Flagged in R4** (USB hub IOCTL path).

**63 — Synthetic-input desktop/journal artifact + extra-info tag.** In the game's own
LL-hook path, read `GetMessageExtraInfo()` and the `KBDLLHOOKSTRUCT.scanCode`/`flags`
(and `MSLLHOOKSTRUCT`). Physical HID input populates a driver-stamped extra-info and a real
scan code; `SendInput` with `KEYEVENTF_UNICODE` or scan-code-less synthesis leaves a gap →
`HK_INFLAG_NO_SCANCODE` / `HK_INFLAG_EXTRAINFO_UNKNOWN`. **Gate to gameplay context**
(`HK_INFLAG_GAMEPLAY_CONTEXT`, set by the SDK when in-combat / text entry is not expected)
and correlate with the `LLMHF_INJECTED` baseline rather than acting on extra-info alone
(catalog FP: clipboard paste, IME composition, on-screen keyboards, Unicode entry, localized
layouts all legitimately produce scan-code-less `KEYEVENTF_UNICODE`). *Concern:* the set of
"known physical driver extra-info stamps" is not enumerable as a fixed list; treat unknown
extra-info as a *soft* flag fused server-side, never a standalone client verdict.

**Server (`input_prov.rs`).** Fully async axum handler on tokio; schema-version check;
`thiserror` error type; no `unwrap()`/`expect()` outside `#[cfg(test)]`. Mirrors the
existing `telemetry::ingest` stub exactly (validate → log → drop in Phase 2).

---

## 4. Build wiring

- **Sensors** compile into `hk_sdk` (the existing static lib in `sdk/CMakeLists.txt`).
  Extend the `if(WIN32)` branch to add the ten `*Win.cpp` files (nine sensors +
  `RawInputInventoryWin.cpp`) to `hk_sdk_backend`, behind a new option:

  ```cmake
  option(HK_INPUT_SENSORS_WIN "Build Windows input-provenance usermode sensors" ON)
  if(WIN32 AND HK_INPUT_SENSORS_WIN)
      list(APPEND hk_sdk_backend
          src/backends/win/RawInputInventoryWin.cpp
          src/backends/win/RawInputProvenanceWin.cpp
          src/backends/win/InputClassFilterWin.cpp
          src/backends/win/HidTransportProvenanceWin.cpp
          src/backends/win/InputTimingFeaturesWin.cpp
          src/backends/win/LowLevelHookChainWin.cpp
          src/backends/win/RawMouseModeWin.cpp
          src/backends/win/InputQueueAttachWin.cpp
          src/backends/win/HidPollRateWin.cpp
          src/backends/win/SyntheticInputArtifactWin.cpp)
      # Win32 link deps confined to the Windows branch:
      #   user32          (RegisterRawInputDevices/GetRawInputData/SetWindowsHookEx/
      #                    GetGUIThreadInfo/GetSystemMetrics)
      #   setupapi cfgmgr32 (SetupDiGetClassDevs / device properties — 56/57/62)
      #   hid             (HidD_*/HidP_* — 57/62)
      #   wintrust crypt32 (filter/HID image signer — 56/57)
      #   advapi32        (Control\Class registry reads — 56)
      #   wtsapi32        (WTSGetActiveConsoleSessionId — 55)
  endif()
  ```

  `target_compile_definitions(hk_sdk PRIVATE HK_PLATFORM_WINDOWS)` already governs the
  conditional code — sources use `HK_PLATFORM_WINDOWS`, never raw `_WIN32` (guardrail #1).
  Default **ON** (these are core product sensors for the platform). The
  `setupapi`/`hid`/`wtsapi32` link libs are added only inside the `if(WIN32 AND
  HK_INPUT_SENSORS_WIN)` branch via `target_link_libraries(hk_sdk PRIVATE ...)`.

- **Toolchain:** MSVC + Windows SDK (WDK **not** required — usermode only; no driver
  build, no test-signing). `setupapi.lib`/`hid.lib`/`cfgmgr32.lib`/`wtsapi32.lib`/
  `wintrust.lib`/`crypt32.lib` ship in the Windows SDK. No third-party deps.

- **Server:** add `pub mod input_prov;` to `server/telemetry/src/lib.rs` and
  `.merge(input_prov::router())` (or fold `POST /api/input-findings` into
  `telemetry::router()`). No new crate; no new Cargo deps (reuses `axum`, `serde`,
  `thiserror`, `tracing`). Extend `TelemetryError` with an `InputSchema` variant.

- **Bypass tests:** add the two new executables to `bypass-tests/win/CMakeLists.txt`
  alongside `hk_bypass_byovd`, disabled-by-default like the existing fixture
  (activation flag `HK_INPUT_BYPASS_ENABLED`, mirroring `HK_BYOVD_TEST_ENABLED`).

---

## 5. Test strategy

### Unit / integration

- **Provenance classifier (55/56/57)** — table-driven test mapping
  `(hDevice-in-inventory?, NULL?, remote/accessibility-flag, filter signer, HID parent-bus,
  VID/PID)` → expected `hk_input_verdict`, including the `HK_INPUT_SRC_UNRESOLVED` path when
  a SetupAPI/HID query fails and the `HK_INPUT_SRC_ACCESSIBILITY_GATED` NULL-`hDevice`-with-
  remote-session case (guards the catalog FP).
- **Ratio folding (55)** — given a sequence of `(hDevice)` observations, assert
  `anomaly_count`/`event_count` is the reported ratio and that a single NULL event below the
  window threshold does not flag (catalog: report the ratio, not single events).
- **Timing-feature math (58/62)** — pure, host-runnable: feed synthetic inter-arrival delta
  sequences (uniform-jitter macro, fixed-period script, true-physical tremor sample) and
  assert `cov_x10000`/`regularity_x10000`/`period_hist` are computed deterministically;
  assert the sensor emits **features only** and exposes no verdict field (guards the catalog
  "never client-side ban" mandate). Highest-value unit — pure and the main correctness axis.
- **Poll-rate derivation (62)** — given a declared `bInterval` and an observed rate, assert
  `declared_hz`/`observed_hz_x100` and that a Bluetooth/`HK_INTRANSPORT_VIRTUAL` transport
  suppresses the mismatch feature (exemption).
- **Flag-bitmask folding (60/63)** — given `RAWMOUSE.usFlags` / `scanCode` / extra-info
  inputs, assert the `HK_INFLAG_*` bitmask, the relative→absolute oscillation detection, and
  the gameplay-context gating for 63.
- **Schema size guard** — `HK_STATIC_ASSERT(sizeof(hk_input_finding) == 48)` and
  `(sizeof(hk_input_timing_features) == 104)` are compile-time tests; a Rust `#[test]`
  asserts the serde mirror round-trips and field/array sizes match (catches drift between
  `input_prov_schema.h` and `input_prov.rs`, including `period_hist[16]`).
- **Server route** — extend `server/telemetry/tests/` with `input_findings.rs` (mirror the
  existing telemetry integration test): a valid `InputFindingBatch` (findings + timing) →
  `202`; wrong `schema_version` → `400`/`422` via `TelemetryError`.

### Bypass tests (guardrail #12 — merge gate)

Any change under a security folder (`sdk/src/backends/win/`) needs a corresponding bypass
test. Two are added, both **disabled stubs** in this scaffolding phase (logic lands under
`/tdd`, guardrail #14), present so the gate stays green and the intent is recorded, exactly
like `byovd_load.cpp` (compile now, print `DISABLED`, return 0):

- **`synthetic_input_provenance`** — must demonstrate: a benign, self-issued `SendInput`
  burst (including a `KEYEVENTF_UNICODE` event) into the test's own window is **reported** by
  signals 55 and 63 with `HK_INFLAG_HDEVICE_NULL` / `HK_INFLAG_NO_SCANCODE` and the resolved
  verdict, and is **not** auto-banned client-side (proves the report-only contract: a
  synthetic event ≠ ban; the server decides). It must also demonstrate that a `SendInput`
  while a simulated accessibility/remote-session flag is set is reported as
  `HK_INPUT_SRC_ACCESSIBILITY_GATED`, not raw `SYNTHETIC` (the FP-gating contract).
  Activation flag `HK_INPUT_BYPASS_ENABLED`.
- **`input_filter_interloper`** — must demonstrate: an unsigned/unknown class upper-filter
  (simulated via an injected inventory/registry fixture entry, **no real driver loaded**)
  surfaces in signal-56 findings with the correct `filter_service`, `filter_count`, and
  `HK_INPUT_SRC_FILTER_UNSIGNED` verdict, while a vendor-allowlisted signed filter (simulated
  signer subject) is **reported but classified benign** — i.e. the sensor does not drop the
  legitimate-vendor-filter case (the FP-gating contract). No real filter driver is built or
  loaded; the repo never commits a real input-filter binary.

Both compile now and print `DISABLED` until the enforcement/scoring path lands.

---

## 6. Sequencing

1. **`input_prov_schema.h` + `data-categories.md` section 6 + `input_prov.rs` mirror.**
   Land the contract first (with both `HK_STATIC_ASSERT`s and the serde round-trip test,
   including `period_hist[16]`). Nothing else compiles against a moving schema. Guardrail
   #11 is satisfied in this same step.
2. **`RawInputInventoryWin.cpp` + `InputSensorWin.h`.** The shared substrate
   (`hDevice`→path/transport map, `hdevice_token` assignment, raw-input sink registration)
   that 55/58/60/62 depend on; ship its unit tests (inventory reconcile + token stability)
   before the consuming sensors.
3. **Signals 55 + 60** (raw-input provenance gap + mouse coordinate-mode) — highest-confidence
   provenance signals, depend only on steps 1–2 and share the inventory + remote-session
   gating. Land with the `synthetic_input_provenance` bypass-test stub.
4. **Signals 63 + 59** (synthetic-artifact + LL-hook chain) — share the game's own LL-hook
   install path; 63's gameplay-context gating and 59's `LLMHF_INJECTED` baseline come from
   the same `MSLLHOOKSTRUCT`/`KBDLLHOOKSTRUCT` read. Land after the hook-timeout concern (R3)
   is confirmed.
5. **Signals 56 + 57** (class-filter interloper + HID transport) — share SetupAPI enumeration
   + `WinVerifyTrust` signer resolution; independent of the raw-input inventory. Land with the
   `input_filter_interloper` bypass-test stub.
6. **Signals 58 + 62** (timing-entropy + poll-rate contradiction) — both emit
   `hk_input_timing_features`; 58 depends on the inventory (step 2), 62 additionally on the
   USB-hub IOCTL path (R4). Land last among sensors because they are feature-only and the
   server model that consumes them is itself later work.
7. **Signal 61** (queue-attach) — independent (`GetGUIThreadInfo`); land any time after step 1.
8. **Server route + CMake wiring + bypass-test CMake** — wire `POST /api/input-findings`, the
   `HK_INPUT_SENSORS_WIN` option, and the two bypass executables. Run the full suite.

Per-sensor logic that makes a *decision* (scoring, baselines, signer allow-lists, timing
thresholds) is deferred to the server signed-rule plumbing and to `/tdd` phases (guardrail
#14) — this plan scaffolds read-only sensors + the report contract, not the verdict engine.
The timing signals (58/62) **must not** acquire client-side thresholds at any point.

---

## 7. Risks & uncertainty flags

- **R1 — payload-size plane mismatch (resolved by design, flag for reviewer).** Input
  findings are 48 bytes + variable strings; timing features are 104 bytes. The kernel record
  is 40 bytes (`HK_EVENT_PAYLOAD_MAX = 16`). Forcing either through `HK_IOCTL_DRAIN_EVENTS`
  would corrupt the ring. This plan deliberately keeps them on a **separate JSON plane** and
  does **not** touch `ioctl.h`/`event_schema.h` sizing. Reviewer should confirm the separate-
  plane decision rather than expecting an IOCTL extension.

- **R2 — timing is fundamentally server-side (58/62).** High-polling-rate mice (1000–8000 Hz),
  frame-locked/vsync input, and OS rate overrides genuinely produce regular deltas; VRR and
  BLE connection-interval variance legitimately break the declared-vs-observed rate. The
  client must ship **raw features only**; if any thresholding leaks client-side it will
  false-positive on high-Hz and frame-generation users. Explicitly out of scope for the
  client and flagged so it is not "optimized" into the sensor later (catalog-mandated).

- **R3 — UNCERTAINTY: LL-hook callback timeout (59/63).** A `WH_*_LL` hook callback runs
  under a system timeout (`HKLM\Control Panel\Desktop\LowLevelHooksTimeout`, default commonly
  cited as ~300 ms) after which Windows silently removes the hook and may not call it. The
  sensor's `CallNextHookEx` latency measurement (59) and scan-code/extra-info read (63) must
  do strictly O(1) work and chain promptly. **I am not fully certain of the exact current-OS
  timeout semantics and whether a removed hook is re-armed or just dropped** — confirm the
  documented `LowLevelHooksTimeout` behavior and the re-arm strategy before implementing 59,
  rather than guessing. The latency-measurement approach also risks *being* the slow hook that
  triggers removal; verify the budget. (Usermode, not a kernel/BSOD risk, but a correctness +
  detection-validity uncertainty per guardrail #13's spirit.)

- **R4 — UNCERTAINTY: USB hub node-connection IOCTL path (62).** Walking from a HID collection
  up to its parent hub and issuing `IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION` to read the
  endpoint `bInterval` requires resolving the hub device path, the port/connection index, and
  the correct request layout — semi-documented and easy to get subtly wrong, and it does not
  apply to Bluetooth/virtual/composite devices. **I am not certain the hub-walk + node-
  connection IOCTL reliably yields the interrupt-IN endpoint `bInterval` across hub
  topologies (root hub vs. external hub, composite parents).** Confirm the topology-walk and
  IOCTL request shape before implementing 62; until then, `declared_hz == 0` (unknown) is the
  safe output and the server simply gets no contradiction feature — never a false positive.

- **R5 — Authenticode verification cost/cache (56/57/59).** `WinVerifyTrust` is expensive and
  may hit the network (revocation). Must be cached per image per session and run off the input
  thread; unverified-due-to-timeout maps to `HK_INPUT_SRC_UNRESOLVED`/null signer, never a
  false "unsigned" verdict. Not a kernel-API uncertainty, but a correctness flag.

- **R6 — `hDevice` is not a stable cross-session identifier.** Raw-input `HANDLE` values are
  not guaranteed stable across reconnects or reboots, and shipping a raw kernel HANDLE leaks
  nothing useful and risks privacy review. The plan ships an opaque per-session
  `hdevice_token` derived from the inventory, paired with the `RIDI_DEVICENAME` string only.
  Reviewer should confirm the token scheme (session-local counter) meets the server's
  correlation needs without a persistent device fingerprint here.

- **R7 — accessibility/remote-session gating is a real-user safety floor (55/60/63).** On-
  screen keyboards, Steam Input, AHK accessibility remappers, RDP/VNC and VM guest-tools
  legitimately produce NULL-`hDevice`, absolute-mode, and scan-code-less input. The gating
  flags (`SM_REMOTESESSION`, console-session check) and the ratio/gameplay-context windows are
  load-bearing FP controls — they must ship with the sensors, not as a later refinement, or
  the first telemetry wave mislabels disabled players. The final allow-list decision is
  server-side, but the client-side gates above are non-negotiable.

None of these nine signals touch a kernel API, IRP lifecycle, IRQL, `ObRegisterCallbacks`,
ES auth deadlines, or code-signing of *our* driver, so guardrail #13's kernel-uncertainty
stops do not bind here. The two genuine API uncertainties (R3 LL-hook timeout semantics, R4
USB hub node-connection IOCTL) are flagged above for confirmation before coding rather than
guessed.
