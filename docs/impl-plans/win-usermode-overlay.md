# Implementation Plan — Windows Usermode: Render / Overlay Hooks (`win-usermode-overlay`)

Scope: read-only usermode sensors that observe the Windows render/present path, window
z-order, and overlay-injection vectors in the game process, and report typed findings to
the server, which holds all ban authority. No prologue patching, no unhooking, no
injection — sample-and-report only.

Catalog signals covered: **46, 47, 48, 49, 50, 51, 52, 53, 54** (the nine
"Windows Usermode — Render / Overlay Hooks" designs in `docs/detection-catalog.md`).

All nine are `windows-user / userspace` sensors. They live under
`sdk/src/backends/win/` (guardrail #1: platform API only inside a `backends/` folder,
and only `HK_PLATFORM_WINDOWS`-gated, never raw `_WIN32`). None run in the kernel; the
kernel/userspace TU split (guardrail #4) is preserved because these sensors share **no**
translation unit with `kernel/win/`. They reuse the kernel's PE-relocation math only via
a header-only helper (signal 47), never a shared `.c`/`.obj`.

---

## 1. New files

| Path | Role | Module-comment summary |
|---|---|---|
| `sdk/include/horkos/render_hook_schema.h` | Public C99 typed report schema for render/overlay findings (numeric verdicts, style/flag bitmasks, fixed-size records). Separate plane from `event_schema.h`. | Role: wire-format source of truth for usermode render/overlay sensor findings; verdict enums + fixed-size `hk_render_finding` record. Target: all (plain C99, no platform headers). Interface: mirrored by `server/telemetry/src/render_hook.rs`; included by SDK usermode TUs only, never a kernel TU (guardrail #4). |
| `sdk/src/backends/win/RenderSensorWin.h` | Internal façade declaring the nine sensor entry points + the shared module-map snapshot type. | Role: internal Windows render-sensor interface; declarations only. Target: Windows. Interface: implemented by the `*Win.cpp` files below; consumed by `sdk.cpp` AC tick. |
| `sdk/src/backends/win/ModuleMapWin.cpp` | Builds the per-process signed-module map (Toolhelp/`EnumProcessModulesEx` + `GetMappedFileName` + Authenticode signer) shared by signals 46, 47, 52, 54. | Role: loaded-module + signer snapshot provider for render sensors. Target: Windows. Interface: implements `hk::sdk::win::build_module_map` from `RenderSensorWin.h`. Guardrail #1: only place these sensors touch `Win32`/`wintrust`. |
| `sdk/src/backends/win/PresentVtableProvenanceWin.cpp` | Signal 46: swapchain/command-queue vtable target-island provenance. | Role: COM vtable-slot provenance sensor (Present/Present1/ResizeBuffers/ExecuteCommandLists). Target: Windows. Interface: implements `sense_present_vtable` from `RenderSensorWin.h`. |
| `sdk/src/backends/win/PresentPrologueReconcileWin.cpp` | Signal 47: Present/ExecuteCommandLists prologue byte-image vs on-disk reconciliation. | Role: export-prologue reconciliation sensor; recomputes clean bytes from on-disk DLL + relocations. Target: Windows. Interface: implements `sense_present_prologue`. Shares header-only `PeRelocate.h` math with the kernel image-load path (no shared TU). |
| `sdk/src/backends/win/PresentFrameStatsCorrelateWin.cpp` | Signal 48: foreign-thread framecounter correlation on Present. | Role: DXGI frame-statistics drift sensor (raw deltas only; baseline lives server-side). Target: Windows. Interface: implements `sense_present_framestats`. |
| `sdk/src/backends/win/LayeredWindowScanWin.cpp` | Signal 49: topmost layered click-through window over the game client rect. | Role: foreign layered/transparent/topmost overlay-window scanner. Target: Windows. Interface: implements `sense_layered_windows`. |
| `sdk/src/backends/win/DwmThumbnailConsumerWin.cpp` | Signal 50: DWM-thumbnail screen-mirror consumer correlation. | Role: consumer-side cloaked DWM-thumbnail mirror sensor. Target: Windows. Interface: implements `sense_dwm_thumbnail`. |
| `sdk/src/backends/win/MagnifierHostScanWin.cpp` | Signal 51: Magnification-API host enumeration over the game surface. | Role: `WC_MAGNIFIER` host-window scanner (source-rect overlap). Target: Windows. Interface: implements `sense_magnifier_host`. |
| `sdk/src/backends/win/HookDllFootprintWin.cpp` | Signal 52: global `SetWindowsHookEx` hook-DLL injection footprint (module diff). | Role: injected GUI-hook-DLL footprint sensor; usermode complement to kernel `PsSetLoadImageNotifyRoutine`. Target: Windows. Interface: implements `sense_hookdll_footprint`. |
| `sdk/src/backends/win/GdiCapturePressureWin.cpp` | Signal 53: GDI screen-DC capture handle pressure (low-weight corroborator). | Role: GDI-object-pressure + capture-rect correlation sensor. Target: Windows. Interface: implements `sense_gdi_pressure`. |
| `sdk/src/backends/win/VulkanLayerChainWin.cpp` | Signal 54: Vulkan implicit/forced-layer overlay-injection chain. | Role: Vulkan implicit-layer manifest + env-var + mapped-layer-DLL sensor. Target: Windows. Interface: implements `sense_vulkan_layers`. |
| `sdk/src/backends/win/PeRelocate.h` | Header-only PE export-RVA + base-relocation math reused by signal 47 and (separately compiled) the kernel image-load path. | Role: pure PE relocation math, no OS calls, no allocation. Target: all (header-only). Interface: included by `PresentPrologueReconcileWin.cpp` and, in its own TU, by the kernel path — never linking the same object (guardrail #4). |
| `server/telemetry/src/render_hook.rs` | Serde mirror of `render_hook_schema.h` + `POST /api/render-findings` ingest route. | Role: render/overlay finding ingest plane; validates schema, logs, drops (Phase-2 stub parity with `TickPayload`). Target: server. Interface: mirrors `hk_render_finding`; mounted by `telemetry::router()`. No `unwrap()` (guardrail #8). |
| `bypass-tests/win/overlay_vtable_swap.cpp` | Bypass-test fixture: benign self-applied Present vtable swap must be *reported with resolved module + signer*, never silently missed and never auto-banned. | Role: render-hook merge-gate bypass test (disabled until enforcement TDD phase). Target: Windows. Interface: consumes `render_hook_schema.h`. Guardrail #12. |
| `bypass-tests/win/external_overlay_window.cpp` | Bypass-test fixture: a foreign layered/topmost click-through window over the game rect must surface in signal-49 findings with the owning PID. | Role: external-overlay-window merge-gate bypass test (disabled stub). Target: Windows. Interface: consumes `render_hook_schema.h`. Guardrail #12. |

Module comment on every file above satisfies guardrail #3.

---

## 2. Interfaces & data structures

### 2.1 New report plane: `sdk/include/horkos/render_hook_schema.h`

These findings carry variable-length strings (module path, Authenticode signer subject)
that do **not** fit the fixed 16-byte `HK_EVENT_PAYLOAD_MAX` kernel ring record. They are
**not** kernel events and must not be forced through the `HK_IOCTL_DRAIN_EVENTS` envelope.
Mirroring the existing two-plane split (kernel `event_schema.h` vs JSON `TickPayload`),
render findings get their **own JSON plane** to the server. `render_hook_schema.h` defines
the *typed numeric* core (enums, bitmasks, fixed-size record) as the source of truth; the
string fields ride alongside in the JSON envelope, not in the C struct.

```c
#define HK_RENDER_SCHEMA_VERSION 1u   /* independent of HK_EVENT_SCHEMA_VERSION */

typedef enum hk_render_signal {       /* catalog signal id, stable */
    HK_RENDER_SIG_VTABLE_PROVENANCE = 46,
    HK_RENDER_SIG_PROLOGUE_RECONCILE = 47,
    HK_RENDER_SIG_FRAMESTATS         = 48,
    HK_RENDER_SIG_LAYERED_WINDOW     = 49,
    HK_RENDER_SIG_DWM_THUMBNAIL      = 50,
    HK_RENDER_SIG_MAGNIFIER          = 51,
    HK_RENDER_SIG_HOOKDLL            = 52,
    HK_RENDER_SIG_GDI_PRESSURE       = 53,
    HK_RENDER_SIG_VULKAN_LAYER       = 54,
} hk_render_signal;

typedef enum hk_provenance_verdict {  /* signals 46/47/52/54 target classification */
    HK_PROV_IMAGE_SIGNED_ALLOWLISTED = 0, /* target in a signed allow-listed module */
    HK_PROV_IMAGE_SIGNED_FOREIGN     = 1, /* image-backed, signed, not allow-listed */
    HK_PROV_IMAGE_UNSIGNED           = 2, /* image-backed, no valid Authenticode */
    HK_PROV_PRIVATE_RX               = 3, /* MEM_PRIVATE / unbacked executable */
    HK_PROV_UNRESOLVED               = 4, /* VirtualQuery failed / sensor inconclusive */
} hk_provenance_verdict;

/* Window-style bitmask (signals 49/51), mirrors GWL_EXSTYLE bits we record. */
#define HK_WSTYLE_LAYERED      0x01u
#define HK_WSTYLE_TRANSPARENT  0x02u
#define HK_WSTYLE_TOPMOST      0x04u
#define HK_WSTYLE_NOACTIVATE   0x08u
#define HK_WSTYLE_CLOAKED      0x10u  /* DWMWA_CLOAKED true */
#define HK_WSTYLE_CLICKTHROUGH 0x20u  /* per-pixel-alpha + transparent */

/* Fixed-size numeric core of one finding. Strings (module_path, signer_subject,
 * window_class) travel in the JSON envelope keyed by record index, never inline,
 * so this struct stays fixed-size and the on-disk paths are not length-bounded. */
typedef struct hk_render_finding {
    uint32_t schema_version;   /* HK_RENDER_SCHEMA_VERSION at emit. */
    uint32_t signal;           /* hk_render_signal. */
    uint32_t verdict;          /* hk_provenance_verdict, or 0 when N/A. */
    uint32_t style_bits;       /* HK_WSTYLE_* (signals 49/51), else 0. */
    uint32_t owning_pid;       /* foreign PID for window/footprint signals, else 0. */
    uint32_t slot_index;       /* vtable slot (46) or export ordinal (47), else 0. */
    uint64_t target_addr;      /* resolved vtable/prologue target VA (46/47), else 0. */
    uint64_t region_hash;      /* divergent-region hash (47) / cadence-fingerprint, else 0. */
    int64_t  cadence_drift_ns; /* signed frame-stat/cadence drift (48/50/53), else 0. */
} hk_render_finding;

HK_STATIC_ASSERT(sizeof(hk_render_finding) == 56, "hk_render_finding size mismatch");
```

`HK_STATIC_ASSERT` is reused from `event_schema.h` (this header `#include`s it for the
macro and `<stdint.h>` only — no platform headers, keeping it kernel-includable in
principle even though no kernel TU includes it).

### 2.2 No new IOCTL codes

`ioctl.h` is **not** modified. These are usermode sensors reporting over HTTP/JSON, not
kernel records. Adding an IOCTL would imply kernel involvement and violate the plane
separation. The existing `HK_IOCTL_DRAIN_EVENTS` envelope and `HK_EVENT_PAYLOAD_MAX`
stay untouched (and would break — see risk R1 — if these 56-byte records were forced
through the 40-byte `hk_event_record`).

### 2.3 Server mirror: `server/telemetry/src/render_hook.rs`

```rust
pub const RENDER_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RenderFinding {
    pub schema_version: u32,
    pub signal: u32,
    pub verdict: u32,
    pub style_bits: u32,
    pub owning_pid: u32,
    pub slot_index: u32,
    pub target_addr: u64,
    pub region_hash: u64,
    pub cadence_drift_ns: i64,
    // String side-channel — not in the C struct; declared in data-categories.md.
    #[serde(default)] pub module_path: Option<String>,
    #[serde(default)] pub signer_subject: Option<String>,
    #[serde(default)] pub window_class: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderFindingBatch {
    pub schema_version: u32,
    pub player_id: u64,
    pub findings: Vec<RenderFinding>,
}
```

Route `POST /api/render-findings` validates `schema_version == RENDER_SCHEMA_VERSION`,
records a tracing span, then drops (Phase-2 stub, exactly like `telemetry::ingest`). No
`unwrap()`/`expect()` outside tests (guardrail #8); errors via the existing
`telemetry::error::TelemetryError` (extend with a `RenderSchema` variant through
`thiserror`).

### 2.4 `data-categories.md` additions (guardrail #11 — same PR)

Every new telemetry field above must be declared. Add a new section **"5. Render/overlay
hook findings (Windows usermode)"** to `server/api/data-categories.md`:

| Field | Source | Notes |
|---|---|---|
| `signal` | render sensor | catalog signal id (46–54) |
| `verdict` | provenance classifier (46/47/52/54) | enum `hk_provenance_verdict` |
| `style_bits` | window scan (49/51) | GWL_EXSTYLE + DWM cloak bitmask |
| `owning_pid` | foreign-window/footprint attribution | `GetWindowThreadProcessId` |
| `slot_index` / `target_addr` / `region_hash` | vtable/prologue sensors (46/47) | resolved target + divergent-region hash, **not** raw memory |
| `cadence_drift_ns` | frame-stat / mirror correlation (48/50/53) | signed drift only |
| `module_path` | resolved module / hook-DLL / layer DLL path | on-disk path of the implicated module |
| `signer_subject` | Authenticode signer (`wintrust`) | publisher subject string the server allow-lists against |
| `window_class` | foreign window class name | e.g. `WC_MAGNIFIER` |

Reviewer rejects the PR if any field above lands without its row here.

---

## 3. Mechanism implementation notes

All sensors are **read-only**: `VirtualQueryEx`/`ReadProcessMemory` on the **own** process,
window enumeration, registry reads, handle-count queries. No `WriteProcessMemory`, no
`VirtualProtect` on foreign code, no unhooking. They run on the SDK AC tick thread, not
in the kernel — none of the IRQL/IRP/`ObRegisterCallbacks` concerns apply (those are
kernel-only and out of scope here). The relevant safety axis is **usermode robustness**:
every Win32 call's failure path is handled, no exceptions cross the C ABI boundary, and a
sensor that cannot resolve a target emits `HK_PROV_UNRESOLVED` rather than a false anomaly.

**Shared (`ModuleMapWin.cpp`).** Build the module map with `EnumProcessModulesEx`
(`LIST_MODULES_ALL`) + `GetModuleInformation` for `[base, base+SizeOfImage)` ranges, plus
`GetMappedFileName` to attribute a VA to a backing file. Authenticode signer via
`WinVerifyTrust` + `CryptQueryObject`/`CryptMsgGetParam` (the `wintrust`/`crypt32` calls
are confined here). Cache per tick; classification is `target VA -> module -> signer ->
allow-list verdict`. The allow-list itself is **server-side signed-rule plumbing** — the
client only reports the resolved signer subject, never decides (catalog: "the server
alone decides; never ban on presence of a hook").

**46 — Present/SwapChain vtable provenance.** Resolve the live swapchain from the game's
own device, or enumerate via `DXGIGetDebugInterface1`. Read each COM vtable slot (Present,
Present1, ResizeBuffers, `ID3D12CommandQueue::ExecuteCommandLists`), `VirtualQueryEx` each
target, compare `MEMORY_BASIC_INFORMATION.Type`/`AllocationBase` against the module map.
Emit `verdict` per slot. *Robustness:* a null/garbage vtable pointer must not deref-crash —
guard every read; `MEM_PRIVATE` target → `HK_PROV_PRIVATE_RX`.

**47 — Present prologue reconciliation.** Map the same DLL **read-only from disk**
(`GetModuleFileNameEx` → `CreateFileMapping`/`MapViewOfFile` `SEC_IMAGE` or raw + manual
parse), parse `IMAGE_EXPORT_DIRECTORY` to find the export RVA, apply `IMAGE_BASE_RELOCATION`
delta for the live load base (via header-only `PeRelocate.h`), then `ReadProcessMemory` the
live prologue and compare. Report `region_hash` of the divergent bytes, never the bytes.
*Concerns:* must account for legitimate **CFG/retpoline thunks** and **ASLR relocation**
so a relocated absolute branch is not misread as a patch (catalog FP note). The relocation
math is the one piece reused from the kernel image-load path — kept header-only in
`PeRelocate.h`, compiled separately in each TU, so guardrail #4 (no shared kernel/userspace
TU) holds.

**48 — Frame-stat correlation.** Sample `IDXGISwapChain::GetFrameStatistics`
(`PresentCount`, `PresentRefreshCount`, `SyncQPCTime`, `SyncRefreshCount`) and
`GetLastPresentCount` on the tick, correlate against the render-thread `QueryPerformanceCounter`
timeline; emit `cadence_drift_ns` only. **The baseline envelope (per-title, per-GPU-driver,
VRR/G-Sync/DLSS-FG aware) lives server-side** in signed-rule plumbing — the client never
flags, it only reports drift. `GetFrameStatistics` returns `DXGI_ERROR_FRAME_STATISTICS_DISJOINT`
routinely; that is handled as "no sample this tick", not an anomaly.

**49 — Layered topmost window.** `EnumWindows` → per visible top-level window
`GetWindowLongPtr(GWL_EXSTYLE)` for `WS_EX_LAYERED|TRANSPARENT|TOPMOST|NOACTIVATE`,
`GetWindowRect` intersected with the game's `GetClientRect` mapped through `ClientToScreen`,
`GetWindowThreadProcessId` for the owning PID, `GetLayeredWindowAttributes` +
`DwmGetWindowAttribute(DWMWA_CLOAKED)` to confirm click-through/per-pixel-alpha. Report
`style_bits` + `owning_pid` + `window_class`; the server scores foreign+unsigned+covering.

**50 — DWM thumbnail consumer.** Source-side `DwmRegisterThumbnail` is **not enumerable**,
so detection is consumer-side correlation: enumerate candidate windows, check
`DwmGetWindowAttribute(DWMWA_CLOAKED)` + `DwmIsCompositionEnabled`, flag a foreign cloaked
non-shell window whose update cadence tracks the game frame rate (`cadence_drift_ns`).
Never flag `dwm.exe`/`explorer.exe`/signed capture tools — that filter is server-side.

**51 — Magnifier host.** `EnumWindows`/`FindWindowEx` for `WC_MAGNIFIER` + `WS_EX_LAYERED`,
attribute PID, correlate whether the magnifier source rect (set via `MagSetWindowSource`)
overlaps the game client rect, report owning image path and whether the host is the signed
OS `Magnify.exe`. The trust decision (genuine accessibility user) is server-side.

**52 — Hook-DLL footprint.** `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE)`/`Module32Next`
(+ `EnumProcessModulesEx`) + `GetMappedFileName`, diff against the expected-module baseline;
the "system-wide hook" signal (same DLL mapped into many concurrent GUI processes) is
inferred and reported as `verdict`+`module_path`+`signer_subject`. This **complements** the
kernel `PsSetLoadImageNotifyRoutine` path — usermode module-diff only, no kernel coupling.

**53 — GDI capture pressure.** `GetGuiResources(hProcess, GR_GDIOBJECTS)` on suspect PIDs to
detect DC/bitmap churn, correlate capture geometry where accessible. Coarse → **low-weight
corroborator** (`region_hash` carries a coarse capture-rect fingerprint, `cadence_drift_ns`
the churn cadence); the server fuses it, it is never a standalone flag.

**54 — Vulkan layer chain.** Read implicit-layer manifests under
`HKLM/HKCU\SOFTWARE\Khronos\Vulkan\ImplicitLayers`, parse the referenced layer JSON
(`library_path`), read the process environment block for
`VK_INSTANCE_LAYERS`/`VK_LAYER_PATH`/`VK_ADD_LAYER_PATH`, and confirm via `EnumProcessModulesEx`
that the layer DLL is actually mapped. Report manifest path + library signer + which env var
forced it; the server fuses with 46/47 to separate a dev's RenderDoc from a forced
present-intercept layer.

**Server (`render_hook.rs`).** Fully async axum handler on tokio; schema-version check;
`thiserror` error type; no `unwrap()`/`expect()` outside `#[cfg(test)]`. Mirrors the
existing `telemetry::ingest` stub exactly (validate → log → drop in Phase 2).

---

## 4. Build wiring

- **Sensors** compile into `hk_sdk` (the existing static lib in `sdk/CMakeLists.txt`).
  Extend the `if(WIN32)` branch to add the eleven `*Win.cpp` files (ten sensors +
  `ModuleMapWin.cpp`) to `hk_sdk_backend`, behind a new option:

  ```cmake
  option(HK_RENDER_SENSORS_WIN "Build Windows render/overlay usermode sensors" ON)
  if(WIN32 AND HK_RENDER_SENSORS_WIN)
      list(APPEND hk_sdk_backend
          src/backends/win/ModuleMapWin.cpp
          src/backends/win/PresentVtableProvenanceWin.cpp
          src/backends/win/PresentPrologueReconcileWin.cpp
          src/backends/win/PresentFrameStatsCorrelateWin.cpp
          src/backends/win/LayeredWindowScanWin.cpp
          src/backends/win/DwmThumbnailConsumerWin.cpp
          src/backends/win/MagnifierHostScanWin.cpp
          src/backends/win/HookDllFootprintWin.cpp
          src/backends/win/GdiCapturePressureWin.cpp
          src/backends/win/VulkanLayerChainWin.cpp)
      # Win32 link deps confined to the Windows branch:
      #   dxgi d3d11 d3d12 (47/46/48) ; dwmapi (49/50) ; Magnification (51)
      #   psapi (module map) ; wintrust crypt32 (signer) ; gdi32 user32 advapi32
  endif()
  ```

  `target_compile_definitions(hk_sdk PRIVATE HK_PLATFORM_WINDOWS)` already governs the
  conditional code — sources use `HK_PLATFORM_WINDOWS`, never raw `_WIN32` (guardrail #1).
  Default **ON** (these are the core product sensors for the platform).

- **Toolchain:** MSVC + Windows SDK (WDK not required — usermode only). `Magnification.lib`
  ships in the Windows SDK; `dxgi`/`d3d11`/`d3d12`/`dwmapi`/`wintrust`/`crypt32`/`psapi`
  likewise. Vulkan layer parsing reads the registry + a JSON file — no Vulkan SDK link
  dependency (manifests are parsed as plain JSON; reuse a header-only JSON parser or a
  minimal hand-rolled reader to avoid a new third-party dep in the SDK).

- **Server:** add `pub mod render_hook;` to `server/telemetry/src/lib.rs` and
  `.merge(render_hook::router())` (or fold the route into `telemetry::router()`). No new
  crate; no new Cargo deps (reuses `axum`, `serde`, `thiserror`, `tracing`).

- **Bypass tests:** add the two new executables to `bypass-tests/win/CMakeLists.txt`
  alongside `hk_bypass_byovd`, disabled-by-default like the existing fixture.

---

## 5. Test strategy

### Unit / integration

- **PE-relocation math (`PeRelocate.h`)** — host-runnable unit tests: feed a synthetic
  export directory + relocation table at a chosen delta, assert the recomputed clean
  prologue matches; assert a CFG thunk / relocated absolute branch is classified as
  *benign relocation*, not a patch (guards the catalog FP). This is the highest-value
  unit because it is pure and the main FP source.
- **Provenance classifier** — table-driven test mapping `(target VA, module-map entry,
  signer)` → expected `hk_provenance_verdict`, including the `HK_PROV_UNRESOLVED` path
  when `VirtualQueryEx` fails.
- **Window-style bitmask folding (49/51)** — given a set of `GWL_EXSTYLE`/DWM-cloak inputs,
  assert the `HK_WSTYLE_*` bitmask and rect-intersection logic.
- **Schema size guard** — `HK_STATIC_ASSERT(sizeof(hk_render_finding) == 56)` is a
  compile-time test; a Rust `#[test]` asserts the serde mirror round-trips and that field
  count matches (catches schema drift between `render_hook_schema.h` and `render_hook.rs`).
- **Server route** — extend `server/telemetry/tests/` with a `render_findings.rs`
  integration test (mirror `ingest.rs`): valid batch → `202`, wrong `schema_version` →
  `400`/`422` via `TelemetryError`.

### Bypass tests (guardrail #12 — merge gate)

Any change under a security folder (`sdk/src/backends/win/`) needs a corresponding bypass
test. Two are added, both **disabled stubs** in this scaffolding phase (logic lands under
`/tdd`, guardrail #14), present so the gate stays green and the intent is recorded:

- **`overlay_vtable_swap`** — must demonstrate: a benign, self-applied Present vtable swap
  (the fixture hooks *its own* swapchain, signed test binary) is **reported** by signal 46
  with the resolved module + signer, and is **not** auto-banned client-side (proves the
  report-only contract: presence of a hook ≠ ban; only the server decides). Activation flag
  `HK_RENDER_BYPASS_ENABLED`, mirroring `HK_BYOVD_TEST_ENABLED`.
- **`external_overlay_window`** — must demonstrate: a foreign-process layered/transparent/
  topmost click-through window placed over the game client rect surfaces in signal-49
  findings with the correct `owning_pid` and `style_bits`, and that a *signed allow-listed*
  overlay (e.g. simulated Steam/Discord signer) is reported but classified benign — i.e. the
  sensor does not drop the legitimate-overlay case (the FP-gating contract).

Both compile now and print `DISABLED` until the enforcement/scoring path lands, exactly
like `byovd_load.cpp`.

---

## 6. Sequencing

1. **`render_hook_schema.h` + `data-categories.md` section 5 + `render_hook.rs` mirror.**
   Land the contract first (with `HK_STATIC_ASSERT` and the serde round-trip test). Nothing
   else compiles against a moving schema. Guardrail #11 is satisfied in this same step.
2. **`ModuleMapWin.cpp` + `RenderSensorWin.h` + `PeRelocate.h`.** The shared substrate for
   46/47/52/54; ship its unit tests (relocation math + classifier) before the sensors.
3. **Signals 46 + 47** (present-path provenance/reconciliation) — highest detection value,
   depend on steps 1–2. Land with the `overlay_vtable_swap` bypass-test stub.
4. **Signals 49 + 51** (window scans) — independent of the module map; share rect/style
   helpers. Land with the `external_overlay_window` bypass-test stub.
5. **Signals 50 + 53 + 48** (cadence/correlation sensors) — depend only on step 1; lower
   weight, more baseline-sensitive, so they land after the high-confidence sensors.
6. **Signals 52 + 54** (injection-vector enumeration) — reuse `ModuleMapWin` (step 2) and
   Vulkan registry/env parsing.
7. **Server route + CMake wiring + bypass-test CMake** — wire `POST /api/render-findings`,
   the `HK_RENDER_SENSORS_WIN` option, and the two bypass executables. Run the full suite.

Per-sensor logic that makes a *decision* (scoring, baselines, allow-lists) is deferred to
the server signed-rule plumbing and to `/tdd` phases (guardrail #14) — this plan scaffolds
read-only sensors + the report contract, not the verdict engine.

---

## 7. Risks & uncertainty flags

- **R1 — payload-size plane mismatch (resolved by design, flag for reviewer).** Render
  findings are 56 bytes + variable strings; the kernel record is 40 bytes
  (`HK_EVENT_PAYLOAD_MAX = 16`). Forcing them through `HK_IOCTL_DRAIN_EVENTS` would corrupt
  the ring. This plan deliberately keeps them on a **separate JSON plane** and does **not**
  touch `ioctl.h`/`event_schema.h` sizing. Reviewer should confirm the separate-plane
  decision rather than expecting an IOCTL extension.

- **R2 — UNCERTAINTY: live swapchain acquisition (signal 46).** Getting a usable
  `IDXGISwapChain*` for a swapchain the game already created, from the same process but
  outside the game's render code, is non-trivial. `DXGIGetDebugInterface1` +
  `IDXGIDebug`/`ReportLiveObjects` enumerates COM objects but does not cleanly hand back a
  callable `IDXGISwapChain` per documented contract. The clean path is the **game handing
  the sensor its own swapchain pointer through the SDK** at device-creation time. **Flagging:
  I am not certain `DXGIGetDebugInterface1` enumeration yields an addressable vtable for an
  arbitrary live swapchain** — confirm the integration shape (SDK-provided pointer vs.
  enumeration) before implementing 46. Do not guess the COM enumeration semantics.

- **R3 — UNCERTAINTY: reading another process's environment block (signal 54).** Reading
  `VK_*` env vars from a *suspect* process requires `NtQueryInformationProcess(ProcessBasicInformation)`
  → PEB → `ProcessParameters` → `Environment`, an undocumented/semi-documented cross-process
  read needing `PROCESS_VM_READ|QUERY_INFORMATION`. **Flagging this as uncertain** (NT
  internal layout, Wow64 PEB differences). For the **own** game process the env block is
  trivially readable via `GetEnvironmentStrings`; for foreign processes, prefer the
  registry-manifest + mapped-DLL signals and treat cross-process env reading as a
  best-effort, may-fail enhancement — never assume it succeeds.

- **R4 — frame-stat baseline is fundamentally server-side (48/50/53).** VRR/G-Sync/FreeSync,
  DLSS-FG, AMD AFMF, and DWM flip-model legitimately desync cadence. The client must ship
  *raw drift only*; if any thresholding leaks client-side it will false-positive on
  frame-generation users. Explicitly out of scope for the client; flagged so it is not
  "optimized" into the sensor later.

- **R5 — Authenticode verification cost/cache.** `WinVerifyTrust` is expensive and may hit
  the network (revocation). Must be cached per module per session and run off the hot tick;
  unverified-due-to-timeout must map to `HK_PROV_UNRESOLVED`/null signer, never a false
  "unsigned" verdict. Not a kernel-API uncertainty, but a correctness flag.

- **R6 — signal 53 is explicitly low-weight.** `GetGuiResources` handle pressure is coarse
  and shared by many legitimate capture tools. Keep it a corroborator the server fuses;
  do not let it gate a flag alone. (Catalog-mandated.)

None of these nine signals touch a kernel API, IRP lifecycle, IRQL, `ObRegisterCallbacks`,
ES auth deadlines, or code-signing of *our* driver, so guardrail #13's kernel-uncertainty
stops do not bind here — the two genuine API uncertainties (R2 live-swapchain COM, R3
cross-process PEB env read) are flagged above for confirmation before coding.
