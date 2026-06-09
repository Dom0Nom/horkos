# Windows Kernel — Driver / Module Trust — Implementation Plan

**Scope:** read-only kernel sensors that audit the trust of loaded drivers, OS
callback tables, code-integrity state, and the boot-load sequence on Windows.
All sensors sample and report; the server scores and bans. No table writes, no
hooks installed, no enforcement in-kernel.

**Catalog signals covered:** 28 (FltMgr altitude audit), 29 (driver .text vs
on-disk authenticode), 30 (CI!g_CiOptions probe), 31 (callback-table residency),
32 (non-image executable allocation scan), 33 (kernel-debug attach state), 34
(DriverObject FastIo/StartIo divergence), 35 (shadow SSDT range integrity), 36
(ELAM/boot-start load-order audit).

These extend the existing capture-only KMDF driver (`kernel/win/`). They reuse
the SPSC ring → `HK_IOCTL_DRAIN_EVENTS` bridge already in place; the only new
wire surface is one additional event type carrying an "integrity finding"
payload plus one status/control IOCTL to drive a manual rescan.

---

## New files

All paths honor guardrail #1 (platform code stays under `kernel/win/`, no raw
`_WIN32`), #3 (module comment on every file), #4 (kernel and userspace never
share a TU — the user-mode companion lives under `sdk/src/backends/win/`).

| Path | Role | Module-comment summary |
|---|---|---|
| `kernel/win/src/MinifilterAudit.c` | Signal 28. Walk registered minifilters + instances, verify each pre/post-op callback pointer resolves inside the owning `FLT_FILTER` image; flag pointers outside every loaded module. | Role: FltMgr callback-node altitude/owner audit. Target: Windows kernel (KMDF). Interface: implements `HkMinifilterAudit` from `horkos_kernel.h`; emits `HK_EVENT_INTEGRITY_FINDING`. |
| `kernel/win/src/ImageHashAudit.c` | Signal 29. PASSIVE_LEVEL work item: hash in-memory code sections of each loaded driver, normalize relocs/IAT against the on-disk PE, compare to on-disk section hash. | Role: in-memory vs on-disk driver `.text` hash audit. Target: Windows kernel (KMDF). Interface: `HkImageHashAudit`; on-disk read guarded behind a `PASSIVE_LEVEL` work item. |
| `kernel/win/src/CodeIntegrityProbe.c` | Signal 30. Snapshot `SYSTEM_CODEINTEGRITY_INFORMATION` + secure-boot + boot-env at `DriverEntry`, re-read on rescan, emit deltas. | Role: code-integrity / DSE / HVCI state probe. Target: Windows kernel (KMDF). Interface: `HkCodeIntegrityBaseline` / `HkCodeIntegrityRescan`. |
| `kernel/win/src/ModuleMap.c` | Shared `SystemModuleInformation` image-range map cache consumed by signals 29/31/32/34/35 (build once per scan, range-lookup by address). | Role: loaded-module address-range map (shared scan cache). Target: Windows kernel (KMDF). Interface: `HkModuleMapBuild` / `HkModuleMapResolve` / `HkModuleMapFree`. |
| `kernel/win/src/CallbackResidency.c` | Signal 31. Self-sentinel registration test + resolve every discoverable notify/registry/bugcheck handler against `ModuleMap`; flag pool-backed / no-image handlers. | Role: registered driver-callback table residency check. Target: Windows kernel (KMDF). Interface: `HkCallbackResidencyScan`; depends on `ModuleMap`. |
| `kernel/win/src/NonImageCodeScan.c` | Signal 32. PASSIVE_LEVEL, rate-limited: enumerate big-pool allocations, flag executable system-space ranges intersecting no module image and no known pool-tag owner. | Role: non-image executable allocation (manually-mapped driver) scan. Target: Windows kernel (KMDF). Interface: `HkNonImageScan`; depends on `ModuleMap`. |
| `kernel/win/src/DebugStateProbe.c` | Signal 33. Read `KdDebuggerEnabled`/`KdDebuggerNotPresent` + `SystemKernelDebuggerInformation[Ex]`; distinguish boot-debug-allowed from currently-attached. | Role: kernel-debugger attach-state probe. Target: Windows kernel (KMDF). Interface: `HkDebugStateProbe`. |
| `kernel/win/src/DriverObjectAudit.c` | Signal 34. Walk `\Driver\*`, verify `FastIoDispatch`/`DriverStartIo`/`DriverUnload`/`AddDevice` and the DeviceObject chain resolve inside the owning image (or any signed module). | Role: DRIVER_OBJECT FastIo/StartIo/Unload/AddDevice divergence audit. Target: Windows kernel (KMDF). Interface: `HkDriverObjectAudit`; depends on `ModuleMap`. |
| `kernel/win/src/SsdtIntegrity.c` | Signal 35. Decode `KiServiceTable` + win32k shadow entries, verify each target lands inside `ntoskrnl`/`win32k`. Read-only, no table writes. | Role: SSDT / shadow-SSDT range integrity check. Target: Windows kernel (KMDF). Interface: `HkSsdtIntegrityScan`; depends on `ModuleMap`. |
| `kernel/win/src/BootLoadAudit.c` | Signal 36 (kernel half). Read live `PsLoadedModuleList` load order + boot-env; confirm our boot-start driver + ELAM verdict present. | Role: boot-start / ELAM load-order audit (live module-order read). Target: Windows kernel (KMDF). Interface: `HkBootLoadAudit`. |
| `sdk/src/backends/win/DriverProbeWin.cpp` (extend existing) | Signal 36 (user-mode half). Read `HKLM\SYSTEM\CCS\Control\ServiceGroupOrder` + per-service `Start`/`Group` from a signed user-mode context; correlate with the kernel finding. | (existing file) add `HkProbeServiceGroupOrder`; user-mode, never shares a TU with kernel code (guardrail #4). |
| `kernel/win/include/horkos_kernel.h` (extend) | Declare the new entry points, the scan-orchestrator (`HkIntegrityScanAll`), and the `ModuleMap` types. | (existing header) kernel-private declarations only. |

A single **scan orchestrator** `HkIntegrityScan.c` (new) owns the PASSIVE_LEVEL
work item that builds the `ModuleMap` once, runs signals 29/31/32/34/35 against
it, runs 28/30/33/36, then frees the map. This avoids each sensor independently
calling `ZwQuerySystemInformation(SystemModuleInformation)`.

| Path | Role | Module-comment summary |
|---|---|---|
| `kernel/win/src/HkIntegrityScan.c` | Orchestrator: schedules the periodic PASSIVE_LEVEL scan, builds/frees the shared `ModuleMap`, fans out to each sensor, throttles. | Role: integrity-scan orchestrator + work-item scheduling. Target: Windows kernel (KMDF). Interface: `HkIntegrityScanAll` / `HkIntegrityScanInit` / `HkIntegrityScanStop`. |

---

## Interfaces & data structures

### New event type (single addition to the wire schema)

`sdk/include/horkos/event_schema.h` — append to `hk_event_type` (existing values
never change, guardrail comment in the file):

```c
HK_EVENT_INTEGRITY_FINDING = 5,
```

Bump `HK_EVENT_SCHEMA_VERSION` 2u → 3u (the header's own rule: any additive
field bumps the version; the Rust serde mirror updates in lockstep).

New fixed-size payload (must be ≤ `HK_EVENT_PAYLOAD_MAX` = 16 so the 40-byte
`hk_event_record` and the ring layout are unchanged — no `HK_EVENT_PAYLOAD_MAX`
bump, no ring resize):

```c
typedef struct hk_event_integrity_finding {
    uint32_t signal_id;   /* Catalog number 28..36. */
    uint32_t finding;     /* HK_INTEGRITY_* code (see below). */
    uint64_t detail;      /* Signal-specific: image-relative offset, altitude,
                             CodeIntegrityOptions bitfield, or a truncated
                             handler address. NEVER a full kernel pointer that
                             would leak KASLR off-box — see masking note. */
} hk_event_integrity_finding;
HK_STATIC_ASSERT(sizeof(hk_event_integrity_finding) == 16,
    "hk_event_integrity_finding size mismatch");
```

16 bytes exactly, so `HK_EVENT_PAYLOAD_MAX` stays 16 and the
`HK_STATIC_ASSERT(sizeof(hk_event_record) == 40, ...)` in `ioctl.h` still holds.
No `ioctl.h` size change.

Finding-code constants (in `event_schema.h`, next to the payload):

```c
#define HK_INTEGRITY_OK                 0x00u
#define HK_INTEGRITY_FLT_OUT_OF_IMAGE   0x01u  /* signal 28 */
#define HK_INTEGRITY_TEXT_HASH_DELTA    0x02u  /* signal 29 */
#define HK_INTEGRITY_CI_STATE_DELTA     0x03u  /* signal 30 */
#define HK_INTEGRITY_CALLBACK_NO_IMAGE  0x04u  /* signal 31 */
#define HK_INTEGRITY_NONIMAGE_EXEC      0x05u  /* signal 32 */
#define HK_INTEGRITY_KDBG_ATTACHED      0x06u  /* signal 33 (attach > boot-flag) */
#define HK_INTEGRITY_KDBG_BOOT_ALLOWED  0x07u  /* signal 33 (lower weight) */
#define HK_INTEGRITY_DRVOBJ_DIVERGENCE  0x08u  /* signal 34 */
#define HK_INTEGRITY_SSDT_OUT_OF_IMAGE  0x09u  /* signal 35 */
#define HK_INTEGRITY_BOOTLOAD_SUPPRESS  0x0Au  /* signal 36 */
```

### New IOCTL (control-plane: trigger a rescan + report scan health)

`sdk/include/horkos/ioctl.h` — add one function code (vendor range, next free):

```c
#define HK_IOCTL_INTEGRITY_RESCAN \
    HK_CTL_CODE(HK_FILE_DEVICE_UNKNOWN, 0x803, HK_METHOD_BUFFERED, HK_FILE_ANY_ACCESS)
```

The findings themselves still flow out through the existing
`HK_IOCTL_DRAIN_EVENTS` ring as `HK_EVENT_INTEGRITY_FINDING` records — no new
output envelope. `HK_IOCTL_INTEGRITY_RESCAN` carries an empty input and returns
the existing `hk_status` (extend it, below) so userspace can confirm the scan
ran and read scan-health counters.

Extend `hk_status` **without changing its 32-byte size** — the two existing
trailing `uint32_t`s (`notify_routines_armed`, `ob_callbacks_armed`) stay; the
new scan-health counters need room. Adding fields would break
`HK_STATIC_ASSERT(sizeof(hk_status) == 32, ...)`. **Decision: do NOT grow
`hk_status`.** Instead repurpose `HK_STATUS_FLAG_*` bits and surface scan
health through finding events (`HK_INTEGRITY_OK` heartbeat with `signal_id` =
the sensor that completed). Add status flags only:

```c
#define HK_STATUS_FLAG_INTEGRITY_SCAN_ACTIVE 0x00000008u
#define HK_STATUS_FLAG_INTEGRITY_SCAN_FAULTED 0x00000010u
```

This keeps every existing `HK_STATIC_ASSERT` green (no struct-layout drift,
matching the Step-3.5 wire-pin philosophy in `ioctl.h`).

### Server-side mirror (Phase 2 Rust)

`server/telemetry` (or the kernel-event ingest path) gains a serde mirror of
`hk_event_integrity_finding` with identical field names/order. Guardrail #8:
`thiserror` for the decode error type, no `unwrap()` outside tests; the decoder
returns `Result` on a short/over-long record rather than panicking.

### Guardrail #11 — `data-categories.md` (same PR)

Every new telemetry field MUST be declared. Add a section to
`server/api/data-categories.md`:

> ### 2b. Kernel driver/module integrity findings (Windows)
>
> | Field | Source | Retention default | Legal basis | Operator-of-record |
> |---|---|---|---|---|
> | `signal_id` | integrity scan (`hk_event_integrity_finding`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
> | `finding` | as above (`HK_INTEGRITY_*` code) | 90 days | Legitimate interest | Horkos Service Operator |
> | `detail` | as above (offset/altitude/CI-bitfield/masked addr) | 90 days | Legitimate interest | Horkos Service Operator |

Note in that section that `detail` is masked (KASLR base subtracted /
image-relative) so no raw kernel pointer leaves the box.

---

## Mechanism implementation notes

Shared safety rules for every sensor (guardrails #5, #13): all kernel C uses
safe string/memory functions (`RtlStringCch*`, `RtlCopyMemory` with bounded
lengths); every `NTSTATUS` and every `Zw*`/`Flt*`/`Ob*` return is checked and a
failure aborts that sensor cleanly (emit nothing rather than emit garbage);
`__try/__except` around any structure walk that dereferences an
externally-controlled pointer. The whole integrity scan runs from a **single
PASSIVE_LEVEL work item** (`IoQueueWorkItem` / KMDF `WDFWORKITEM`) — none of
these touch `IRP`/DPC paths, so there is no DISPATCH_LEVEL concern except the
ring push itself, which already supports `_IRQL_requires_max_(DISPATCH_LEVEL)`.

**Signal 28 — MinifilterAudit.c.** `FltEnumerateFilters` → for each filter
`FltGetFilterInformation(FilterAggregateBasicInformation)` for altitude, then
`FltEnumerateInstances` + `FltGetInstanceContext`. Cross-check each
`FLT_OPERATION_REGISTRATION` pre/post pointer against
`[FilterBase, FilterBase+SizeOfImage)`. Requires a registered Flt context →
this TU calls `FltRegisterFilter` at init with an empty callback set purely to
get an enumeration handle, or uses `FltEnumerateFilters` which does not require
registration. **UNCERTAINTY (flag):** whether `FltEnumerateFilters` is callable
without our own `FltRegisterFilter` handle, and the exact lifetime/refcount
rules of `FltObjectDereference` on each enumerated `PFLT_FILTER`/`PFLT_INSTANCE`
— a missed dereference leaks; a double-deref is a UAF. See Risks.

**Signal 29 — ImageHashAudit.c.** Module list via
`ZwQuerySystemInformation(SystemModuleInformation)` (preferred over the
deprecated `AuxKlibQueryModuleInformation`). Parse in-memory PE with
`RtlImageNtHeader` + `IMAGE_SECTION_HEADER` to find executable sections. Open
the on-disk file with `ZwCreateFile`+`ZwReadFile` — **PASSIVE_LEVEL only**, in
the work item; file I/O at raised IRQL is illegal. Normalize relocations and
IAT thunks (apply the on-disk base-reloc delta) before hashing so legitimate
fixups don't read as deltas. Hotpatch regions and CFG/retpoline thunks are
excluded (see FP gate). Report only non-reloc, non-import-thunk byte deltas as
`HK_INTEGRITY_TEXT_HASH_DELTA` with `detail` = image-relative offset of the
first delta. **UNCERTAINTY (flag):** robust reloc/IAT normalization across
hotpatch images is non-trivial; ship behind a feature flag default-OFF and
report-only until validated. No ban from this signal alone (catalog: "never
auto-ban").

**Signal 30 — CodeIntegrityProbe.c.** `ZwQuerySystemInformation` with
`SystemCodeIntegrityInformation` → `SYSTEM_CODEINTEGRITY_INFORMATION`
(`CodeIntegrityOptions` bitfield), plus `SystemSecureBootInformation` and
`SystemBootEnvironmentInformation`. Snapshot at `DriverEntry` (baseline) — call
must be at PASSIVE_LEVEL, which `DriverEntry` is. Re-read on rescan; emit
`HK_INTEGRITY_CI_STATE_DELTA` only when a flag flipped vs baseline (catalog: a
post-boot flip is far more suspicious than a stable dev config). `detail` =
raw `CodeIntegrityOptions` so the server scores the exact bits. No parsing of
`ci.dll` internals.

**Signal 31 — CallbackResidency.c.** The OS arrays
(`PspCreateProcessNotifyRoutine`, `PspLoadImageNotifyRoutine`,
`CmCallbackListHead`) are **not exported**. Use only documented surfaces: a
**self-sentinel** — register our own callback via
`PsSetCreateProcessNotifyRoutineEx` / `CmRegisterCallbackEx`, then confirm our
slot is intact (detects something stripping our callbacks). For broader
enumeration, resolve any handler address we *can* observe against `ModuleMap`
and flag pool-backed (`MmIsAddressValid` + not-in-any-image) handlers. **DO NOT
hardcode `PspCreateProcessNotifyRoutine` offsets or pattern-scan ntoskrnl — that
is undocumented and version-fragile; flag as out-of-scope for kernel.** The
catalog itself says "indirectly through the documented enumeration surfaces
where available" — where unavailable, the sensor ships only the self-sentinel
half. **UNCERTAINTY (flag):** see Risks; the full table walk is the riskiest
sensor.

**Signal 32 — NonImageCodeScan.c.** `ZwQuerySystemInformation(SystemBigPoolInformation)`
→ `SYSTEM_BIGPOOL_INFORMATION`. For each big-pool allocation, classify
executable + private (non-image), check it intersects no `ModuleMap` range and
no known pool-tag owner. Rate-limited and **sampled** (catalog: do not
enumerate every PTE). `MmGetPhysicalAddress` for corroboration only. Report as
a server-scored anomaly (`HK_INTEGRITY_NONIMAGE_EXEC`); FP risk is HIGH so this
is the lowest-weight, default-OFF sensor. **UNCERTAINTY (flag):** determining
"executable" for a big-pool range without a documented protection query — may
require `MmIsAddressValid` plus heuristics; flag and keep report-only.

**Signal 33 — DebugStateProbe.c.** Read exported `KdDebuggerEnabled` /
`KdDebuggerNotPresent` globals; corroborate with
`ZwQuerySystemInformation(SystemKernelDebuggerInformation)` and
`...InformationEx`. `KdRefreshDebuggerNotPresent` to refresh the cached present
flag before reading (if available on the target build). Emit
`HK_INTEGRITY_KDBG_ATTACHED` (high weight) vs `HK_INTEGRITY_KDBG_BOOT_ALLOWED`
(low weight) as distinct findings so the server scores attach state, not the
boot flag. Lowest-risk sensor; ship first.

**Signal 34 — DriverObjectAudit.c.** `IoEnumerateDeviceObjectList` per driver,
or `ObReferenceObjectByName` on `\Driver\*` (the directory walk). Read
`DRIVER_OBJECT.FastIoDispatch` (`PFAST_IO_DISPATCH`), `DriverStartIo`,
`DriverUnload`, `DriverExtension->AddDevice`; verify each non-NULL pointer is in
`[DriverStart, DriverStart+DriverSize)` *or* in any signed loaded module
(fltmgr.sys thunks are legit, per catalog FP gate). `ObDereferenceObject` every
referenced object — checked. Flag pointers outside all images / in pool as
`HK_INTEGRITY_DRVOBJ_DIVERGENCE`. **UNCERTAINTY (flag):** `ObReferenceObjectByName`
needs `IoDriverObjectType` (not officially exported on all WDK versions);
prefer `IoEnumerateDeviceObjectList` where it avoids that dependency.

**Signal 35 — SsdtIntegrity.c.** Resolve `KeServiceDescriptorTable` /
`KeServiceDescriptorTableShadow`, decode each `KiServiceTable` entry (x64 packed
form: `(entry >> 4)` signed offset added to table base), verify the target is in
`ntoskrnl`/`win32k` per `ModuleMap`. **READ-ONLY — no table writes** (guardrail
echoed in the file comment). On HVCI systems an out-of-image entry is
high-confidence (PatchGuard would otherwise have bugchecked).
**UNCERTAINTY (flag):** `KeServiceDescriptorTableShadow` is not exported;
locating it is undocumented. Ship the non-shadow `KiServiceTable` half (resolved
via the exported `KeServiceDescriptorTable`) and flag the shadow half as
deferred/uncertain rather than pattern-scanning win32k.

**Signal 36 — BootLoadAudit.c + DriverProbeWin.cpp.** Kernel half: walk
`PsLoadedModuleList` (roughly load-ordered) to confirm our boot-start driver
loaded and is early; read `SystemBootEnvironmentInformation`. User-mode half
(signed, `DriverProbeWin.cpp`): read
`HKLM\SYSTEM\CurrentControlSet\Control\ServiceGroupOrder\List` and each driver's
`Start`/`Group`; in-kernel registry reads use `ZwOpenKey`/`ZwQueryValueKey` at
PASSIVE_LEVEL only. Correlate: flag `HK_INTEGRITY_BOOTLOAD_SUPPRESS` only when
OUR driver or the ELAM verdict is missing/suppressed — not every service-order
quirk (catalog FP gate: dual-boot, safe-mode, WinPE produce benign deviations).
ELAM verdict via `IoRegisterBootDriverCallback` is the canonical surface.
**UNCERTAINTY (flag):** `IoRegisterBootDriverCallback` must be registered very
early (boot-start) and has strict callback constraints; confirm registration
timing before wiring.

**Server (guardrail #8).** The ingest decoder for `HK_EVENT_INTEGRITY_FINDING`
is fully async on tokio, `thiserror` error type, no `unwrap()` outside tests;
scoring weights per `finding` code live in the ban-engine config, not hardcoded
panics.

---

## Build wiring

- Add the new `.c` files to `HK_DRIVER_SRC` in `kernel/win/CMakeLists.txt` and
  to `<ClCompile>` in `kernel/win/horkos.vcxproj` (the vcxproj remains the
  source of truth for production signing).
- New CMake feature options (cached, documented in `docs/windows-build.md`),
  default tuned to FP risk from the catalog:
  - `HK_WIN_INTEGRITY_DEBUGSTATE` — signal 33 — **default ON** (low FP, low risk).
  - `HK_WIN_INTEGRITY_CISTATE` — signal 30 — **default ON** (low FP).
  - `HK_WIN_INTEGRITY_SSDT` — signal 35 — **default ON** (low FP; non-shadow half only initially).
  - `HK_WIN_INTEGRITY_DRVOBJ` — signal 34 — **default ON** (low FP).
  - `HK_WIN_INTEGRITY_FLT` — signal 28 — **default OFF** until Flt lifetime is verified.
  - `HK_WIN_INTEGRITY_CALLBACKS` — signal 31 — **default OFF**, self-sentinel half only when ON.
  - `HK_WIN_INTEGRITY_IMAGEHASH` — signal 29 — **default OFF** (reloc normalization unproven).
  - `HK_WIN_INTEGRITY_NONIMAGE` — signal 32 — **default OFF** (HIGH FP).
  - `HK_WIN_INTEGRITY_BOOTLOAD` — signal 36 — **default OFF** until ELAM timing confirmed.
- These map to `target_compile_definitions` so each sensor `.c` compiles to a
  no-op stub when its flag is OFF, keeping the driver linkable with any subset.
- `ModuleMap.c` and `HkIntegrityScan.c` are always compiled (they are the
  shared substrate); they fan out only to enabled sensors.
- Toolchain unchanged: WDK + MSVC `/kernel /GS /W4 /WX` (the existing
  `kernel/win/CMakeLists.txt` flags satisfy the "every warning is an error"
  posture for kernel C). User-mode `DriverProbeWin.cpp` builds in the existing
  SDK backend target.

---

## Test strategy

### Unit / host-buildable tests (guardrail #14: logic where testable)

- **Schema pin tests** (host, no WDK): a C++ TU that includes
  `event_schema.h` + `ioctl.h` and asserts
  `sizeof(hk_event_integrity_finding) == 16`, `HK_EVENT_PAYLOAD_MAX == 16`,
  `sizeof(hk_event_record) == 40` still hold after the additions. Runs in CI on
  every host.
- **Module-map resolve logic** factored into a pure function over an array of
  `{base,size,name}` and unit-tested host-side (no kernel calls) for: address
  inside one range, address in a gap, boundary `base+size` exclusive, empty map.
- **SSDT decode** of the x64 packed-offset form tested host-side against known
  encoded values (pure arithmetic, no kernel).
- **Server decoder** Rust unit tests: valid record round-trips; short record →
  `Err`; unknown `finding` code → `Err` or quarantine, never panic (guardrail
  #8).

### Bypass tests (guardrail #12 — merge gate; any change under `kernel/win/`
needs a corresponding bypass test under `bypass-tests/win/`)

Following the disabled-but-compiled pattern of the existing
`bypass-tests/win/byovd_load.cpp` (compiles now, asserts activate when the
signed fixture lands). New files under `bypass-tests/win/`, all added to
`bypass-tests/win/CMakeLists.txt`:

- `ssdt_hook_detect.cpp` — must demonstrate: with a (Phase-5, self-built,
  test-signed) fixture that points a `KiServiceTable` entry outside ntoskrnl,
  the AC emits `HK_INTEGRITY_SSDT_OUT_OF_IMAGE`. Disabled no-op until the
  fixture exists.
- `drvobj_fastio_detour.cpp` — fixture detours a `FastIoDispatch` pointer out of
  its image; assert `HK_INTEGRITY_DRVOBJ_DIVERGENCE` fires and that an
  fltmgr.sys-resident thunk does NOT fire (FP gate proof).
- `ci_state_flip.cpp` — flip `testsigning`/HVCI in a VM post-boot; assert
  `HK_INTEGRITY_CI_STATE_DELTA` fires for the post-boot delta but a stable boot
  config at startup does NOT (delta-only proof).
- `kdbg_attach.cpp` — assert attach state yields `HK_INTEGRITY_KDBG_ATTACHED`
  (high) while a boot-debug-allowed-but-detached config yields only
  `HK_INTEGRITY_KDBG_BOOT_ALLOWED` (low) — proves the weight split.
- `nonimage_exec_map.cpp` — manually-map a benign test page executable in system
  space (fixture) and assert `HK_INTEGRITY_NONIMAGE_EXEC` reports it as a
  server-scored anomaly, NOT a standalone ban.
- `callback_strip_sentinel.cpp` — fixture strips our sentinel callback; assert
  the self-sentinel half detects the missing slot.

Each ships disabled (compiled no-op returning success) until the Phase-5
signed-fixture driver target exists, matching the gate-keeping convention
already in the repo. The merge gate is satisfied by their presence + compile.

---

## Sequencing

1. **Wire + substrate first.** Land the `event_schema.h` /`ioctl.h` additions
   (new event type, schema bump 2→3, `HK_IOCTL_INTEGRITY_RESCAN`, status flags),
   the Rust serde mirror, the `data-categories.md` section (guardrail #11 — same
   PR), and the schema-pin + server-decoder tests. Nothing kernel yet. This PR
   is fully testable host-side.
2. **ModuleMap + orchestrator.** `ModuleMap.c`, `HkIntegrityScan.c`, the
   PASSIVE_LEVEL work item, host-side ModuleMap unit tests. No sensors enabled.
3. **Low-risk, default-ON sensors** (no exported-internal dependence): signal 33
   (DebugState), 30 (CodeIntegrity), 34 (DriverObject), then 35 (SSDT non-shadow
   half). Each lands with its bypass-test stub.
4. **Default-OFF sensors gated on uncertainty resolution**, in ascending risk:
   28 (Minifilter, after Flt lifetime confirmed), 36 (BootLoad, after ELAM
   timing confirmed), 29 (ImageHash, after reloc normalization validated), 31
   (Callbacks, self-sentinel only), 32 (NonImage, last — highest FP).
5. **Phase 5:** signed test-fixture drivers activate the bypass-test assertions;
   SSDT shadow half and full callback-table enumeration only if the undocumented
   surfaces are resolved safely.

Dependencies: 29/31/32/34/35 all depend on `ModuleMap` (step 2). 36's user-mode
half depends on the `DriverProbeWin.cpp` backend already present. The server
decoder (step 1) gates every sensor's findings being interpretable.

---

## Risks & UNCERTAINTY FLAGS

Per guardrail #13, these are flagged for the user **before any kernel code is
written** — a BSOD is worse than a delay:

1. **Signal 31 (CallbackResidency) full table walk — HIGHEST RISK.**
   `PspCreateProcessNotifyRoutine` / `PspLoadImageNotifyRoutine` /
   `CmCallbackListHead` are **undocumented and unexported**. Reading them
   requires pattern-scanning ntoskrnl or hardcoded version offsets — fragile and
   exactly the kind of "guess on a kernel API" the guardrail forbids. **Plan
   ships only the documented self-sentinel half by default.** The full
   enumeration is OUT until a documented or robustly version-resolved surface is
   agreed. FLAGGED — do not implement the table walk on a guess.
2. **Signal 28 (Minifilter) Flt object lifetime.** Exact refcount/dereference
   semantics of `FltEnumerateFilters` / `FltEnumerateInstances` returned objects,
   and whether enumeration needs our own `FltRegisterFilter` handle. A missed
   `FltObjectDereference` leaks; a double-deref is a UAF/bugcheck. FLAGGED —
   confirm against WDK docs before enabling.
3. **Signal 35 shadow SSDT.** `KeServiceDescriptorTableShadow` is unexported;
   locating it and the win32k base safely is undocumented. **Ship non-shadow
   `KiServiceTable` only**; shadow half deferred. FLAGGED.
4. **Signal 29 reloc/IAT normalization.** Correctly normalizing base relocations,
   IAT thunks, hotpatch regions, and CFG/retpoline rewrites before hashing is
   error-prone; a wrong normalization produces false `TEXT_HASH_DELTA` on clean
   machines. Default-OFF, report-only until validated against a clean-machine
   corpus. FLAGGED.
5. **Signal 36 ELAM callback timing.** `IoRegisterBootDriverCallback` must be
   registered at boot-start with strict constraints; mis-timing yields no verdict
   or a load failure. FLAGGED — confirm registration point.
6. **Signal 32 executability classification.** No clean documented query for
   "is this big-pool range executable"; relying on heuristics risks both FPs and
   misses. HIGH FP per catalog. Default-OFF, lowest weight, server-scored only.
7. **KASLR leak hygiene.** `detail` must never carry a raw kernel pointer
   off-box. All address-derived details are image-relative offsets or masked.
   Confirm the server never logs an unmasked value.
8. **`AuxKlibQueryModuleInformation` is legacy.** Prefer
   `ZwQuerySystemInformation(SystemModuleInformation)`; `AuxKlib` is the
   fallback only. Noted so the build doesn't pull `aux_klib.lib` unnecessarily.
9. **PatchGuard interaction.** All sensors are strictly read-only (no SSDT/IDT/
   table writes), so they do not themselves trip PatchGuard — but any future
   "verify by self-test write" idea is explicitly out of scope.

No detection-efficacy or bypass-resistance claims are made here; those are
server-scored and out of scope for this kernel plan (guardrail #13).
