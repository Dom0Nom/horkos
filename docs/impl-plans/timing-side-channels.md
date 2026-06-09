# timing-side-channels — Implementation Plan

**Scope:** Timing & execution-trace side-channels — read-only sensors that observe exception-dispatch ownership/latency, hardware-breakpoint/single-step traces, guard-page fault cadence, and TSC/CPUID-virtualization skew. Clients sample and report only; all classification and ban authority is server-side. No tampering/injection code.

**Catalog signals covered:** 154, 155, 156, 157, 158, 159, 160, 161, 162 (`docs/detection-catalog.md` §`timing-side-channels`, lines 1605–1695).

Split by layer:
- **Usermode (`ac/src/timing/`):** 154 (VEH fault attribution), 156 (sibling-thread RDTSCP watchdog, cross-platform core), 157 (KUSER_SHARED_DATA clock skew), 159 (INT3 decoy dispatch-latency histogram), 161 (guard-fault inter-arrival cadence), 162 (CPUID leaf-fan latency).
- **Kernel (`kernel/win/src/`):** 155 (APERF/MPERF vs RDTSC, MSR reads require ring 0 → KMDF). Surfaced via the existing SPSC ring → `HK_IOCTL_DRAIN_EVENTS` bridge.
- **Linux eBPF (`kernel/linux/bpf/src/`):** 158 (HW-breakpoint census on guarded symbols).
- **macOS ES (`kernel/macos/es/`):** 160 (Mach exception-port ownership audit), invoked from the `EsClient.mm` process-handling path.

The usermode correlator drains the kernel ring (signal 155) and folds it into the per-tick timing report before upload. Server is the only classifier — the client ships raw vectors/histograms/port-owner lists, never a verdict.

---

## New files

All usermode sensor `.cpp` live under `ac/src/timing/` (a `backends`-equivalent subtree for platform-specific sensors; guardrail #1 — every Windows-only API in these files is gated behind `HK_PLATFORM_WINDOWS`, the cross-platform clock intrinsics behind the matching `HK_PLATFORM_*`). Kernel sensors live under `kernel/win/src/` / `kernel/linux/bpf/src/` / `kernel/macos/es/` and never share a TU with userspace (guardrail #4). Every file opens with the role / target-platform / interface module comment (guardrail #3).

| Path | Role | Module-comment summary |
|---|---|---|
| `ac/include/horkos/timing/timing_signals.h` | Declares the usermode timing-sensor surface: one sampler per signal returning a fixed POD result; a `timing_collect_all()` aggregator. | Role: usermode timing/execution-trace sensor interface. Target: Windows + cross (clock core). Interface: this header IS the timing sensor surface; `ac/src/timing/*.cpp` implement it; consumed by `ac/src/ac.cpp`. |
| `ac/include/horkos/timing/fault_attribution.h` | Declares signal-154 VEH fault-attribution sampler + decoy PAGE_GUARD arming. | Role: guard-page-fault resolver-attribution interface. Target: Windows. Interface: implemented by `ac/src/timing/veh_fault_attribution_win.cpp`; aggregated via `timing_signals.h`. |
| `ac/include/horkos/timing/watchdog.h` | Declares signal-156 sibling-thread RDTSCP watchdog; cross-platform clock intrinsic seam. | Role: dual-clock RDTSCP watchdog interface. Target: cross (Win/Linux/macOS via `platform/` time intrinsics). Interface: implemented by `sibling_watchdog.cpp`. |
| `ac/include/horkos/timing/clock_consistency.h` | Declares signal-157 KUSER_SHARED_DATA vs time-API ratio sampler (Windows-only, behind `HK_PLATFORM_WINDOWS`). | Role: shared-page-vs-API clock-consistency interface. Target: Windows. Interface: implemented by `shared_data_clock_win.cpp`. |
| `ac/include/horkos/timing/exc_latency.h` | Declares signal-159 INT3-decoy dispatch-latency histogram sampler. | Role: exception-dispatch latency-histogram interface. Target: Windows. Interface: implemented by `exception_latency_win.cpp`. |
| `ac/include/horkos/timing/guard_cadence.h` | Declares signal-161 guard-fault inter-arrival cadence sampler. | Role: guard-fault single-step-cadence interface. Target: Windows. Interface: implemented by `guard_fault_cadence_win.cpp`. |
| `ac/include/horkos/timing/cpuid_fan.h` | Declares signal-162 CPUID per-leaf latency-fan sampler (cross-platform core, x86-only guard). | Role: CPUID VMEXIT leaf-fan latency interface. Target: cross (x86 only). Interface: implemented by `cpuid_leaf_fan_win.cpp`. |
| `ac/src/timing/veh_fault_attribution_win.cpp` | Signal 154: first-chain VEH reads `CONTEXT.Dr6/Dr7` + `RtlPcToFileHeader(ReturnAddress)`; correlates with self-armed decoy PAGE_GUARD. | Role: VEH-ordering / fault-resolver attribution sensor. Target: Windows. Interface: implements `fault_attribution.h`. |
| `ac/src/timing/sibling_watchdog.cpp` | Signal 156: in-section RDTSCP vs sibling-core watchdog RDTSCP via lock-free atomic slot; AUX core-id migration check. | Role: dual-clock sibling RDTSCP watchdog sensor. Target: cross. Interface: implements `watchdog.h`; uses `platform/` clock intrinsics. |
| `ac/src/timing/shared_data_clock_win.cpp` | Signal 157: reads KUSER_SHARED_DATA @ 0x7FFE0000 InterruptTime/SystemTime/TickCount/QpcBias vs `GetTickCount64`/`QPC`/`GetSystemTimePreciseAsFileTime`. | Role: KUSER_SHARED_DATA monotonicity-break sensor. Target: Windows. Interface: implements `clock_consistency.h`. |
| `ac/src/timing/exception_latency_win.cpp` | Signal 159: times round-trip from a planted decoy 0xCC to first-chain VEH; builds latency histogram vs per-machine baseline. | Role: INT3-decoy dispatch-latency histogram sensor. Target: Windows. Interface: implements `exc_latency.h`. |
| `ac/src/timing/guard_fault_cadence_win.cpp` | Signal 161: re-arms PAGE_GUARD in the guard VEH, timestamps each STATUS_GUARD_PAGE_VIOLATION, builds inter-arrival distribution + EFLAGS.TF/DR6 correlation. | Role: guard-fault single-step cadence sensor. Target: Windows. Interface: implements `guard_cadence.h`. |
| `ac/src/timing/cpuid_leaf_fan_win.cpp` | Signal 162: times `__cpuidex` across a fixed leaf sweep with RDTSCP+LFENCE fences; emits per-leaf latency vector. | Role: CPUID leaf-fan latency sensor. Target: Windows (x86). Interface: implements `cpuid_fan.h`. |
| `ac/src/timing/timing_kernel_correlate.cpp` | Drains kernel timing records (signal 155) via the SDK IOCTL bridge and folds them into the usermode report. | Role: kernel-timing-record correlator. Target: Windows. Interface: implements `timing_collect_kernel()`; consumes `sdk/include/horkos/ioctl.h`. |
| `kernel/win/src/TimingProbe.c` | Signal 155 kernel sensor: guarded `__readmsr(IA32_APERF/IA32_MPERF)` around a fixed busy-loop vs `__rdtsc`/`KeQueryPerformanceCounter`; emits effective-freq-vs-TSC skew. | Role: APERF/MPERF-vs-RDTSC invariant-skew sensor. Target: Windows kernel (KMDF). Interface: declared in `kernel/win/include/horkos_kernel.h`; emits via `HkRingEmit`. |
| `kernel/linux/bpf/src/hw_breakpoint_census.bpf.c` | Signal 158: counts `PERF_TYPE_BREAKPOINT` perf events whose target task is in the game's thread group; uprobe/tracepoint on `do_debug`. | Role: HW-breakpoint census on guarded symbols (CO-RE). Target: Linux eBPF. Interface: ringbuf event mirrors `event_schema.h`. |
| `kernel/macos/es/ExceptionPortAudit.mm` | Signal 160: `task_get_exception_ports` for EXC_MASK_BREAKPOINT/BAD_INSTRUCTION/BAD_ACCESS; resolves owning task vs self/OS-default. | Role: Mach exception-port ownership audit. Target: macOS ES. Interface: invoked from `EsClient.mm` process-handling path; never drops an ES reply (guardrail #7). |
| `server/telemetry/src/timing.rs` | serde structs mirroring the timing report sub-payload on the per-tick/periodic ingest plane; validation, no `unwrap()`. | Role: server-side timing-posture ingest contract. Target: server. Interface: `mod timing` under `server/telemetry`; mirrors `timing_signals.h` field names. |
| `bypass-tests/win/timing/*`, `bypass-tests/linux/timing/*`, `bypass-tests/macos/timing/*` | Bypass tests (one per merge-gated sensor). See Test strategy. | Role: timing-sensor bypass merge gate (guardrail #12). Target: per-platform. Interface: drives the timing sensors. |

Header additions (not new files): new kernel event type/payload in `sdk/include/horkos/event_schema.h`; new timing sub-payload in `server/telemetry/src/schema.rs` (or `timing.rs` submodule); new data-category rows in `server/api/data-categories.md` (guardrail #11).

---

## Interfaces & data structures

### Usermode sensor surface (`ac/include/horkos/timing/timing_signals.h`)

Plain POD result structs, fixed-size, no platform headers in the header (platform calls live in the `.cpp`). The header is the only place the per-signal headers are aggregated. Sketch:

```c
typedef struct timing_veh_attrib {      /* signal 154 */
    uint32_t foreign_resolver;     /* 1 if first resolver's image outside game/known runtime */
    uint32_t resolver_signed;      /* 1 if resolver image is signed/on attest module list */
    uint32_t dr6_stepbit;          /* CONTEXT.Dr6 single-step/BP bit observed */
    uint32_t dr7_local_enable;     /* CONTEXT.Dr7 L0..L3 mask */
    uint64_t resolver_image_base;  /* RtlPcToFileHeader(ReturnAddress); 0 = unmapped */
} timing_veh_attrib;

typedef struct timing_watchdog {        /* signal 156 */
    uint64_t in_section_tsc_delta;
    uint64_t watchdog_tsc_delta;
    uint32_t aux_core_in;          /* IA32_TSC_AUX read in-section */
    uint32_t aux_core_watch;       /* IA32_TSC_AUX read by watchdog */
    uint32_t ctx_switch_seen;      /* GetThreadTimes-derived: window had a switch */
    uint32_t divergence_pct;       /* |delta| / in_section * 100, clamped */
} timing_watchdog;

typedef struct timing_clock_consistency { /* signal 157 */
    uint64_t shared_interrupt_dt;  /* KUSER_SHARED_DATA.InterruptTime delta */
    uint64_t shared_system_dt;     /* KUSER_SHARED_DATA.SystemTime delta */
    uint64_t api_tick_dt;          /* GetTickCount64 delta over same window */
    uint64_t api_qpc_dt;           /* QueryPerformanceCounter delta */
    uint32_t ratio_drift_ppm;      /* sustained directional drift, parts-per-million */
    uint32_t wine_vm_ctx;          /* 1 if Wine/Proton/VM context already tagged */
} timing_clock_consistency;

typedef struct timing_exc_latency {     /* signal 159 */
    uint32_t hist[32];             /* dispatch-latency buckets (QPC/RDTSCP units) */
    uint32_t baseline_modes;       /* mode count of the per-machine startup baseline */
    uint32_t live_modes;           /* mode count of the live distribution */
    uint32_t reserved;
} timing_exc_latency;

typedef struct timing_guard_cadence {   /* signal 161 */
    uint32_t inter_arrival[32];    /* guard-fault inter-arrival buckets */
    uint32_t fault_count;          /* faults per logical invocation */
    uint32_t uniform_cadence;      /* 1 if tight high-count uniform-cadence burst */
    uint32_t eflags_tf_or_dr6;     /* TF set or DR6 BP bit in same VEH */
} timing_guard_cadence;

typedef struct timing_cpuid_fan {       /* signal 162 */
    uint32_t leaf_latency[16];     /* per-leaf RDTSCP-fenced latency (cycles) */
    uint32_t leaf_id[16];          /* the swept leaf values (0x0,0x1,0x7,0xB,0x15,0x40000000..10) */
    uint32_t flat_baseline_cycles; /* near-flat bare-metal reference */
    uint32_t reserved;
} timing_cpuid_fan;

typedef struct timing_kernel_summary {  /* signal 155, folded from kernel ring */
    uint32_t aperf_mperf_eff_mhz;  /* derived effective frequency */
    uint32_t rdtsc_nominal_mhz;    /* nominal base from CPUID 0x15 */
    uint32_t skew_pct;             /* mismatch beyond P-state bounds, percent */
    uint32_t hv_present_bit;       /* cross-checked hypervisor-present tag */
} timing_kernel_summary;

typedef struct timing_report {
    timing_veh_attrib        veh;      /* 154 */
    timing_watchdog          wdog;     /* 156 */
    timing_clock_consistency clock;    /* 157 */
    timing_exc_latency       exc;      /* 159 */
    timing_guard_cadence     guard;    /* 161 */
    timing_cpuid_fan         cpuid;    /* 162 */
    timing_kernel_summary    kern;     /* 155 */
    uint32_t                 sensors_ok; /* bitmask: which samplers ran cleanly */
} timing_report;
```

Each `timing_sample_*` returns one result by out-param plus an `HK_AC_*` status (reuse `ac.h` codes). The aggregator builds a `timing_report`; `ac/src/ac.cpp` serializes it to the server.

### Kernel event-schema addition (`sdk/include/horkos/event_schema.h`)

Signal 155 is the only signal whose data must traverse the C99 kernel ring. Bump `HK_EVENT_SCHEMA_VERSION 2u → 3u`. Append one event type (existing values never change):

```c
HK_EVENT_TIMING_FREQ_SKEW = 5,  /* signal 155 */
```

**Payload-size constraint (load-bearing):** `ioctl.h` pins `HK_EVENT_PAYLOAD_MAX = 16u` and `HK_STATIC_ASSERT(sizeof(hk_event_record) == 40, ...)`. The new payload MUST be ≤ 16 bytes or every size pin in `ioctl.h` (`HK_EVENT_PAYLOAD_MAX`, `hk_event_record == 40`, `hk_drain_header`, `hk_status`, `hk_policy`) must be re-derived in lockstep on both kernel and userspace sides. Keep it exactly 16 bytes:

```c
typedef struct hk_event_timing_freq_skew {  /* 16 bytes */
    uint32_t eff_mhz;       /* APERF/MPERF-derived effective frequency */
    uint32_t nominal_mhz;   /* CPUID 0x15 nominal base frequency */
    uint32_t skew_pct;      /* mismatch beyond P-state bounds, percent */
    uint32_t flags;         /* HK_TIMING_* : msr_gp_faulted, hv_present, tsc_invariant */
} hk_event_timing_freq_skew;

HK_STATIC_ASSERT(sizeof(hk_event_timing_freq_skew) == 16,
    "hk_event_timing_freq_skew size mismatch");
```

No change to `HK_EVENT_PAYLOAD_MAX` or `hk_event_record` size — the 16-byte ceiling is preserved, so `ioctl.h`'s asserts stay green. The Rust serde mirror for the kernel-event plane lands when that mirror lands (it is not yet present in `server/`, per the existing note in `event_schema.h`).

### Server ingest (`server/telemetry/src/timing.rs`)

JSON serde struct mirroring `timing_report` field names (this is the independent per-tick/periodic plane, NOT byte-compatible with the C struct — same separation `schema.rs` documents for `TickPayload`). `Deserialize` + range/length validation returning `Result<_, thiserror::Error>`; no `unwrap()` outside `#[cfg(test)]` (guardrail #8). Bump `SCHEMA_VERSION` in `schema.rs`. Histograms arrive as fixed-length arrays; validate lengths on deserialize rather than indexing blindly.

### Telemetry fields → data-categories.md (guardrail #11)

Every new field above is telemetry leaving the client and MUST get a row in `server/api/data-categories.md` **in the same PR**. New section **"6. Timing & execution-trace side-channels"** with rows for: `veh_*` resolver attribution, `watchdog_*` dual-clock deltas + core ids, `clock_*` shared-page/API deltas, `exc_latency_hist`, `guard_cadence_*`, `cpuid_leaf_latency[]`, and the kernel `timing_freq_skew` fields (eff_mhz/nominal_mhz/skew_pct/flags). Source column: per-signal sensor; legal basis: legitimate interest — anti-cheat enforcement; retention default 90 days (histograms 365 days if used for rule training, matching the `image_sha256` precedent). The reviewer rejects any undeclared field.

---

## Mechanism implementation notes

### Signal 154 — VEH fault attribution (`veh_fault_attribution_win.cpp`)
`AddVectoredExceptionHandler(TRUE, ...)` to install first-in-chain. Inside the handler, on `STATUS_GUARD_PAGE_VIOLATION` against the self-armed decoy region (armed via `VirtualProtect(..., PAGE_GUARD, ...)`), read `ExceptionInfo->ContextRecord->Dr6/Dr7` and resolve the dispatch-frame return address through `RtlPcToFileHeader`. Attribute the owning image; flag only when the resolver image is unsigned OR absent from the attestation module list AND DR6 shows a live step/BP bit. **Safety:** the VEH runs at the faulting thread's context — keep it allocation-free and re-entrancy-safe; never call back into anything that can fault the decoy again. Report server-side; do not locally decide (FP risk: overlays/IME/.NET/GPU drivers register legitimate VEHs).

### Signal 156 — sibling-thread RDTSCP watchdog (`sibling_watchdog.cpp`)
Cross-platform. Two `__rdtscp` reads (with embedded `IA32_TSC_AUX` core id): one inside the guarded function, one from a watchdog thread pinned via `SetThreadAffinityMask` (Windows) / `pthread_setaffinity_np` (Linux) / `thread_policy_set` affinity-hint (macOS — best-effort; macOS gives no hard pinning, flag below) reading a `std::atomic<uint64_t>` slot. Diff the two clocks; discard windows where `GetThreadTimes` shows a context switch or the AUX core id changed unexpectedly. The clock intrinsic seam lives in `platform/` (guardrail #1) — the `.cpp` calls `hk_rdtscp_aux()` not raw intrinsics so the affinity API stays platform-gated. High-percentile threshold over many samples; low FP.

### Signal 157 — KUSER_SHARED_DATA monotonicity (`shared_data_clock_win.cpp`)
Read the fixed user-mode mapping at `0x7FFE0000` (`InterruptTime`, `SystemTime`, `TickCount`, `QpcBias`) and compare advance ratios against `GetTickCount64()`, `QueryPerformanceCounter()`, `GetSystemTimePreciseAsFileTime()` over the same window. Direct read of the documented read-only page is allowed (no write, no hook). Require a *sustained directional* ratio drift, not one-off jitter; tag Wine/Proton/VM context (already detectable) before reporting. Windows-only, entire TU behind `HK_PLATFORM_WINDOWS`.

### Signal 159 — INT3-decoy dispatch latency (`exception_latency_win.cpp`)
Plant a known `0xCC` at a deliberately-executed decoy address, time the round-trip into the AC's first-chain VEH with `QueryPerformanceCounter` (and `__rdtscp`). Build a histogram; compare modality/tail against a **per-machine baseline captured at startup before any third-party module loads** (calibration is mandatory — crash reporters/Sentry/WER/.NET/AV add benign latency). Flag only multi-modal/step-change shifts after baseline. The VEH must re-continue with `DBG_CONTINUE` after observing. **Safety:** the decoy executes intentionally; ensure the planted byte is in a writable+executable AC-owned page and is restored, never in the GAME hot loop (guardrail #9).

### Signal 161 — guard-fault inter-arrival cadence (`guard_fault_cadence_win.cpp`)
Re-arm `PAGE_GUARD` via `VirtualProtect` inside the guard-fault VEH (the read auto-clears PAGE_GUARD; re-arm to keep observing), timestamp each `STATUS_GUARD_PAGE_VIOLATION` with `QueryPerformanceCounter`, analyze inter-arrival distribution + count per logical invocation. A tight high-count uniform-cadence burst is the single-step fingerprint. Correlate with `CONTEXT.EFlags.TF` / `Dr6` read in the same VEH. **Safety:** same VEH re-entrancy discipline as 154; bounded re-arm count to avoid livelock under heavy contention; report the histogram, never locally ban.

### Signal 162 — CPUID leaf-fan latency (`cpuid_leaf_fan_win.cpp`)
Time `__cpuidex` across a fixed sweep `{0x0,0x1,0x7,0xB,0x15,0x40000000..0x40000010}` with `__rdtscp` + `_mm_lfence` serialization fences, building a per-leaf latency vector. Bare-metal baselines are near-flat; selectively-emulated VMM leaves spike. **x86-only guard** (the `cpuid_fan.h` core is cross-arch-declared but the sweep is `#if defined(HK_ARCH_X86_64)`-gated inside the `.cpp`; on ARM macOS the sampler returns `HK_AC_NOT_IMPLEMENTED`). Strictly a VM-context tag combined with signal 155 + hypervisor-present bit for server scoring — never standalone (VBS on by default on Win11 produces the same fan).

### Signal 155 — APERF/MPERF vs RDTSC (`kernel/win/src/TimingProbe.c`, KMDF)
Userspace cannot read these MSRs, so this is a KMDF-assisted probe. Read `__readmsr(IA32_APERF /*0xE8*/)` and `__readmsr(IA32_MPERF /*0xE7*/)` around a fixed busy-loop; derive effective frequency; compare to `__rdtsc` delta / `KeQueryPerformanceCounter` delta; nominal base from CPUID leaf 0x15. Emit `HK_EVENT_TIMING_FREQ_SKEW` via `HkRingEmit`. **IRQL:** `__readmsr` and the busy-loop must run at a known IRQL — the probe should execute pinned to a CPU at a raised-but-bounded level so the loop isn't migrated/preempted mid-window; **FLAG (below)** the exact IRQL/`KeRaiseIrql` choice and CPU-pin mechanism as uncertain. Every `NTSTATUS` checked; safe string functions only (guardrail #5); kernel/userspace TUs never shared (guardrail #4). Treat the skew as a **VM-context tag**, never an autonomous ban (WSL2/Hyper-V/Credential Guard legitimately virtualize TSC).

### Signal 158 — HW-breakpoint census (`hw_breakpoint_census.bpf.c`, CO-RE)
eBPF program counting `perf_event_attr.type == PERF_TYPE_BREAKPOINT` events whose owning task is in the game's thread group, via a uprobe/tracepoint on `do_debug` / `hw_breakpoint_handler` plus `/proc/<tid>/task` enumeration in userspace (libbpf loader). CO-RE relocations for the `perf_event` / `task_struct` field reads; compiles `-Wall -Wextra -Werror` at the kernel warning level (guardrail #6). Ringbuf event mirrors `event_schema.h`. Gate by counting only events whose owning task is outside the game's own thread group and absent from an allowlisted-tracer set; **audit-only on Steam Deck Game Mode** (locked decision: Game Mode requires eBPF, no LKM). Default build flag OFF where eBPF is gated.

### Signal 160 — Mach exception-port audit (`ExceptionPortAudit.mm`)
`task_get_exception_ports` for `EXC_MASK_BREAKPOINT | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_BAD_ACCESS`; resolve the returned port's owning task (via the ES client's `es_message_t` process context) and compare against self and the OS default catcher. Foreign/unsigned owner ⇒ stepping debugger. **Guardrail #7 (CRITICAL):** this runs in the `EsClient.mm` process-handling path; the audit must complete and the ES event MUST be replied to (`es_respond_*`) within the kernel deadline regardless of audit outcome — the audit never gates the reply. No blocking calls on the ES handler queue (guardrail #8 spirit). Allowlist the OS `ReportCrash` port and the game's signed crash handler; flag only third-party/unsigned owners. **FLAG (below)** the exact `task_get_exception_ports` call against a *foreign* task from within an ES client (which task port is legitimately available, and whether the ES context yields a usable task port) as uncertain.

### Server (`server/telemetry/src/timing.rs`)
Fully async on tokio; `thiserror` error type for the ingest validation; no `unwrap()` outside tests (guardrail #8). Deserialize fixed-length histogram arrays with length validation; reject out-of-range `*_pct`/`*_ppm` fields rather than panicking. All scoring (skew thresholds, modality shifts, cadence signatures) is server-side; the client ships raw vectors only.

---

## Build wiring

- **Usermode (`ac/CMakeLists.txt`):** add `ac/src/timing/*.cpp` to the AC target under a new option `HORKOS_TIMING_SENSORS` (default **ON** — these are core PC sensors). Windows-only `.cpp` (`*_win.cpp`) compiled only when targeting Windows; `sibling_watchdog.cpp` and the `cpuid_leaf_fan` core compile cross-platform with platform intrinsics behind `platform/`. Toolchain: MSVC/clang-cl for Windows usermode; the obfuscator (LLVM 19) opt-in via `__attribute__((annotate("hk_obfuscate")))` on the init/integrity entry points only (guardrail #9) — the timing hot-sampling loops are NOT obfuscated.
- **Kernel (`kernel/win`):** add `TimingProbe.c` to the KMDF driver source list; WDK toolchain; built as part of the existing boot-start driver. No new feature flag (it joins the existing sensor set), but gated behind a runtime policy toggle so the MSR probe can be disabled in the field.
- **Linux (`kernel/linux/CMakeLists.txt`):** add `hw_breakpoint_census.bpf.c` under the existing eBPF gate (`HORKOS_ENABLE_EBPF`, default **OFF** per the locked decision); libbpf + clang-19 CO-RE build, `-Wall -Wextra -Werror`. No LKM variant (HW-bp census is eBPF-only here).
- **macOS (`kernel/macos/es/CMakeLists.txt`):** add `ExceptionPortAudit.mm` to the ES client target under the existing `HORKOS_MACOS_ES` option (default OFF until the EndpointSecurity entitlement lands; the userspace daemon bring-up path covers the interim per the locked decision). Xcode/clang toolchain, EndpointSecurity framework link.
- **Server (`server/telemetry`):** add `mod timing;` to the telemetry crate; no new cargo feature.

---

## Test strategy

### Unit tests
- **Server (`server/telemetry/tests/`):** `timing.rs` deserialize round-trip; reject malformed histograms (wrong length), out-of-range `skew_pct`/`ratio_drift_ppm`; verify `SCHEMA_VERSION` bump; confirm no panic path (no `unwrap`).
- **Schema (compile-time):** the `HK_STATIC_ASSERT(sizeof(hk_event_timing_freq_skew) == 16)` and the unchanged `ioctl.h` size pins ARE the wire-size unit test; a layout drift fails the build on both sides.
- **Usermode samplers:** baseline-calibration math for 159/161 (modality/cadence classifiers) tested with synthetic histograms on a host build (no debugger present) — these are pure functions over the captured vectors, testable without the OS hooks.
- **Kernel 155:** effective-frequency derivation math factored into a pure helper and unit-tested host-side; the MSR read path itself is integration-only.

### Bypass tests (guardrail #12 — merge gate; any change under a security folder needs a corresponding bypass test)
- `bypass-tests/win/timing/hw_bp_stepper.cpp` — arms a real DR0-DR3 hardware breakpoint / sets EFLAGS.TF on a guarded decoy; must demonstrate signals **154, 161** fire (foreign-resolver + uniform-cadence burst observed) and the histogram is shipped, not locally banned.
- `bypass-tests/win/timing/foreign_veh.cpp` — installs a foreign first-chain VEH (unsigned module) ahead of the AC; must demonstrate signal **154** flags a non-attested resolver image.
- `bypass-tests/win/timing/time_hook.cpp` — IAT/inline-hooks `GetTickCount64`/`QueryPerformanceCounter` to dilate time; must demonstrate signal **157** detects sustained shared-page-vs-API ratio drift.
- `bypass-tests/win/timing/exc_hook.cpp` — a present debugger / exception-port interposer that swallows-and-reinjects the decoy 0xCC; must demonstrate signal **159** detects the multi-modal latency inflation even with correct re-injection.
- `bypass-tests/win/timing/tsc_offset_vm.cpp` — runs the probe under a TSC-offsetting/RDTSC-trapping VM context; must demonstrate signal **155** reports effective-freq-vs-RDTSC skew AND that it is tagged VM-context (not an autonomous ban).
- `bypass-tests/linux/timing/hw_bp_perf.cpp` — opens a `PERF_TYPE_BREAKPOINT` perf event on a guarded symbol from outside the game's thread group; must demonstrate signal **158** census counts it (and audit-only on Game Mode).
- `bypass-tests/macos/timing/lldb_exc_port.cpp` — installs a foreign Mach exception port for EXC_BREAKPOINT (LLDB-style); must demonstrate signal **160** flags the non-self/non-system owner AND that the ES event was still replied to (guardrail #7 assertion in the test).

Each bypass test asserts the sensor produced the expected raw report field; none assert a local ban (ban authority is server-side).

---

## Sequencing

1. **Schema + contract first.** Add `HK_EVENT_TIMING_FREQ_SKEW` + `hk_event_timing_freq_skew` (16 bytes) to `event_schema.h`, bump `HK_EVENT_SCHEMA_VERSION → 3`; add `server/telemetry/src/timing.rs` + `SCHEMA_VERSION` bump; add the data-categories.md section. This unblocks everything downstream and is purely additive/testable.
2. **`timing_signals.h` + per-signal headers.** Define the POD result structs and the aggregator surface. No logic yet (guardrail #14 — logic lands under TDD).
3. **Cross-platform core sensors (no OS hooks):** signal 156 watchdog (depends on `platform/` clock intrinsic seam — add `hk_rdtscp_aux()` there first) and signal 162 CPUID fan. Lowest risk, host-testable classifiers.
4. **Windows VEH/guard-page family:** 154, 159, 161 share the first-chain-VEH + decoy-PAGE_GUARD machinery — land the shared VEH install/teardown helper once, then the three samplers on top. 157 (shared-page clock) is independent and can land in parallel.
5. **Kernel 155 (`TimingProbe.c`)** + `timing_kernel_correlate.cpp` drain path — gated on resolving the IRQL/CPU-pin uncertainty flag below. Depends on the schema from step 1.
6. **Linux 158** under the eBPF gate; **macOS 160** under the ES gate — both depend only on step 1's schema, can land last and in parallel, both audit-only on their gated platforms.
7. **Bypass tests** land with each sensor (merge gate — not deferred).

---

## Risks & UNCERTAINTY FLAGS

- **FLAG (signal 155, Windows kernel IRQL):** The exact IRQL at which to run the APERF/MPERF busy-loop and the CPU-pinning primitive (`KeSetSystemAffinityThreadEx` / `KeRaiseIrql` to what level / DPC vs passive) is **not certain**. Running the timing window without pinning lets the scheduler migrate the loop across cores and corrupt the APERF/MPERF ratio; raising IRQL too high risks watchdog timeouts/BSOD. Per guardrail #13 this must be resolved (WDK docs / a kernel dev) before `TimingProbe.c` touches `__readmsr` — do not guess.
- **FLAG (signal 160, macOS ES):** Whether `task_get_exception_ports` can be called against a *foreign* (game) task from within an EndpointSecurity client, and which task port the `es_message_t` process context legitimately yields, is **uncertain**. ES clients are not general task-port holders; this may require a different API (e.g. resolving via the audit token / `task_name_for_pid`) or may not be possible without additional entitlement. Resolve before implementing; the ES reply (guardrail #7) must never be gated on this audit regardless.
- **FLAG (signal 156, macOS affinity):** macOS provides no hard thread-to-core pinning (only `thread_policy_set` affinity *hints*). The sibling-watchdog cross-check's core-migration discard logic is weaker on macOS; the `IA32_TSC_AUX` core-id check partially compensates but the watchdog may have elevated FP there. Treat macOS 156 as best-effort and weight it lower server-side.
- **FP-by-design (155, 162):** VBS/HVCI on by default on Win11, WSL2, Hyper-V, Credential Guard, cloud-gaming and VDI all produce the same TSC/CPUID-virtualization skew. Both signals are **VM-context tags only**, correlated server-side with the hypervisor-present bit — never an autonomous ban. Enforced by the `tsc_offset_vm` bypass test asserting tag-not-ban.
- **FP (154, 159, 161):** Overlays/IME/.NET/GPU drivers (154), crash reporters/Sentry/WER/AV (159), and JIT/heavy-contention re-entry (161) inflate these signals benignly. All three require the gating conditions in the catalog (unsigned/non-attested resolver + live DR6 bit; multi-modal step-change after per-machine baseline; uniform-cadence statistical signature + TF/DR6) and report histograms for server-side modeling rather than deciding locally.
- **Signing/toolchain:** signals 158 (eBPF) and 160 (ES SysExt) ride on the already-flagged locked-decision gates — eBPF default OFF, ES default OFF pending the Apple EndpointSecurity entitlement. No new signing requirement introduced by this plan, but the macOS path remains entitlement-blocked.
