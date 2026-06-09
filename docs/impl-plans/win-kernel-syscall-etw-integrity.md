# Windows Kernel — Syscall / ETW / PatchGuard Surface Integrity — Implementation Plan

**Scope:** read-only kernel sensors that bounds-check and tamper-scan the x64
syscall dispatch surface (SSDT, shadow SSDT, LSTAR MSR, syscall-entry prologue,
IDT) and the kernel ETW telemetry surface (ETW-TI provider liveness, kernel
logger-session census, infinity-hook perf-trace callback). Every sensor only
*reads and bounds-checks* kernel pointers/globals against module image ranges
and a boot baseline, then reports anomalies to the server. **No table writes, no
MSR writes, no hooks installed, no enforcement in-kernel.** The server scores and
bans.

**Catalog signals covered:** 208 (KiServiceTable/SSDT entry bounds), 209 (shadow
SSDT / W32pServiceTable bounds), 210 (IA32_LSTAR MSR entry validation), 211
(infinity-hook perf-trace callback validation), 212 (ETW-TI provider liveness),
213 (syscall-entry prologue tamper scan), 214 (IDT handler bounds), 215 (kernel
ETW logger-session census), 216 (KeServiceDescriptorTable base-swap detection).

These extend the existing capture-only KMDF driver (`kernel/win/`). They reuse
the SPSC ring → `HK_IOCTL_DRAIN_EVENTS` bridge already in place and the
`HK_EVENT_INTEGRITY_FINDING` event type + scan orchestrator introduced by the
sibling plan `docs/impl-plans/win-kernel-driver-integrity.md`. The only new wire
surface is additional `HK_INTEGRITY_*` finding codes (no new event type, no ring
resize) plus reuse of the `HK_IOCTL_INTEGRITY_RESCAN` control IOCTL.

> **Coordination note (overlap with the sibling plan).** The driver-integrity
> plan's signal 35 (`SsdtIntegrity.c`) already decodes `KiServiceTable` for a
> range check, and the catalog `Horkos slot` for several of these signals names
> `kernel/win/src/SyscallIntegrity.c (new)` and a `HK_DEVICE_CONTEXT.SsdtBaseline`
> field. **This plan owns `SyscallIntegrity.c`/`EtwIntegrity.c` and the
> `SsdtBaseline` field**; the per-entry KiServiceTable range check (208) is the
> canonical implementation and the sibling plan's signal-35 stub should call into
> `HkSsdtValidate` here rather than duplicate the decode. This must be resolved in
> sequencing (see §Sequencing) so the two PRs do not both add a KiServiceTable
> decoder.

---

## New files

All paths honor guardrail #1 (platform code stays under `kernel/win/`, no raw
`_WIN32`/`__APPLE__`/`__linux__`; conditional code keys on `HK_PLATFORM_WINDOWS`),
#3 (module comment on every file), #4 (kernel and userspace never share a TU —
there is no user-mode companion here; every sensor is kernel-only and emits
through the existing ring).

| Path | Role | Module-comment summary |
|---|---|---|
| `kernel/win/src/SyscallIntegrity.c` | Signals 208, 209, 210, 213, 214, 216. Decode + bounds-check the syscall dispatch surface: native SSDT entries, shadow SSDT entries, LSTAR MSR per-CPU, syscall-entry prologue bytes vs on-disk, IDT gates per-CPU, and the SSDT descriptor base/limit vs boot baseline. Read-only. | Role: x64 syscall/IDT dispatch-surface integrity scan (read-only bounds + prologue + MSR checks). Target: Windows kernel (KMDF). Interface: implements `HkSsdtValidate`/`HkShadowSsdtValidate`/`HkLstarValidate`/`HkSyscallPrologueScan`/`HkIdtValidate`/`HkSsdtBaselineCheck` from `horkos_kernel.h`; emits `HK_EVENT_INTEGRITY_FINDING`. |
| `kernel/win/src/EtwIntegrity.c` | Signals 211, 212, 215. Validate the kernel ETW telemetry surface: ETW-TI provider registration + consumer keepalive liveness (212), kernel logger-session census vs boot baseline (215), and the infinity-hook perf-trace callback bounds check (211). Read-only. | Role: kernel ETW provider/logger-session integrity + infinity-hook probe. Target: Windows kernel (KMDF). Interface: implements `HkEtwTiLiveness`/`HkEtwSessionCensus`/`HkInfinityHookProbe`; emits `HK_EVENT_INTEGRITY_FINDING`. Keepalive counter coordinates with `Notify.c`. |
| `kernel/win/src/KernelImageMap.c` | Per-scan cache mapping `ntoskrnl`/`hal`/`win32k*` image ranges (base..base+SizeOfImage) and the on-disk `ntoskrnl` `.text` view, consumed by 208/209/211/213/214. Built once per scan via `ZwQuerySystemInformation(SystemModuleInformation)`. | Role: kernel image-range + on-disk `.text` map (shared scan cache). Target: Windows kernel (KMDF). Interface: `HkKernelImageMapBuild`/`HkKernelImageResolve`/`HkKernelImageMapFree`. If the sibling plan's `ModuleMap.c` lands first, this file is a thin adapter over it (see Sequencing). |
| `kernel/win/include/horkos_kernel.h` (extend) | Declare the new entry points, the `SsdtBaseline`/`EtwBaseline` snapshot structs in `HK_DEVICE_CONTEXT`, and the per-CPU IPI result struct. | (existing header) kernel-private declarations only; no platform headers beyond the `ntddk.h`/`wdf.h` it already pulls. |
| `kernel/win/src/Notify.c` (extend) | Add the ETW-TI consumer keepalive counter (signal 212) that the existing notify path bumps on each TI event, read by `HkEtwTiLiveness`. | (existing file) add a `volatile LONG64 EtwTiKeepalive` bump; no new TU. |

The scan itself is driven by the **existing PASSIVE_LEVEL scan orchestrator**
(`HkIntegrityScan.c`, introduced by the sibling plan). This plan adds no second
work item; its sensors register as additional fan-out targets of that
orchestrator. The per-CPU reads (210 LSTAR, 214 IDT) are dispatched from the
work item via `KeIpiGenericCall`, which raises to IPI level *only for the brief
read* and returns — see §Mechanism for the IRQL discipline.

---

## Interfaces & data structures

### Reused event type (no new wire type)

Findings flow through the `HK_EVENT_INTEGRITY_FINDING` event type and the
`hk_event_integrity_finding` payload **already defined by the sibling
driver-integrity plan**:

```c
typedef struct hk_event_integrity_finding {
    uint32_t signal_id;   /* Catalog number — here 208..216. */
    uint32_t finding;     /* HK_INTEGRITY_* code (see below). */
    uint64_t detail;      /* Signal-specific, ALWAYS masked: image-relative
                             offset, per-CPU index in the low bits, an enabled-
                             provider delta bitmask, or a truncated/base-subtracted
                             address. NEVER a raw kernel pointer (KASLR hygiene). */
} hk_event_integrity_finding;     /* 16 bytes — fits HK_EVENT_PAYLOAD_MAX. */
```

It is 16 bytes, so `HK_EVENT_PAYLOAD_MAX` stays 16, `hk_event_record` stays 40,
and every existing `HK_STATIC_ASSERT` in `ioctl.h` holds unchanged. **No
`ioctl.h` size change, no ring resize.**

> If this plan's PR lands *before* the sibling plan, this PR introduces
> `HK_EVENT_INTEGRITY_FINDING = 5`, the schema bump `HK_EVENT_SCHEMA_VERSION`
> 2u→3u, the payload struct, and the `HK_STATIC_ASSERT(... == 16)`. Whichever
> PR is first owns the additive change; the second rebases onto it. Decided in
> §Sequencing.

### New finding-code constants

Appended in `sdk/include/horkos/event_schema.h` next to the payload, in a range
disjoint from the sibling plan's `0x01..0x0A` (signals 28–36):

```c
/* Syscall / ETW / PatchGuard surface integrity (signals 208..216). */
#define HK_INTEGRITY_SSDT_ENTRY_OOI      0x20u  /* 208 native SSDT entry out-of-image */
#define HK_INTEGRITY_SHADOW_SSDT_OOI     0x21u  /* 209 shadow SSDT entry out-of-image */
#define HK_INTEGRITY_LSTAR_MISMATCH      0x22u  /* 210 IA32_LSTAR != KiSystemCall64[Shadow] */
#define HK_INTEGRITY_LSTAR_CPU_DIVERGE   0x23u  /* 210 per-CPU LSTAR divergence */
#define HK_INTEGRITY_INFINITY_HOOK       0x24u  /* 211 perf-trace callback out-of-image */
#define HK_INTEGRITY_ETWTI_DOWN          0x25u  /* 212 ETW-TI handle nulled / disabled */
#define HK_INTEGRITY_ETWTI_NO_KEEPALIVE  0x26u  /* 212 consumer keepalive stale (version-independent half) */
#define HK_INTEGRITY_SYSCALL_PROLOGUE    0x27u  /* 213 KiSystemCall64 prologue byte delta */
#define HK_INTEGRITY_IDT_OOI             0x28u  /* 214 IDT gate handler out-of-image */
#define HK_INTEGRITY_ETW_SESSION_SUPPR   0x29u  /* 215 security provider/session disabled vs baseline */
#define HK_INTEGRITY_SSDT_BASE_SWAP      0x2Au  /* 216 ServiceTableBase/Limit changed from baseline */

/* Build-fragility outcome (catalog FP gate): every signal above can resolve to
 * "unverifiable" on an unknown build rather than false-positive. Carried as a
 * separate code so the server weights it as no-signal, not as clean. */
#define HK_INTEGRITY_UNVERIFIABLE        0x2Fu
```

### Control IOCTL

Reuses `HK_IOCTL_INTEGRITY_RESCAN` (`0x803`) from the sibling plan — no new
function code. If this plan lands first, it adds that code to `ioctl.h`.

### `HK_DEVICE_CONTEXT` additions (baselines)

These are *snapshots taken at arm time* and re-read on each scan; they are not
wire-visible. Declared in `horkos_kernel.h`:

```c
typedef struct _HK_SSDT_BASELINE {
    PVOID  ServiceTableBase;     /* KeServiceDescriptorTable.Base at arm time (216). */
    ULONG  ServiceLimit;         /* KeServiceDescriptorTable.Limit at arm time (216). */
    PVOID  ShadowServiceTableBase;
    ULONG  ShadowServiceLimit;
    PVOID  ExpectedLstar;        /* &KiSystemCall64 or ...Shadow under KVA-shadow (210). */
    UCHAR  PrologueBytes[32];    /* Stable-window bytes of KiSystemCall64 (213). */
    ULONG  PrologueLen;          /* Bytes captured; 0 => prologue check unverifiable. */
    BOOLEAN Valid;               /* FALSE => emit HK_INTEGRITY_UNVERIFIABLE, not a hook. */
} HK_SSDT_BASELINE;

typedef struct _HK_ETW_BASELINE {
    /* Boot-time enabled-provider census for the security-relevant providers
     * Horkos depends on (NT Kernel Logger, ETW-TI). Identified by provider GUID,
     * not by unexported global, so the baseline half is version-independent. */
    ULONG    SecurityProviderMask;  /* Bit per tracked provider, enabled at boot. */
    BOOLEAN  EtwTiHandlePresent;    /* EtwThreatIntProvRegHandle non-null at arm (offset-resolved). */
    BOOLEAN  Valid;
} HK_ETW_BASELINE;
```

Added to `HK_DEVICE_CONTEXT` after `ObRegistrationHandle`. `WDF_DECLARE_CONTEXT_TYPE`
layout grows internally only — no wire struct, no `HK_STATIC_ASSERT` affected.
The `EtwTiKeepalive` counter lives in the context too (read by 212).

Per-CPU IPI result struct (stack/pool, not wire):

```c
typedef struct _HK_PERCPU_READ {
    ULONG64 Lstar[64];           /* One slot per processor; 64 caps current x64. */
    ULONG64 IdtHandler[64][20];  /* First N gates per CPU we bounds-check (#PF/#DB/#BP...). */
    ULONG   ProcessorCount;
} HK_PERCPU_READ;
```

### Server-side mirror (Phase 2 Rust)

The existing `HK_EVENT_INTEGRITY_FINDING` serde mirror in `server/telemetry`
needs only the new `finding`-code constants added to its scoring map; no new
struct. Guardrail #8: `thiserror` decode error type, no `unwrap()` outside tests;
an unknown `finding` code decodes to a quarantine variant, never a panic. Scoring
weights per code live in ban-engine config (e.g. `LSTAR_MISMATCH` is
high-confidence; `INFINITY_HOOK`/`ETW_SESSION_SUPPR` are medium per catalog FP
risk; `UNVERIFIABLE` weights as no-signal).

### Guardrail #11 — `server/api/data-categories.md` (same PR)

The three fields (`signal_id`, `finding`, `detail`) are already declared by the
sibling plan's section "2b. Kernel driver/module integrity findings (Windows)".
This plan **broadens that same section** (same PR as the wire change) to state
that `signal_id` now also ranges 208..216 and that `detail` for these signals
carries a per-CPU index / enabled-provider delta bitmask / image-relative offset
/ base-subtracted address — never a raw kernel pointer. No new row schema; the
existing row covers the three fields, the note is updated so no undeclared field
ships.

---

## Mechanism implementation notes

Shared safety rules (guardrails #5, #13): all kernel C uses safe string/memory
functions (`RtlStringCch*`, bounded `RtlCopyMemory`); every `NTSTATUS` and every
`Zw*`/`Ke*`/`Etw*` return is checked, and a failure aborts that sensor cleanly —
emit `HK_INTEGRITY_UNVERIFIABLE` or nothing rather than garbage. `__try/__except`
wraps every walk that dereferences an externally-controlled pointer (IDT/SSDT
decode, perf-trace callback chain). All non-IPI work runs from the existing
**single PASSIVE_LEVEL work item**; the only raised-IRQL code is the brief
per-CPU read inside `KeIpiGenericCall` (signals 210, 214). **Read-only
throughout — no `__writemsr`, no SSDT/IDT writes** (this would itself trip
PatchGuard and is explicitly out of scope).

**Signal 208 — KiServiceTable (SSDT) entry bounds (`HkSsdtValidate`).** Resolve
`KeServiceDescriptorTable` (exported). On x64 each entry is a 4-byte
sign-extended offset packed in the high bits of the table dword: decode
`target = (LONG64)(table[i] >> 4) + (ULONG_PTR)ServiceTableBase`
(the `>> 4` packed form per catalog). Bounds-check each decoded target against
the `ntoskrnl` image range from `KernelImageMap`. Out-of-image ⇒
`HK_INTEGRITY_SSDT_ENTRY_OOI`, `detail` = entry index. **Build-fragility gate:**
the packed-offset decode and the `ServiceLimit` count are per-build; if the build
is unrecognized (limit out of expected band, decode sanity fails), emit
`HK_INTEGRITY_UNVERIFIABLE` — never false-positive (catalog FP gate). No table
writes.

**Signal 209 — Shadow SSDT / W32pServiceTable bounds (`HkShadowSsdtValidate`).**
`KeServiceDescriptorTableShadow` is **not exported**. The shadow descriptor must
be read from a GUI-thread context (KTHREAD with non-null `Win32Thread`); the
catalog calls for `KeStackAttachProcess` into a known GUI process (e.g. csrss/the
game window owner) then decoding `W32pServiceTable` as in 208 and bounds-checking
against the win32k module range. **UNCERTAINTY (flag):** locating
`KeServiceDescriptorTableShadow` and the per-build `W32pServiceTable` layout is
undocumented/version-fragile; `KeStackAttachProcess`/`KeUnstackDetachProcess`
must be perfectly paired (a missed detach corrupts the thread). **Ship the native
208 half first; 209 is default-OFF and emits `HK_INTEGRITY_UNVERIFIABLE` on any
unknown win32k layout.** See Risks.

**Signal 210 — IA32_LSTAR MSR (`HkLstarValidate`).** `KeIpiGenericCall` runs a
callback on every processor at IPI level; in it, `__readmsr(0xC0000082)` into the
per-CPU `HK_PERCPU_READ.Lstar[cpu]`. Back at PASSIVE_LEVEL compare each against
the expected entry: `&KiSystemCall64`, or `&KiSystemCall64Shadow` when KVA-shadow
is active. Mismatch ⇒ `HK_INTEGRITY_LSTAR_MISMATCH`; any per-CPU divergence ⇒
`HK_INTEGRITY_LSTAR_CPU_DIVERGE`, `detail` = CPU index. **IRQL/safety:** the IPI
callback must do *nothing* but the MSR read and a store — no allocation, no
logging, no lock that could be held at lower IRQL (all deadlock at IPI level).
Resolving `KiSystemCall64`/`...Shadow` addresses (both unexported) and detecting
KVA-shadow state is the fragile part. **UNCERTAINTY (flag):** address resolution
of `KiSystemCall64[Shadow]` — see Risks; on an unknown build emit
`HK_INTEGRITY_UNVERIFIABLE`. The catalog explicitly says "run the IPI off the hot
path" — it is scheduled from the periodic work item, never per-syscall.

**Signal 211 — Infinity-hook perf-trace callback (`HkInfinityHookProbe`).** The
catalog targets `HalpPerfInterrupt` and the `WMI_LOGGER_CONTEXT` trace-clock
callback, bounds-checked against `ntoskrnl`/`hal`. **UNCERTAINTY (flag,
catalog-acknowledged medium FP):** `WMI_LOGGER_CONTEXT` internals and
`EtwpDebuggerData` are undocumented and shift across builds. Plan ships only the
*version-independent corroboration*: detect whether circular-kernel-trace /
high-frequency perf logging was silently enabled (a precondition of the
technique) and flag a callback target outside *any signed image* only when the
struct layout is recognized; otherwise `HK_INTEGRITY_UNVERIFIABLE`. Gate by the
known-tracing-session census (signal 215) so xperf/WPR do not false-positive.
Default-OFF until the struct walk is validated. See Risks.

**Signal 212 — ETW-TI provider liveness (`HkEtwTiLiveness`).** Two halves:
(a) **handle read** — `EtwThreatIntProvRegHandle` is an unexported global; if
resolvable per build, confirm non-null and enable-mask set; a nulled handle ⇒
`HK_INTEGRITY_ETWTI_DOWN`. (b) **keepalive** (version-independent, weighted
higher per catalog) — Horkos's own ETW-TI consumer bumps
`HK_DEVICE_CONTEXT.EtwTiKeepalive` on each TI ReadVm/WriteVm event (the bump is
added in `Notify.c`); `HkEtwTiLiveness` checks the counter advanced within the
expected interval, else `HK_INTEGRITY_ETWTI_NO_KEEPALIVE`. The keepalive half
needs no unexported global, so it is the default-ON half; the raw-handle half is
default-OFF/offset-gated and emits `HK_INTEGRITY_UNVERIFIABLE` on unknown builds.
**Note:** whether the kernel ETW-TI feed is consumed in-kernel or via a user-mode
consumer affects where the keepalive is bumped — flagged in Risks.

**Signal 213 — Syscall-entry prologue scan (`HkSyscallPrologueScan`).** Capture a
*stable-window* of `KiSystemCall64`/`KiSystemServiceStart` bytes at arm time into
`HK_SSDT_BASELINE.PrologueBytes` and re-compare on each scan (in-memory vs
in-memory baseline), OR compare against the on-disk `ntoskrnl` `.text` mapped by
`KernelImageMap`. **FP gate (catalog medium):** the kernel legitimately patches
itself at boot (retpoline/Spectre thunks, KVA-shadow, hotpatch); a naive
disk-vs-memory diff false-positives. Plan restricts the compared window to bytes
known-stable across those mitigations (the catalog's "restrict the window"
option) rather than attempting full reloc/hotpatch normalization. On-disk read is
**PASSIVE_LEVEL only** (`ZwCreateFile`/`ZwReadFile` in the work item; file I/O at
raised IRQL is illegal). A non-mitigation byte delta ⇒
`HK_INTEGRITY_SYSCALL_PROLOGUE`, `detail` = image-relative offset of first delta.
**UNCERTAINTY (flag):** the stable-window selection is build-sensitive; ship
default-OFF, report-only until validated against a clean-machine corpus.

**Signal 214 — IDT handler bounds (`HkIdtValidate`).** Per-CPU read via
`KeIpiGenericCall`: `__sidt` to get the IDTR, then walk each `KIDTENTRY64`,
reconstruct the 64-bit handler (`OffsetLow | OffsetMiddle<<16 | OffsetHigh<<32`),
store into `HK_PERCPU_READ.IdtHandler[cpu][gate]`. At PASSIVE_LEVEL bounds-check
each against `ntoskrnl`/`hal` from `KernelImageMap`. Out-of-image gate ⇒
`HK_INTEGRITY_IDT_OOI`, `detail` = (cpu << 8 | gate). Per-CPU divergence is itself
reported. **IRQL/safety:** same IPI discipline as 210 — the callback only reads
IDTR + copies bytes, no allocation/lock. Catalog notes in-guest IDT handlers
still resolve into the kernel under a hypervisor, so out-of-image is
high-confidence. **UNCERTAINTY (flag):** reading the IDT base per-CPU safely —
prefer `__sidt` inside the IPI over poking the KPCR; KPCR layout is version-
fragile. Confirm before wiring.

**Signal 215 — ETW logger-session census (`HkEtwSessionCensus`).** Snapshot the
enabled security-relevant providers at boot into `HK_ETW_BASELINE.SecurityProviderMask`
(keyed by **provider GUID**, the version-independent identifier — NT Kernel
Logger, Microsoft-Windows-Threat-Intelligence). On each scan, query the logger
table (`NtTraceControl` `EtwQueryAllTraces` / `EVENT_TRACE_PROPERTIES`) and diff;
a disable of a provider Horkos depends on ⇒ `HK_INTEGRITY_ETW_SESSION_SUPPR`,
`detail` = provider bit. **FP gate (catalog medium):** profiling/EDR toggle ETW
constantly — alert only on disables of *our* dependency set, corroborated with
our own consumer losing keepalives (signal 212). **UNCERTAINTY (flag):** calling
`NtTraceControl`/`EtwQueryAllTraces` from kernel mode and the exact
`EVENT_TRACE_PROPERTIES` buffer sizing — confirm the kernel-callable surface
before wiring. Default-OFF until confirmed.

**Signal 216 — SSDT base-swap (`HkSsdtBaselineCheck`).** Snapshot
`ServiceTableBase` + `ServiceLimit` (and the shadow descriptor if 209 is
enabled) into `HK_SSDT_BASELINE` at arm time. On each scan re-read and confirm
the base still points into `ntoskrnl` and equals the baseline; a relocated base
or altered limit ⇒ `HK_INTEGRITY_SSDT_BASE_SWAP`, `detail` = masked
base-delta. Catalog: the descriptor base is stable across the OS lifetime, so
this is low-FP and pairs with 208 (a clone-table swap leaves per-entry checks
clean but moves the base). Read-only.

**Server (guardrail #8).** Ingest decoder for the new `finding` codes is fully
async on tokio, `thiserror` error type, no `unwrap()` outside tests; scoring
weights per code live in ban-engine config. `UNVERIFIABLE` is scored as
no-signal so build-fragility never produces a ban.

---

## Build wiring

- Add `SyscallIntegrity.c`, `EtwIntegrity.c`, `KernelImageMap.c` to
  `HK_DRIVER_SRC` in `kernel/win/CMakeLists.txt` and to `<ClCompile>` in
  `kernel/win/horkos.vcxproj` (the vcxproj is the source of truth for production
  signing).
- New CMake feature options (cached, documented in `docs/windows-build.md`),
  default tuned to the catalog FP/uncertainty profile:
  - `HK_WIN_SYSCALL_SSDT` — signal 208 + 216 — **default ON** (low FP; build-fragility gated to UNVERIFIABLE).
  - `HK_WIN_SYSCALL_LSTAR` — signal 210 — **default ON** (low FP; off-hot-path IPI).
  - `HK_WIN_SYSCALL_IDT` — signal 214 — **default ON** (low FP; off-hot-path IPI), *pending* `__sidt`/IPI confirmation.
  - `HK_WIN_SYSCALL_SHADOW_SSDT` — signal 209 — **default OFF** (unexported shadow table + KeStackAttachProcess pairing risk).
  - `HK_WIN_SYSCALL_PROLOGUE` — signal 213 — **default OFF** (boot self-patch normalization unproven).
  - `HK_WIN_ETW_TI` — signal 212 — **default ON for the keepalive half**, raw-handle half compiled but offset-gated to UNVERIFIABLE.
  - `HK_WIN_ETW_SESSION` — signal 215 — **default OFF** until kernel `NtTraceControl` surface confirmed.
  - `HK_WIN_ETW_INFINITYHOOK` — signal 211 — **default OFF** (undocumented WMI_LOGGER_CONTEXT).
- Each option maps to a `target_compile_definitions` so its sensor compiles to a
  no-op stub when OFF, keeping the driver linkable with any subset.
- `KernelImageMap.c` is always compiled (shared substrate); if the sibling plan's
  `ModuleMap.c` is present it becomes a thin adapter and is conditionally a no-op.
- Toolchain unchanged: WDK + MSVC `/kernel /GS /W4 /WX` (existing
  `kernel/win/CMakeLists.txt` flags satisfy the "every warning is an error"
  posture for kernel C — guardrail equivalent of #6 on the Windows side). No new
  libs (`KeIpiGenericCall`, `__readmsr`, `__sidt` are intrinsics/ntoskrnl
  exports).

---

## Test strategy

### Unit / host-buildable tests (guardrail #14: logic where testable)

- **Schema-pin tests** (host, no WDK): assert `sizeof(hk_event_integrity_finding)
  == 16`, `HK_EVENT_PAYLOAD_MAX == 16`, `sizeof(hk_event_record) == 40` still
  hold after the new finding-code constants. (No struct added, so these are the
  same pins; the test guards against an accidental payload widening.)
- **SSDT packed-offset decode** (pure arithmetic): host-side test of
  `target = (entry >> 4) + base` against known encoded values incl. negative
  offsets (sign extension) and limit-band sanity → UNVERIFIABLE path.
- **IDT handler reconstruction** (pure arithmetic): host-side test of
  `OffsetLow | OffsetMiddle<<16 | OffsetHigh<<32` from a synthetic `KIDTENTRY64`.
- **KernelImageMap resolve** factored into a pure function over
  `{base,size,name}` ranges and unit-tested host-side: in-range, gap,
  exclusive upper bound, empty map.
- **Keepalive staleness logic** (signal 212) factored into a pure
  `(last_count, now_count, interval) -> stale?` predicate, host-tested.
- **ETW provider-mask diff** (signal 215) as a pure
  `(baseline_mask, current_mask, dependency_mask) -> suppressed_bits` function,
  host-tested incl. the "non-dependency disable does NOT alert" FP gate.
- **Server decoder** Rust unit tests: each new `finding` code round-trips;
  `UNVERIFIABLE` scores as no-signal; unknown code → quarantine, never panic
  (guardrail #8).

### Bypass tests (guardrail #12 — merge gate; any change under `kernel/win/`
needs a corresponding bypass test under `bypass-tests/win/`)

Following the disabled-but-compiled pattern of `bypass-tests/win/byovd_load.cpp`
(compiles now, asserts activate when the Phase-5 signed/test-signed fixture
lands). New files under `bypass-tests/win/`, all added to
`bypass-tests/win/CMakeLists.txt`:

- `ssdt_entry_hook.cpp` — fixture repoints one `KiServiceTable` entry outside
  ntoskrnl; assert `HK_INTEGRITY_SSDT_ENTRY_OOI` fires and a clean table does
  NOT. Also assert an unknown-build fixture yields `HK_INTEGRITY_UNVERIFIABLE`,
  not a false positive.
- `ssdt_base_swap.cpp` — fixture redirects `ServiceTableBase` to a cloned,
  pre-hooked SSDT leaving original entries pristine; assert
  `HK_INTEGRITY_SSDT_BASE_SWAP` fires (proves 216 catches what 208 alone misses).
- `lstar_repoint.cpp` — fixture rewrites `IA32_LSTAR` on one CPU; assert
  `HK_INTEGRITY_LSTAR_MISMATCH` + `HK_INTEGRITY_LSTAR_CPU_DIVERGE` fire and a
  clean KVA-shadow box (expected = `KiSystemCall64Shadow`) does NOT false-positive.
- `idt_pf_hook.cpp` — fixture detours a #PF/#DB IDT gate out of image; assert
  `HK_INTEGRITY_IDT_OOI` fires with the right CPU/gate in `detail`.
- `syscall_prologue_patch.cpp` — fixture inline-patches `KiSystemCall64`; assert
  `HK_INTEGRITY_SYSCALL_PROLOGUE` fires AND a clean machine with retpoline/
  KVA-shadow/hotpatch in the window does NOT (boot-self-patch FP-gate proof).
- `etwti_teardown.cpp` — fixture nulls `EtwThreatIntProvRegHandle`; assert the
  keepalive half (`HK_INTEGRITY_ETWTI_NO_KEEPALIVE`) fires even when the raw
  handle read is unverifiable (proves the version-independent half stands alone).
- `etw_session_disable.cpp` — fixture stops a Horkos-dependency provider; assert
  `HK_INTEGRITY_ETW_SESSION_SUPPR` fires, but stopping an unrelated profiling
  session does NOT (dependency-set FP gate).
- `infinity_hook_probe.cpp` — fixture enables the perf-trace callback technique;
  assert `HK_INTEGRITY_INFINITY_HOOK` fires only when the struct layout is
  recognized, else `HK_INTEGRITY_UNVERIFIABLE`; xperf/WPR tracing alone does NOT
  fire (census FP gate).
- `shadow_ssdt_hook.cpp` — fixture hooks a `W32pServiceTable` entry; assert
  `HK_INTEGRITY_SHADOW_SSDT_OOI` fires (Phase-5, gated on the shadow-table
  resolution being agreed).

Each ships disabled (compiled no-op returning success) until the Phase-5
signed-fixture driver target exists, matching the repo convention. The merge gate
is satisfied by their presence + compile.

---

## Sequencing

0. **Resolve the sibling-plan overlap FIRST.** Decide which PR owns
   `HK_EVENT_INTEGRITY_FINDING` (= 5), the schema bump 2→3, the payload struct,
   `HK_IOCTL_INTEGRITY_RESCAN`, `HkIntegrityScan.c`, and `ModuleMap.c`. Default:
   the sibling `win-kernel-driver-integrity` plan lands that substrate; this plan
   rebases onto it, adds only the `0x20..0x2F` finding codes, `SyscallIntegrity.c`,
   `EtwIntegrity.c`, and reuses `ModuleMap.c` via the `KernelImageMap.c` adapter.
   The sibling plan's signal-35 KiServiceTable stub is replaced by a call into
   `HkSsdtValidate` (208) here — no duplicate decoder.
1. **Wire codes + server (host-testable, no kernel).** Add the `0x20..0x2F`
   finding codes to `event_schema.h`, the server scoring-map entries + decoder
   tests, and the `data-categories.md` note broadening (guardrail #11, same PR).
2. **KernelImageMap + baseline snapshots.** `KernelImageMap.c` (or adapter), the
   `HK_SSDT_BASELINE`/`HK_ETW_BASELINE` context fields, arm-time snapshot in
   `DriverEntry`, host-side map/decode/diff unit tests. No sensors enabled.
3. **Low-risk default-ON sensors:** 208+216 (SSDT entry + base swap, exported
   `KeServiceDescriptorTable` only), 210 (LSTAR via IPI), 212 keepalive half.
   Then 214 (IDT) **once `__sidt`/IPI safety is confirmed** (see Risks). Each
   lands with its bypass-test stub.
4. **Default-OFF sensors gated on uncertainty resolution**, ascending risk:
   213 (prologue, after stable-window validation), 215 (session census, after
   kernel `NtTraceControl` surface confirmed), 212 raw-handle half (after
   `EtwThreatIntProvRegHandle` offset strategy agreed), 211 (infinity-hook, after
   `WMI_LOGGER_CONTEXT` layout validated), 209 (shadow SSDT, last — unexported
   table + attach pairing).
5. **Phase 5:** signed test-fixture drivers activate the bypass-test assertions;
   209/211 enabled only if their undocumented surfaces are resolved safely.

Dependencies: 208/209/211/213/214 depend on `KernelImageMap` (step 2). 212's
keepalive half depends on the `Notify.c` counter bump. The server decoder (step
1) gates every finding being interpretable. The whole thing depends on the
sibling-plan substrate (step 0).

---

## Risks & UNCERTAINTY FLAGS

Per guardrail #13, flagged for the user **before any kernel code is written** — a
BSOD is worse than a delay. The catalog itself prefaces this domain noting the
topic "reads as offensive tooling"; these are read-only integrity checks, but
several depend on undocumented kernel internals that must not be guessed.

1. **Unexported address resolution (208 decode band, 210 `KiSystemCall64[Shadow]`,
   209 `KeServiceDescriptorTableShadow`/`W32pServiceTable`, 212
   `EtwThreatIntProvRegHandle`, 211 `WMI_LOGGER_CONTEXT`/`HalpPerfInterrupt`/
   `EtwpDebuggerData`).** None are officially exported. Resolving them requires
   per-build offset tables or pattern scanning — exactly the version-fragile
   territory the guardrail forbids guessing on. **Plan ships per-build offset
   tables with an explicit UNVERIFIABLE fallback** (`HK_INTEGRITY_UNVERIFIABLE`)
   on any unrecognized build, and **prefers the version-independent half** wherever
   one exists (212 keepalive over raw handle; 215 GUID-keyed provider mask; 210
   per-CPU divergence is meaningful even without the absolute expected value).
   FLAGGED — the offset-table strategy and its maintenance must be agreed before
   the raw-global reads are enabled. The keepalive/divergence/GUID halves can
   ship without resolving this.

2. **KVA-shadow expected-value selection (210).** Under KVA-shadow the expected
   LSTAR is `&KiSystemCall64Shadow`, otherwise `&KiSystemCall64`. Mis-detecting
   KVA-shadow state would false-positive on every clean machine. FLAGGED —
   confirm the KVA-shadow detection surface (and that both symbols are resolvable)
   before enabling 210's absolute-match check; the per-CPU *divergence* check is
   safe regardless and can ship first.

3. **IPI callback discipline (210, 214) — DEADLOCK/BSOD risk.** The
   `KeIpiGenericCall` broadcast function runs at IPI level on every processor; it
   must do nothing but `__readmsr`/`__sidt` + a store. Any allocation, lock
   acquisition, or paged access there deadlocks or bugchecks. FLAGGED — the IPI
   callbacks are reviewed for zero side effects before merge.

4. **`KeStackAttachProcess` pairing (209).** Every `KeStackAttachProcess` must be
   matched with `KeUnstackDetachProcess` on the same `KAPC_STATE`; an unbalanced
   or cross-thread detach corrupts the thread/bugchecks. FLAGGED — 209 stays
   default-OFF until the attach/detach lifetime is reviewed. Combined with the
   unexported shadow-table location, 209 is the highest-risk sensor here.

5. **Boot self-patch normalization (213).** The kernel legitimately patches
   `KiSystemCall64`/`KiSystemServiceStart` at boot (retpoline/Spectre thunks,
   KVA-shadow, hotpatch). A naive disk-vs-memory diff false-positives. Plan
   restricts to a known-stable byte window rather than full reloc/hotpatch
   normalization. FLAGGED — the stable window must be validated against a
   clean-machine corpus across mitigation states before 213 leaves report-only.

6. **Kernel-mode `NtTraceControl`/`EtwQueryAllTraces` surface (215).** Whether
   `EtwQueryAllTraces` is cleanly callable from kernel mode and the correct
   `EVENT_TRACE_PROPERTIES` buffer sizing is undocumented. FLAGGED — confirm the
   kernel-callable ETW logger-table query before wiring; default-OFF until then.

7. **ETW-TI consumer location (212).** Where the ETW-TI feed is actually consumed
   (in-kernel vs a user-mode consumer) determines where the keepalive counter is
   bumped and whether `Notify.c` is even the right home. FLAGGED — confirm the
   Horkos ETW-TI consumption architecture before wiring the keepalive.

8. **`WMI_LOGGER_CONTEXT` layout drift (211).** Medium FP per catalog; the struct
   is undocumented and shifts across builds. Default-OFF; ships only the
   census-corroborated, recognized-layout path with UNVERIFIABLE fallback.
   FLAGGED.

9. **PatchGuard interaction.** Every sensor is strictly read-only (no SSDT/IDT/
   MSR/table writes), so it does not itself trip PatchGuard. Any future
   "verify by self-test write" idea is explicitly OUT of scope. Conversely,
   detecting that PatchGuard *would have* bugchecked (e.g. an out-of-image SSDT
   entry on an HVCI box) is what makes these high-confidence — but Horkos never
   relies on triggering PatchGuard.

10. **KASLR leak hygiene.** `detail` must never carry a raw kernel pointer
    off-box: all address-derived details are image-relative offsets, base-
    subtracted deltas, or CPU/gate/provider indices. Confirm the server never
    logs an unmasked value (shared with the sibling plan's hygiene note).

11. **KPCR/IDTR read path (214).** Prefer `__sidt` inside the IPI over reading the
    KPCR for the IDT base; KPCR field layout is version-fragile. FLAGGED — confirm
    the `__sidt`-based path before enabling 214 (it is default-ON *pending* this).

No detection-efficacy or bypass-resistance claims are made here; those are
server-scored and out of scope for this kernel plan (guardrail #13).
