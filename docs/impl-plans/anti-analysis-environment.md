# anti-analysis-environment — Implementation Plan

**Scope:** Cross-platform analysis-tooling presence — read-only sensors that observe debugger/instrumentation residency on the host and inside the game process (hardware debug registers, kernel-debugger flags, inline/IAT/GOT hooks, dynamic-instrumentation runtimes, external ptrace/exception-port hijack, memory-editor host artifacts, single-step timing inflation). Clients sample and report only; all classification and ban authority is server-side. No tampering/injection/evasion code — only read-only inspection of the client's own process and host.

**Catalog signals covered:** 190, 191, 192, 193, 194, 195, 196, 197, 198 (`docs/detection-catalog.md` §`anti-analysis-environment`, lines 1981–2071).

Split by layer:
- **Usermode (`ac/src/anti_analysis/`):** 190 (HW debug register scan, Win), 192 (inline-hook prologue divergence, cross), 193 (IAT/GOT-PLT redirection, cross), 194 (Frida/DBI residency fingerprint, cross), 196 (Mach exception-port hijack, macOS `.mm`), 197 (memory-editor host fingerprint, Win), 198 (RDTSC/single-step timing variance, cross).
- **Kernel (`kernel/win/src/`):** 191 (KdDebuggerEnabled / kernel-debugger flag — KUSER_SHARED_DATA + `KdRefreshDebuggerNotPresent`, ring 0). Surfaced via the existing SPSC ring → `HK_IOCTL_DRAIN_EVENTS` bridge and the `hk_status` IOCTL.
- **Linux eBPF (`kernel/linux/bpf/src/`):** 195 (self-ptrace / external-tracer tripwire — BPF LSM `ptrace_access_check`/`ptrace_traceme` + extends the existing `sys_enter_ptrace` tracepoint in `tracepoints.bpf.c`).

The usermode correlator (`anti_analysis_collect.cpp`) drains the kernel ring (signal 191 on Windows) and folds the host-environment flag into the periodic anti-analysis report before upload. Signal 194 on Windows folds in the kernel handle-open records (existing `hk_event_handle_open` from `ObRegisterCallbacks`) to attribute which foreign process opened a handle to the game. Signal 197's driver attribution reuses the kernel driver whitelist (`kernel/win/src/Whitelist.c`). Server is the only classifier — the client ships raw register state / hook descriptors / module-attribution tuples / port-owner identities, never a verdict.

---

## New files

All usermode sensor `.cpp` live under `ac/src/anti_analysis/` (a `backends`-equivalent subtree for platform-specific sensors; guardrail #1 — every Windows-only API is gated behind `HK_PLATFORM_WINDOWS`, every macOS-only Mach/Security API behind `HK_PLATFORM_MACOS`, every Linux `/proc` read behind `HK_PLATFORM_LINUX`; the cross-platform PE/ELF/Mach parsing core dispatches through these). Kernel sensors live under `kernel/win/src/` / `kernel/linux/bpf/src/` and never share a TU with userspace (guardrail #4). Every file opens with the role / target-platform / interface module comment (guardrail #3).

| Path | Role | Module-comment summary |
|---|---|---|
| `ac/include/horkos/anti_analysis/anti_analysis_signals.h` | Declares the usermode anti-analysis sensor surface: one sampler per signal returning a fixed POD result; an `anti_analysis_collect_all()` aggregator; the `anti_analysis_report` envelope. | Role: usermode analysis-tooling-presence sensor interface. Target: Windows + Linux + macOS (cross core, platform-gated samplers). Interface: this header IS the anti-analysis sensor surface; `ac/src/anti_analysis/*.cpp` implement it; consumed by `ac/src/ac.cpp`. |
| `ac/include/horkos/anti_analysis/debug_registers.h` | Declares signal-190 per-thread DR0–DR3/DR7 scan sampler (Windows). | Role: hardware-debug-register occupancy interface. Target: Windows. Interface: implemented by `ac/src/anti_analysis/DebugRegisterScan.cpp`; aggregated via `anti_analysis_signals.h`. |
| `ac/include/horkos/anti_analysis/module_integrity.h` | Declares signal-192 inline-hook prologue divergence and signal-193 IAT/GOT-PLT redirection samplers; the shared on-disk-image mapping / module-VA-range resolver seam. | Role: in-memory-vs-on-disk module-integrity interface. Target: cross. Interface: implemented by `InlineHookScan.cpp` + `ImportRedirectScan.cpp`; shared loader/resolver in `module_map_*.cpp`. |
| `ac/include/horkos/anti_analysis/instrumentation.h` | Declares signal-194 dynamic-instrumentation residency fingerprint sampler (unbacked-RX thread starts, runtime export symbols, control-port listener). | Role: DBI/instrumentation-runtime residency interface. Target: cross. Interface: implemented by `InstrumentationResidency.cpp`. |
| `ac/include/horkos/anti_analysis/host_tools.h` | Declares signal-197 memory-editor/debugger host named-object + driver fingerprint sampler (Windows). | Role: host-resident analysis-tool fingerprint interface. Target: Windows. Interface: implemented by `HostToolFingerprint.cpp`; driver attribution via the kernel whitelist record. |
| `ac/include/horkos/anti_analysis/timing_variance.h` | Declares signal-198 fixed-block instruction-stream latency-envelope sampler (cross). | Role: single-step/trace timing-inflation interface. Target: cross. Interface: implemented by `TimingProbe.cpp`. |
| `ac/include/horkos/anti_analysis/mach_exception.h` | Declares signal-196 task exception-port owner audit (macOS). | Role: Mach exception-port hijack interface. Target: macOS. Interface: implemented by `MachExceptionPortScan.mm`; receiver attributed via `kernel/macos/es/EsClient.mm`. |
| `ac/src/anti_analysis/DebugRegisterScan.cpp` | Signal 190: `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)` + `Thread32First/Next`, `GetThreadContext(CONTEXT_DEBUG_REGISTERS)` per thread; reads Dr0–Dr3/Dr7; subtracts Horkos-owned DRs; cross-checks the kernel thread-create record set. | Role: HW-debug-register occupancy sensor. Target: Windows. Interface: implements `debug_registers.h`. |
| `ac/src/anti_analysis/InlineHookScan.cpp` | Signal 192: maps each loaded module's on-disk file read-only, applies relocations, compares first 16 prologue bytes of exports/critical fns against live VA; decodes leading branch opcode and resolves target vs owning-module VA range. | Role: inline-hook (trampoline) prologue-divergence sensor. Target: cross. Interface: implements `module_integrity.h` (192 half). |
| `ac/src/anti_analysis/ImportRedirectScan.cpp` | Signal 193: parses IAT/`IMAGE_DELAYLOAD_DESCRIPTOR` (PE) / `.rela.plt`+`.got` (ELF), reads each thunk, resolves the backing module + signing identity, flags foreign/unbacked targets. | Role: IAT/GOT-PLT redirection sensor. Target: cross. Interface: implements `module_integrity.h` (193 half). |
| `ac/src/anti_analysis/module_map_win.cpp` | Shared PE backend for 192/193: `CreateFileMapping`/`MapViewOfFile`, `VirtualQueryEx`+`GetMappedFileNameW`, `GetModuleInformation`, export/import directory walk. | Role: PE module-map + VA-range resolver backend. Target: Windows. Interface: backs `module_integrity.h`; Windows-gated. |
| `ac/src/anti_analysis/module_map_posix.cpp` | Shared ELF/Mach backend for 192/193/194: `mmap`, `/proc/self/maps`, `dladdr`, `mach vm_region_recurse`, ELF `.dynsym`/`.plt`/`.rela.plt` walk. | Role: ELF/Mach module-map + VA-range resolver backend. Target: Linux + macOS. Interface: backs `module_integrity.h` + `instrumentation.h`; POSIX-gated. |
| `ac/src/anti_analysis/InstrumentationResidency.cpp` | Signal 194: enumerates thread start addresses (`NtQueryInformationThread` / `/proc/self/task/*/stat` / `thread_get_state`+`proc_pidinfo`), flags starts in unbacked anon-RX mappings; scans module exports for runtime symbol names; checks `/proc/net/tcp` for the control-port listener. | Role: DBI/instrumentation residency fingerprint sensor. Target: cross. Interface: implements `instrumentation.h`. |
| `ac/src/anti_analysis/HostToolFingerprint.cpp` | Signal 197: `EnumWindows`+`RealGetWindowClassW` for known debugger window classes; `NtOpenDirectoryObject`/`NtQueryDirectoryObject` over `\Device` + `\GLOBAL??`; `EnumDeviceDrivers`+`GetDeviceDriverBaseNameW`; cross-checks the kernel driver whitelist. | Role: host-resident memory-editor/debugger fingerprint sensor. Target: Windows. Interface: implements `host_tools.h`; driver attribution via `kernel/win/src/Whitelist.c` records. |
| `ac/src/anti_analysis/TimingProbe.cpp` | Signal 198: times a fixed arithmetic block with `QueryPerformanceCounter`/`clock_gettime(CLOCK_MONOTONIC_RAW)`/`mach_absolute_time`; builds a per-sample delta distribution; reports median + tail inflation vs a clean-startup baseline. | Role: single-step/DBI timing-inflation sensor. Target: cross. Interface: implements `timing_variance.h`; clock seam via `platform/`. |
| `ac/src/anti_analysis/MachExceptionPortScan.mm` | Signal 196: `task_get_exception_ports(mach_task_self(), EXC_MASK_ALL, ...)`; resolves owning task via `pid_for_task`/`proc_pidpath`; reports receiver signing identity via `SecCodeCopySigningInformation`. | Role: Mach exception-port hijack sensor. Target: macOS. Interface: implements `mach_exception.h`; receiver attributed through `kernel/macos/es/EsClient.mm`. |
| `ac/src/anti_analysis/anti_analysis_collect.cpp` | Aggregator: runs every available sampler, drains the kernel ring (signal 191 on Windows) via the SDK IOCTL bridge, folds kernel handle-open records into 194 attribution, builds the `anti_analysis_report`. | Role: anti-analysis aggregator + kernel-record correlator. Target: cross (kernel drain Windows-only). Interface: implements `anti_analysis_collect_all()`; consumes `sdk/include/horkos/ioctl.h`. |
| `kernel/win/src/HostEnvProbe.c` | Signal 191 kernel sensor: reads `SharedUserData->KdDebuggerEnabled`, calls `KdRefreshDebuggerNotPresent()`, inspects `KdDebuggerNotPresent`/`KdDebuggerEnabled` globals; emits the host-environment flag (enabled-vs-actively-present distinguished). | Role: kernel-debugger presence sensor. Target: Windows kernel (KMDF). Interface: declared in `kernel/win/include/horkos_kernel.h`; emits via `HkRingEmit`; also raises a `hk_status` flag bit. |
| `kernel/linux/bpf/src/ptrace_lsm.bpf.c` | Signal 195: BPF LSM hooks `lsm/ptrace_access_check` + `lsm/ptrace_traceme` recording tracer→tracee task pairs (audit-only); reads `task_struct->ptracer_cred`; complements the `sys_enter_ptrace` tracepoint in `tracepoints.bpf.c`. | Role: external-tracer / self-ptrace tripwire sensor (CO-RE). Target: Linux eBPF (BPF LSM). Interface: shares `hk_ringbuf` (extern, repointed in `Loader.cpp`); never shares a TU with userspace. |
| `server/telemetry/src/anti_analysis.rs` | serde structs mirroring the anti-analysis report sub-payload on the periodic ingest plane; validation, `thiserror`, no `unwrap()`. | Role: server-side anti-analysis-posture ingest contract. Target: server. Interface: `mod anti_analysis` under `server/telemetry`; mirrors `anti_analysis_signals.h` field names. |
| `bypass-tests/win/anti_analysis/*`, `bypass-tests/linux/anti_analysis/*`, `bypass-tests/macos/anti_analysis/*` | Bypass tests (one per merge-gated sensor). See Test strategy. | Role: anti-analysis-sensor bypass merge gate (guardrail #12). Target: per-platform. Interface: drives the sensors and asserts the raw report field. |

Header additions (not new files): new kernel event type/payload in `sdk/include/horkos/event_schema.h` (signal 191) and one new `hk_status` flag bit in `sdk/include/horkos/ioctl.h`; a new BPF event tag + struct in `ptrace_lsm.bpf.c` mirroring the existing `tracepoints.bpf.c` constants; new anti-analysis sub-payload in `server/telemetry/src/schema.rs` (or the `anti_analysis.rs` submodule); new data-category rows in `server/api/data-categories.md` (guardrail #11).

---

## Interfaces & data structures

### Usermode sensor surface (`ac/include/horkos/anti_analysis/anti_analysis_signals.h`)

Plain POD result structs, fixed-size, no platform headers in the header (all platform calls live in the `.cpp`). Each sampler reports raw observations; no verdict. Variable-cardinality observations (hooked functions, suspicious threads, host tool hits) are reported as fixed-capacity arrays with a count, so the server gets bounded, validatable payloads. Sketch:

```c
typedef struct aa_debug_registers {        /* signal 190 */
    uint32_t threads_scanned;       /* threads enumerated */
    uint32_t threads_dr_nonzero;    /* threads with any non-Horkos DR set */
    uint32_t dr7_enable_mask_or;    /* OR of all threads' Dr7 L/G enable bits */
    uint32_t dr_slots_populated;    /* count of Dr0-Dr3 set, excluding own */
    uint32_t persistent_samples;    /* consecutive samples the state persisted */
    uint32_t kernel_thread_mismatch;/* threads seen by GetThreadContext absent from
                                       kernel thread-create record set */
} aa_debug_registers;

typedef struct aa_hook_hit {               /* one inline/import hook */
    uint64_t target_va;             /* hooked function VA */
    uint64_t trampoline_target_va;  /* branch target */
    uint32_t opcode_class;          /* 0=none,1=E9,2=FF25,3=push+ret,4=mov+jmp */
    uint32_t target_in_owning_mod;  /* 1 if target inside owning module range */
    uint32_t target_module_signed;  /* 1 if backing module signed */
    uint32_t target_module_backed;  /* 1 if backing region file-backed */
    char     target_module_name[64];/* resolved backing module basename */
} aa_hook_hit;

typedef struct aa_module_integrity {       /* signals 192 + 193 */
    uint32_t modules_scanned;
    uint32_t inline_hook_count;     /* 192: prologue divergences */
    uint32_t import_redirect_count; /* 193: foreign/unbacked IAT/GOT slots */
    uint32_t hit_count;             /* entries used in hits[] */
    aa_hook_hit hits[24];           /* fixed cap; overflow sets truncated flag */
    uint32_t truncated;
    uint32_t reserved;
} aa_module_integrity;

typedef struct aa_instrumentation {        /* signal 194 */
    uint32_t unbacked_rx_threads;   /* thread starts in anon-RX, not module-backed */
    uint32_t runtime_export_match;  /* modules exporting framework symbols */
    uint32_t control_port_listener; /* 1 if framework default port listening in tree */
    uint32_t jit_module_present;    /* 1 if a known-JIT module is loaded (FP context) */
    uint32_t confidence_tier;       /* 0=none,1=info(single),2=high(combined) */
    uint32_t reserved;
} aa_instrumentation;

typedef struct aa_host_tools {             /* signal 197 */
    uint32_t debugger_window_classes; /* known x64dbg/Olly/etc. window classes */
    uint32_t known_device_objects;    /* CE/ReClass device/symlink names present */
    uint32_t suspicious_drivers;      /* editor helper drivers loaded (e.g. DBK64) */
    uint32_t byovd_driver_match;      /* matched the kernel whitelist known-bad set */
    uint32_t opened_handle_to_game;   /* from kernel Ob records: editor opened a handle */
    uint32_t severity_tier;           /* 0=none,1=info,2=tool-present,3=handle-open */
} aa_host_tools;

typedef struct aa_timing_variance {        /* signal 198 */
    uint64_t baseline_median_ns;    /* clean-startup median over the fixed block */
    uint64_t live_median_ns;        /* current median */
    uint32_t inflation_factor_x100; /* live/baseline * 100 */
    uint32_t tail_inflation_x100;   /* p99 ratio * 100 */
    uint32_t sustained_samples;     /* samples the inflation persisted */
    uint32_t vm_or_cloud_ctx;       /* 1 if VM/cloud-gaming context already tagged */
} aa_timing_variance;

typedef struct aa_mach_exception {         /* signal 196 (macOS) */
    uint32_t foreign_port_owner;    /* 1 if any exc port owned by foreign task */
    uint32_t owner_apple_signed;    /* 1 if owner Apple-platform-signed */
    uint32_t owner_app_crash_sdk;   /* 1 if owner is the app's embedded crash SDK */
    uint32_t owner_pid;             /* receiver pid (0 = kernel default) */
    char     owner_signing_id[64];  /* SecCodeCopySigningInformation identity */
    uint32_t mask_breakpoint;       /* 1 if EXC_BREAKPOINT port is the foreign one */
    uint32_t reserved;
} aa_mach_exception;

typedef struct aa_kernel_dbg {             /* signal 191, folded from kernel ring */
    uint32_t kd_enabled;            /* SharedUserData->KdDebuggerEnabled */
    uint32_t kd_present;            /* !KdDebuggerNotPresent (actively attached) */
    uint32_t flags;                 /* HK_KDBG_* : boot_enabled_only vs live */
    uint32_t reserved;
} aa_kernel_dbg;

typedef struct anti_analysis_report {
    aa_debug_registers   dr;        /* 190 */
    aa_module_integrity  mods;      /* 192 + 193 */
    aa_instrumentation   instr;     /* 194 */
    aa_host_tools        host;      /* 197 */
    aa_timing_variance   timing;    /* 198 */
    aa_mach_exception    mach;      /* 196 */
    aa_kernel_dbg        kdbg;      /* 191 */
    uint32_t             sensors_ok;/* bitmask: which samplers ran on this platform */
} anti_analysis_report;
```

Each `anti_analysis_sample_*` returns one result by out-param plus an `HK_AC_*` status (reuse `ac.h` codes; samplers not available on the current platform return `HK_AC_NOT_IMPLEMENTED` and set their `sensors_ok` bit to 0). `anti_analysis_collect_all()` builds the report; `ac/src/ac.cpp` serializes it to the server.

### Kernel event-schema addition (`sdk/include/horkos/event_schema.h`)

Signal 191 is the only signal whose data must traverse the C99 kernel ring. Bump `HK_EVENT_SCHEMA_VERSION` (currently `2u`; note signal-155 in the timing-side-channels plan also claims the next bump — whichever lands first takes `3u`, the other rebases to `4u`; the two plans must coordinate the version number and the `hk_event_type` enum value at merge time). Append one event type (existing values never change):

```c
HK_EVENT_KERNEL_DBG_STATE = 5,  /* signal 191; value coordinates with timing plan */
```

**Payload-size constraint (load-bearing):** `ioctl.h` pins `HK_EVENT_PAYLOAD_MAX = 16u` and `HK_STATIC_ASSERT(sizeof(hk_event_record) == 40, ...)`. The new payload MUST be ≤ 16 bytes or every size pin in `ioctl.h` (`HK_EVENT_PAYLOAD_MAX`, `hk_event_record == 40`, `hk_drain_header`, `hk_status`, `hk_policy`) must be re-derived in lockstep on both kernel and userspace sides. Keep it exactly 16 bytes:

```c
typedef struct hk_event_kernel_dbg_state {  /* 16 bytes, signal 191 */
    uint32_t kd_enabled;     /* SharedUserData->KdDebuggerEnabled byte (0/1) */
    uint32_t kd_present;     /* 1 if KdDebuggerNotPresent == FALSE (live attach) */
    uint32_t flags;          /* HK_KDBG_* : boot_enabled_only, refresh_failed */
    uint32_t reserved;       /* must be zero */
} hk_event_kernel_dbg_state;

HK_STATIC_ASSERT(sizeof(hk_event_kernel_dbg_state) == 16,
    "hk_event_kernel_dbg_state size mismatch");
```

No change to `HK_EVENT_PAYLOAD_MAX` or `hk_event_record` size — the 16-byte ceiling is preserved, so `ioctl.h`'s asserts stay green.

### Status-flag addition (`sdk/include/horkos/ioctl.h`)

Signal 191 also surfaces as a sticky bit in the existing `hk_status` flags word so a status poll reports kernel-debugger presence without a full drain. Add (next free bit; `hk_status` layout/size unchanged — purely a new `#define`):

```c
#define HK_STATUS_FLAG_KDBG_PRESENT 0x00000008u  /* signal 191: live kernel debugger */
```

`hk_status` struct layout is untouched (the flag lives in the existing `flags` field), so `HK_STATIC_ASSERT(sizeof(hk_status) == 32, ...)` stays green.

### Linux BPF event addition (`ptrace_lsm.bpf.c`)

Signal 195 rides the existing `hk_ringbuf` (no kernel C-schema change — the BPF side uses its own tags, mapped to server types by `Loader.cpp`, exactly as `tracepoints.bpf.c` documents). Mirror the existing constant style and add a tag + struct:

```c
#define HK_EVENT_PTRACE_LSM  0x22u   /* BPF-side tag; loader maps to server type */

struct hk_bpf_ptrace_lsm_event {
    __u32 schema_version;   /* HK_SCHEMA_VERSION, mirrors tracepoints.bpf.c */
    __u32 event_tag;        /* HK_EVENT_PTRACE_LSM */
    __u64 timestamp_ns;
    __u32 tracer_pid;       /* tracer task pid */
    __u32 tracee_pid;       /* game/tracee task pid */
    __u32 ptracer_cred_uid; /* from task_struct->ptracer_cred (CO-RE) */
    __u32 lsm_hook;         /* 0=access_check, 1=traceme */
    char  tracer_comm[16];  /* tracer comm for server allowlisting */
};
```

The `sys_enter_ptrace` tracepoint already in `tracepoints.bpf.c` is extended only in that it is already capturing request + target pid; signal 195 adds the LSM corroboration in the new TU. The loader (`kernel/linux/userspace/Loader.cpp`) maps `HK_EVENT_PTRACE_LSM` onto the existing `hk_event_handle_open`-style server record (tracer→tracee with the ptrace request code in `access_mask`, as `data-categories.md` §2a already documents for the Linux eBPF path).

### Server ingest (`server/telemetry/src/anti_analysis.rs`)

JSON serde struct mirroring `anti_analysis_report` field names (this is the independent periodic plane, NOT byte-compatible with the C struct — same separation `schema.rs` documents for `TickPayload`). `Deserialize` + range/length validation returning `Result<_, thiserror::Error>`; no `unwrap()` outside `#[cfg(test)]` (guardrail #8). Fixed-length `hits[24]` arrives as a bounded `Vec`; validate `hit_count <= 24` and array length on deserialize rather than indexing blindly; reject out-of-range tier/factor fields. Bump `SCHEMA_VERSION` in `schema.rs`. All scoring (allowlist matching, severity tiering, combined-signal confidence for 194, baseline-vs-live for 198) is server-side.

### Telemetry fields → data-categories.md (guardrail #11)

Every new field above is telemetry leaving the client and MUST get a row in `server/api/data-categories.md` **in the same PR**. New section **"5. Analysis-tooling presence"** with rows for: `aa_debug_registers` (190 — DR occupancy counts, no raw addresses leave the client beyond owning-image attribution), `aa_module_integrity` incl. `aa_hook_hit` (192/193 — hooked-function VA, trampoline target, backing module name + signing status), `aa_instrumentation` (194 — unbacked-RX-thread count, runtime export match, control-port listener, JIT-context flag), `aa_host_tools` (197 — debugger window-class / device-object / driver hits, handle-to-game flag), `aa_timing_variance` (198 — baseline/live medians, inflation factors), `aa_mach_exception` (196 — exception-port owner pid + signing identity), and the kernel `aa_kernel_dbg`/`hk_event_kernel_dbg_state` fields (191 — `kd_enabled`/`kd_present`/flags). Source column: per-signal sensor; legal basis: legitimate interest — anti-cheat enforcement; retention default 90 days (precedent: §1/§2 rows). The Linux ptrace-LSM path reuses the existing §2a row (`requesting_pid`/`target_pid`/`access_mask` — already documents the truncated ptrace request code), plus a new row for `tracer_comm`/`ptracer_cred_uid`. The macOS `owner_signing_id` and Windows host-tool driver base names are new identifier-adjacent fields and get explicit rows. The reviewer rejects any undeclared field.

---

## Mechanism implementation notes

### Signal 190 — HW debug register scan (`DebugRegisterScan.cpp`, Windows)
`CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)` then `Thread32First`/`Thread32Next`, filtering to the game's PID. For each TID, `OpenThread(THREAD_GET_CONTEXT, ...)`, `CONTEXT ctx; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS; GetThreadContext(h, &ctx)`; read `ctx.Dr0..Dr3` and `ctx.Dr7`. Subtract any DR the client itself programs (the AC keeps a registry of its own armed DRs). **Race:** a thread can spawn between snapshot and scan; cross-check the enumerated TID set against the kernel driver's thread-create records (the kernel already emits process/thread notifications) so a freshly spawned thread cannot hide — `kernel_thread_mismatch` reports the delta. **Persistence gating:** sample repeatedly; report `persistent_samples`, never flag on a single transient DR (legit crash handlers / DRM packers set DRs briefly — catalog FP note). Entire TU behind `HK_PLATFORM_WINDOWS`. Report raw register state; server decides. Optional kernel corroboration via `PsGetContextThread` is **out of scope for this plan's kernel work** (the catalog lists it as a cross-check; if added it lands in `kernel/win/src/` under signal 190's own follow-up, not here) — flagged below.

### Signal 191 — KdDebuggerEnabled / kernel-debugger flag (`kernel/win/src/HostEnvProbe.c`, KMDF)
Read `SharedUserData->KdDebuggerEnabled` (the `KUSER_SHARED_DATA` mapping; the kernel-mode constant address, NOT the usermode `0x7FFE0000` shadow). Call `KdRefreshDebuggerNotPresent()` and read the exported `KdDebuggerNotPresent`/`KdDebuggerEnabled` globals to distinguish **enabled-in-boot-config** (`bcdedit /debug on`, `kd_enabled` set but `KdDebuggerNotPresent == TRUE`) from **actively attached** (`KdDebuggerNotPresent == FALSE`). Emit `HK_EVENT_KERNEL_DBG_STATE` via `HkRingEmit`; set `HK_STATUS_FLAG_KDBG_PRESENT` only on live attach. **Every `NTSTATUS` / return checked; safe string functions only (guardrail #5); kernel/userspace TUs never shared (guardrail #4).** **IRQL:** `KdRefreshDebuggerNotPresent` and the `KUSER_SHARED_DATA`/exported-global reads — confirm the IRQL constraint before calling on a probe path that may run at `DISPATCH_LEVEL` (the ring emit already runs there). **FLAG (below)** the exact IRQL of `KdRefreshDebuggerNotPresent` and whether reading `SharedUserData->KdDebuggerEnabled` from the driver is the supported access (vs an exported global) as uncertain — do not guess (guardrail #13). Report enabled-vs-present both ways so the server soft-flags enabled-but-absent and hard-flags actively-attached.

### Signal 192 — inline-hook prologue divergence (`InlineHookScan.cpp` + `module_map_*.cpp`)
For each loaded module: map its on-disk file read-only (`CreateFileMapping`/`MapViewOfFile` on Windows, `mmap` on POSIX), parse PE/ELF headers to find `.text` and the export/PLT addresses, apply base relocations to the on-disk copy, then `memcmp` the first 16 bytes of each target against the live in-memory copy read through the process's own VA. Classify any mismatch by decoding the leading opcode (`E9` rel-jmp, `FF 25` jmp `[rip]`, `push`+`ret`, `48 B8 mov rax,imm64`+`jmp rax`) and resolving the branch target against the owning module's VA range (`VirtualQuery`/`GetMappedFileNameW` on Windows, `/proc/self/maps` on Linux, `mach vm_region_recurse` on macOS). **Read-only by construction** — the on-disk mapping is `PAGE_READONLY`/`PROT_READ`, and the live read is a plain VA read; no patching. Report each divergence as an `aa_hook_hit` with the resolved target module name + signing status so benign overlays (Steam/Discord/RTSS/MSI AB, EDR agents — catalog medium-FP list) are server-side excludable, never hard-flagged. Cross-platform core; platform calls in `module_map_win.cpp` / `module_map_posix.cpp` behind the matching `HK_PLATFORM_*` (guardrail #1).

### Signal 193 — IAT/GOT-PLT redirection (`ImportRedirectScan.cpp` + `module_map_*.cpp`)
Parse `IMAGE_IMPORT_DESCRIPTOR` + `IMAGE_DELAYLOAD_DESCRIPTOR` (Windows) or `.rela.plt` + `.got` (Linux) to enumerate each import thunk; read the current pointer; resolve the backing module via `VirtualQueryEx`+`GetMappedFileNameW`/`GetModuleInformation` (Windows) or `dladdr`+`/proc/self/maps` (Linux). Flag entries whose backing module is not the documented exporter, is not file-backed, or is unsigned. Report the backing module's signing identity + name; the server allowlists Microsoft API-set hosts (`api-ms-win-*`), AppCompat shims, and signed vendor overlays, and tiers redirect-into-unbacked-memory as high vs redirect-into-signed-module as informational (catalog FP guidance). Shares the POSIX/Win module-map backend with 192. Read-only thunk reads; no writes.

### Signal 194 — Frida/DBI residency fingerprint (`InstrumentationResidency.cpp`)
Three combined observables (the catalog mandates combination — single signal is informational only): (a) enumerate thread start addresses — `NtQueryInformationThread(ThreadQuerySetWin32StartAddress)` (Windows), `/proc/self/task/*/stat` + `/proc/self/maps` (Linux), `thread_get_state` + `proc_pidinfo(PROC_PIDLISTTHREADS)` (macOS) — and flag starts inside anonymous RX mappings not backed by any module; (b) scan loaded-module export tables for the runtime's well-known exported symbol names; (c) on Linux read `/proc/net/tcp` for a listener on the framework's default control port owned by the process tree. Set `confidence_tier`: unbacked-RX-thread **alone** = info (1); unbacked-RX + framework exports + control-port = high (2). Report `jit_module_present` (Java/V8/.NET/LuaJIT also create anon-RX-with-threads — the principal FP) so the server can allowlist known-JIT signatures. All `/proc` reads behind `HK_PLATFORM_LINUX`, Mach behind `HK_PLATFORM_MACOS`, `Nt*` behind `HK_PLATFORM_WINDOWS`. The Windows variant folds the kernel `hk_event_handle_open` records (already emitted by `ObRegisterCallbacks`) to attribute a foreign process that opened a handle to the game.

### Signal 195 — self-ptrace / external-tracer tripwire (`ptrace_lsm.bpf.c`, CO-RE)
BPF LSM programs on `lsm/ptrace_access_check` and `lsm/ptrace_traceme` (audit-only — these hooks **observe**, they do not deny; returning 0 to never block) recording tracer→tracee task pairs; read `task_struct->ptracer_cred` via a CO-RE `BPF_CORE_READ`; correlate with the existing `sys_enter_ptrace` tracepoint (request type + target pid) in `tracepoints.bpf.c`. Surface the tracer's pid/comm so the server distinguishes a debugger (GDB/LLDB/strace) from the Horkos supervisor or an allowlisted crash reporter (Steam crashhandler, Breakpad/Sentry). On Steam Deck Game Mode no legitimate tracer should be present, so the server weights this higher there. Compiles `-Wall -Wextra -Werror` at the kernel warning level (guardrail #6); shares `hk_ringbuf` via the `bpf_map__reuse_fd()` repointing already documented in `tracepoints.bpf.c`. **FLAG (below):** BPF LSM (`BPF_PROG_TYPE_LSM`) requires `CONFIG_BPF_LSM=y` and the hook present in `/sys/kernel/security/lsm` — availability and the exact `ptracer_cred` CO-RE field path across kernels are version-dependent; confirm against target BTF before relying on it. Default OFF (rides the existing eBPF gate, locked decision).

### Signal 196 — Mach exception-port hijack (`MachExceptionPortScan.mm`)
`task_get_exception_ports(mach_task_self(), EXC_MASK_ALL, masks, &count, ports, behaviors, flavors)` to retrieve the current handler ports for the game's own task; for each non-default port, resolve the receiving task via `pid_for_task`/`proc_pidpath` and obtain its code-signing identity via `SecCodeCopySigningInformation`. Apple-platform-signed (`ReportCrash`) or the app's own embedded crash SDK (PLCrashReporter/KSCrash/Sentry) is benign; a foreign or ad-hoc-signed receiver is the anomaly. Report identity, never hard-flag on presence alone (catalog FP guidance). This is a **userspace sampler** querying the client's **own** task (`mach_task_self()`), which is allowed — it does not need a foreign task port; the ES client (`kernel/macos/es/EsClient.mm`) only **attributes** the receiver process by pid. **Guardrail #7:** if any attribution call is routed through the ES handler path, the ES event MUST still be replied to (`es_respond_*`) within the kernel deadline regardless of audit outcome — the audit never gates the reply, and no blocking Security-framework call runs on the ES handler queue. Entire TU behind `HK_PLATFORM_MACOS`. **FLAG (below):** whether `pid_for_task` on a foreign receiver task port is reliably permitted from the game's own (non-root, sandboxed) process is uncertain — if the receiver task port is not resolvable, report the port without pid attribution rather than failing.

### Signal 197 — memory-editor / debugger host fingerprint (`HostToolFingerprint.cpp`, Windows)
`EnumWindows` + `RealGetWindowClassW` for known debugger top-level window classes (x64dbg/OllyDbg); probe the object-manager namespace via `NtOpenDirectoryObject` + `NtQueryDirectoryObject` over `\Device` and `\GLOBAL??` for known device/symlink names (Cheat Engine `DBK64`/`dbk`, ReClass device names); enumerate loaded kernel drivers via `EnumDeviceDrivers` + `GetDeviceDriverBaseNameW` and match base names; cross-check the kernel driver whitelist (`kernel/win/src/Whitelist.c`) to attribute a BYOVD editor driver. **Severity tiering** (catalog medium-FP — x64dbg/HxD/Process Hacker have legit dev uses): a known cheat-helper driver (`DBK64`) = high (`byovd_driver_match`); a generic RE-tool window with no handle to the game = info. Escalate to `opened_handle_to_game` only when the kernel `ObRegisterCallbacks` handle records show the editor actually opened a handle to the game process. All `Nt*`/`Enum*` behind `HK_PLATFORM_WINDOWS`; `NtOpenDirectoryObject`/`NtQueryDirectoryObject` are documented-but-`Nt`-prefixed — declared locally (no proprietary SDK header; guardrail #2). Read-only enumeration only.

### Signal 198 — RDTSC/single-step timing variance (`TimingProbe.cpp`)
Sample a monotonic high-resolution counter twice around a fixed-length arithmetic block: `QueryPerformanceCounter` (Windows), `clock_gettime(CLOCK_MONOTONIC_RAW)` (Linux), `mach_absolute_time` (macOS) — clock seam in `platform/` (guardrail #1), so the `.cpp` calls `hk_monotonic_ns()` not raw APIs. Compute the per-sample delta distribution over many iterations; report median + tail inflation vs a **per-machine baseline captured at clean startup** (calibration mandatory — catalog **high FP**: scheduler preemption, SMT, frequency scaling, thermal, VM/cloud hosts all inflate the envelope). No raw `RDTSC` (avoids rdtsc-virtualization confounders). Require **sustained** inflation across many samples (`sustained_samples`); tag `vm_or_cloud_ctx`. **This is a low-weight corroborating signal only** — the catalog is explicit it must fire only in combination with a structural detection (190 debug registers, 196 exception-port hijack) and is **never a standalone ban input**. The block runs on AC-owned integrity/licence threads, NOT the GAME hot loop (guardrail #9). Median/tail classifier is a pure function over the captured vector — host-testable.

### Server (`server/telemetry/src/anti_analysis.rs`)
Fully async on tokio; `thiserror` error type for ingest validation; no `unwrap()` outside tests (guardrail #8). Deserialize the bounded `hits` vec with `hit_count`/length validation; reject out-of-range tier/factor fields rather than panicking. All scoring (overlay/driver/JIT allowlist matching, 194 combined-confidence, 197 severity tiering, 198 baseline-vs-live, 191 enabled-vs-present) is server-side; the client ships raw observations only.

---

## Build wiring

- **Usermode (`ac/CMakeLists.txt`):** add `ac/src/anti_analysis/*.cpp` to the `hk_ac` target under a new option `HORKOS_ANTI_ANALYSIS_SENSORS` (default **ON** — core PC sensors). Per-platform `.cpp` compiled only for the matching target: `DebugRegisterScan.cpp`/`HostToolFingerprint.cpp`/`module_map_win.cpp` Windows-only; `MachExceptionPortScan.mm` + the Security/Mach frameworks macOS-only; `module_map_posix.cpp` Linux+macOS; the cross-platform cores (`InlineHookScan.cpp`, `ImportRedirectScan.cpp`, `InstrumentationResidency.cpp`, `TimingProbe.cpp`, `anti_analysis_collect.cpp`) compile everywhere with platform calls behind `platform/`. macOS `.mm` needs `-framework Security -framework CoreFoundation`. Toolchain: MSVC/clang-cl (Windows usermode), clang (Linux), Xcode/clang (macOS). The obfuscator (LLVM 19) opt-in via `__attribute__((annotate("hk_obfuscate")))` on the AC's init/integrity entry points only (guardrail #9) — the timing sampling loop (198) is NOT obfuscated.
- **Kernel (`kernel/win`):** add `HostEnvProbe.c` to the KMDF driver source list and declare `HkHostEnvProbe()` in `kernel/win/include/horkos_kernel.h`; WDK toolchain; part of the existing boot-start driver. No new feature flag (joins the existing sensor set); gated behind a runtime policy toggle so the probe can be disabled in the field. **Blocked on the IRQL uncertainty flag below.**
- **Linux (`kernel/linux/CMakeLists.txt`):** add `ptrace_lsm.bpf.c` under the existing eBPF gate (`HORKOS_ENABLE_EBPF`, default **OFF** per the locked decision); libbpf + clang-19 CO-RE build, `-Wall -Wextra -Werror`; `Loader.cpp` adds the `bpf_map__reuse_fd()` repoint for the new object and the `HK_EVENT_PTRACE_LSM` → server-record mapping. Requires `CONFIG_BPF_LSM` on the target (flagged). No LKM variant for 195 (BPF LSM is eBPF-only).
- **macOS (`kernel/macos/es/CMakeLists.txt` / `ac` target):** signal 196's sampler is a userspace `.mm` in the `hk_ac` target (queries the client's own task), not the ES client; the ES client's attribution helper, if used, builds under the existing `HORKOS_MACOS_ES` option (default OFF until the EndpointSecurity entitlement lands — locked decision; the userspace daemon bring-up covers the interim).
- **Server (`server/telemetry`):** add `mod anti_analysis;` to the telemetry crate; no new cargo feature.
- **Schema:** `event_schema.h` gains `HK_EVENT_KERNEL_DBG_STATE` + `hk_event_kernel_dbg_state` (16 bytes), version bump; `ioctl.h` gains `HK_STATUS_FLAG_KDBG_PRESENT`.

---

## Test strategy

### Unit tests
- **Server (`server/telemetry/tests/`):** `anti_analysis.rs` deserialize round-trip; reject malformed `hits` (length > 24, `hit_count` mismatch), out-of-range tiers/factors; verify `SCHEMA_VERSION` bump; confirm no panic path (no `unwrap`).
- **Schema (compile-time):** the `HK_STATIC_ASSERT(sizeof(hk_event_kernel_dbg_state) == 16)` plus the unchanged `ioctl.h` size pins (`hk_event_record == 40`, `hk_status == 32`) ARE the wire-size unit test; layout drift fails the build on both sides.
- **Usermode classifiers (pure functions, host-testable, no live tooling):** 192/193 opcode-decode + branch-target-vs-VA-range classifier over synthetic prologue/import byte fixtures; 194 confidence-tier combiner over synthetic observable sets (incl. JIT-context FP case); 197 severity-tier function over synthetic hit sets; 198 median/tail-inflation classifier over synthetic delta vectors (incl. a noisy-but-clean vector that must NOT flag); 190 DR-subtraction (own-DR exclusion) over synthetic contexts.
- **Kernel 191:** the enabled-vs-present derivation (mapping `kd_enabled`/`KdDebuggerNotPresent` → `HK_KDBG_*` flags) factored into a pure helper, unit-tested host-side; the `KUSER_SHARED_DATA`/`KdRefresh*` reads are integration-only.

### Bypass tests (guardrail #12 — merge gate; any change under a security folder needs a corresponding bypass test)
- `bypass-tests/win/anti_analysis/hw_breakpoint_set.cpp` — sets a real Dr0–Dr3 + Dr7 enable on a game thread via `SetThreadContext` from outside; must demonstrate signal **190** reports a non-zero DR not owned by the client and the persistent-sample gate fires.
- `bypass-tests/win/anti_analysis/inline_hook.cpp` — installs a MinHook/Detours-style trampoline (`E9`/`FF25`) on a watched export; must demonstrate signal **192** reports the divergence with the resolved trampoline-target module and signing status (and that a benign signed-overlay hook is reported as excludable, not hard-flagged).
- `bypass-tests/win/anti_analysis/iat_redirect.cpp` — overwrites an IAT slot to point into an unbacked region; must demonstrate signal **193** flags the foreign/unbacked backing module as high severity.
- `bypass-tests/cross/anti_analysis/frida_gadget.cpp` — spawns a thread starting in an anon-RX mapping + a fake control-port listener + a module exporting a framework symbol name; must demonstrate signal **194** escalates to `confidence_tier = high` only when combined, and stays `info` for the unbacked-thread-alone (JIT-like) case.
- `bypass-tests/linux/anti_analysis/ptrace_attach.cpp` — `ptrace(PTRACE_ATTACH/SEIZE)` the game from a foreign process; must demonstrate signal **195** records the tracer→tracee pair + tracer comm via the LSM hook (and audit-only — never denies), weighted higher under Game Mode.
- `bypass-tests/macos/anti_analysis/exc_port_hijack.cpp` — `task_set_exception_ports` from a foreign (non-Apple-signed) task to catch the game's `EXC_BREAKPOINT`; must demonstrate signal **196** flags the foreign non-self/non-system owner with its signing identity, and (if ES-attributed) that the ES event was still replied to (guardrail #7 assertion).
- `bypass-tests/win/anti_analysis/host_memory_editor.cpp` — loads a Cheat-Engine-style helper driver name + opens an x64dbg-class window, then opens a handle to the game; must demonstrate signal **197** escalates from info → `byovd_driver_match`/high → `opened_handle_to_game` as the handle is opened.
- `bypass-tests/win/anti_analysis/kernel_debugger_flag.cpp` *(integration / VM with `bcdedit /debug on`)* — must demonstrate signal **191** distinguishes boot-enabled-but-absent (`kd_enabled` set, `kd_present` clear, no `HK_STATUS_FLAG_KDBG_PRESENT`) from an actively attached kernel debugger (flag set). Marked VM-only; depends on resolving the IRQL flag first.
- `bypass-tests/cross/anti_analysis/single_step_timing.cpp` — runs the fixed block under a single-stepping debugger / DBI; must demonstrate signal **198** reports sustained inflation AND that it is shipped as a low-weight corroborating field, never a standalone ban (test asserts tag-not-ban and that a noisy-but-undebugged baseline run does not flag).

Each bypass test asserts the sensor produced the expected raw report field; none assert a local ban (ban authority is server-side).

---

## Sequencing

1. **Schema + contract first.** Add `HK_EVENT_KERNEL_DBG_STATE` + `hk_event_kernel_dbg_state` (16 bytes) to `event_schema.h` and `HK_STATUS_FLAG_KDBG_PRESENT` to `ioctl.h` (coordinate the version bump / enum value with the timing-side-channels plan); add `server/telemetry/src/anti_analysis.rs` + `SCHEMA_VERSION` bump; add the data-categories.md section. Purely additive, testable, unblocks everything.
2. **`anti_analysis_signals.h` + per-signal headers.** Define the POD result structs + aggregator surface. No logic yet (guardrail #14 — logic lands under TDD).
3. **Cross-platform module-integrity core (no OS hooks beyond read-only mapping):** signals 192 + 193 share `module_map_win.cpp` / `module_map_posix.cpp` — land the shared map/resolver backend once, then the two samplers on top. Opcode/import classifiers are pure and host-testable first.
4. **Cross-platform residency + timing:** signal 194 (depends on the POSIX module-map for backing-region resolution) and signal 198 (depends on the `platform/` `hk_monotonic_ns()` clock seam — add it first). Both host-testable classifiers.
5. **Windows-only host/process sensors:** 190 (debug registers, cross-checked against kernel thread records) and 197 (host-tool fingerprint, reusing `Whitelist.c`). Depend on the kernel record/whitelist plumbing already present.
6. **Kernel 191 (`HostEnvProbe.c`)** + the `anti_analysis_collect.cpp` drain path — **gated on resolving the IRQL/`KUSER_SHARED_DATA`-access uncertainty flag below.** Depends on step 1's schema.
7. **Linux 195** (`ptrace_lsm.bpf.c`) under the eBPF gate and **macOS 196** (`MachExceptionPortScan.mm`) — both depend only on step 1's schema (195 actually on no C-schema change) and can land last and in parallel; 195 gated on `CONFIG_BPF_LSM` availability, 196 gated on the `pid_for_task` attribution flag.
8. **Bypass tests** land with each sensor (merge gate — not deferred).

---

## Risks & UNCERTAINTY FLAGS

- **FLAG (signal 191, Windows kernel):** The exact IRQL at which `KdRefreshDebuggerNotPresent()` may be called, and whether reading `SharedUserData->KdDebuggerEnabled` directly from the driver is the supported access path (vs reading the exported `KdDebuggerEnabled`/`KdDebuggerNotPresent` kernel globals), is **not certain**. The probe may run from the ring-emit path at `DISPATCH_LEVEL`; calling a passive-only routine there would be a bug (potential BSOD). Per guardrail #13 this must be resolved (WDK docs / a kernel dev) before `HostEnvProbe.c` touches these APIs — do not guess.
- **FLAG (signal 195, Linux BPF LSM):** `BPF_PROG_TYPE_LSM` (`lsm/ptrace_access_check`, `lsm/ptrace_traceme`) requires `CONFIG_BPF_LSM=y` and the BPF LSM enabled in the boot `lsm=` list / `/sys/kernel/security/lsm`. Availability is **kernel/config-dependent** (notably on stock Steam Deck SteamOS — confirm before relying on it; the `sys_enter_ptrace` tracepoint already in `tracepoints.bpf.c` is the fallback observable if LSM is absent). The exact CO-RE field path for `task_struct->ptracer_cred` across kernel versions must be confirmed against the target BTF.
- **FLAG (signal 196, macOS):** Whether `pid_for_task`/`proc_pidpath` on a **foreign** receiver task port is reliably permitted from the game's own non-root, sandboxed process is **uncertain** (task-port access is restricted by SIP/hardened-runtime). If the receiver task port is not resolvable, the sampler must report the raw port + behavior without pid/signing attribution rather than failing. Querying the client's **own** task via `mach_task_self()` is fine.
- **FLAG (signal 190, kernel corroboration scope):** The catalog mentions kernel-side `PsGetContextThread` corroboration. This plan implements only the **usermode** `GetThreadContext` scan plus the existing kernel thread-create record cross-check; a kernel `PsGetContextThread` reader is **out of scope here** and, if added later, needs its own IRQL review (it has thread-state and IRQL constraints) — flagged so it is not silently assumed implemented.
- **FP-by-design (198):** Timing is **high-FP** — scheduler preemption, SMT contention, frequency/thermal scaling, VM/cloud-gaming/VDI hosts all inflate the envelope. Signal 198 is a **low-weight corroborating tag only**, mandatory per-machine startup baseline, fires only in combination with a structural detection (190/196) — **never a standalone ban**. Enforced by the `single_step_timing` bypass test asserting tag-not-ban and a clean-but-noisy non-flag.
- **FP (192, 193, 197):** Legitimate in-process hooks (Steam/Discord/RTSS/MSI-AB/EDR overlays for 192/193) and legitimate RE tools (x64dbg/HxD/Process Hacker for 197) produce benign hits. All report the backing-module signing identity / severity tier and rely on **server-side allowlists** (overlay tuples, API-set hosts, AppCompat shims, known-JIT signatures) — the client never hard-flags on presence alone.
- **Signing/toolchain:** signals 195 (eBPF) and 196/ES-attribution (macOS ES) ride the already-flagged locked-decision gates — eBPF default OFF, ES default OFF pending the Apple EndpointSecurity entitlement. No new signing requirement introduced by this plan beyond those existing gates.
- **Schema-version coordination:** this plan and the timing-side-channels plan both consume the next `HK_EVENT_SCHEMA_VERSION` bump and the next free `hk_event_type` value. Whichever merges first takes the slot; the other rebases — must be reconciled at merge, not assumed.
