# Process Genealogy & Loader Trust (`process-genealogy`)

**Scope:** Read-only launch-trust sensors that verify a protected game's *ancestry* and *loader chain* match a signed-launcher baseline — true creator vs. inherited parent, suspended-launch windows, LOLBin proxies, manual-mapped modules, integrity/token divergence, job/silo containment, and the POSIX equivalents (ptrace-launched, LD_PRELOAD/PT_INTERP hijack, macOS responsibility laundering). All sensors sample-and-report; **ban authority is server-side** (locked decision; CLAUDE.md). No tampering/evasion code is designed.

**Catalog signals covered:** 199–207
- 199 Parent-launcher PPID-spoof / reparent (win-kernel)
- 200 Create-suspended→resume launch window (win-kernel)
- 201 LOLBin / signed-binary-proxy in ancestry (win-kernel + userspace catalog)
- 202 Unsigned / catalog-absent manual-mapped module (win-kernel + userspace)
- 203 Integrity-level / token mismatch game↔launcher (win-userspace)
- 204 Job-object / silo containment anomaly (win-userspace, advisory-only)
- 205 execve preceded by PTRACE_TRACEME/ATTACH in genealogy (linux-ebpf)
- 206 LD_PRELOAD / dynamic-linker hijack at exec (linux-ebpf)
- 207 Responsible-process / parent-responsibility mismatch (macos-es)

Grouping by mechanism/TU (guardrail #4 — kernel and userspace never share a TU; guardrail #1 — platform API only under `kernel/<os>/` or a `backends/` folder):

- **Windows kernel:** `proc_genealogy.c` (199 reparent), `launch_timing.c` (200 suspend window), `module_reconcile.c` (202 manual-map notify-set). LOLBin chain (201) is built from the existing `PsSetCreateProcessNotifyRoutineEx` stream — the kernel just emits ancestry-image data; the *match* is a userspace catalog.
- **Windows userspace (SDK backend, `backends/win/`):** `ancestry_walker.cpp` (201 chain + LOLBin catalog match), `region_walk.cpp` (202 userspace region/PEB-Ldr half), `token_check.cpp` (203), `job_silo_check.cpp` (204).
- **Linux eBPF:** `genealogy.bpf.c` (205 ptrace+exec join + LSM `ptrace_access_check`), `loader_trust.bpf.c` (206 envp scan on execve) + userspace `/proc/<pid>/maps`/`PT_INTERP` reconcile in the existing `Loader.cpp`.
- **macOS ES:** `genealogy_handler.cpp` (207 NOTIFY_EXEC responsible/team-id extraction), mirrored in the `daemon/macos/horkosd.cpp` bring-up path.
- **Server:** ancestry/launch-trust correlation in `server/telemetry/src/schema.rs` (new `LaunchTrustReport`) and a signed-LOLBin/launcher-baseline rule store under `server/api/`.

---

## New files

| Path | Role | Module-comment summary (guardrail #3) |
|---|---|---|
| `kernel/win/src/proc_genealogy.c` | Signal 199: in the process-create notify, capture the *true creator* (`PsGetCurrentProcessId()`, the creating thread's owning process) and compare against the inherited `ParentProcessId`; set `HK_PROC_FLAG_REPARENT_SUSPECT` on divergence (gating deferred to server). | Role: PPID-spoof/reparent sensor in the create-process notify. Target: Windows kernel (KMDF). Interface: extends `HkProcessNotifyEx` (Notify.c) via `HkGenealogyClassify` declared in `horkos_kernel.h`; emits the extended `hk_event_process_create` flags from `event_schema.h`. |
| `kernel/win/src/launch_timing.c` | Signal 200: correlate create-process-notify timestamp with the initial thread's first RUN transition (`PsSetCreateThreadNotifyRoutine`) and pre-resume image-loads; set `HK_PROC_FLAG_SUSPENDED_LAUNCH` when an image-load precedes first-resume. | Role: create-suspended→resume launch-window timing sensor. Target: Windows kernel (KMDF). Interface: implements `HkLaunchTimingArm/Disarm` + `HkLaunchTimingOnThread/OnImage` declared in `horkos_kernel.h`; flags into `hk_event_process_create`. |
| `kernel/win/src/module_reconcile.c` | Signal 202 (kernel half): maintain the authoritative loader-loaded module set from `PsSetLoadImageNotifyRoutine` (base+size+FILE_OBJECT presence) so userspace can diff against executable-region enumeration. | Role: image-load notify-set authority for manual-map reconciliation. Target: Windows kernel (KMDF). Interface: implements `HkModuleReconcileOnImage` declared in `horkos_kernel.h`; emits `hk_event_image_load` with `HK_IMAGE_FLAG_MANUAL_MAP_SUSPECT` left for the server to confirm against the userspace region report. |
| `sdk/src/backends/win/ancestry_walker.cpp` | Signal 201: walk the recorded ancestry chain (PID+create_time keyed to survive PID reuse), match each ancestor image against a signed-LOLBin name+path catalog and require the store client as chain root; capture command-line shape. | Role: launch-ancestry walker + LOLBin catalog match (userspace). Target: Windows userspace (guardrail #1: `backends/win/`). Interface: declared in `sdk_backend.h`; feeds the SDK report plane → server, not the kernel ring. |
| `sdk/src/backends/win/region_walk.cpp` | Signal 202 (userspace half): enumerate executable regions (`VirtualQueryEx` MEM_PRIVATE/MEM_IMAGE + PAGE_EXECUTE_*) and the PEB Ldr module list; report regions absent from both the kernel image-load set and PEB Ldr, attributed against known JIT allocator ranges. | Role: executable-region / PEB-Ldr enumerator for manual-map reconciliation. Target: Windows userspace (`backends/win/`). Interface: declared in `sdk_backend.h`; pairs with `module_reconcile.c`'s notify set server-side. |
| `sdk/src/backends/win/token_check.cpp` | Signal 203: `OpenProcessToken` on game + recorded parent; compare integrity level, elevation, session id, linked token; emit `token_integrity_delta`. | Role: integrity/token divergence sensor game↔launcher. Target: Windows userspace (`backends/win/`). Interface: declared in `sdk_backend.h`; emits the `token_integrity_delta` telemetry field. |
| `sdk/src/backends/win/job_silo_check.cpp` | Signal 204: job/silo membership of the game vs. expected launcher job; advisory-only (high FP), no autonomous ban. | Role: job-object/silo containment anomaly sensor (advisory). Target: Windows userspace (`backends/win/`). Interface: declared in `sdk_backend.h`; emits an advisory-only telemetry field. |
| `kernel/linux/bpf/src/genealogy.bpf.c` | Signal 205: join `sys_enter_ptrace` with `sched_process_exec` keyed by (tgid,pid) + BPF LSM `lsm/ptrace_access_check`; tag exec-under-tracer in the shared ringbuf. | Role: launch-under-tracer (ptrace+exec join) eBPF sensor. Target: Linux eBPF (TRACEPOINT + BPF_LSM). Interface: shares `hk_ringbuf` with `tracepoints.bpf.c`/`lsm_file_open.bpf.c`; new event tag consumed by `Loader.cpp`. |
| `kernel/linux/bpf/src/loader_trust.bpf.c` | Signal 206: on `sys_enter_execve`, scan argv/envp via `bpf_probe_read_user` for `LD_PRELOAD`/`LD_AUDIT`/`LD_LIBRARY_PATH`; tag tainted-loader-env in the ringbuf. Userspace reconcile (maps/PT_INTERP/`/etc/ld.so.preload`) lives in `Loader.cpp`. | Role: dynamic-linker-hijack (envp) eBPF sensor. Target: Linux eBPF (TRACEPOINT). Interface: shares `hk_ringbuf`; reuses the `lsm/file_open` mmap-exec audit stream; new tag consumed by `Loader.cpp`. |
| `kernel/macos/es/genealogy_handler.cpp` | Signal 207: in the `ES_EVENT_TYPE_NOTIFY_EXEC` handler, extract `responsible_audit_token`/`parent_audit_token`/`team_id`/`signing_id`/`cdhash`; compare the launch chain against the accepted-launcher baseline. | Role: responsible-process/team-id launch-trust extraction. Target: macOS ES (userspace ES client). Interface: invoked from `EsClient.mm`'s NOTIFY_EXEC path; mirrors into `daemon/macos/horkosd.cpp`. NOTIFY-only → no reply deadline (guardrail #7). |
| `server/api/launcher-baseline.md` | Signed-launcher / LOLBin rule store spec (chain roots, accepted launcher Team IDs/cdhashes, LOLBin name+path catalog, per-launcher expected integrity level). | Role: launch-trust rule-data spec consumed by the ban-engine correlation. Target: server. Interface: documents the rule shape; rules themselves are signed bundles (no live secrets in repo). |
| `bypass-tests/win/reparent_spoof.cpp` | Merge-gate bypass test (guardrail #12): spawn a child with `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)` forging a launcher parent; assert `HK_PROC_FLAG_REPARENT_SUSPECT`. Ships disabled pre-enforcement (like `byovd_load.cpp`). | Role: bypass test for PPID-spoof + LOLBin ancestry. Target: Windows only (`if(WIN32)`). Interface: consumes `ioctl.h` + flag surface. |
| `bypass-tests/linux/ld_preload_launch.cpp` | Merge-gate bypass test (guardrail #12): exec a target with `LD_PRELOAD` set to an unlisted `.so`; assert the loader-trust tag fires. Disabled until the eBPF enforcement path lands. | Role: bypass test for LD_PRELOAD/linker hijack. Target: Linux only (`if(UNIX AND NOT APPLE)`). Interface: consumes the AC flag surface. |
| `bypass-tests/macos/responsible_launder.cpp` | Merge-gate bypass test (guardrail #12): launch the target from an unsigned/ad-hoc launcher (Terminal-equivalent) and assert the responsibility-mismatch flag. Disabled pre-enforcement. | Role: bypass test for responsibility laundering. Target: macOS only (`if(APPLE)`). Interface: consumes the AC flag surface. |

Guardrail #4 honored: every kernel `.c`/`.bpf.c` is a separate TU from the userspace `.cpp`; they share only the pure-C99 wire headers (`event_schema.h`, `ioctl.h`). The Linux ptrace bypass fixture already exists (`bypass-tests/linux/ptrace_attach.cpp`) and covers signal 205 — no new file for it.

---

## Interfaces & data structures

### `event_schema.h` additions (schema bump 2 → 3)

New process-create flags. **`hk_event_process_create` stays 16 bytes** — there is no spare word in the current struct (pid/parent_pid/create_time_ns fully occupy 16). To carry flags without breaking the 16-byte `HK_STATIC_ASSERT` and the 40-byte `hk_event_record`, the flags ride in the **header's `reserved` word**, which is currently mandated zero. Repurpose `hk_event_header.reserved` → `proc_flags` *only for `HK_EVENT_PROCESS_CREATE`* (documented in `docs/event-schema.md`; old readers saw zero = no flags):

```c
/* hk_event_header.reserved is reinterpreted as proc_flags for
 * HK_EVENT_PROCESS_CREATE events (schema v3). Zero for all other types. */
#define HK_PROC_FLAG_REPARENT_SUSPECT   0x00000001u  /* signal 199 */
#define HK_PROC_FLAG_SUSPENDED_LAUNCH   0x00000002u  /* signal 200 */
#define HK_PROC_FLAG_LOLBIN_ANCESTOR    0x00000004u  /* signal 201 (set server-side
                                                        after catalog match; kernel
                                                        only ships ancestry data) */
```

> **Design decision to confirm with reviewer:** repurposing `header.reserved` keeps every wire-size assert intact but overloads a header field with type-specific meaning. The cleaner alternative is a **new event type** `HK_EVENT_PROCESS_CREATE_EX` (24-byte payload: pid, parent_pid, create_time_ns, true_creator_pid, flags) which bumps `HK_EVENT_PAYLOAD_MAX` 16→24 and therefore `hk_event_record` 40→48 and every dependent assert + `HK_EVENT_PAYLOAD_MAX`. Signal 199's mechanism *needs* `true_creator_pid` on the wire (it is not derivable server-side), so **the new-type route is the correct one** — the `reserved`-overload only carries the boolean flag, not the creator PID. Plan adopts `HK_EVENT_PROCESS_CREATE_EX`:

```c
/* Appended to hk_event_type (existing values unchanged): */
HK_EVENT_PROCESS_CREATE_EX = 5,

typedef struct hk_event_process_create_ex {
    uint32_t pid;
    uint32_t parent_pid;        /* inherited InheritedFromUniqueProcessId */
    uint64_t create_time_ns;    /* FILETIME epoch, as hk_event_process_create */
    uint32_t true_creator_pid;  /* PsGetCurrentProcessId() in the notify (signal 199) */
    uint32_t proc_flags;        /* HK_PROC_FLAG_* */
} hk_event_process_create_ex;   /* 24 bytes */

HK_STATIC_ASSERT(sizeof(hk_event_process_create_ex) == 24,
    "hk_event_process_create_ex size mismatch");

/* Manual-map flag rides on the existing hk_event_image_load.flags word. */
#define HK_IMAGE_FLAG_MANUAL_MAP_SUSPECT 0x00000002u  /* signal 202; BYOVD is 0x1 */
```

`HK_EVENT_PAYLOAD_MAX` rises 16 → 24; `hk_event_record` 40 → 48. Update the three asserts in `ioctl.h` and the BPF/loader-side mirrors. Bump `HK_EVENT_SCHEMA_VERSION` 2 → 3 (and the BPF `HK_SCHEMA_VERSION` constant in both `.bpf.c` files + `Loader.cpp`'s `HK_EVENT_SCHEMA_VERSION` use).

### `ioctl.h` additions

```c
#define HK_EVENT_PAYLOAD_MAX 24u   /* was 16; largest is hk_event_process_create_ex */
HK_STATIC_ASSERT(sizeof(hk_event_record) == 48, "hk_event_record wire size drift"); /* was 40 */
```

`hk_status` gains no new struct field, but two status flags (no size change):

```c
#define HK_STATUS_FLAG_GENEALOGY_ACTIVE 0x00000008u
#define HK_STATUS_FLAG_TIMING_ACTIVE    0x00000010u
```

### Linux BPF ringbuf record additions

`genealogy.bpf.c` reuses the existing `hk_bpf_exec_event` layout and adds a flag word (new struct, new tag so old loaders skip it):

```c
#define HK_EVENT_LAUNCH_TRACED   0x22u   /* exec-under-tracer (signal 205) */
#define HK_EVENT_LOADER_TAINT    0x23u   /* LD_PRELOAD/PT_INTERP (signal 206) */
struct hk_bpf_launch_event {
    __u32 schema_version; __u32 event_tag; __u64 timestamp_ns;
    __u32 pid; __u32 tracer_pid;      /* 205 */
    __u32 taint_flags;                /* 206: bit0 LD_PRELOAD, bit1 LD_AUDIT, bit2 LD_LIBRARY_PATH */
    char  filename[HK_PATH_MAX];
};
```

`Loader.cpp` maps `HK_EVENT_LAUNCH_TRACED`/`HK_EVENT_LOADER_TAINT` onto `HK_EVENT_PROCESS_CREATE_EX` with the appropriate `proc_flags` (define Linux-side flag bits `HK_PROC_FLAG_TRACED_LAUNCH`, `HK_PROC_FLAG_LOADER_TAINT` in `event_schema.h`).

### Server: `server/telemetry/src/schema.rs`

New JSON report (separate wire plane from the C kernel schema, per the file's own doc):

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LaunchTrustReport {
    pub schema_version: u32,
    pub player_id: u64,
    pub game_pid: u32,
    pub true_creator_pid: u32,
    pub declared_parent_pid: u32,
    pub proc_flags: u32,                 // HK_PROC_FLAG_* mirror
    pub ancestry_image_hashes: Vec<String>, // ordered root→game (signal 201)
    pub token_integrity_delta: i32,      // signal 203
    pub job_silo_anomaly: bool,          // signal 204 (advisory)
    pub responsible_team_id: String,     // signal 207 (macOS)
    #[serde(default)]
    pub server_received_ts: u64,
}
```

### Guardrail #11 — every new telemetry field must land in `server/api/data-categories.md` in the same PR

New rows to add under §1 Process information (or a new §1a "Launch trust"):
`true_creator_pid`, `proc_flags` (reparent/suspended/lolbin/traced/loader-taint), `ancestry_image_hashes`, `token_integrity_delta`, `job_silo_anomaly`, `responsible_team_id`, `loader_taint_flags`. Each row: source hook, retention (90 d, aligned with existing process-info), legal basis (legitimate interest — anti-cheat), operator-of-record. The PR that adds any of these to `schema.rs` is rejected by review if this file is not updated in the same PR.

---

## Mechanism implementation notes

### Signal 199 — PPID-spoof / reparent (`proc_genealogy.c`, kernel)
- API: inside `HkProcessNotifyEx` (the existing `PsSetCreateProcessNotifyRoutineEx` callback), `PsGetCurrentProcessId()` is the **true creating thread's process**; compare to `CreateInfo->ParentProcessId` (inherited/assigned). Emit `true_creator_pid` + `HK_PROC_FLAG_REPARENT_SUSPECT` when they diverge. The userspace `ZwQueryInformationProcess(ProcessBasicInformation).InheritedFromUniqueProcessId` cross-check happens in `ancestry_walker.cpp`, not the kernel.
- IRQL/safety: the notify runs at **PASSIVE_LEVEL** in the creating thread's context — `PsGetCurrentProcessId()` is valid here. No string ops beyond what `Notify.c` already does; ring write is via the existing `HkRingEmit` (DISPATCH-safe spinlock path). Every value is a copy of an already-validated `CreateInfo` field — no new probe. Server gates the flag against the (true_creator_image, declared_parent_image) signed-launcher pair (catalog) to suppress the medium-FP cases (Battle.net, Steam helper relaunch, AppContainer brokers, CreateProcessAsUser).

### Signal 200 — suspended-launch window (`launch_timing.c`, kernel)
- API: arm `PsSetCreateThreadNotifyRoutine`; record create-process timestamp (already in `header.timestamp_ns`), and for the **initial thread** detect first RUN transition. Flag `HK_PROC_FLAG_SUSPENDED_LAUNCH` if a `PsSetLoadImageNotifyRoutine` image-load for that PID arrives before the initial thread leaves suspended.
- **UNCERTAINTY FLAG (guardrail #13):** the thread *create* notify fires at thread creation, **not** at resume; there is no kernel notify for `NtResumeThread`. Inferring "first RUN" from kernel callbacks alone is not reliable — KTHREAD state inspection at arbitrary IRQL is unsafe and undocumented for this use. The catalog itself routes the *suspend inference* to userspace `NtQuerySystemInformation(SystemProcessInformation)` thread-state/wait-reason. **Plan: kernel only timestamps create + first-image-load + thread-create; the suspend→resume gap is computed server-side from those timestamps plus the userspace thread-state sample.** Do not attempt a kernel resume-hook. Flagged for review before coding the timing correlation.
- FP gate (server): allow when the suspending creator is the expected signed launcher or a registered protector (Denuvo/Arxan/EAC/BattlEye protected-launch shims, debuggers).

### Signal 201 — LOLBin proxy in ancestry (`ancestry_walker.cpp`, userspace + server catalog)
- API: walk the ancestry chain assembled from the create/exit stream (persist parent images by **PID + create_time** to survive PID reuse — `module_reconcile`/server keep this map). For each ancestor read image path; match against a signed-LOLBin name+path catalog (rundll32, regsvr32, mshta, wmic, msbuild, conhost-detached, explorer-spawn; MITRE T1218). Capture command-line shape via the create-notify `CommandLine`. Emit `HK_PROC_FLAG_LOLBIN_ANCESTOR` **server-side** after catalog match — kernel ships ancestry data only.
- FP gate: require the store client as chain root; a bare `rundll32 → game` with no launcher root is the strong signal. Shell-launched shortcuts (explorer.exe) and modding frameworks are the FP class.

### Signal 202 — manual-mapped module (`module_reconcile.c` kernel + `region_walk.cpp` userspace)
- Kernel: `PsSetLoadImageNotifyRoutine` already fires in `HkImageNotify`; `module_reconcile.c` records the authoritative set (base, size, FILE_OBJECT presence) per PID. `IMAGE_INFO` gives base/size; absence of a backing `FILE_OBJECT` is itself a precursor signal but **not** conclusive (see uncertainty).
- Userspace: `VirtualQueryEx` MEM_PRIVATE/MEM_IMAGE + PAGE_EXECUTE_*; PEB Ldr via `NtQueryInformationProcess(ProcessBasicInformation)` → PEB → Ldr. Region executable + not in image-load set + not in PEB Ldr = manual-map artifact. Reconciliation (the diff) is server-side: kernel notify-set ⨯ userspace region-set.
- FP gate: attribute regions to known JIT host module ranges (.NET, JVM, V8, EAC JIT) and require the region to be unbacked **and** outside any registered JIT allocator before the server confirms the flag.

### Signal 203 — token/integrity mismatch (`token_check.cpp`, userspace)
- API: `OpenProcessToken(PROCESS_QUERY_LIMITED_INFORMATION)` on game + recorded parent; `GetTokenInformation` for `TokenIntegrityLevel` (TOKEN_MANDATORY_LABEL), `TokenElevation`, `TokenSessionId`, `TokenLinkedToken`. Emit `token_integrity_delta`. Kernel corroboration via `SeQueryInformationToken` in process-create context is optional and **deferred** (the userspace read is sufficient and avoids kernel token-ref lifetime hazards).
- FP gate (server): baseline expected integrity *per known launcher* (UAC-elevated admin launchers legitimately yield High from Medium); flag only divergence from that launcher's documented level, never absolute High.

### Signal 204 — job/silo containment (`job_silo_check.cpp`, userspace, advisory-only)
- API: `IsProcessInJob` + `QueryInformationJobObject(JobObjectBasicProcessIdList / JobObjectExtendedLimitInformation)`; `NtQueryInformationProcess(ProcessJobMemoryInformation)`; silo membership. Compare the job's member set + creator against the expected launcher job.
- **High FP** (Windows itself, UWP AppContainers, steamwebhelper job, GameBar, Sandboxie, Game Mode all use jobs/silos). **Advisory-only telemetry field; no autonomous ban** (catalog mandate). Gate hard server-side: only surface when the job creator is unsigned/unknown AND a non-whitelisted instrumentation binary is in the member set.

### Signal 205 — exec-under-tracer (`genealogy.bpf.c`, eBPF) + existing `bypass-tests/linux/ptrace_attach.cpp`
- API: join `tracepoint/syscalls/sys_enter_ptrace` (existing in `tracepoints.bpf.c`) with `tracepoint/sched/sched_process_exec`, keyed by (tgid,pid); add a **BPF LSM** `lsm/ptrace_access_check` hook and read `task->ptrace` / `real_parent` via CO-RE (`BPF_CORE_READ`). Tag `HK_EVENT_LAUNCH_TRACED` with `tracer_pid`.
- CO-RE / -Werror (guardrail #6): `task_struct->ptrace` and `->real_parent` are CO-RE-relocatable; access strictly via `BPF_CORE_READ` against vmlinux BTF. The new `.bpf.c` compiles under the same `-Wall -Wextra -Werror -mcpu=v3` flags wired in `bpf/CMakeLists.txt`; add it via the existing `bpf_program(genealogy)` macro.
- **UNCERTAINTY FLAG:** BPF LSM (`lsm/ptrace_access_check`) requires `CONFIG_BPF_LSM=y` **and** the LSM enabled in `lsm=` boot param — not universal, and **Steam Deck Game Mode** is the locked eBPF target (decision #3). If `ptrace_access_check` is unavailable, the tracepoint-join path (`sys_enter_ptrace` × `sched_process_exec`) is the fallback and must stand alone. Confirm BPF-LSM availability on the Deck kernel before relying on the LSM hook; do not hard-require it.
- FP gate (server): tracer outside the Steam/Proton process group and not a registered overlay helper (gameoverlayrenderer, crashpad).

### Signal 206 — LD_PRELOAD / linker hijack (`loader_trust.bpf.c`, eBPF + `Loader.cpp` reconcile)
- API: on `tracepoint/syscalls/sys_enter_execve`, read argv/envp pointers from the user stack via `bpf_probe_read_user` to detect `LD_PRELOAD`/`LD_AUDIT`/`LD_LIBRARY_PATH`. Userspace reconcile in `Loader.cpp`: `/proc/<pid>/maps` mapped-.so set vs `DT_NEEDED`, the binary's `PT_INTERP`, and `stat(/etc/ld.so.preload)`; cross-check the existing `lsm/file_open` mmap-exec audit stream.
- CO-RE / -Werror: envp walking is bounded — **the verifier rejects unbounded loops**; use a fixed `#pragma unroll` bound (e.g. scan first N env entries, N≤32) and bounded `bpf_probe_read_user_str` with explicit length caps. Any unbounded read fails the verifier at load, not compile — test under `HORKOS_LINUX_EBPF=ON` on a real kernel.
- **UNCERTAINTY FLAG:** reading argv/envp off the user stack at `sys_enter_execve` is layout-fragile (the new process image's stack is being set up); the exact pointer to envp must come from the syscall args (`execve(path, argv, envp)` — third arg), read via the tracepoint context, **not** guessed from the stack. Confirm the `sys_enter_execve` context exposes `envp` as a directly-readable arg on the target kernel before coding the scan.
- FP gate (server): signed-allowlist of overlay/HUD `.so` by path+hash (gameoverlayrenderer.so, MangoHud, vkBasalt, OBS game-capture); only unlisted preloads flag.

### Signal 207 — responsibility mismatch (`genealogy_handler.cpp`, macOS ES)
- API: in `ES_EVENT_TYPE_NOTIFY_EXEC`, read `es_process_t->responsible_audit_token`, `parent_audit_token`, `team_id`, `signing_id`, `cdhash`; resolve PIDs via `audit_token_to_pid`. Compare the launch chain's signing identities against the accepted-launcher baseline (Team IDs/cdhashes).
- **Guardrail #7:** this is `NOTIFY_EXEC` only — **no AUTH event, no reply deadline**. The handler does a fixed-size token extraction + async hand-off (mirroring `EsClient.mm`'s existing pattern: copy record, dispatch to the private sink queue, never block the ES serial queue). If a future variant subscribes AUTH, every path must `es_respond_auth_result` before returning.
- FP gate (server): allowlist accepted launcher Team IDs/cdhashes (Steam, plus Whisky/CrossOver/Heroic, dev Terminal/Xcode); flag only when responsibility resolves outside the set with no store client in the chain.

### Server (`schema.rs` + ban-engine correlation)
- Fully async tokio; `thiserror` for the new `LaunchTrustError`; **no `unwrap()`** outside `#[cfg(test)]` (guardrail #8). The correlation join (ancestry chain × launcher baseline, suspend→resume gap, region-diff) runs on the async ingest path; rule-store reads are async, cached, non-blocking. Ban authority server-side only — the report carries flags, the engine decides.

---

## Build wiring

- **Windows:** add `proc_genealogy.c`, `launch_timing.c`, `module_reconcile.c` to the `kernel/win` KMDF driver source list (WDK toolchain). New userspace `.cpp` join the SDK win backend under `sdk/src/backends/win/` (guarded by the SDK's existing `if(WIN32)`). No new feature flag — genealogy sensors are part of the always-on driver; the suspend-timing arm self-gates on `HkLaunchTimingArm` success and reports liveness via `HK_STATUS_FLAG_TIMING_ACTIVE`. Default **ON** (sensors are read-only).
- **Linux:** register both new BPF programs in `kernel/linux/bpf/CMakeLists.txt` via `bpf_program(genealogy)` and `bpf_program(loader_trust)`; add both skel targets to the `hk_bpf_generated` INTERFACE deps. Stays behind `HORKOS_LINUX_EBPF` (default **OFF**; CI runner with clang≥14 + libbpf + bpftool enables it to enforce -Werror). The LSM hook in `genealogy.bpf.c` is a separate `SEC("lsm/ptrace_access_check")` program in the same object — guard its *attach* (not compile) on BPF-LSM availability in `Loader.cpp`.
- **macOS:** `genealogy_handler.cpp` compiles under the existing `HORKOS_MACOS_ES` CMake option (Xcode toolchain, EndpointSecurity.framework); also referenced from the `daemon/macos` bring-up target. Default **OFF** until the ES entitlement lands (locked decision #4).
- **Server:** `schema.rs` change is in the existing `server/telemetry` crate; `launcher-baseline.md` is doc-only. No new crate.
- **Bypass tests:** add `reparent_spoof.cpp` to `bypass-tests/win/CMakeLists.txt`, `ld_preload_launch.cpp` to `bypass-tests/linux/CMakeLists.txt`, `responsible_launder.cpp` to `bypass-tests/macos/CMakeLists.txt`. All ship **disabled** (undefined `HK_*_TEST_ENABLED`) like `byovd_load.cpp` — compiled for the gate, asserting once enforcement lands.

---

## Test strategy

### Unit tests
- **Wire-schema (host, no kernel):** a host C/C++ TU includes `event_schema.h` + `ioctl.h` and relies on the `HK_STATIC_ASSERT`s — `hk_event_process_create_ex == 24`, `hk_event_record == 48`, `HK_EVENT_PAYLOAD_MAX == 24`. Build-fails on drift (mirrors the existing Step 3.5 size-pin pattern).
- **Server (`cargo test`, TDD):** `LaunchTrustReport` serde round-trip; ban-engine correlation cases — reparent-divergence-with-whitelisted-pair → no flag; LOLBin-with-store-root vs. bare-rundll32-no-root; token-delta-vs-baseline (UAC High from known admin launcher → no flag); suspend-gap-under-registered-protector → no flag. No `unwrap()` in non-test code; assert error paths via `LaunchTrustError`.
- **Loader mapping (`Loader.cpp`):** unit test that `HK_EVENT_LAUNCH_TRACED`/`HK_EVENT_LOADER_TAINT` tags map to `HK_EVENT_PROCESS_CREATE_EX` with the right `proc_flags`, and undersized/unknown-tag records are skipped (extends the existing tag-dispatch tests).
- **eBPF (CI runner):** load `genealogy.bpf.o` / `loader_trust.bpf.o` into a real kernel and assert the verifier accepts them (bounded envp loop, CO-RE relocations resolve). This is the real -Werror + verifier gate.

### Required bypass tests (guardrail #12 — merge gate)
- **`bypass-tests/win/reparent_spoof.cpp`** — spawn a child via `CreateProcess` with `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)` forging a launcher PID as parent; drain events and assert `HK_PROC_FLAG_REPARENT_SUSPECT` (199) and, with a `rundll32` proxy in the chain, `HK_PROC_FLAG_LOLBIN_ANCESTOR` (201). Must demonstrate true_creator ≠ declared_parent is caught.
- **`bypass-tests/linux/ptrace_attach.cpp`** (existing) — covers 205: launch a target under `PTRACE_ATTACH` and assert the traced-launch flag fires. Activate its assertions when the eBPF join lands.
- **`bypass-tests/linux/ld_preload_launch.cpp`** — exec a target with `LD_PRELOAD=<unlisted.so>`; assert the loader-taint flag fires and that an allowlisted overlay `.so` does **not** flag. Must demonstrate the linker-hijack vector is caught without flagging legitimate overlays.
- **`bypass-tests/macos/responsible_launder.cpp`** — launch the target from an unsigned/ad-hoc launcher with no store client in the chain; assert the responsibility-mismatch flag, and that a Steam-rooted chain does not flag. Must demonstrate responsibility laundering is caught.
- Manual-map (202) reuses/extends the existing `bypass-tests/macos/dylib_inject.cpp` pattern on the Windows side via `reparent_spoof.cpp`'s harness or a dedicated `manual_map.cpp` if the region-diff fixture grows — noted as a follow-up; 202's primary gate is the server reconciliation test.

All new bypass fixtures ship disabled pre-enforcement (return 0 / "DISABLED") so the gate stays green until the enforcement+sensor paths land, exactly as `byovd_load.cpp` / `ptrace_attach.cpp` do today.

---

## Sequencing

1. **Schema first (blocks everything):** land `HK_EVENT_PROCESS_CREATE_EX`, `HK_IMAGE_FLAG_MANUAL_MAP_SUSPECT`, `HK_EVENT_PAYLOAD_MAX` 16→24, the bumped asserts, and `HK_EVENT_SCHEMA_VERSION` 3 in `event_schema.h`/`ioctl.h` — plus the matching BPF `HK_SCHEMA_VERSION` and `Loader.cpp` constants. Update `server/api/data-categories.md` in the *same* PR (guardrail #11). Reviewer-confirm the new-type-vs-reserved-overload decision here.
2. **Windows kernel 199 (`proc_genealogy.c`)** — smallest, highest-value, needs only the create-notify already present. Lands `true_creator_pid` + reparent flag.
3. **Server correlation skeleton (`LaunchTrustReport` + `launcher-baseline.md`)** — needed before any flag is meaningful (ban authority is server-side). TDD the reparent + LOLBin gates.
4. **Userspace 201/203 (`ancestry_walker.cpp`, `token_check.cpp`)** — depend on (1) ancestry data + (3) the baseline store. 201 is the chain consumer of 199's data.
5. **202 (`module_reconcile.c` + `region_walk.cpp`)** — independent of 199 but needs the image-load notify set (kernel) and region walk (userspace) before the server reconcile.
6. **204 (`job_silo_check.cpp`)** — advisory-only, lowest priority, no ban path; lands after the higher-confidence signals.
7. **200 (`launch_timing.c`)** — **gated on the uncertainty resolution** (no kernel resume hook): land the timestamp emission + userspace thread-state sample, server computes the gap. Do not start until the timing approach is reviewer-approved.
8. **Linux 205/206 (`genealogy.bpf.c`, `loader_trust.bpf.c`)** — parallel to the Windows track; 205's LSM hook gated on BPF-LSM availability check, 206's envp scan gated on the `sys_enter_execve` envp-arg confirmation.
9. **macOS 207 (`genealogy_handler.cpp`)** — parallel; behind the ES entitlement, NOTIFY-only.
10. **Bypass tests** land *with* each enforcement path (disabled stubs land with the sensor; assertions activate with enforcement) — the gate requires the file present from the first PR touching each security folder.

---

## Risks & UNCERTAINTY FLAGS (guardrail #13 — not papered over)

- **[FLAG — signal 200, Windows kernel] No kernel resume notify.** There is no documented callback for `NtResumeThread`; "first thread RUN transition" cannot be observed reliably from kernel notify routines, and inspecting KTHREAD state at IRQL is undocumented/unsafe for this. **Resolution in plan:** kernel timestamps create + thread-create + first-image-load only; the suspend→resume gap is computed server-side from those plus a userspace `NtQuerySystemInformation(SystemProcessInformation)` thread-state sample. **Stop-and-confirm with the user before coding any kernel resume-tracking.**
- **[FLAG — signal 205, Linux] BPF-LSM availability on Steam Deck.** `lsm/ptrace_access_check` needs `CONFIG_BPF_LSM=y` + `bpf` in the boot-time `lsm=` list. The Deck (locked eBPF target) may not ship it. The tracepoint-join fallback must stand alone; the LSM hook is attach-gated, never hard-required. **Confirm Deck kernel config before relying on the LSM path.**
- **[FLAG — signal 206, Linux] execve envp read.** Reading `LD_PRELOAD`/`LD_AUDIT` from envp at `sys_enter_execve` must use the syscall's third arg (`envp`) via the tracepoint context, not stack-walking; the new-image stack is mid-setup. The verifier rejects unbounded env scans — fixed unroll bound (N≤32) + length-capped `bpf_probe_read_user_str`. **Confirm the `sys_enter_execve` context exposes `envp` as a readable arg on the target kernel; verify the bounded loop loads cleanly.**
- **[FLAG — signal 202] Unbacked-region heuristic FP surface.** "Executable region absent from image-load set and PEB Ldr" legitimately matches JIT (.NET/JVM/V8), packers, DRM, and anti-cheat's own JIT. The flag is a *suspect*, never a ban; server requires JIT-allocator attribution + unbacked + outside registered allocators before confirming. Do not autonomously ban on 202.
- **[Schema] Wire-size bump touches every consumer.** `hk_event_record` 40→48 and `HK_EVENT_PAYLOAD_MAX` 16→24 ripple through the kernel ring, `ioctl.h` asserts, BPF mirrors, `Loader.cpp`, and the server. Land schema as a single isolated PR with the asserts as the guard; a missed mirror fails the build (intended).
- **[Guardrail #11] Telemetry-field discipline.** Seven+ new fields reach the server; the PR adding any of them to `schema.rs` without the matching `data-categories.md` rows is reviewer-rejected. Treat the doc update as part of the schema PR, not a follow-up.
- **[Not a kernel-API uncertainty, but FP-tuning risk]** Every signal here is medium-to-high FP by the catalog's own assessment; the entire value depends on the signed-launcher / LOLBin / overlay allowlists in `launcher-baseline.md`. An empty or stale baseline turns these sensors into false-positive generators. The baseline store and its signing path are a prerequisite, not an afterthought.
