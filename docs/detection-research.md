# Detection Techniques Research

> Honest inventory of what Horkos currently detects vs. what commercial anti-cheats
> (Vanguard, BattlEye, EAC, Xigncode, Denuvo Anti-Cheat, nProtect GameGuard,
> etc.) actually deploy.  Categorized by platform and maturity level.
>
> Last updated: 2026-06-09
>
> Legend: [LIVE] = implemented and working in Horkos | [AUTHED] = kernel /
> eBPF code authored but not compiled/tested | [STUB] = interface / scaffolding
> only | [NEW] = not yet invented in this repo.

---

## Table of Contents

1. [Gap Summary](#gap-summary)
2. [Windows Kernel Detection](#windows-kernel-detection)
3. [Linux eBPF / LKM Detection](#linux-ebpf--lkm-detection)
4. [macOS EndpointSecurity / Daemon Detection](#macos-endpointsecurity--daemon-detection)
5. [Cross-Platform Techniques](#cross-platform-techniques)
6. [Server-Side Techniques](#server-side-techniques)
7. [Implementation Roadmap](#implementation-roadmap)

---

## Gap Summary

The biggest coverage gaps vs. production anti-cheats today:

| Category              | Horkos now | Production ACs |
|-----------------------|------------|----------------|
| Kernel memory scanning (open handles, module lists, IDT/GDT) | STUB | LIVE (all major) |
| Anti-debug depth       | STUB        | LIVE (all major) |
| Process injection detection (NtMapViewOfSection, APC, thread hijack) | STUB | LIVE |
| File system monitoring | STUB (Linux LSM file_open only) | LIVE (minifilter / FIM) |
| Network-level scam detection | STUB | LIVE (EAC WFP, ESE) |
| Timing / TSC side-channel | STUB | LIVE (Vanguard) |
| Hardware breakpoint abuse | STUB | LIVE |
| Atestation enforcement   | STUB        | LIVE (all major) |
| Client integrity verification | STUB | LIVE (hash game + AC images) |
| Hypervisor / VM detection | STUB | LIVE (Vanguard, EAC) |

Each section below lists specific techniques with the API to use and the cheat
class(es) each one detects.

---

## Windows Kernel Detection

### 1. Process / Thread / Image Notify (existing)       [LIVE]

- APIs: `PsSetCreateProcessNotifyRoutineEx`, `PsSetCreateThreadNotifyRoutine`,
  `PsSetLoadImageNotifyRoutine`
- Cheats caught: process injection targets, injected module loads, suspicious
  parent-child chains (e.g., `explorer.exe` spawning `cheat.exe`)
- Status: implemented in `kernel/win/src/Notify.c`

### 2. Cross-Process Handle Access (existing)              [LIVE]

- API: `ObRegisterCallbacks` on `PsProcessType` + `PsThreadType`
- Cheats caught: memory editors (Cheat Engine handle), debuggers, injectors
- Status: implemented in `kernel/win/src/Callbacks.c`

### 3. BYOVD Detection (existing, detect-only)             [LIVE]

- Mechanism: image-load notify consults static blocklist
- Cheats caught: bring-your-own-vulnerable-driver attacks
- Limitation: empty blocklist in Phase 3; detect-only

### 4. ETW-Ti (Extended Tracking — thread injection, APC, handle)  [NEW]

- API: `EtwTi` provider `(Microsoft-Windows-Threat-Intelligence)` via
  `EtwRegister` + `EtwSetInformation` with `EventSecurityDescriptor`
- What ETW-Ti emits:
  - `EventID 1`  — `KERNEL_THREATINT_TASK_ALLOCVM` (NtAllocateVirtualMemory
    cross-process)
  - `EventID 2`  — `KERNEL_THREATINT_TASK_PROTECTVM` (NtProtectVirtualMemory)
  - `EventID 3`  — `KERNEL_THREATINT_TASK_MAPVIEW` (NtMapViewOfSection — classic
    injection vector)
  - `EventID 4`  — `KERNEL_THREATINT_TASK_QUEUEAPC` (user-mode APC)
  - `EventID 5`  — `KERNEL_THREATINT_TASK_SETCONTEXT` (thread context hijack)
  - `EventID 6`  — `KERNEL_THREATINT_TASK_REMOTEATTACH`
  - `EventID 7`  — `KERNEL_THREATINT_TASK_SUSPEND` (process suspend via
    NtSuspendProcess)
  - `EventID 8`  — `KERNEL_THREATINT_TASK_RESUME`
  - `EventID 11` — `KERNEL_THREATINT_TASK_HANDLE` (duplicate handle request)
  - `EventID 12` — `KERNEL_THREATINT_TASK_SETTHREAD` (handle creation)
- Cheats caught: nearly every injection technique in a single provider — DLL
  injection via `MapViewOfSection`, thread hijack via `SetThreadContext`, APC
  injection, cross-process memory read/write
- IRQL: `PASSIVE_LEVEL` delivery; subscriber callback runs at `PASSIVE_LEVEL`
- Who uses it: Vanguard (confirmed reverse-engineered), EAC (confirmed),
  Windows Defender ATP
- Implementation: register a trace session with the TI provider GUID; events
  arrive as `EVENT_TRACE` callbacks.  Must run in a system worker thread, not
  in `DriverEntry`.
- BSOD risk: low — ETW infrastructure is safe at `PASSIVE_LEVEL`; the risk is
  only malformed event parsing.  Use safe string helpers per CLAUDE.md #5.

### 5. File System Minifilter                                        [NEW]

- API: `FltRegisterFilter` + altitude registration (Microsoft-assigned)
- Attach altitudes:
  - `328000–329998` — generic activity monitor (Microsoft-reserved; third-party
    filters must pick a non-conflicting altitude; contact Microsoft for one)
- Cheats caught:
  - Game executable / config tampering (e.g., modified `.pak` files in UE4)
  - Speedhack DLLs written to disk before injection
  - Wallhack shader replacement
  - Modified game config that enables illegal FOV / no-recoil
- IRQL: `PASSIVE_LEVEL` for pre/post callbacks on most operations; `APC_LEVEL`
  for some
- Complexity: high — full filter driver with altitude collision handling, PnP
  awareness, and detourUnload
- Who uses it: EAC (confirmed), BattlEye (likely), anti-DRM products
  (Denuvo, VMProtect staging)
- Note: Minifilter requires WHQL signing for production; test-signing works
  for dev.  For Phase N+1, consider a **passive monitoring-only** minifilter
  that logs creates/writes/deletes on the game directory without blocking.

### 6. Registry Callback (CmRegisterCallbackEx)                    [NEW]

- API: `CmRegisterCallbackEx` or `CmRegisterCallback`
- What to watch:
  - `RegNtPreSetValueKey` under `HKLM\SYSTEM\CurrentControlSet\Services` —
    service installation (BYOVD staging)
  - `RegNtPreSetValueKey` under `HKLM\SOFTWARE\Microsoft\Windows
    NT\CurrentVersion\Image File Execution Options` — debugger hijack (IFEO)
  - `RegNtPreSetValueKey` under `HKCU\...\Run` — persistence
  - `RegNtPreCreateKeyEx` under game-related keys — cheat config persistence
- Cheats caught: service-based persistence, debugger hijack, cheat config
  persistence
- IRQL: `PASSIVE_LEVEL`
- BSOD risk: moderate — registry callbacks run in the context of the calling
  thread and can block; long operations cause timeouts.  Do minimal work, defer
  ring-buffer writes.
- Who uses it: Vanguard (confirmed), Windows Defender

### 7. Network Detection via WFP Callout                             [NEW]

- API: `FwpmEngineOpen0`, `FwpmCalloutAdd0`, `FwpsCalloutRegister0` + `FWPM_LAYER_*`
- Layers:
  - `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` — outbound connection authorization
  - `FWPM_LAYER_ALE_ACCEPT_RECV_ACCEPT_V4/V6` — inbound connection authorization
  - `FWPM_LAYER_STREAM_V4/V6` — payload inspection (lightweight)
- Cheats caught:
  - Speedhack via network desync (detect anomalous tick rates)
  - Lag switches / packet manipulation
  - Proxy / VPN-based evasion (unexpected outbound to non-game IP)
  - Packet replay attacks (timing correlation)
- IRQL: `PASSIVE_LEVEL` for the callout function (if `FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW`);
  otherwise `DISPATCH_LEVEL` for inspection callouts (limited API surface)
- Complexity: very high — WFP is notoriously tricky to get signed and stable
- Recommendation: defer to post-production; start with userspace firewall
  (see Cross-Platform section)

### 8. Anti-Debug (Kernel Depth)                                   [NEW]

Beyond userspace `IsDebuggerPresent` (trivially bypassed):
- Check `KdDebuggerEnabled` and `KdDebuggerNotPresent` via `KdRefreshDebuggerNotPresent`
- Validate the `KdDebuggerEnabled` flag at `PASSIVE_LEVEL` (must not read at
  elevated IRQL — will bugcheck)
- Patch `KeServiceDescriptorTable` shadow / check sysenter MSR: if an unknown
  MSR hook exists, hardware breakpoints or inline hooks are active on kernel
  services
- Walk the loaded module list (`PsLoadedModuleList` — undocumented but stable)
  to find unsigned or unexpected kernel modules
- Cheats caught: kernel debuggers, live kernel patching, driver-based cheats
  that hook SSDT or service table
- Status: userspace stubs exist (`IsDebuggerPresent`, `TracerPid`,
  `P_TRACED`) — deliberately weak per CLAUDE.md
- BSOD risk: HIGH for SSDT/MSR probing.  `PsLoadedModuleList` walk must be
  under a guarded mutex.  Recommendation: **ship a reduced set + flag the
  MSR probe as a future phase.**

### 9. IDT / GDT Inspection                                          [NEW]

- API: `KeGetPcr()` → `PIDT` via assembly; `sgdt`/`sidt` store instructions
- Cheat class: kernel hooks of interrupt handlers (old-school rootkits, less
  common in game cheats but used by BYOVD toolkits)
- Status: not in codebase; moderate complexity, high value for BYOVD defense

### 10. Hypervisor / VM Detection                                    [NEW]

- Check CPUID.1:ECX[bit 31] (hypervisor present)
- Check hypervisor vendor string (CPUID leaf 0x40000000–0x40000005)
- In kernel: read `HYPERVISOR_PRESENT_BIT` flag via `KeQueryAuxiliaryCounterFrequency`
  + timing anomaly detection
- Validate MSR `HV_X64_MSR_GUEST_ID` for Hyper-V; `LGT` virtualization
- Cheats caught: cheats running in lightweight VMs to sandbox the game (common
  in professional cheating rings); analysis environments
- Note: legitimate users run Hyper-V / WSL — do not ban, just **flag** for
  risk scoring server-side

### 11. Timer / DPC / IO Timer Inspection                           [NEW]

- Walk `KiTimerTableListHead` (documented on MSDN for WDK, but changes between
  Windows versions)
- Enumerate registered `IoInitializeTimer` / `IoStartTimer` objects
- Cheats caught: timer-based aimbots and speedhacks that use `KeSetTimer` /
  `KeSetCoalescableTimer` with manipulated intervals
- BSOD risk: HIGH — timer table structure is version-specific.  Avoid in
  Phase N unless targeting a single Windows build.

### 12. Thread Start-Address Validation (improvement to #1)         [NEW]

- From `PsSetCreateThreadNotifyRoutine` or ETW-Ti event 5: inspect the thread's
  `StartAddress` (or `Win32StartAddress` from `NtQueryInformationThread`)
- Legitimate threads start inside `ntdll.dll`, `kernel32.dll`, or known game
  modules.  Suspicious threads start in heap, unknown DLL, or unmapped pages.
- Cheats caught: thread hijacking, reflective DLL injection via new threads

### 13. Kernel Handle Table Walking                                  [NEW]

- Given a PID, open the process with `ObReferenceObjectByHandle` (indirectly),
  then enumerate handles by walking `EPROCESS.ObjectTable`
- Cheats caught: Cheat Engine keeps handles open to the game process; debuggers
  hold `PROCESS_ALL_ACCESS` handles
- Complexity: high (undocumented structures) but stable across Windows 10/11
- BSOD risk: moderate — `ObjectTable` access must hold `EX_PUSH_LOCK`

### 14. Signed Driver Enforcement (Production)                      [NEW]

- In production: `SeValidateImageHeader` callbacks, Microsoft VBS/HVCI
- In development: verify that `PsLoadedModuleList` contains only
  `IMAGE_DOS_SIGNATURE` + `IMAGE_NT_SIGNATURE` modules with valid PE signing
- Cheats caught: BYOVD attacks (unknown drivers in kernel)
- **Production-only** — requires WHQL signing and MSFT attestation policy

### 15. Desktop Heap / Window Station Monitoring                     [NEW]

- API: `NtUserGetThreadState` (via syscall) or GUI-message hooks in the driver
- Cheats caught:
  - Overlay-based wallhacks (invisible window over game)
  - Input spoofing windows
- Status: not recommended for kernel path — this is better handled from a
  lightweight userspace component (see Cross-Platform)

---

## Linux eBPF / LKM Detection

### 1. Tracepoints (existing)                          [AUTHED]

- `tracepoint/syscalls/sys_enter_ptrace` — anti-debug
- `tracepoint/sched/sched_process_exec` — exec monitoring
- Status: authored in `kernel/linux/bpf/src/tracepoints.bpf.c`

### 2. LSM file_open Hook (existing)                    [AUTHED]

- LSM hook: `bprm_check_security` and `file_open`
- Status: authored in `kernel/linux/bpf/src/lsm_file_open.bpf.c`

### 3. Additional eBPF Hooks (new)                         [NEW]

#### 3a. `sched_process_exit` Tracepoint
- Fires on every `do_exit()`
- Cheat class: detects when a suspicious child process exits immediately after
  spawning (common in launcher-based cheats)
- BPF type: `BPF_PROG_TYPE_TRACEPOINT`

#### 3b. `sched_process_fork` / `sched_process_clone` Tracepoint
- Complement to exec monitoring; catches `fork()`+`exec()` chains
- Cheat class: process hollowing, zombie process spawns

#### 3c. `kprobe/do_mmap` / `kprobe/__x64_sys_mmap`
- Inspects `vm_area_struct` flags and permissions
- Cheat class: reflective DLL injection via `mmap(PROT_READ|PROT_WRITE|PROT_EXEC)`
- Flags to flag: `VM_EXEC` on anonymous mappings (not backed by a file) —
  classic shellcode injection marker
- BPF type: `BPF_PROG_TYPE_KPROBE` (requires BTF)

#### 3d. `kprobe/do_mprotect`
- Catches `mprotect(PROT_EXEC)` transitions on existing mappings
- Cheat class: self-modifying code, runtime decryption of cheat modules
- Who uses this: BattlEye Linux (confirmed via public eBPF programs)

#### 3e. `kprobe/__x64_sys_process_vm_writev`
- Cross-process memory write
- Cheat class: `WriteProcessMemory` equivalent — Cheat Engine, GameGuardian
- BPF type: `BPF_PROG_TYPE_TRACEPOINT` (sys_enter tracepoint)

#### 3f. `kprobe/__x64_sys_memfd_create`
- Creates anonymous in-memory file descriptors — popular injection vector
- Cheat class: reflective loading of cheat shared objects
- Detection: flag `memfd_create()` calls with suspicious names (random chars)
  or from non-game processes

#### 3g. `kprobe/__x64_sys_ptrace`
- Already partially covered by tracepoint; kprobe version allows inspection
  of `request` parameter at entry
- Flag `PTRACE_ATTACH`, `PTRACE_POKETEXT`, `PTRACE_POKEDATA` from non-debugger
  processes

#### 3h. `kprobe/__x64_sys_ptrace`
- Already partially covered by tracepoint; kprobe version allows inspection
  of `request` parameter at entry
- Flag `PTRACE_ATTACH`, `PTRACE_POKETEXT`, `PTRACE_POKEDATA` from non-debugger
  processes

#### 3i. LSM `bprm_check_security`
- Fires when `execve()` is called, BEFORE the new image runs
- Can DENY execution (AUTH LSM hook)
- Cheat class: prevents known-cheat binaries from executing
- Kill chain: deny `exec()` of anything in `/tmp`, `/dev/shm`, `$HOME/.local`
  that isn't on an allowlist

#### 3j. LSM `file_mprotect`
- Fires on `mprotect()` syscalls — complement to kprobe version
- Can deny `PROT_EXEC` transitions
- BPF type: `BPF_PROG_TYPE_LSM` (requires `CONFIG_BPF_LSM`)

#### 3k. LSM `mmap_file` + `mmap_addr`
- Controls file-backed and anonymous mmap
- Can block MMAP of game files or anonymous RWX regions
- BPF type: `BPF_PROG_TYPE_LSM`

#### 3l. Raw Tracepoint `signal_generate`
- Catches `kill(pid, SIGSTOP)` / `SIGKILL` targeting the game process
- Cheat class: process freeze attacks (freeze game state, edit, resume)
- BPF type: `BPF_PROG_TYPE_RAW_TRACEPOINT`

#### 3m. BPF Iterator for Process Enumeration
- Use `task`, `task_file`, `task_vma` BPF iterators to periodically walk
  all processes and their memory maps
- Cheat class: detects hidden processes, unexpected modules, RWX VMAs
- Implementation: a timer BPF program (BPF_PROG_TYPE_KPROBE on hrtimer or
  a userspace-triggered BPF event)

### 4. eBPF Map-Based Behavioral Heuristics                 [NEW]

- Maintain per-PID maps in BPF:
  - `ptrace_rate[pid]` — count ptrace calls per PID per window; flag > N
  - `exec_rate[pid]`  — count exec/s; flag bursts
  - `memfd_count[pid]` — count memfd_create calls
  - `mprotect_rwx_count[pid]` — count RWX transitions
- Server-side: feed these counts into the existing telemetry pipeline for
  risk scoring
- Zero additional kernel code — pure eBPF map logic

### 5. Namespace / Container Detection                       [NEW]

- Read `task->nsproxy` via `BPF_CORE_READ` to detect if the game process is
  running in a different PID, mount, or network namespace than expected
- Cheat class: some cheats try to run the game in a container to isolate
  memory access
- Low priority — rare attack vector but trivial to detect

### 6. BPF Map Tampering Detection                       [NEW]

Periodically validate that Horkos's own BPF maps haven't been modified:
- Use `bpf_map_lookup_elem` in kernel from a timer to read known sentinel values
- Verify ring-buffer consumer/producer positions haven't been forcibly advanced
- Cheat class: attackers trying to blind the driver by manipulating eBPF maps
- Who uses this: EAC (confirmed)

### 7. LKM Path (only where eBPF is unavailable)       [NEW]

eBPF limitations on kernel 4.x Steam Deck, certain hardened kernels where
`CONFIG_BPF_LSM=n`, or when you need attachment points BPf can't reach:
- `sys_call_table` monitoring (detect syscall hooks — fragile, version-specific)
- `filldir` interception for `/proc` hiding detection
- Netfilter hook for kernel-level packet inspection
- TTY ldisc hook for keylogger detection (old-school)
- **Recommendation**: only use the LKM path when eBPF truly can't deliver the
  detection, per CLAUDE.md locked decision #3.

### 8. Anti-Debug Extensions (Linux)                     [NEW]

Beyond `PTRACE_TRACEME` self-attach (existing stub):
- `/proc/self/status` `TracerPid` check — periodically re-read from userspace
- `PR_SET_DUMPABLE` manipulation detection (prctl)
- `seccomp` status inspection (confirm the process hasn't relaxed seccomp)
- `LD_PRELOAD` read from `/proc/self/environ` + `/proc/self/maps` — detect
  injected shared objects
- `perf_event_open` for hardware-breakpoint detection (HW breakpoint 0–3
  held by another process)
- `personality(ADDR_NO_RANDOMIZE)` — detect ASLR bypass attempts
- All of these can run from the macOS/Linux daemon userspace component
  without kernel code

---

## macOS EndpointSecurity / Daemon Detection

### 1. ES NOTIFY_EXEC + AUTH_EXEC (existing)                [LIVE]

- `ES_EVENT_TYPE_AUTH_EXEC` — gating exec (can deny)
- `ES_EVENT_TYPE_NOTIFY_EXEC` — observe-only exec
- Status: authored in `kernel/macos/es/EsClient.mm`
- Current behavior: observe-only (allows all)
- Improvement: escalate to AUTH_EXEC + deny-list for known cheat binaries

### 2. ES OPEN / UNLINK / RENAME / CREATE Events            [NEW]

- `ES_EVENT_TYPE_NOTIFY_OPEN` — intercept file-open attempts
- `ES_EVENT_TYPE_NOTIFY_UNLINK` — deletion monitoring
- `ES_EVENT_TYPE_NOTIFY_RENAME` — rename monitoring (cheat-stash-rename pattern)
- `ES_EVENT_TYPE_NOTIFY_CREATE` — new-file creation (cheat write to disk)
- Filter: only observe paths under:
  - Game application bundle (`*.app/Contents/`)
  - Game support directories (`~/Library/Application Support/<game>`)
  - Known cheat staging areas (`/tmp`, `/dev/shm`, `~/.config/.*`)
- Cheats caught: file replacement, config tampering, cheat binary staging

### 3. ES AUTH_OPEN (FILE_OPEN Gating)                       [NEW]

- `ES_EVENT_TYPE_AUTH_OPEN` — can deny file open
- Use: block open of game executable / config by non-game processes
- This is the macOS equivalent of a Windows minifilter
- Entitlement: required for AUTH events — must have Apple ES entitlement
  (self-gated on `HORKOS_MACOS_ES` per locked decision #4)

### 4. ES SIGNATURE / CODE SIGNING Events                     [NEW]

- `ES_EVENT_TYPE_NOTIFY_CS_VALIDATED` — code-signing validation events
- Inspect: `es_event_cs_validated_t.team_id`, `es_event_cs_validated_t.signing_id`
- Flag: processes with:
  - `team_id == NULL` (unsigned)
  - `flags & CS_KILL` (kill-flag set by kernel)
  - `flags & CS_FORCED_LV` (library validation forced — injection indicator)
- Cheats caught: unsigned cheat binaries, code-signing bypass, library injection
  with forced library validation

### 5. ES DYNAMIC_CODE Events                                [NEW]

- `ES_EVENT_TYPE_NOTIFY_DYLD_NOTIFY` (dyld image-mapping events in older ES)
- Newer ES: `ES_EVENT_TYPE_NOTIFY_EXEC` with `EXIT_REASON_INVALID_CS` flag
- Flag: any `mmap(MAP_ANON | PROT_EXEC)` from `mach_vm_map()` — kernel
  reports as missing code signature
- Cheats caught: reflective loading, JIT-spray attacks, memory-execution tricks

### 6. ES ENVIRONMENT VARIABLE Monitoring                    [NEW]

- `es_message_t.exec.init_*` fields (available in macOS 13 Ventura+):
  - `es_event_exec_t.argv[0..N]`
  - `es_event_exec_t.env` — full environment variable array
- Inspect for:
  - `DYLD_INSERT_LIBRARIES` (library injection)
  - `DYLD_LIBRARY_PATH` (library hijack)
  - `DYLD_FORCE_FLAT_NAMESPACE`
  - `OBJC_DISABLE_INITIALIZE_FORK_SAFETY`
  - `MallocScribble`, `MallocGuardEdges` (debug indicator)
  - Custom vars: `_MSSafeMode`, `DYLD_` prefix combos
- Cheats caught: dyld injection, Objective-C runtime tampering, anti-ASLR

### 7. ES AUTH_VNODE / AUTH_EXTLOOKUP (SIP-aware paths)     [NEW]

- `ES_EVENT_TYPE_AUTH_VNODE` — vnode-level authorization (macOS 13+)
- `ES_EVENT_TYPE_AUTH_EXTLOOKUP` — lookups past mount points
- Cheat class: accessing game binaries through unusual access paths
  (mount-loop attacks, bind mounts)

### 8. ES AUTH_MOUNT (macOS 13+)                            [NEW]

- `ES_EVENT_TYPE_AUTH_MOUNT` — gating filesystem mount
- Cheat class: mount-based isolation attacks, overlay filesystems used to
  hide cheat binaries
- Low priority — used by professional cheat vendors to hide their tools

### 9. ES NOTIFY_XPC / MACH Events                           [NEW]

- MACH IPC monitoring: inspect `mach_msg()` headers for cross-process
  communication patterns
- Cheat class: XPC proxy injection, MACH service hijacking
- ES does not have a dedicated XPC event type (as of macOS 15); monitor
  `MACH_MSG_TYPE_COPY_SEND` to known system services as proxy
- Alternative: register for `ES_EVENT_TYPE_NOTIFY_RECEIVE` on MACH messaging

### 10. ES AUTH_IOKIT_OPEN                                    [NEW]

- `ES_EVENT_TYPE_AUTH_IOKIT_OPEN` — gating IOKit user-client open
- Cheat class: DMA attacks via PCIe, custom kernel extension loading,
  frame buffer access for wallhack overlays (via IOKit)
- Block: non-Apple IOKit user-clients targeting the GPU class
  (`IOFramebuffer`, `IOPCIDevice`)

### 11. ES AUTH_TASK_FOR_PID (macOS 14+)                      [NEW]

- `ES_EVENT_TYPE_AUTH_TASK_FOR_PID` — gating task port acquisition
- **Critical** — this is the macOS equivalent of ObRegisterCallbacks for
  handle access.  `task_for_pid()` is required for memory inspection.
- Deny: `task_for_pid()` requests targeting the game process from non-Apple,
  non-game processes
- Cheats caught: nearly every memory hack on macOS requires `task_for_pid()`
  — blocking it stops Cheat Engine, GameGuardian, and nearly all macOS cheats
  at once
- Entitlement: `com.apple.security.get-task-allow` (development builds) or
  SIP-disabled (test environments).  Production requires Apple approval.

### 12. Hardware Breakpoint / Debug Register Monitoring      [NEW]

- From daemon: read `thread_get_state(..., ARM_DEBUG_STATE64)` for each thread
- Or on x86_64: read `thread_get_state(..., x86_DEBUG_STATE64)`
- Cheat class: hardware breakpoints used by anti-anti-cheat tools to bypass
  software breakpoints; also used by speedhacks to step-execute
- Complexity: moderate — requires TASK_INSPECT_PORT (weaker than TASK_ALL_PORT)
- Platform: Apple Silicon and x86_64 supported

### 13. Framebuffer / Screen Capture Detection              [NEW]

- Monitor `CGWindowListCreateImage` API usage from non-game processes
  (requires EndpointSecurity `NOTIFY_RENAME` + code-signing checks)
- Monitor `IOSurface` creation + `IOMobileFramebufferGetLayer` for
  screen-scraping bots (ESP bots)
- Low priority — detection is noisy (legitimate screen recorders)

### 14. System Extension Integrity Check                    [NEW]

- Verify Horkos's own kernel extension / system extension is unmodified:
  - Read bundle identifier at boot
  - Monitor `/Library/SystemExtensions/` for changes via `FSEvents` or
    `notifyd`
- Cheat class: tampering with or unloading the anti-cheat extension itself

### 15. System Integrity Protection (SIP) Enforcement Check   [NEW]

- Read `csr-active-config` via `sysctl kern.csr_active_config`
- Or use `csr_check()` from libc for specific flags
- Cheat class: SIP-disabled machines (required for some kernel-level cheats)
- Recommendation: **flag** for risk scoring; do not ban — legitimate users
  disable SIP for development / Hackintosh builds

---

## Cross-Platform Techniques

### 1. Memory Integrity Verification (Userspace)         [NEW]

- Walk `/proc/self/maps` (Linux) or `VirtualQueryEx` (Windows) or
  `mach_vm_region_recurse` (macOS) to enumerate the calling process's memory map
- Flag:
  - RWX (Read-Write-Execute) memory regions
  - Anonymous executable mappings
  - Memory backed by deleted files (`(deleted)` in `/proc/self/maps`)
  - Modules loaded from `/tmp`, `/dev/shm`, or `$HOME`
- Run at periodic intervals or after a suspicious event
- Server-side: hash the memory map and compare to a known-good baseline
  for the game

### 2. Environment Integrity Scan (Userspace)            [NEW]

- Read `/proc/self/environ` → check for `LD_PRELOAD`, `LD_AUDIT`, `DYLD_*`
- Check loaded shared objects (`/proc/self/maps`, `dlllist` on Windows,
  `_dyld_get_image_name()` on macOS) for unknown libraries
- Scan running processes for known cheat-suite names (`gameguardian`,
  `cheatengine`, `frida_server`, `xposed`, `substrate`)
- Check `/proc/pid/exe` symlinks for suspicious paths

### 3. Filesystem Integrity Monitoring (Userspace)         [NEW]

- Compute HMAC-SHA256 (with TPM-backed key) of game binary, game config,
  anti-cheat binary
- Re-verify on each heartbeat
- HMAC incorporates TPM/SE measurement so client can't forge it
  (server-side verification)
- Cheat class: game binary patching, config tampering, AC binary replacement

### 4. Behavioral Timing Analysis (Userspace / Server)    [NEW]

- Client-side: measure tick time deltas; report to server
  (`QueryPerformanceCounter` / `CLOCK_MONOTONIC` / `mach_absolute_time`)
- Server-side: compare reported tick deltas to expected server tick
  - Consistent deviation → speedhack / clock manipulation
  - Irregular spikes → lag switch / network manipulation
- Also detects: RDTSC/TSC-based cheats (the common speedhack API pattern is
  `rdtsc` delta manipulation)

### 5. Input Device Fingerprinting                          [NEW]

- Windows: `Raw Input API` (`GetRawInputData`) — identify unique devices
- Linux: `libevdev` — read `/dev/input/event*` device names, vendor/product IDs
- macOS: `IOHIDManager` — iterate HID devices
- Check for:
  - Virtual input devices (VMware Virtual USB Mouse, vJoy)
  - VM-synthesized keyboards (VirtualBox, QEMU)
  - USB-based keyboard emulators (arduino-based aimbot controllers)
- Cheat class: hardware-based input spoofing (common in professional cheating)

### 6. Network-Level Anomaly Detection                     [NEW]

- No kernel WFP / eBPF needed to start — in userspace daemon:
  - Track packets/sec; flag > N standard deviations from mean
  - Monitor for unexpected outbound connections (non-game-server IPs)
  - Detect DNS-over-HTTPS / DoH usage (DPI evasion)
  - Correlate network events with in-game action timestamps
- Later: escalate to kernel WFP / eBPF once the server ML model can consume
  network anomaly features

### 7. Windows Message Hook Detection (All platforms)       [NEW]

- Detect SetWindowsHookEx / WH_CBT / WH_SHELL hooks pointing into foreign DLLs
- On macOS: check `CGEventTap` for non-game taps
- On Linux: check X11 selection ownership, `XGrabKey` calls
- Cheat class: input interception hooks, overlay injection, alt-tab detection

### 8. Anti-Tampering (Self-Integrity)                     [NEW]

- Client AC component checks its own PE/ELF/Mach-O binary for modification
  (HMAC with TPM key)
- Check that process is running with expected privilege level
- Check for `ptrace` attach (Linux: read `/proc/self/status` `TracerPid`)
- Check for debugger attachment (Windows: `CheckRemoteDebuggerPresent`,
  `NtQueryInformationProcess` `DebugPort`; macOS: `sysctl
  P_TRACED`)
- If tamper detected: escalate attestation failure to server; **never
  self-ban** (ban authority is server-side per guardrail #1 on README)

### 9. Server-Side Statistical / ML Detection            [NEW]

All push features into ONNX model via existing telemetry pipeline:

| Feature vector                  | Source component  | Cheat class                     |
|--------------------------------|-------------------|---------------------------------|
| Aim delta variance per tick    | Input telemetry   | Aimbot (inhuman consistency)     |
| Reaction time distribution     | Input + game event| Aimbot (impossibly fast snap)    |
| Input event entropy            | Raw input stream  | Bot (too-consistent patterns)    |
| Crosshair distance at fire     | Aim coordinates   | Aimbot (distance → 0 consistently)|
| Headshot ratio over time       | Server game event | Aimbot (abnormal accuracy)       |
| Movement pattern analysis      | Position stream   | Wallhack (prefire around corners)|
| Network tick delta variance    | Client timing     | Speedhack / lag switch           |
| Process enumeration anomalies  | Driver telemetry  | Memory hack tools                |
| Memory map entropy changes     | Client integrity  | DLL injection                    |
| Player report correlation      | Community reports | Any cheat type                   |
| Hardware input device changes  | Input fingerprint | Account sharing / bot farms      |

- Implementation note: existing Rust `ort` crate is wired; what's needed is:
  1. Feature extraction server crate
  2. ONNX model (start with logistic regression → random forest)
  3. Fall-back to rule-based scoring until model quality is proven

### 10. Process Hollowing Detection                       [NEW]

- Windows: compare PEB `ImageBaseAddress` with the module from `LDR_DATA_TABLE_ENTRY` in `InMemoryOrderModuleList` — mismatch = hollowing
- Linux: read `/proc/pid/exe` symlink and `/proc/pid/maps` text segment; mismatch
  between expected binary path and actual mapped text
- macOS: `task_info(TASK_DYLD_INFO)` → compare `all_image_info_addr` base
  with the expected Mach-O address
- Cheat class: process hollowing — a legitimate process (e.g., `notepad.exe`
  or `svchost.exe`) is hollowed out and replaced with the cheat in memory

---

## Server-Side Techniques

### 1. Signed Rule Bundles (improvement)                   [STUB]

- Current: `server/ban-engine` has bundle plumbing but no real Ed25519 verify
- Action: Implement `ed25519_dalek` verification of rule bundles
- Add fail-closed: if signature verification fails → no local rule enforcement
- Locked decision #10 (compile-time gate) already exists

### 2. Account Reputation System                           [NEW]

- Per-account scoring from the feature vectors in §Server-Side ML Detection
- Cross-account clustering (multiple accounts, same hardware ID → linked)
- Device fingerprint correlation (TPM attestation → identity binding)
- Reputation feeds into the ban-engine risk score

### 3. Game-Sanctioned Telemetry Correlation               [NEW]

- Game server already sees: shots fired, hits, kills, positions, ticks
- Fuse game-server telemetry with client-side detection events:
  - Client reports suspicious memory map → server checks if player accuracy
    spiked at the same moment
  - Server detects impossible aim snap → client re-scans memory map of that
    player
- This two-sided approach is what makes Vanguard and EAC effective: neither
  side alone is sufficient

### 4. Ghost / Shadow Banning                             [NEW]

- Players flagged by ML model enter a pool matched only with other flagged
- No explicit ban notification — cheats lose effectiveness (matched with
  other cheaters) without knowing they've been caught
- Industry standard: Valve (VAC), Riot (Vanguard), Epic (EAC)

### 5. Hardware Bans (Persistent)                          [NEW]

- TPM-based machine identity (the whole point of the `Attestation` interface)
- On first detection: bind the hardware identity to a ban record
- Cheat class: prevents account-evasion cheaters from simply making new
- Note: limited effectiveness if the cheater can spoof TPM (VMs do this); use
  along with account bans

---

## Implementation Roadmap

Phase the new techniques roughly as follows, balancing detection value
against implementation risk:

### Tier 1 — High value, low kernel risk

1. **ETW-Ti subscription** (Windows) — massive injection coverage in one API
2. **LSM bprm_check_security** deny-list (Linux) — blocks cheat execs entirely
3. **ES AUTH_EXEC + AUTH_OPEN** escalation (macOS) — gate file/exec operations
4. **Process hollowing detection** (all platforms) — high detection value
5. **Environment integrity scan** (userspace, all platforms)
6. **eBPF map behavioral heuristics** (Linux) — pure eBPF, no new hooks

### Tier 2 — Medium risk, fill coverage gaps

7. **Registry callback** (Windows `CmRegisterCallbackEx`)
8. **ES CODE_SIGNING validation** (macOS §4)
9. **ES AUTH_TASK_FOR_PID** denial (macOS §11) — huge coverage on macOS
10. **Filesystem HMAC + attestation** (all platforms)
11. **Server-side feature extraction + ONNX logreg** (wire existing `ort` crate)

### Tier 3 — Higher complexity, production gates

12. **File system minifilter** (Windows — requires WHQL for production)
13. **ES AUTH_IOKIT_OPEN** denial (macOS — blocks DMA + GPU abuse)
14. **WFP callout** (Windows — very complex, defer to post-production)
15. **Kernel Handle Table walking** (Windows — undoc structures)
16. **Hardware breakpoint monitoring** (macOS)
17. **Server-side reputation system** (database + ML pipeline)

### Tier 4 — Nice-to-have / research

18. **IDT/GDT inspection** (Windows)
19. **Timer table walking** (Windows)
20. **VM detection** (all platforms)
21. **Screen capture detection** (macOS)
22. **Input device fingerprinting** (cross-platform)
