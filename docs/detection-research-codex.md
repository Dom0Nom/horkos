# Horkos Detection Research Codex Addendum
This document complements, and does not duplicate, the existing Horkos detection research docs by defining read-only observer signals, clean baselines, anomaly gates, and Horkos integration slots.

Document role: defensive host-integrity observability research. Target platforms: Windows, Linux, macOS, PCIe/DMA surfaces, Horkos client integrity, and server-side behavioral telemetry. Interface: plugs into existing Horkos event, telemetry, DMA, EndpointSecurity, eBPF, and kernel ring-buffer modules; no source logic is implemented here.

## Windows Kernel: Hypervisor, ETW, VAD, Driver, and DKOM Observers

### 1. Hypervisor Leaf and MSR Posture Mismatch
- **Name and Platform/Layer**: Hypervisor leaf and MSR posture mismatch; Windows kernel.
- **Observable**: Clean baseline is CPUID, Hyper-V/VBS state, and virtualization MSRs agreeing with the installed Windows virtualization stack. Anomaly is a hypervisor-present bit, vendor leaf, VMX/SVM enablement, or synthetic MSR posture that contradicts VBS/Hyper-V policy evidence.
- **Mechanism**: Sample `__cpuidex` leaves `1` and `0x40000000`, `__readmsr(IA32_FEATURE_CONTROL)`, `__readmsr(IA32_VMX_BASIC)` only when CPUID advertises VMX, and documented Windows VBS posture through `NtQuerySystemInformation(SystemCodeIntegrityInformation)` plus the Device Guard registry/WMI surface from a userspace companion.
- **Tampering class surfaced**: Covert bare-metal hypervisors, EPT/NPT inspection layers, and pre-boot loaders hiding behind malformed virtualization identity.
- **False-positive risk + gating**: Hyper-V, VBS, WSL2, VMware, and cloud PCs are legitimate. Gate on contradictions, not virtualization alone, and require corroboration from timing or memory-view signals before enforcement.
- **Horkos slot**: New passive Windows telemetry worker adjacent to `kernel/win/src/Notify.c`, with usermode VBS corroboration through `sdk/src/backends/win/DriverProbeWin.cpp`.

### 2. EPT Read-Versus-Execute Permission Split
- **Name and Platform/Layer**: EPT read-versus-execute permission split; Windows kernel.
- **Observable**: Clean baseline has similar read and execute timing for hot, immutable Horkos code pages after cache-warm controls. Anomaly is a stable execute-only penalty or asymmetric page behavior where reads see normal bytes but execution incurs VM-exit-like latency.
- **Mechanism**: From a pinned passive worker, time a volatile byte read and a call into the same known RX page with `__rdtscp`, compare against control pages, and correlate with CPUID hypervisor leaves. This is read-only timing, not page-table mutation.
- **Tampering class surfaced**: EPT/NPT execute hooks that return clean bytes on read while redirecting execution.
- **False-positive risk + gating**: VBS, EDR hypervisors, CPU power transitions, and SMI noise affect timing. Gate on persistent multi-page asymmetry across processor affinity pins and never ban on this alone.
- **Horkos slot**: Future `kernel/win/src/Timing.c`; reported through `sdk/include/horkos/event_schema.h` after data-category declaration.

### 3. Shadowed Syscall Entry Cross-View
- **Name and Platform/Layer**: Shadowed syscall entry cross-view; Windows kernel plus userspace companion.
- **Observable**: Clean baseline has `IA32_LSTAR`, `IA32_SYSENTER_EIP`, and `ntdll.dll` syscall stubs resolving into expected kernel and KnownDll ranges for the OS build. Anomaly is a syscall entry MSR outside known signed kernel image ranges or user stubs dispatching to unexpected service numbers.
- **Mechanism**: Read `__readmsr(0xC0000082)` and `__readmsr(0x176)` in kernel at `PASSIVE_LEVEL`; parse `ntdll.dll` from `\KnownDlls` in userspace and compare `mov eax, imm32; syscall` stubs against a build-bound baseline.
- **Tampering class surfaced**: SSDT/syscall redirection, usermode syscall-stub patching, and hypervisor-mediated syscall interception.
- **False-positive risk + gating**: Windows build drift changes syscall IDs, and secure-kernel ranges vary. Gate by exact build number, image timestamp, and signed module ownership.
- **Horkos slot**: Windows usermode collector plus a guarded kernel integrity module; correlation with `kernel/win/src/Callbacks.c` handle-open telemetry.

### 4. ETW Threat-Intelligence Provider Health
- **Name and Platform/Layer**: ETW-TI provider health; Windows kernel/user service.
- **Observable**: Clean baseline is the `Microsoft-Windows-Threat-Intelligence` provider emitting expected memory, APC, and handle events that correlate with Horkos object callbacks. Anomaly is provider silence, disabled sessions, or access-control drift while Horkos still sees suspicious handles/images.
- **Mechanism**: Run an ETW trace session with `EnableTraceEx2` for the Threat-Intelligence provider and compare event cadence against `ObRegisterCallbacks` emissions from `kernel/win/src/Callbacks.c`.
- **Tampering class surfaced**: ETW-TI blinding, event-provider patching, or session control abuse by anti-EDR loaders.
- **False-positive risk + gating**: ETW-TI availability differs by edition, build, and privilege. Establish startup health first and treat later silence as a tamper score only when a parallel Horkos source still fires.
- **Horkos slot**: Windows service ETW collector mapped into `HK_EVENT_HANDLE_OPEN` correlation and `server/telemetry/src/schema.rs` features.

### 5. ETW Session Control Actor Inventory
- **Name and Platform/Layer**: ETW session control actor inventory; Windows usermode service.
- **Observable**: Clean baseline has ETW sessions controlled by Windows, Horkos, developer profilers, or trusted EDR. Anomaly is an unsigned or untrusted process starting, stopping, or reconfiguring Horkos-relevant providers near telemetry gaps.
- **Mechanism**: Subscribe to `Microsoft-Windows-Kernel-EventTracing` and record `StartTrace`, `ControlTrace`, `EnableTraceEx2`, and `NtTraceControl`-backed changes with controlling PID and signer metadata.
- **Tampering class surfaced**: Trace-session starvation, provider disablement, and anti-observability tooling.
- **False-positive risk + gating**: WPR, WPA, `logman.exe`, Visual Studio, and EDRs control ETW legitimately. Gate by signer, provider affected, and temporal proximity to handle/memory anomalies.
- **Horkos slot**: Windows daemon collector feeding `server/telemetry`; no kernel edit required.

### 6. PatchGuard Surface Usermode Corroborator
- **Name and Platform/Layer**: PatchGuard surface usermode corroborator; Windows usermode plus kernel snapshot.
- **Observable**: Clean baseline is code-integrity, kernel-debugger, test-signing, and loaded-driver posture remaining stable during a session. Anomaly is a mid-session shift in Code Integrity or debugger state, or Windows event-log evidence of CI failures after vulnerable-driver loading.
- **Mechanism**: From usermode, sample `NtQuerySystemInformation(SystemCodeIntegrityInformation)`, `NtQuerySystemInformation(SystemKernelDebuggerInformation)`, BCD/test-signing state, and Code Integrity operational log entries; correlate with driver image loads reported by `PsSetLoadImageNotifyRoutine`.
- **Tampering class surfaced**: DSE bypasses, kernel debugger enablement, PatchGuard-adjacent tamper attempts, and CI policy rollback.
- **False-positive risk + gating**: Developer and test-signed systems are common. Gate on unexpected changes after game start and on conflict with signed attestation posture, not on dev posture alone.
- **Horkos slot**: `kernel/win/src/Notify.c` image-load correlation plus Windows daemon health telemetry.

### 7. Fileless Executable VAD With No Image Backing
- **Name and Platform/Layer**: Fileless executable VAD with no image backing; Windows kernel.
- **Observable**: Clean baseline has game executable pages backed by `MEM_IMAGE` regions with valid section objects, except known JIT/engine allocations. Anomaly is persistent `PAGE_EXECUTE*` memory of type `MEM_PRIVATE` or executable VADs without a file-backed `ControlArea`.
- **Mechanism**: Query protected-process regions with `ZwQueryVirtualMemory(MemoryBasicInformation)` and only perform symbol-gated VAD inspection when offsets are validated for the build.
- **Tampering class surfaced**: Manual mapping, shellcode allocation, reflective loaders, and hidden module payloads.
- **False-positive risk + gating**: JIT engines, anti-tamper packers, and shader compilers can allocate executable memory. Gate by known engine allocator ranges, match phase, and recent external handle/APC events.
- **Horkos slot**: Future `kernel/win/src/ProcessMemory.c`, correlated with existing `kernel/win/src/Callbacks.c`.

### 8. Module-Stomp Dirty Image Page
- **Name and Platform/Layer**: Module-stomp dirty image page; Windows kernel.
- **Observable**: Clean baseline has immutable `.text` pages of loaded game/AC modules matching their file-backed image. Anomaly is a `MEM_IMAGE` region whose in-memory page hash differs from its signed file image after loader quiescence.
- **Mechanism**: Use `PsSetLoadImageNotifyRoutine` load records, `MmCopyVirtualMemory` for sampled image pages, and passive-worker file reads through `ZwCreateFile`/`ZwReadFile` to hash the corresponding section bytes.
- **Tampering class surfaced**: Module stomping and copy-on-write patching of legitimate DLL code sections.
- **False-positive risk + gating**: Legitimate hotpatching, overlays, launchers, and game updates can modify code. Restrict to Horkos/game-owned immutable modules and suppress during patch/update windows.
- **Horkos slot**: Extends image-load telemetry from `kernel/win/src/Notify.c`.

### 9. Thread Start and Context Provenance
- **Name and Platform/Layer**: Thread start and context provenance; Windows kernel with native-query caveat.
- **Observable**: Clean baseline has new game threads starting in known game, runtime, or system module ranges with stack pointers inside expected TEB stack bounds. Anomaly is start RIP or current context in private executable memory, a stack pivot, or start-address divergence.
- **Mechanism**: Use `PsSetCreateThreadNotifyRoutine` for trigger, defer to a passive worker, and prefer `NtQueryInformationThread(ThreadQuerySetWin32StartAddress)` from a trusted service. `PsGetThreadStartAddress`, `PsGetContextThread`, and `PspGetContextThreadInternal` are undocumented or symbol-sensitive; treat them as research-only until validated per Windows build.
- **Tampering class surfaced**: Remote-thread injection, context hijacking, stack pivoting, and shellcode starts.
- **False-positive risk + gating**: Thread pools, fibers, and runtime dispatchers start in generic system thunks. Gate on final resolved instruction pointer and memory-region ownership, not the dispatcher alone.
- **Horkos slot**: Extends the live but currently schema-less thread path in `kernel/win/src/Notify.c`.

### 10. BYOVD Hash Inventory via Horkos IOCTL
- **Name and Platform/Layer**: BYOVD hash inventory via Horkos IOCTL; Windows kernel/userspace.
- **Observable**: Clean baseline has loaded drivers matching trusted signer/hash inventory. Anomaly is a loaded vulnerable driver hash, renamed vulnerable binary, or driver path whose file hash is unavailable/deleted after load.
- **Mechanism**: Kernel reports loaded image base/path from `PsSetLoadImageNotifyRoutine`; the usermode service requests inventory over Horkos IOCTLs defined by `sdk/include/horkos/ioctl.h`, opens the image path, and hashes with Windows CNG `BCryptHashData`.
- **Tampering class surfaced**: Bring-your-own-vulnerable-driver loaders and post-load artifact deletion.
- **False-positive risk + gating**: Hardware utilities may load vulnerable historical drivers. Gate by vulnerable hash/version, active game session, and presence of dangerous device objects or memory handles.
- **Horkos slot**: Existing `kernel/win/src/Notify.c`, `kernel/win/src/Whitelist.c`, `sdk/src/backends/win/DriverProbeWin.cpp`.

### 11. EPROCESS DKOM Cross-View
- **Name and Platform/Layer**: EPROCESS DKOM cross-view; Windows kernel.
- **Observable**: Clean baseline has process PIDs agreeing across process notify history, handle references, active process enumeration, and system process snapshots. Anomaly is a PID referenced by handles/threads but missing from one process list view.
- **Mechanism**: Compare Horkos process-create/exit history, `ZwQuerySystemInformation(SystemProcessInformation)`, process handles captured by `ObRegisterCallbacks`, and symbol-gated `EPROCESS.ActiveProcessLinks` only when build layouts are known.
- **Tampering class surfaced**: Kernel DKOM process hiding and process list unlinking.
- **False-positive risk + gating**: Process exit races and PID reuse cause transient divergence. Gate on resampling, create-time matching, and persistent discrepancy over multiple ticks.
- **Horkos slot**: `kernel/win/src/Notify.c`, `kernel/win/src/Callbacks.c`, and server correlation in `server/telemetry`.

### 12. Driver Object Dispatch Pointer Ownership
- **Name and Platform/Layer**: Driver object dispatch pointer ownership; Windows kernel.
- **Observable**: Clean baseline has `DRIVER_OBJECT.MajorFunction` and `FastIoDispatch` pointers belonging to the owning signed driver image. Anomaly is a dispatch pointer redirected into an unrelated module or non-image executable memory.
- **Mechanism**: Enumerate loaded driver objects reachable from known device objects, resolve dispatch pointers to module ranges from `ZwQuerySystemInformation(SystemModuleInformation)` or `AuxKlibQueryModuleInformation`, and report ownership mismatches.
- **Tampering class surfaced**: IRP dispatch hooking, filter hijack, and kernel implant interception.
- **False-positive risk + gating**: Some legitimate filters wrap I/O paths. Gate by signed module ownership, altitude/stack position, and whether the target is Horkos or game-relevant devices.
- **Horkos slot**: Adjacent to `kernel/win/src/IrpDispatch.c` self-protection checks.

### 13. Object Callback Altitude Neighbor Drift
- **Name and Platform/Layer**: Object callback altitude neighbor drift; Windows kernel.
- **Observable**: Clean baseline has Horkos object callbacks registered at the expected altitude with stable neighboring callback entries. Anomaly is Horkos callback removal, disabled flags, or a new untrusted callback immediately above Horkos that strips evidence first.
- **Mechanism**: Use `ObRegisterCallbacks` return state as primary evidence; any callback-list walk is undocumented and must be symbol-gated and read-only. Correlate with handle-open telemetry unexpectedly dropping to zero.
- **Tampering class surfaced**: Anti-observability drivers suppressing process/thread handle telemetry.
- **False-positive risk + gating**: Security products legitimately register callbacks. Gate by signer, altitude, and telemetry liveness, and skip undocumented list inspection when symbols are missing.
- **Horkos slot**: `kernel/win/src/Callbacks.c` liveness and `kernel/win/include/horkos_kernel.h` status fields.

### 14. Kernel Module Cross-View With AuxKlib
- **Name and Platform/Layer**: Kernel module cross-view with AuxKlib; Windows kernel.
- **Observable**: Clean baseline has `AuxKlibQueryModuleInformation`, `ZwQuerySystemInformation(SystemModuleInformation)`, and image-load history agreeing on loaded modules. Anomaly is a module present in one view but absent in another, or an image-load record with no surviving module entry.
- **Mechanism**: Initialize AuxKlib with `AuxKlibInitialize`, query module ranges, compare to `SystemModuleInformation`, and reconcile with Horkos image-load events.
- **Tampering class surfaced**: Unlinked drivers, manually mapped drivers, and post-load artifact scrubbing.
- **False-positive risk + gating**: Driver load/unload races produce short mismatches. Resample after a delay and suppress known unload windows.
- **Horkos slot**: Future `kernel/win/src/DriverInventory.c` fed by `kernel/win/src/Notify.c`.

### 15. Kernel Handle Rights Histogram
- **Name and Platform/Layer**: Kernel handle rights histogram; Windows kernel.
- **Observable**: Clean baseline has low-rate, low-rights handle access to the game from expected processes. Anomaly is repeated `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`, `PROCESS_CREATE_THREAD`, or thread-context rights from a foreign process.
- **Mechanism**: Aggregate `OB_OPERATION_HANDLE_CREATE` and `OB_OPERATION_HANDLE_DUPLICATE` records already emitted by `ObRegisterCallbacks`, preserving `OriginalDesiredAccess` as intent.
- **Tampering class surfaced**: Memory editors, debuggers, injectors, handle-duplication chains, and process-open polling.
- **False-positive risk + gating**: Task Manager, Process Explorer, EDR, and accessibility tools enumerate processes. Gate by access mask, rate, signer, and target-specific persistence.
- **Horkos slot**: Existing `kernel/win/src/Callbacks.c`; feature extraction in `server/telemetry`.

### 16. Kernel ETW Write-Path Prologue Owner
- **Name and Platform/Layer**: Kernel ETW write-path prologue owner; Windows kernel.
- **Observable**: Clean baseline has ETW write routines beginning with expected bytes and branch targets inside signed Windows modules. Anomaly is a trampoline or branch island outside `ntoskrnl.exe`, `ntdll` user stubs, or trusted EDR modules.
- **Mechanism**: Symbol-resolve ETW write routines in a build-gated passive worker, read the first cache line, and classify `JMP/CALL/MOV RAX; JMP RAX` patterns without patching anything.
- **Tampering class surfaced**: ETW patching used to blind Threat-Intelligence or kernel providers.
- **False-positive risk + gating**: EDRs can instrument ETW. Gate by signer, branch target module, and simultaneous provider-health loss.
- **Horkos slot**: Windows integrity collector correlated with signal 4.

## Windows Usermode: Render, Overlay, Input, Instrumentation, and Memory Observers

### 17. DXGI Present VTable Ownership
- **Name and Platform/Layer**: DXGI Present vtable ownership; Windows usermode.
- **Observable**: Clean baseline has `IDXGISwapChain::Present`, `Present1`, and resize vtable entries resolving into `dxgi.dll`, Direct3D runtime DLLs, GPU driver DLLs, or the game renderer. Anomaly is a vtable slot pointing to an untrusted module, heap allocation, or private executable page.
- **Mechanism**: Obtain the active swapchain from the game renderer, read vtable slots, resolve addresses with `VirtualQuery` and `GetModuleHandleEx`, and inspect signer/path with `WinVerifyTrust`.
- **Tampering class surfaced**: ESP overlays, render-menu hooks, and DirectX Present detours.
- **False-positive risk + gating**: Steam, Discord, NVIDIA, AMD, OBS, ReShade, and accessibility overlays hook rendering. Gate by signer allowlist, user opt-in, and memory-read correlation.
- **Horkos slot**: `sdk/src/backends/win/` render-integrity probe feeding `server/telemetry`.

### 18. Present Prologue and VTable Double-View
- **Name and Platform/Layer**: Present prologue and vtable double-view; Windows usermode.
- **Observable**: Clean baseline has both vtable pointer and target function prologue matching the mapped image. Anomaly is a normal-looking vtable whose target prologue starts with a trampoline or whose first bytes differ from the file-backed image.
- **Mechanism**: Compare vtable target bytes from process memory against the corresponding PE section on disk using `CreateFileW`, `CreateFileMappingW`, `MapViewOfFile`, `VirtualQuery`, and PE section RVAs.
- **Tampering class surfaced**: Inline Present hooks that preserve vtable ownership.
- **False-positive risk + gating**: Legitimate overlays and hotpatch frameworks can patch prologues. Gate by signer and known overlay policy; report as advisory when only a trusted overlay is present.
- **Horkos slot**: Windows SDK self-integrity backend plus `server/api/data-categories.md` when promoted to telemetry.

### 19. Layered Transparent Overlay Window
- **Name and Platform/Layer**: Layered transparent overlay window; Windows usermode.
- **Observable**: Clean baseline has top-level windows over the game belonging to the game, shell, or known overlays. Anomaly is a topmost layered/transparent/tool window intersecting the game rect without taskbar presence or trusted signer.
- **Mechanism**: Enumerate with `EnumWindows`, inspect `GetWindowLongPtrW(GWL_EXSTYLE)` for `WS_EX_LAYERED`, `WS_EX_TRANSPARENT`, `WS_EX_TOPMOST`, `WS_EX_TOOLWINDOW`, map HWND to PID with `GetWindowThreadProcessId`, and validate signer/path.
- **Tampering class surfaced**: External ESP overlays and click-through cheat menus.
- **False-positive risk + gating**: Discord, Steam, Xbox Game Bar, OBS, capture tools, and accessibility magnifiers are normal. Gate by signer, user setting, and sustained overlap during match.
- **Horkos slot**: Windows daemon/window probe, correlated with server-side aim/vision features.

### 20. DWM Thumbnail and Magnification Consumer
- **Name and Platform/Layer**: DWM thumbnail and magnification consumer; Windows usermode.
- **Observable**: Clean baseline has no unknown process mirroring the game window through DWM thumbnails or Magnification API. Anomaly is an untrusted process with thumbnail/magnifier activity sourced from the game rect.
- **Mechanism**: Enumerate visible/cloaked windows with `DwmGetWindowAttribute`, detect magnifier class windows (`WC_MAGNIFIER`), and correlate owning processes with `DwmRegisterThumbnail`-style behavior where observable through window/class patterns and module imports.
- **Tampering class surfaced**: Screen-scraping overlays and external CV-assisted ESP.
- **False-positive risk + gating**: Streamers, accessibility magnifiers, and capture software are legitimate. Gate by signer, foreground mode, and whether the process also opens game handles.
- **Horkos slot**: Windows usermode overlay probe.

### 21. Low-Level Injected Input Flag Rate
- **Name and Platform/Layer**: Low-level injected input flag rate; Windows usermode.
- **Observable**: Clean baseline has input events from Raw Input devices with low or explainable injected-hook flags. Anomaly is a high fraction of mouse/keyboard events marked `LLMHF_INJECTED` or `LLKHF_INJECTED` during combat windows.
- **Mechanism**: Install a low-level hook with `SetWindowsHookExW(WH_MOUSE_LL/WH_KEYBOARD_LL)` in the Horkos process and inspect `MSLLHOOKSTRUCT.flags` and `KBDLLHOOKSTRUCT.flags`; compare with Raw Input `GetRawInputData` device timestamps.
- **Tampering class surfaced**: `SendInput`, automation frameworks, and software aimbot input injection.
- **False-positive risk + gating**: Accessibility software, remote desktop, Steam Input, and macro tools inject input. Gate by user accessibility mode, signer, and high-confidence behavioral correlation.
- **Horkos slot**: SDK input backend feeding `server/telemetry/src/schema.rs`.

### 22. No-Coalesce Mouse Burst Pattern
- **Name and Platform/Layer**: No-coalesce mouse burst pattern; Windows usermode.
- **Observable**: Clean baseline has mouse movement coalescing and device-poll jitter consistent with the reported HID polling interval. Anomaly is repeated `MOUSEEVENTF_MOVE_NOCOALESCE`-like sub-frame bursts with unrealistically regular spacing.
- **Mechanism**: Compare Raw Input deltas from `RegisterRawInputDevices`/`GetRawInputData` with low-level mouse hook timestamps and `GetMessageTime`; model burst timing and missing coalescence.
- **Tampering class surfaced**: Synthetic fine-grained mouse movement for aim assist.
- **False-positive risk + gating**: High-polling gaming mice and driver software can reduce coalescing. Gate against HID `bInterval`/poll rate and device model.
- **Horkos slot**: Cross-platform input sampler in `sdk/src/` and server feature extraction.

### 23. Microcontroller HID Descriptor Fingerprint
- **Name and Platform/Layer**: Microcontroller HID descriptor fingerprint; Windows usermode.
- **Observable**: Clean baseline has HID descriptors consistent with commercial mice/keyboards/controllers. Anomaly is a microcontroller-like descriptor with generic strings, mismatched usage pages, impossible report lengths, or known cheat-controller VID/PID.
- **Mechanism**: Enumerate devices with Raw Input and SetupAPI, open HID handles, call `HidD_GetPreparsedData`, `HidP_GetCaps`, `HidD_GetAttributes`, and read USB VID/PID/manufacturer/product strings.
- **Tampering class surfaced**: Arduino/Teensy/USB Host Shield mouse emulation and recoil/aim microcontrollers.
- **False-positive risk + gating**: Custom keyboards, accessibility devices, and DIY controllers are legitimate. Gate by descriptor anomalies plus timing/aim features, not VID/PID alone.
- **Horkos slot**: Windows input-device inventory under `sdk/src/backends/win/`.

### 24. Serial-HID Bridge Cheat Controller
- **Name and Platform/Layer**: Serial-HID bridge cheat controller; Windows usermode.
- **Observable**: Clean baseline has input devices without simultaneous suspicious COM-port control channels. Anomaly is a USB serial device and HID mouse/keyboard sharing VID/PID, parent hub, or arrival time with frame-synchronous command traffic.
- **Mechanism**: Use SetupAPI `GUID_DEVINTERFACE_COMPORT`, HID device enumeration, `CM_Get_Parent`, and device instance IDs to correlate COM and HID interfaces under one composite USB device.
- **Tampering class surfaced**: External controller boards that receive aim coordinates over serial and emit HID movement.
- **False-positive risk + gating**: Stream decks, flight sticks, development boards, and accessibility hardware are legitimate. Gate by active serial traffic cadence and known user-device allowlist.
- **Horkos slot**: SDK hardware inventory and server feature correlation.

### 25. Frida Named Pipe and Gadget Residency
- **Name and Platform/Layer**: Frida named pipe and gadget residency; Windows usermode.
- **Observable**: Clean baseline has no Frida-named pipes, modules, threads, or heap trampolines inside or near the game. Anomaly is `\\.\pipe\frida-*`, loaded modules with Frida identifiers, or private executable trampolines with Frida-like RPC threads.
- **Mechanism**: Enumerate named pipes where permitted, inspect loaded modules with `EnumProcessModulesEx`/`K32GetModuleFileNameExW`, scan thread start addresses via `NtQueryInformationThread`, and validate private executable regions with `VirtualQueryEx`.
- **Tampering class surfaced**: Dynamic instrumentation and script-driven memory manipulation.
- **False-positive risk + gating**: Developer instrumentation and QA may use Frida. Gate by build channel, signer, and whether the target is a production match process.
- **Horkos slot**: Windows usermode instrumentation scanner; correlated with `HK_EVENT_HANDLE_OPEN`.

### 26. Foreign NtReadVirtualMemory Hammering
- **Name and Platform/Layer**: Foreign `NtReadVirtualMemory` hammering; Windows usermode service with ETW.
- **Observable**: Clean baseline has low-rate diagnostic memory reads by trusted tools outside matches. Anomaly is high-rate cross-process reads targeting the game, especially at frame cadence.
- **Mechanism**: Consume ETW Threat-Intelligence or kernel process/memory events where available, correlate source PID with Horkos handle-open telemetry, and bucket call rate per source/target pair.
- **Tampering class surfaced**: External memory readers, radar tools, and wallhack state scrapers.
- **False-positive risk + gating**: EDR, debuggers, crash reporters, and accessibility tools can read memory. Gate by access rate, signer, match state, and whether reads persist after game focus.
- **Horkos slot**: Windows ETW collector plus `kernel/win/src/Callbacks.c`.

### 27. Global Windows Hook Ownership
- **Name and Platform/Layer**: Global Windows hook ownership; Windows usermode.
- **Observable**: Clean baseline has no unknown global hooks affecting the game GUI thread. Anomaly is `WH_GETMESSAGE`, `WH_CALLWNDPROC`, `WH_CBT`, `WH_MOUSE`, or `WH_KEYBOARD` hooks whose DLL owner is unsigned or unrelated to allowed overlays.
- **Mechanism**: Correlate GUI-thread modules, loaded hook DLLs, and window-message behavior using `SetWinEventHook` observation, module list deltas, and `GetWindowThreadProcessId`; direct global hook enumeration is limited, so use loaded-DLL footprint and thread message anomalies.
- **Tampering class surfaced**: Input interception, overlay injection, and message-loop manipulation.
- **False-positive risk + gating**: IMEs, accessibility tools, overlays, and capture software hook messages. Gate by signer and whether the hook DLL also opens process handles.
- **Horkos slot**: SDK/window collector and process/image telemetry.

### 28. Loader List Cross-View Drift
- **Name and Platform/Layer**: Loader list cross-view drift; Windows usermode.
- **Observable**: Clean baseline has PEB loader lists, Toolhelp snapshots, PSAPI enumeration, and VAD image regions agreeing on loaded modules. Anomaly is an executable image VAD absent from loader lists or a loader entry whose memory region is gone.
- **Mechanism**: Compare `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE)`, `EnumProcessModulesEx`, PEB `Ldr` lists read from self process, and `VirtualQuery` image regions.
- **Tampering class surfaced**: Manual mapping, unlinked modules, and loader-list hiding.
- **False-positive risk + gating**: Race during DLL load/unload and anti-tamper packers can diverge briefly. Gate on stable divergence after loader quiescence.
- **Horkos slot**: Client self-integrity scanner under `sdk/src/`.

### 29. NTDLL Stub and IAT Target Drift
- **Name and Platform/Layer**: NTDLL stub and IAT target drift; Windows usermode.
- **Observable**: Clean baseline has imported `Nt*` functions and critical Win32 APIs pointing into expected KnownDll or signed module ranges. Anomaly is an IAT entry or syscall stub redirected into foreign private memory.
- **Mechanism**: Parse PE import tables, delay-import tables, and `ntdll.dll` export stubs in memory; resolve target module ownership with `VirtualQuery` and compare to KnownDll file image.
- **Tampering class surfaced**: Usermode API hooks, syscall trampolines, and instrumentation shims.
- **False-positive risk + gating**: Overlays, EDR, and profilers hook APIs legitimately. Gate by module signer and target API sensitivity.
- **Horkos slot**: SDK self-integrity scanner and `server/telemetry` risk features.

### 30. UIAccess and Accessibility Control Channel
- **Name and Platform/Layer**: UIAccess and accessibility control channel; Windows usermode.
- **Observable**: Clean baseline has no untrusted `uiAccess=true` or accessibility process sending focus/input events to the game. Anomaly is a non-Microsoft/non-user-approved UIAccess binary controlling the foreground game or injecting input.
- **Mechanism**: Enumerate foreground/related processes, inspect process token integrity level and UIAccess via `GetTokenInformation(TokenUIAccess)`, and correlate with low-level hook/Raw Input anomalies.
- **Tampering class surfaced**: Accessibility-permission abuse for input automation and overlay control.
- **False-positive risk + gating**: Screen readers, assistive input tools, and remote support software are legitimate. Gate by explicit accessibility allowlist and behavior correlation.
- **Horkos slot**: Windows daemon process inventory.

## Linux eBPF and Userspace: Cross-Process Memory, Loader, Kernel-Hook, and Proton Observers

### 31. process_vm_readv Foreign Reader
- **Name and Platform/Layer**: `process_vm_readv` foreign reader; Linux eBPF.
- **Observable**: Clean baseline has no untrusted process repeatedly reading the game address space. Anomaly is `process_vm_readv` targeting the game PID with high byte counts or frame-cadence repetition.
- **Mechanism**: Attach to `tracepoint/syscalls/sys_enter_process_vm_readv`, read caller PID and target PID from syscall args, then bucket byte counts at `sys_exit_process_vm_readv` with a kretprobe or tracepoint where available.
- **Tampering class surfaced**: External memory readers, radar tools, and wallhack state scraping.
- **False-positive risk + gating**: Debuggers, crash reporters, and Wine tooling may read memory. Gate by signer/package provenance, session phase, and whether caller is `wineserver`/Steam runtime on Proton.
- **Horkos slot**: New BPF TU adjacent to `kernel/linux/bpf/src/tracepoints.bpf.c`, mapped in `kernel/linux/userspace/Loader.cpp`.

### 32. process_vm_writev Foreign Writer
- **Name and Platform/Layer**: `process_vm_writev` foreign writer; Linux eBPF.
- **Observable**: Clean baseline has no foreign writes into the game process. Anomaly is any untrusted `process_vm_writev` targeting game memory, especially into executable or GOT-like regions.
- **Mechanism**: Attach to `tracepoint/syscalls/sys_enter_process_vm_writev`, capture remote iovec base/length with bounded `bpf_probe_read_user`, and classify destination via userspace `/proc/<pid>/maps` correlation.
- **Tampering class surfaced**: Memory editors, GOT patchers, and runtime code injection.
- **False-positive risk + gating**: Debuggers and hot-reload developer builds can write memory. Gate by build channel and target region class.
- **Horkos slot**: New tracepoint BPF program plus userspace correlation in `kernel/linux/userspace/Loader.cpp`.

### 33. /proc/pid/mem Foreign Open and Read
- **Name and Platform/Layer**: `/proc/<pid>/mem` foreign open and read; Linux eBPF LSM.
- **Observable**: Clean baseline has no non-debugger foreign process opening or reading the game `mem` file. Anomaly is `file_open` on `/proc/<game_pid>/mem` followed by reads from a different PID.
- **Mechanism**: Extend `lsm/file_open` to identify procfs inode paths for `mem`; supplement with fentry/fexit on proc mem file operations when BTF exposes them, or userspace fd inspection as fallback.
- **Tampering class surfaced**: Classic Linux memory editing and external inspection.
- **False-positive risk + gating**: GDB, crash dumpers, and Proton helpers may inspect memory. Gate by process role, user dev mode, and syscall cadence.
- **Horkos slot**: Extends `kernel/linux/bpf/src/lsm_file_open.bpf.c`.

### 34. /proc/pid/maps and smaps Scrape Cadence
- **Name and Platform/Layer**: `/proc/<pid>/maps` and `smaps` scrape cadence; Linux eBPF/userspace.
- **Observable**: Clean baseline has occasional maps reads by diagnostics. Anomaly is frequent maps/smaps reads targeting the game before memory reads or aim events.
- **Mechanism**: Observe `lsm/file_open` for procfs `maps`, `smaps`, `pagemap`, and `clear_refs`; correlate opener PID with `read` byte counts and subsequent `process_vm_readv`.
- **Tampering class surfaced**: Address-discovery phase of external memory cheats.
- **False-positive risk + gating**: Profilers, debuggers, and memory monitors read these files. Gate by package provenance and repeated match-time access.
- **Horkos slot**: `lsm_file_open.bpf.c` event expansion and `Loader.cpp` path classifier.

### 35. LD_PRELOAD Environment at Exec
- **Name and Platform/Layer**: `LD_PRELOAD` environment at exec; Linux eBPF/userspace.
- **Observable**: Clean baseline for protected game exec has no unexpected `LD_PRELOAD` or runtime-injection environment variables outside known Steam/Proton wrappers. Anomaly is untrusted preload paths, deleted backing files, or preload variables present only at exec.
- **Mechanism**: Use `tracepoint/sched/sched_process_exec` for executable identity, then userspace loader reads `/proc/<pid>/environ` immediately after exec; optional LSM `bprm_check_security` can snapshot env before user code runs.
- **Tampering class surfaced**: Dynamic linker injection and pre-main cheat dylib loading.
- **False-positive risk + gating**: Steam Runtime, MangoHud, gamescope, Proton, and accessibility overlays use environment hooks. Gate by known prefix tree, package, and user opt-in.
- **Horkos slot**: Existing `kernel/linux/bpf/src/tracepoints.bpf.c` plus `kernel/linux/userspace/Loader.cpp`.

### 36. Global ld.so.preload Trust Drift
- **Name and Platform/Layer**: Global `ld.so.preload` trust drift; Linux userspace/eBPF.
- **Observable**: Clean baseline has `/etc/ld.so.preload` absent or containing trusted administrative entries. Anomaly is a new preload path appearing before game launch or pointing to untrusted/deleted libraries.
- **Mechanism**: Observe `lsm/file_open` and userspace file-integrity snapshots for `/etc/ld.so.preload`; hash listed libraries and compare inode/path ownership.
- **Tampering class surfaced**: System-wide library injection into the game.
- **False-positive risk + gating**: Some performance/debug tools use global preload. Gate by root-owned path, package manager database, and explicit dev mode.
- **Horkos slot**: Linux daemon file-integrity collector plus `lsm_file_open.bpf.c`.

### 37. GOT/PLT Runtime Target Integrity
- **Name and Platform/Layer**: GOT/PLT runtime target integrity; Linux userspace.
- **Observable**: Clean baseline has GOT entries resolving to expected symbols inside the owning DSO or its legitimate dependency. Anomaly is a GOT/PLT slot pointing into an unknown DSO, deleted mapping, memfd, or anonymous executable memory.
- **Mechanism**: Parse ELF program headers and dynamic sections with `dl_iterate_phdr`, compare relocation targets to `/proc/self/maps`, `.dynsym`, `.rela.plt`, and loader-resolved symbol ownership.
- **Tampering class surfaced**: GOT hooks, PLT interposition, and runtime symbol hijacking.
- **False-positive risk + gating**: Legitimate interposers, Steam overlays, MangoHud, and Proton layers modify symbol resolution. Gate by known library set and protected symbol list.
- **Horkos slot**: SDK POSIX backend under `sdk/src/backends/posix/DriverProbePosix.cpp` or a sibling integrity module.

### 38. ftrace Enabled-Function Foreign Hook Set
- **Name and Platform/Layer**: ftrace enabled-function foreign hook set; Linux userspace/LKM-only observer.
- **Observable**: Clean baseline has ftrace enabled only by trusted tooling or disabled during production matches. Anomaly is active ftrace on syscall, memory, credential, or Horkos hook points owned by unknown modules.
- **Mechanism**: Read `/sys/kernel/debug/tracing/enabled_functions`, `available_filter_functions`, and tracing instances when debugfs is mounted; an LKM-only path can inspect ftrace ops if available.
- **Tampering class surfaced**: Kernel function hooks used to hide ptrace/memory activity or blind eBPF.
- **False-positive risk + gating**: Perf, BCC, bpftrace, and kernel developers use ftrace. Gate by root/dev mode, process ancestry, and production match policy.
- **Horkos slot**: Linux daemon health probe; LKM path only under `kernel/linux/lkm/` build flag.

### 39. Foreign eBPF Program Inventory on Horkos Hook Points
- **Name and Platform/Layer**: foreign eBPF program inventory; Linux userspace.
- **Observable**: Clean baseline has only Horkos and known system BPF programs attached to relevant syscall, LSM, kprobe, and tracepoint targets. Anomaly is an unknown BPF program attached to ptrace, process_vm, mmap, file_open, or Horkos maps.
- **Mechanism**: Enumerate with `bpf_prog_get_next_id`, `bpf_prog_get_fd_by_id`, and `bpf_obj_get_info_by_fd`; inspect `prog_type`, `name`, `created_by_uid`, map IDs, and attach target where exposed.
- **Tampering class surfaced**: BPF-based hiding, syscall filtering, and anti-observability implants.
- **False-positive risk + gating**: Cilium, systemd, Falco, Tetragon, and observability stacks install BPF programs. Gate by attach point, signer/package, and host policy.
- **Horkos slot**: Linux userspace loader health module in `kernel/linux/userspace/Loader.cpp`.

### 40. Kernel Module Cross-View and Uevent Ledger
- **Name and Platform/Layer**: kernel module cross-view and uevent ledger; Linux eBPF/userspace.
- **Observable**: Clean baseline has `/proc/modules`, `/sys/module`, kobject uevents, and BPF-observed module load activity agreeing. Anomaly is a module present in one view but absent in another, or a load/unload with missing uevent.
- **Mechanism**: Snapshot `/proc/modules`, `/sys/module`, and subscribe to netlink `KOBJECT_UEVENT`; optionally attach tracepoints/kprobes to module load/unload paths for event timing.
- **Tampering class surfaced**: LKM hiding, DKOM unlinking, and post-load cleanup.
- **False-positive risk + gating**: Fast unloads and initramfs modules cause races. Gate by resampling and persistent discrepancy.
- **Horkos slot**: Linux daemon plus optional eBPF tracepoint TU.

### 41. LSM ptrace_access_check Unexpected Attach
- **Name and Platform/Layer**: LSM `ptrace_access_check`; Linux eBPF LSM.
- **Observable**: Clean baseline has no untrusted ptrace access decisions targeting the game. Anomaly is `PTRACE_ATTACH`, `PTRACE_SEIZE`, register access, or memory access requests from non-debugger processes.
- **Mechanism**: Attach BPF LSM program to `ptrace_access_check`, preserving prior LSM return, and emit caller/target/request metadata; correlate with existing `sys_enter_ptrace` tracepoint.
- **Tampering class surfaced**: Debugger attach, stealth `PTRACE_SEIZE`, and launch-under-tracer patterns.
- **False-positive risk + gating**: GDB, crash handlers, Steam/Proton diagnostics, and developer builds may attach. Gate by build channel, signer/package, and target phase.
- **Horkos slot**: New `kernel/linux/bpf/src/lsm_ptrace.bpf.c`, sharing `hk_ringbuf`.

### 42. perf_event_open Hardware Breakpoint Target
- **Name and Platform/Layer**: `perf_event_open` hardware breakpoint target; Linux eBPF/userspace.
- **Observable**: Clean baseline has no foreign process installing hardware breakpoints on game addresses. Anomaly is `perf_event_open` with breakpoint attributes targeting the game or sensitive symbols.
- **Mechanism**: Trace `sys_enter_perf_event_open`, read bounded `perf_event_attr` fields from user memory, and classify `type == PERF_TYPE_BREAKPOINT`, `bp_type`, `bp_addr`, and `pid` target.
- **Tampering class surfaced**: Hardware breakpoint based memory/code tracing.
- **False-positive risk + gating**: Profilers and debuggers use perf. Gate by CAP_PERFMON/CAP_SYS_ADMIN owner, dev mode, target PID, and breakpoint address class.
- **Horkos slot**: New Linux tracepoint BPF TU and userspace symbol resolver.

### 43. Uprobe Attachment to Game Symbols
- **Name and Platform/Layer**: uprobe attachment to game symbols; Linux userspace/eBPF inventory.
- **Observable**: Clean baseline has no unknown uprobes attached to game text or critical libraries. Anomaly is a uprobe targeting gameplay, render, input, or Horkos symbols.
- **Mechanism**: Inspect `/sys/kernel/debug/tracing/uprobe_events` and enumerate BPF programs with uprobe attach metadata via `bpf_obj_get_info_by_fd` where available.
- **Tampering class surfaced**: Userland function tracing, data extraction, and instrumentation without ptrace.
- **False-positive risk + gating**: Profilers, BCC, and performance tools use uprobes. Gate by root/dev mode and symbol allowlist.
- **Horkos slot**: Linux daemon health inventory.

### 44. Proton/Wine Syscall Baseline Disambiguator
- **Name and Platform/Layer**: Proton/Wine syscall baseline disambiguator; Linux userspace/eBPF.
- **Observable**: Clean baseline on Steam Deck/Proton has expected `wineserver`, pressure-vessel, gamescope, and Wine syscall patterns. Anomaly is a non-Wine peer reading/writing game memory, injected native DLL override, or namespace escape outside the runtime prefix.
- **Mechanism**: At exec, classify Proton runtime via environment and process tree; track `process_vm_readv/writev`, `ptrace`, `WINEDLLOVERRIDES`, mapped SO paths, and cgroup/namespace IDs.
- **Tampering class surfaced**: Proton-specific native DLL injection, non-wineserver memory access, and runtime sandbox escape.
- **False-positive risk + gating**: Proton itself is noisy. Gate against a Proton-specific clean baseline instead of applying native Linux thresholds.
- **Horkos slot**: `kernel/linux/userspace/Loader.cpp` correlation and `server/telemetry` platform feature tags.

### 45. /dev/uinput Synthetic Device Provenance
- **Name and Platform/Layer**: `/dev/uinput` synthetic device provenance; Linux eBPF/userspace.
- **Observable**: Clean baseline has uinput devices from known desktop, Steam Input, or accessibility stacks. Anomaly is a new virtual pointer/keyboard created shortly before match activity by an untrusted process.
- **Mechanism**: Observe `lsm/file_open` for `/dev/uinput`, `ioctl` creation paths where available through kprobes, and reconcile `/sys/class/input/event*/device/name`, `uniq`, vendor/product, and creator process.
- **Tampering class surfaced**: Synthetic input aimbots and hardware-assist bridges.
- **False-positive risk + gating**: Steam Input, controllers, accessibility software, and virtual KVMs use uinput. Gate by device creator, session phase, and input timing entropy.
- **Horkos slot**: Linux input inventory collector plus eBPF file-open signal.

### 46. ELF Interpreter and Runtime Loader Drift
- **Name and Platform/Layer**: ELF interpreter and runtime loader drift; Linux userspace.
- **Observable**: Clean baseline has `PT_INTERP` and the mapped dynamic loader matching the game distribution/runtime. Anomaly is a different loader, deleted loader mapping, or loader path outside Steam/Proton/game trust roots.
- **Mechanism**: Parse the on-disk ELF `PT_INTERP`, compare to `/proc/<pid>/maps` loader mapping and `/proc/<pid>/exe`; hash loader inode and package provenance.
- **Tampering class surfaced**: Loader hijacking and dynamic linker trust bypass.
- **False-positive risk + gating**: AppImage, Flatpak, Steam Runtime, and Proton legitimately redirect loaders. Gate by known runtime identity.
- **Horkos slot**: POSIX SDK self-integrity and Linux loader correlation.

## macOS EndpointSecurity and Daemon: Task, DYLD, AMFI, Mach, and IOKit Observers

### 47. task_for_pid Grant to Non-Entitled Caller
- **Name and Platform/Layer**: `task_for_pid` grant to non-entitled caller; macOS EndpointSecurity.
- **Observable**: Clean baseline has task-port requests to the game only from Horkos, Apple tools, or trusted developer builds. Anomaly is `AUTH_TASK_FOR_PID` where caller lacks expected signer/team/entitlement or targets the production game.
- **Mechanism**: Subscribe to `ES_EVENT_TYPE_AUTH_TASK_FOR_PID`, inspect caller/target `es_process_t`, and verify entitlements with `csops(CS_OPS_ENTITLEMENTS_BLOB)` outside the ES handler.
- **Tampering class surfaced**: Memory inspection/write access via Mach task ports.
- **False-positive risk + gating**: Xcode, lldb, crash reporters, and development builds may request TFP. Gate by build channel, signer, and user dev mode.
- **Horkos slot**: Extends `kernel/macos/es/EsClient.mm`; preserve immediate AUTH replies per guardrail #7.

### 48. task_read_for_pid and task_inspect Acquisition
- **Name and Platform/Layer**: read-only task access acquisition; macOS EndpointSecurity.
- **Observable**: Clean baseline has no unknown process acquiring task read/inspect rights to the game. Anomaly is `NOTIFY_GET_TASK` for the game from an untrusted process on macOS versions that expose the event.
- **Mechanism**: Subscribe to `ES_EVENT_TYPE_NOTIFY_GET_TASK` where available and inspect `es_event_get_task_t.type` for read/inspect/name control rights.
- **Tampering class surfaced**: Read-only memory scraping and thread-state inspection that bypasses full `task_for_pid` auth.
- **False-positive risk + gating**: Crash reporters and performance tools may inspect tasks. Gate by signer and target game PID.
- **Horkos slot**: `kernel/macos/es/EsClient.mm` event expansion.

### 49. DYLD_INSERT_LIBRARIES Exec Environment
- **Name and Platform/Layer**: `DYLD_INSERT_LIBRARIES` exec environment; macOS EndpointSecurity.
- **Observable**: Clean baseline has no dangerous `DYLD_*` variables honored by the protected game under hardened runtime. Anomaly is `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`, `DYLD_FORCE_FLAT_NAMESPACE`, or related variables in the exec snapshot.
- **Mechanism**: Inspect `es_event_exec_t` argv/env fields from `ES_EVENT_TYPE_NOTIFY_EXEC` or `AUTH_EXEC` when available; verify whether the target has `com.apple.security.cs.allow-dyld-environment-variables`.
- **Tampering class surfaced**: DYLD library injection and loader path hijacking.
- **False-positive risk + gating**: Developer tools and modding workflows may use DYLD variables. Gate by build channel and signed/allowed plugin directories.
- **Horkos slot**: Existing `kernel/macos/es/EsClient.mm` exec path.

### 50. SIP and AMFI Posture Corroborator
- **Name and Platform/Layer**: SIP and AMFI posture corroborator; macOS daemon.
- **Observable**: Clean baseline has SIP/AMFI settings matching production policy and code-signing flags consistent with the game signature. Anomaly is SIP disabled, developer mode unexpectedly enabled, AMFI trust override evidence, or code-signing flags drifting mid-session.
- **Mechanism**: Use `csr_check()` or `sysctl`-exposed CSR state where available, `csops` for `csflags` and entitlements, and ES `es_process_t.cs_flags` snapshots.
- **Tampering class surfaced**: AMFI bypasses, SIP-disabled cheat paths, and code-signing policy weakening.
- **False-positive risk + gating**: Developers legitimately disable SIP. Gate as risk telemetry only unless production policy explicitly disallows it.
- **Horkos slot**: macOS daemon adjacent to `kernel/macos/es/EsClient.mm`.

### 51. Code-Signing Invalidation Receipt
- **Name and Platform/Layer**: code-signing invalidation receipt; macOS EndpointSecurity.
- **Observable**: Clean baseline has no `NOTIFY_CS_INVALIDATED` for the game after launch. Anomaly is code-signing invalidation for the game or critical helper during a session.
- **Mechanism**: Subscribe to `ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED`, record target PID, and immediately schedule a non-blocking `csops`/SecCode validity rescan outside the ES handler.
- **Tampering class surfaced**: Code-signing bypass, invalid page execution, and runtime binary transformation.
- **False-positive risk + gating**: Crashes, bad updates, and legitimate debugging may invalidate code in dev. Gate by production build and follow-up code validity result.
- **Horkos slot**: `kernel/macos/es/EsClient.mm` subscription expansion.

### 52. Mach Exception Port Hijack
- **Name and Platform/Layer**: Mach exception port hijack; macOS daemon.
- **Observable**: Clean baseline has no foreign exception handlers installed on the game task, except Horkos/crash reporter policy. Anomaly is a task/thread exception port resolving to an untrusted process.
- **Mechanism**: Use `task_get_exception_ports` and `thread_get_exception_ports` from the daemon when it has appropriate inspect rights; resolve send rights to owner where possible and correlate with ES task-access events.
- **Tampering class surfaced**: Debugger-style control, single-step instrumentation, and crash-handler hijack.
- **False-positive risk + gating**: Crash reporters, lldb, and developer tools install exception ports. Gate by signer/build channel and whether port changes occur after match start.
- **Horkos slot**: macOS daemon integrity probe.

### 53. dyld Shared Cache UUID and Region Integrity
- **Name and Platform/Layer**: dyld shared cache UUID and region integrity; macOS daemon.
- **Observable**: Clean baseline has dyld shared cache mappings with expected UUID, protection, and file-backed regions. Anomaly is writable shared-cache pages, private remaps, or cache UUID mismatch for the OS build.
- **Mechanism**: Use `_dyld_get_shared_cache_uuid`/`_dyld_get_shared_cache_range` for self baseline and `mach_vm_region_recurse` plus `task_info(TASK_DYLD_INFO)` for target inspection when authorized.
- **Tampering class surfaced**: Shared-cache patching, function-hooking by cache remap, and dyld trust manipulation.
- **False-positive risk + gating**: OS updates and Rosetta/architecture differences alter cache identity. Gate by OS build and architecture.
- **Horkos slot**: macOS daemon memory-integrity task; triggered by ES `MMAP`/`MPROTECT` events.

### 54. DTrace and kdebug Abuse Posture
- **Name and Platform/Layer**: DTrace/kdebug posture; macOS daemon plus ES file events.
- **Observable**: Clean baseline has no untrusted process opening DTrace devices or enabling DTrace-heavy tracing against the game. Anomaly is `/dev/dtracehelper` access, suspicious `dtrace` execution, or sysctl DTrace state enabled during production match.
- **Mechanism**: Subscribe to `ES_EVENT_TYPE_NOTIFY_OPEN`/`AUTH_OPEN` for `/dev/dtracehelper`, observe `dtrace` exec, and sample documented `sysctl` keys under `kern.dtrace.*` where present.
- **Tampering class surfaced**: Dynamic tracing and syscall/function instrumentation.
- **False-positive risk + gating**: Developers and performance engineers use DTrace. Gate by build channel, SIP/dev mode, and target process.
- **Horkos slot**: `kernel/macos/es/EsClient.mm` file-open subscription plus daemon sysctl sampler.

### 55. Mach Right Delegation Graph
- **Name and Platform/Layer**: Mach right delegation graph; macOS EndpointSecurity.
- **Observable**: Clean baseline has task/control rights staying within trusted process relationships. Anomaly is a task or bootstrap send right copied from a trusted helper to an untrusted process.
- **Mechanism**: Subscribe to `ES_EVENT_TYPE_AUTH_MACH_RIGHT` and `ES_EVENT_TYPE_NOTIFY_MACH_RIGHT`, record caller/target/right type, and correlate with previous `AUTH_TASK_FOR_PID` approvals.
- **Tampering class surfaced**: Task-port laundering, bootstrap-port delegation, and XPC proxy injection.
- **False-positive risk + gating**: XPC services and launchd legitimately pass rights. Gate by right type, process graph, and signer.
- **Horkos slot**: `kernel/macos/es/EsClient.mm` event expansion and server graph feature.

### 56. MAP_JIT Entitlement Mismatch
- **Name and Platform/Layer**: MAP_JIT entitlement mismatch; macOS EndpointSecurity/daemon.
- **Observable**: Clean baseline has executable/JIT mappings only in processes with known JIT entitlement and expected runtime behavior. Anomaly is `MAP_JIT` or executable anonymous mapping by a process lacking `com.apple.security.cs.allow-jit` or `allow-unsigned-executable-memory`.
- **Mechanism**: Subscribe to `ES_EVENT_TYPE_NOTIFY_MMAP` and `NOTIFY_MPROTECT`, inspect `prot`, `flags`, and source file; query entitlements with `csops` outside handler.
- **Tampering class surfaced**: Shellcode generation, JIT abuse, and code injection.
- **False-positive risk + gating**: Browsers, Electron overlays, emulators, and scripting engines use JIT. Gate by process identity and protected game PID.
- **Horkos slot**: ES client expansion plus macOS daemon entitlement cache.

### 57. Remote Thread Creation Into Game
- **Name and Platform/Layer**: remote thread creation into game; macOS EndpointSecurity.
- **Observable**: Clean baseline has game threads created by the game process itself. Anomaly is `NOTIFY_REMOTE_THREAD_CREATE` targeting the game from a foreign process where supported.
- **Mechanism**: Subscribe to `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` on macOS versions that expose it and correlate with task-port grants and target memory mappings.
- **Tampering class surfaced**: Mach thread injection and remote execution.
- **False-positive risk + gating**: Debuggers and crash reporters may create helper threads in dev. Gate by production build and signer.
- **Horkos slot**: `kernel/macos/es/EsClient.mm` event expansion.

### 58. CGEventTap and IOHID Input Interposer
- **Name and Platform/Layer**: input event tap and IOHID interposer; macOS daemon.
- **Observable**: Clean baseline has event taps from trusted accessibility tools or none. Anomaly is an untrusted process with an active `CGEventTap` or IOHID user client influencing game input.
- **Mechanism**: Correlate accessibility permission state, process list, ES `AUTH_IOKIT_OPEN` for `IOHIDSystem`, and observed input timing; public APIs do not enumerate all taps reliably, so treat this as a multi-source heuristic.
- **Tampering class surfaced**: Synthetic input, aim macros, and input interception.
- **False-positive risk + gating**: Accessibility tools, remote desktop, and macro utilities are legitimate. Gate by user-approved accessibility list and behavioral anomalies.
- **Horkos slot**: macOS daemon input inventory and ES `IOKIT_OPEN`.

### 59. Framebuffer and GPU UserClient Open
- **Name and Platform/Layer**: framebuffer/GPU UserClient open; macOS EndpointSecurity.
- **Observable**: Clean baseline has GPU and framebuffer user clients opened by the game, WindowServer, and trusted capture tools. Anomaly is an untrusted process opening `IOFramebufferSharedUserClient`, `IOAccelerator`, `IOGPUDevice`, or related classes during a match.
- **Mechanism**: Subscribe to `ES_EVENT_TYPE_AUTH_IOKIT_OPEN`, inspect `es_event_iokit_open_t.user_client_class`, and correlate with screen-capture or overlay behavior.
- **Tampering class surfaced**: Framebuffer scraping, overlay rendering, and GPU-assisted memory scans.
- **False-positive risk + gating**: OBS, Discord, Steam, display drivers, and accessibility capture tools are legitimate. Gate by signer and game-window access.
- **Horkos slot**: `kernel/macos/es/EsClient.mm` IOKit subscription.

### 60. EndpointSecurity Client Queue Health
- **Name and Platform/Layer**: ES client queue health; macOS daemon.
- **Observable**: Clean baseline has ES queue pressure within normal range and no AUTH reply deadline risk. Anomaly is queue saturation, disconnects, or dropped notify events coinciding with suspicious process activity.
- **Mechanism**: Monitor `es_get_client_state` where available, internal sink queue backlog, `es_new_client`/`es_subscribe` errors, and event-rate gaps; never perform blocking work in the ES handler.
- **Tampering class surfaced**: ES client starvation, event-flood blinding, and self-observability loss.
- **False-positive risk + gating**: File-heavy updates and developer tools can spike ES load. Gate by duration and concurrent tamper signals.
- **Horkos slot**: Existing `kernel/macos/es/EsClient.mm` async sink path.

## DMA and PCIe Board Fingerprinting Observers

### 61. Known PCILeech and FPGA VID/PID Match
- **Name and Platform/Layer**: known PCILeech and FPGA VID/PID match; DMA/PCIe.
- **Observable**: Clean baseline has PCI devices matching expected consumer hardware inventory. Anomaly is a known or suspicious FPGA/DMA board VID/PID, subsystem ID, or device description.
- **Mechanism**: Windows: SetupAPI `SetupDiGetClassDevsA`/`SetupDiEnumDeviceInfo` and registry hardware IDs. Linux: `/sys/bus/pci/devices/<BDF>/vendor`, `device`, `subsystem_vendor`, `subsystem_device`. macOS: IOKit `IOPCIDevice` properties when backend is implemented.
- **Tampering class surfaced**: PCILeech-style FPGA DMA boards and rogue PCIe endpoints.
- **False-positive risk + gating**: FPGA development boards and capture cards may share identifiers. Gate by user hardware allowlist, class code, BAR/capability anomalies, and IOMMU posture.
- **Horkos slot**: `dma_detect/backends/win/PcieEnumWin.cpp`, `dma_detect/backends/linux/PcieEnumLinux.cpp`, and future macOS IOKit backend.

### 62. BAR Size and Class Plausibility
- **Name and Platform/Layer**: BAR size and class plausibility; DMA/PCIe.
- **Observable**: Clean baseline has BAR layouts consistent with device class and known vendor models. Anomaly is a network/storage/display-like endpoint with tiny, oversized, or inconsistent BAR0/BAR2 sizes typical of generic FPGA firmware.
- **Mechanism**: Windows: SetupAPI/CM resource descriptors where available. Linux: read `/sys/bus/pci/devices/<BDF>/resource` and class code. macOS: IOKit `assigned-addresses` property.
- **Tampering class surfaced**: Rogue FPGA boards masquerading as benign PCIe devices.
- **False-positive risk + gating**: Some capture cards, RAID HBAs, and Thunderbolt devices have unusual BARs. Gate by vendor database and driver binding.
- **Horkos slot**: `dma_detect/backends/` BAR inventory extension.

### 63. MSI-X Table Structural Plausibility
- **Name and Platform/Layer**: MSI-X table structural plausibility; DMA/PCIe.
- **Observable**: Clean baseline has MSI/MSI-X capability structures whose table BAR indicator, offset, and pending-bit array fit inside declared BAR resources. Anomaly is missing MSI-X on a class that normally has it, or table offsets outside BAR bounds.
- **Mechanism**: Linux: read PCI config space through `/sys/bus/pci/devices/<BDF>/config` and resource sizes. Windows: query PCI configuration via documented device property/resource paths where available, avoiding privileged config writes.
- **Tampering class surfaced**: Minimal FPGA endpoint firmware and malformed cheat DMA boards.
- **False-positive risk + gating**: Legacy devices may lack MSI-X. Gate by class/vendor expectation and multiple malformed capabilities.
- **Horkos slot**: `dma_detect/backends/linux/PcieEnumLinux.cpp`; Windows support gated by documented read path availability.

### 64. PCIe Capability Chain Integrity
- **Name and Platform/Layer**: PCIe capability chain integrity; DMA/PCIe.
- **Observable**: Clean baseline has a well-formed PCI/PCIe capability linked list terminating cleanly without loops and with plausible lengths. Anomaly is a capability loop, duplicate pointer, reserved capability misuse, or truncated extended capability header.
- **Mechanism**: Read config space bytes from `/sys/bus/pci/devices/<BDF>/config` on Linux and documented platform APIs where available; parse read-only PCI capability headers.
- **Tampering class surfaced**: Poorly implemented FPGA endpoints and device identity spoofing.
- **False-positive risk + gating**: Broken firmware exists. Gate as advisory unless paired with BME, IOMMU, and suspicious identifier signals.
- **Horkos slot**: DMA backend shared parser under `dma_detect/`.

### 65. ACS and Peer-to-Peer Topology Anomaly
- **Name and Platform/Layer**: ACS/topology anomaly; DMA/PCIe.
- **Observable**: Clean baseline has external or high-risk DMA devices behind IOMMU-isolated root ports with Access Control Services where expected. Anomaly is a DMA-capable device in a peer-to-peer reachable group with no ACS isolation.
- **Mechanism**: Linux: inspect `/sys/kernel/iommu_groups`, `/sys/bus/pci/devices/<BDF>/acs_cap` if exposed by kernel/debugfs, and parent bridge topology. Windows: use Kernel DMA Protection posture and SetupAPI parent device tree as a weaker proxy.
- **Tampering class surfaced**: DMA devices positioned to bypass remapping or access peer memory.
- **False-positive risk + gating**: Many consumer motherboards lack ACS. Gate as host-risk telemetry, not cheat proof.
- **Horkos slot**: Extends `dma_detect` high-confidence calculation.

### 66. DMA-Capable Device Without IOMMU Group
- **Name and Platform/Layer**: DMA-capable device without IOMMU group; DMA/Linux.
- **Observable**: Clean baseline has DMA-capable devices assigned to IOMMU groups when firmware claims IOMMU protection. Anomaly is a bus-master-capable endpoint with no group or no driver while firmware claims remapping.
- **Mechanism**: Linux: compare `/proc/iomem` DMAR/SMMU claims, `/sys/kernel/iommu_groups`, device `driver` symlink, and PCI command Bus Master Enable from config offset `0x04`.
- **Tampering class surfaced**: Post-POST BDF swap, firmware lies, or rogue DMA endpoint outside remapping.
- **False-positive risk + gating**: Kernel config and older systems may lack group exposure. Gate by modern OS/hardware expectation and suspicious device class.
- **Horkos slot**: Existing `dma_detect/backends/linux/PcieEnumLinux.cpp`.

### 67. Thunderbolt External PCIe Hotplug Timing
- **Name and Platform/Layer**: Thunderbolt/external PCIe hotplug timing; DMA/PCIe.
- **Observable**: Clean baseline has stable PCI topology before game start. Anomaly is a new external PCIe/Thunderbolt endpoint arriving during a protected session or just before match start.
- **Mechanism**: Windows: SetupAPI device interface arrival notifications and PnP event log. Linux: udev/netlink `KOBJECT_UEVENT` and `/sys/bus/pci/devices` diff. macOS: IOKit matching notifications for `IOPCIDevice`.
- **Tampering class surfaced**: Hot-plugged DMA boards and late-attached capture/injection hardware.
- **False-positive risk + gating**: Docks and eGPUs are legitimate. Gate by device class, user allowlist, and IOMMU posture.
- **Horkos slot**: `dma_detect/backends/` hotplug monitor.

### 68. Option ROM Presence on Implausible Device
- **Name and Platform/Layer**: option ROM plausibility; DMA/PCIe.
- **Observable**: Clean baseline has option ROMs only on expected GPUs/NICs/storage controllers with valid vendor identity. Anomaly is an option ROM exposed by a generic FPGA-like device or a device class that should not need one.
- **Mechanism**: Linux: inspect `/sys/bus/pci/devices/<BDF>/rom` metadata only after safe read-enable policy is defined; Windows/macOS use device properties where documented. Avoid writing config bits just for scanning.
- **Tampering class surfaced**: Firmware-level DMA implants or identity-spoofing endpoints.
- **False-positive risk + gating**: GPUs, NIC PXE, HBAs, and Thunderbolt devices may have ROMs. Gate by class/vendor and do not force-enable ROM reads in production.
- **Horkos slot**: DMA research backlog; no current code change.

### 69. IOMMU Fault Counter and Remap Fault Telemetry
- **Name and Platform/Layer**: IOMMU fault counter telemetry; DMA/OS.
- **Observable**: Clean baseline has no repeated DMA remapping faults during normal gameplay. Anomaly is remapping faults from an untrusted BDF near game start or memory-scan windows.
- **Mechanism**: Linux: read kernel tracepoints/logs for IOMMU faults where exposed and correlate BDF. Windows: consume documented Event Log/ETW sources for Kernel DMA Protection or IOMMU faults where available; skip when unavailable.
- **Tampering class surfaced**: DMA probing against protected memory and misconfigured rogue DMA devices.
- **False-positive risk + gating**: Faulty drivers and flaky hardware generate faults. Gate by BDF identity, recurrence, and correlation with suspicious devices.
- **Horkos slot**: DMA telemetry path defined in `docs/dma-detection.md` and `server/telemetry`.

### 70. LLC Eviction Side-Channel Under Perf APIs
- **Name and Platform/Layer**: LLC eviction side-channel; DMA/client host telemetry.
- **Observable**: Clean baseline has cache-miss/bandwidth counters within hardware-specific envelopes during a fixed calibration workload. Anomaly is repeatable LLC eviction or memory-bandwidth disturbance consistent with external DMA reads during quiet windows.
- **Mechanism**: Prefer documented OS perf APIs such as Linux `perf_event_open` for LLC misses and memory bandwidth counters; raw `RDPMC` is used only if the OS explicitly enables user-mode PMU access. Windows support should use documented performance counter APIs where available.
- **Tampering class surfaced**: External DMA memory reads causing cache and memory-bus side effects.
- **False-positive risk + gating**: Background workloads, browsers, overlays, and CPU power states cause noise. Gate by controlled quiet windows, hardware model, and device-fingerprint corroboration.
- **Horkos slot**: Client self-integrity/perf sampler feeding server risk score.

## Client Self-Integrity Observers

### 71. Rolling .text Page Hash
- **Name and Platform/Layer**: rolling `.text` page hash; client self-integrity.
- **Observable**: Clean baseline has sampled 4 KiB code pages matching the signed load-time baseline. Anomaly is a page hash change outside patch/update windows.
- **Mechanism**: At module load, hash immutable `.text` pages with SHA-256 or CRC32C for cheap rolling checks, then periodically resample a randomized subset with `VirtualQuery`/`/proc/self/maps`/`mach_vm_region` as platform backends.
- **Tampering class surfaced**: Inline patching, module stomping, and self-code modification.
- **False-positive risk + gating**: Hotpatching, JIT, and game updates can change code. Restrict to immutable Horkos/game modules and signed patch windows.
- **Horkos slot**: `sdk/src/` self-integrity module; schema addition via `sdk/include/horkos/event_schema.h`.

### 72. IAT and Delay-IAT Target Ownership
- **Name and Platform/Layer**: IAT and delay-IAT target ownership; client self-integrity.
- **Observable**: Clean baseline has import slots resolving into expected signed modules. Anomaly is an import slot pointing to foreign executable memory, unknown DLL, or heap trampoline.
- **Mechanism**: Parse PE import and delay-import directories, resolve each function pointer with `VirtualQuery`, and compare target module path/signer against import descriptor expectation.
- **Tampering class surfaced**: Import address table hooks and API interception.
- **False-positive risk + gating**: EDR, overlays, and profilers hook APIs. Gate by import sensitivity and signer.
- **Horkos slot**: Windows SDK integrity backend.

### 73. Inline Hook Prologue Scanner
- **Name and Platform/Layer**: inline hook prologue scanner; client self-integrity.
- **Observable**: Clean baseline has sensitive function prologues matching the file image or signed hotpatch baseline. Anomaly is a `JMP`, `CALL`, `PUSH/RET`, `MOV RAX; JMP RAX`, or branch target outside trusted modules.
- **Mechanism**: Read first 5 to 16 bytes of selected APIs and Horkos entry points, compare to disk mapping, and resolve branch targets.
- **Tampering class surfaced**: Inline API hooks and instrumentation trampolines.
- **False-positive risk + gating**: Security products and overlays patch APIs. Gate by module signer and only on protected function sets.
- **Horkos slot**: `sdk/src/` self-integrity scanner.

### 74. Hardware Debug Register Occupancy
- **Name and Platform/Layer**: hardware debug register occupancy; client self-integrity.
- **Observable**: Clean baseline has `DR0`-`DR3`/`DR7` clear on game/Horkos threads outside developer mode. Anomaly is non-zero hardware breakpoints on protected threads or code/data addresses.
- **Mechanism**: Windows: suspend/inspect own threads with `GetThreadContext(CONTEXT_DEBUG_REGISTERS)` where safe. Linux: use perf/ptrace evidence from kernel observers. macOS: `thread_get_state` debug state when entitled.
- **Tampering class surfaced**: Hardware breakpoints used for tracing, patch timing, or anti-anti-cheat bypass.
- **False-positive risk + gating**: Debuggers and profilers use hardware breakpoints. Gate by build channel and user dev mode.
- **Horkos slot**: Cross-platform SDK self-check plus platform-specific daemon support.

### 75. Deterministic RDTSC Timing Probe
- **Name and Platform/Layer**: deterministic timing probe; client self-integrity.
- **Observable**: Clean baseline has stable cycle deltas for a fixed instruction sequence under pinned affinity. Anomaly is inflated variance or latency spikes consistent with single-step, breakpoint, or VM-exit interference.
- **Mechanism**: Use `RDTSC/RDTSCP` or platform monotonic counters around a known-cycle loop, pin affinity where supported, and compare to boot-time baseline and server cohort.
- **Tampering class surfaced**: Debug stepping, hypervisor interception, and timing API manipulation.
- **False-positive risk + gating**: CPU power management, thermal throttling, and background load are noisy. Gate by repeated controlled samples and corroborating debug/hypervisor signals.
- **Horkos slot**: `sdk/src/` timing sampler and `server/telemetry` feature extraction.

### 76. TLS Callback Directory Integrity
- **Name and Platform/Layer**: TLS callback directory integrity; client self-integrity.
- **Observable**: Clean baseline has TLS callbacks matching the PE/Mach-O/ELF baseline at load. Anomaly is a new or redirected TLS/init callback after load.
- **Mechanism**: Windows: parse PE TLS directory. Linux: inspect `.init_array`/`.preinit_array`. macOS: inspect Mach-O init sections. Compare callback addresses to signed module ranges.
- **Tampering class surfaced**: Early execution injection and stealth loader persistence.
- **False-positive risk + gating**: Plugins and legitimate modules have their own init arrays. Gate per-module baseline and post-load drift.
- **Horkos slot**: SDK loader-integrity module.

### 77. Debugger Heap and PEB Artifact Check
- **Name and Platform/Layer**: debugger heap and PEB artifact check; Windows client self-integrity.
- **Observable**: Clean baseline has `PEB.NtGlobalFlag`, heap debug flags, and debugger process information consistent with production launch. Anomaly is debug heap flags, `BeingDebugged`, or heap tail/free checks unexpectedly enabled.
- **Mechanism**: Read PEB fields in-process, query `NtQueryInformationProcess(ProcessDebugPort/ProcessDebugFlags/ProcessDebugObjectHandle)`, and inspect heap flags with documented heap APIs where possible.
- **Tampering class surfaced**: Usermode debugger attachment and launch-under-debugger artifacts.
- **False-positive risk + gating**: Developer builds and crash diagnostics enable debug flags. Gate by build channel.
- **Horkos slot**: Windows SDK self-check.

### 78. Exception Handler and VEH Chain Ownership
- **Name and Platform/Layer**: exception handler and VEH chain ownership; client self-integrity.
- **Observable**: Clean baseline has exception handlers and unwind targets owned by the game, Horkos, runtime, or trusted crash reporter. Anomaly is a vectored handler or unwind target in unknown private executable memory.
- **Mechanism**: Windows: enumerate vectored handler evidence where safely available and validate unwind metadata with `RtlLookupFunctionEntry`; Linux/macOS: inspect signal handlers with `sigaction` snapshots for protected signals.
- **Tampering class surfaced**: Guard-page hooks, single-step trampolines, and exception-driven instrumentation.
- **False-positive risk + gating**: Crash reporters, profilers, and anti-tamper runtimes use exception handlers. Gate by signer and protected signal/vector set.
- **Horkos slot**: SDK self-integrity module.

### 79. CFG/CET Runtime Policy Drift
- **Name and Platform/Layer**: CFG/CET policy drift; Windows client self-integrity.
- **Observable**: Clean baseline has Control Flow Guard and CET/shadow-stack mitigation policy matching build expectations. Anomaly is disabled mitigations, unexpected dynamic-code permissions, or mismatch between process mitigation policy and signed binary metadata.
- **Mechanism**: Query `GetProcessMitigationPolicy` for `ProcessControlFlowGuardPolicy`, `ProcessUserShadowStackPolicy`, and dynamic-code policy; compare to PE Load Config directory.
- **Tampering class surfaced**: Mitigation downgrades enabling hooks, ROP, or shellcode.
- **False-positive risk + gating**: Older OS versions and compatibility modes lack mitigations. Gate by OS/build capability and game support matrix.
- **Horkos slot**: Windows SDK posture collector.

### 80. Working-Set Execute Page Protection Drift
- **Name and Platform/Layer**: working-set execute page protection drift; client self-integrity.
- **Observable**: Clean baseline has executable pages non-writable and matching expected sharing/dirty state. Anomaly is an executable page becoming private dirty or writable after load.
- **Mechanism**: Windows: `QueryWorkingSetEx` and `VirtualQuery`. Linux: `/proc/self/smaps` private dirty and maps permissions. macOS: `mach_vm_region_recurse` protection/max-protection state.
- **Tampering class surfaced**: Copy-on-write code patching, W^X bypass, and runtime code injection.
- **False-positive risk + gating**: JIT and legitimate hotpatching can dirty executable pages. Gate on protected module ranges and known JIT exclusions.
- **Horkos slot**: Cross-platform SDK self-integrity backend.

## Server-Side Behavioral and Network Observers

### 81. Angular Velocity Distribution Outlier
- **Name and Platform/Layer**: angular velocity distribution outlier; server-side telemetry.
- **Observable**: Clean baseline has aim angular velocity, acceleration, and jerk distributed by device class, sensitivity, weapon, and player skill. Anomaly is a distribution with repeated high-precision, low-noise corrections inconsistent with the matched cohort.
- **Mechanism**: Server computes features from per-tick yaw/pitch deltas in `TickPayload`, conditioned on DPI/sensitivity buckets and weapon state.
- **Tampering class surfaced**: Aimbot smoothing and aim-assist automation.
- **False-positive risk + gating**: High-skill players and unusual devices can be outliers. Gate on long windows, device class, and multiple independent features.
- **Horkos slot**: `server/telemetry/src/schema.rs` feature ingest and `server/ban-engine/src/` scoring.

### 82. Snap-to-Target Delta Cluster
- **Name and Platform/Layer**: snap-to-target delta cluster; server-side telemetry.
- **Observable**: Clean baseline has aim corrections that undershoot/overshoot and vary with context. Anomaly is repeated endpoint deltas landing within tiny angular error of target bones immediately before firing.
- **Mechanism**: Server reconstructs target positions from authoritative game state and measures pre-shot aim delta, endpoint error, and time-to-fire.
- **Tampering class surfaced**: Snap aimbots and trigger-assist aim correction.
- **False-positive risk + gating**: Flick-shot specialists can snap accurately. Gate by repetition, target visibility onset, and biomechanical timing.
- **Horkos slot**: `server/ban-engine` analyzer consuming game-server snapshot telemetry.

### 83. Fitts-Law Plausibility Check
- **Name and Platform/Layer**: Fitts-law plausibility; server-side telemetry.
- **Observable**: Clean baseline shows movement time increasing with angular distance and decreasing target size. Anomaly is near-constant acquisition time regardless of distance/difficulty.
- **Mechanism**: Compute index of difficulty from target angular size/distance and compare observed acquisition time over many engagements.
- **Tampering class surfaced**: Aim automation with uniform lock timing.
- **False-positive risk + gating**: Skilled players and low sensitivity settings shift curves. Gate by player-specific baseline and device class.
- **Horkos slot**: `server/telemetry` feature extractor and `ban-engine` model.

### 84. Occluded Target Prefire
- **Name and Platform/Layer**: occluded target prefire; server-side game-state telemetry.
- **Observable**: Clean baseline has shots toward targets after line-of-sight, audio cue, or plausible prediction. Anomaly is repeated fire or crosshair placement on fully occluded targets before LOS or audio path exists.
- **Mechanism**: Server ray-tests authoritative positions against the same collision/PVS data used for gameplay and correlates fire ticks with LOS onset.
- **Tampering class surfaced**: Wallhacks, radar, and external game-state readers.
- **False-positive risk + gating**: Map knowledge and prediction are legitimate. Gate by repeated low-information contexts and absence of sound/teammate intel.
- **Horkos slot**: `server/ban-engine` analyzer with game-server snapshot IPC.

### 85. Lag-Switch Bimodal RTT
- **Name and Platform/Layer**: lag-switch bimodal RTT; server-side network telemetry.
- **Observable**: Clean baseline has RTT jitter shaped by network path and congestion. Anomaly is a bimodal RTT distribution with periodic spikes tightly correlated to peeks, shots, or kill events.
- **Mechanism**: Use server receive timestamps, engine ping EWMA, UDP/QUIC transport stats, or TCP `TCP_INFO` where applicable; compute spike periodicity and event correlation.
- **Tampering class surfaced**: Lag switches and artificial packet holding.
- **False-positive risk + gating**: Wi-Fi, cellular, and congested networks spike. Gate by event correlation, regularity, and independent network-path indicators.
- **Horkos slot**: `server/telemetry/src/schema.rs` network fields and `server/ban-engine`.

### 86. Sub-Millisecond Packet Timing Regularity
- **Name and Platform/Layer**: packet timing regularity; server-side network telemetry.
- **Observable**: Clean baseline has human and OS scheduling jitter in input packet cadence. Anomaly is sub-millisecond regular input timing over long windows, independent of frame variance.
- **Mechanism**: Server computes inter-arrival deltas from monotonic receive timestamps and compares against client tick counters and reported frame timings.
- **Tampering class surfaced**: Bots, macro-driven clients, and synthetic input pipelines.
- **False-positive risk + gating**: High-refresh systems and stable wired networks reduce jitter. Gate by impossibly low entropy over long windows and input-device corroboration.
- **Horkos slot**: `server/telemetry` cadence analyzer.

### 87. Camera Yaw/Pitch Continuity Violation
- **Name and Platform/Layer**: camera continuity violation; server-side telemetry.
- **Observable**: Clean baseline has camera yaw/pitch changes bounded by device physics, sensitivity, and tick rate. Anomaly is discontinuity or angular acceleration beyond plausible device/user limits without matching raw input evidence.
- **Mechanism**: Interpolate camera state between server ticks, compute angular velocity/acceleration/jerk, and compare to sensitivity/device-conditioned envelopes.
- **Tampering class surfaced**: Silent aim, view-angle patching, and packet-level aim manipulation.
- **False-positive risk + gating**: Teleports, cutscenes, spectator transitions, and tick loss can jump camera state. Gate by game state and raw input consistency.
- **Horkos slot**: `server/ban-engine` feature module.

### 88. Hit-Registration Path Inconsistency
- **Name and Platform/Layer**: hit-registration path inconsistency; server-side game telemetry.
- **Observable**: Clean baseline has projectile/raycast path, shooter pose, target pose, and client-reported fire state agreeing within lag compensation bounds. Anomaly is a hit claim requiring impossible position delta, impossible projectile path, or inconsistent view vector.
- **Mechanism**: Server replays authoritative projectile path and lag-compensated poses; compare to client fire tick, view basis, and hit result.
- **Tampering class surfaced**: Hitbox manipulation, packet tampering, silent aim, and lag-compensation abuse.
- **False-positive risk + gating**: Desync and server bugs can cause outliers. Gate by robust replay evidence and repeated pattern.
- **Horkos slot**: `server/ban-engine` authoritative replay analyzer.

### 89. Reaction-Time Floor to Visibility Onset
- **Name and Platform/Layer**: reaction-time floor; server-side behavioral telemetry.
- **Observable**: Clean baseline has reaction times bounded by human perception and network/tick delays. Anomaly is repeated aim or fire response below plausible latency after target visibility onset.
- **Mechanism**: Compute target visibility onset from server snapshots, subtract RTT/jitter budget, and measure first aim impulse/fire tick.
- **Tampering class surfaced**: Triggerbots, wallhacks, and auto-peek assist.
- **False-positive risk + gating**: Prediction and pre-aim can look fast. Gate on targets with no prior cue and aggregate over many encounters.
- **Horkos slot**: `server/telemetry` plus `server/ban-engine` reaction model.

### 90. Recoil and Spread RNG Correlation
- **Name and Platform/Layer**: recoil/spread RNG correlation; server-side behavioral telemetry.
- **Observable**: Clean baseline has compensation error around the weapon's public recoil pattern, not exact hidden per-shot RNG. Anomaly is counter-motion correlated to server-secret recoil/spread samples before visual feedback is available.
- **Mechanism**: Server compares per-tick aim deltas against authoritative recoil/spread RNG generated for the player and weapon, conditioned on shot index and stance.
- **Tampering class surfaced**: No-recoil automation, memory-read of weapon RNG, and aim assist with internal state access.
- **False-positive risk + gating**: Skilled recoil control can match average patterns. Gate only on correlation to hidden random components across many shots.
- **Horkos slot**: `server/ban-engine` signed-rule/model feature consuming authoritative weapon state.
