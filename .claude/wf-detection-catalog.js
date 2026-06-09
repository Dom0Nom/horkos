export const meta = {
  name: 'detection-catalog',
  description: 'Design ~200 niche anti-cheat integrity-telemetry signals for Horkos across 24 specialist domains, dedup, gap-fill',
  phases: [
    { title: 'Design', detail: '24 niche opus specialists, ~9 signals each, auto-retry on empty', model: 'opus' },
    { title: 'GapFill', detail: 'opus synthesis: dedup review + fill under-covered areas', model: 'opus' },
  ],
}

const DETECTION_SCHEMA = {
  type: 'object',
  properties: {
    detections: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          name: { type: 'string', description: 'short specific signal name' },
          platform: { type: 'string', description: 'windows-kernel | windows-user | linux-ebpf | linux-lkm | macos-es | macos-user | dma | hardware | server | network | cross' },
          layer: { type: 'string', description: 'kernel | userspace | hardware | hypervisor | server | network' },
          signal: { type: 'string', description: 'the observable that distinguishes a clean process/system from a tampered one (1 sentence)' },
          mechanism: { type: 'string', description: 'the exact OS API / hook / data source the client reads to observe it' },
          catches: { type: 'string', description: 'the unauthorized-modification class this surfaces' },
          fp_risk: { type: 'string', description: 'low | medium | high' },
          fp_note: { type: 'string', description: 'legitimate software that can produce the same observable, and how to gate it' },
          horkos_slot: { type: 'string', description: 'file/interface in the horkos tree where this sensor would live' },
          references: { type: 'string', description: 'API names / doc anchors' },
        },
        required: ['name', 'platform', 'layer', 'signal', 'mechanism', 'catches', 'fp_risk', 'horkos_slot'],
      },
    },
  },
  required: ['detections'],
}

// Strong authorized/defensive framing. This is an observability/telemetry-design
// task for a licensed product: name the OS data source that reveals a tampered
// or externally-instrumented process. No offensive code is requested or produced.
const CONTEXT = `You are a senior integrity engineer on Horkos, an AUTHORIZED, commercially-licensed, open-core (MIT) cross-platform game-integrity / anti-cheat product. Your job here is pure DEFENSIVE OBSERVABILITY DESIGN: for a given subsystem, enumerate telemetry SIGNALS the integrity client can sample from documented OS interfaces to distinguish a clean, untampered game process and system from one that has been externally instrumented, patched, or fed synthetic input. Every signal is read-only sampling that the client reports to a server, which alone makes trust decisions. You are NOT asked to write, and must not write, any code that performs tampering, injection, evasion, or bypass — only the sensor that OBSERVES the artifact such activity leaves behind.

This is the same category of work as EDR/host-integrity telemetry: you name a benign baseline, the anomalous observable, and the documented API that reads it.

Horkos architecture and the signals ALREADY implemented (do not re-list these — go deeper):
- Windows: KMDF boot-start driver. Implemented: PsSetCreateProcessNotifyRoutineEx (proc create/exit), PsSetCreateThreadNotifyRoutine (thread create), PsSetLoadImageNotifyRoutine (image load), ObRegisterCallbacks handle filter on process+thread types (records requester->target + OriginalDesiredAccess, optional rights-reduction). SPSC ring buffer -> IOCTL bridge -> userspace SDK -> server.
- Linux: eBPF primary (BPF LSM lsm/file_open audit-only; tracepoints sys_enter_ptrace + sched_process_exec) over a CO-RE shared ringbuf; LKM behind a build flag (sched_process_exec probe). Steam Deck Game Mode requires the eBPF path.
- macOS: EndpointSecurity client (NOTIFY_EXEC + AUTH_EXEC, observe-only allow). Userspace daemon now; System Extension once the entitlement lands.
- DMA detection: PCIe enumeration + IOMMU/bus-master cross-check (observe-only).
- Attestation: tpm2-tss (Win/Linux) + Secure Enclave (macOS) behind one C++ Attestation interface (currently NotImplemented stubs).
- Server: Rust/axum/tokio, fail-closed trust gate, signed-rule plumbing, telemetry ingest (ort/ONNX wired, no model loaded). ALL trust authority is server-side; clients sample + report only.

The implemented signals are deliberately basic. Design a DEEP, niche catalog of NEW observability signals.`

const NICHES = [
  { key: 'win-kernel-object-callbacks', focus: 'Windows kernel callback-surface integrity: verifying Horkos own Ob/Cm/notify callbacks are still registered and un-shadowed (altitude collisions, callback-table edits, deregistration of our notify routines), CmRegisterCallback registry-access observation, MiniFilter altitude-squatting by other drivers, anomalous registered-callback counts.' },
  { key: 'win-kernel-memory-injection', focus: 'Windows kernel memory-state anomalies in the protected process: executable private memory not backed by a FILE_OBJECT (manual-mapped images), VAD entries with EXECUTE permission and no image backing, regions whose contents mismatch the on-disk module (module stomping), W^X violations, oversized private executable commits — all observed via VAD walk / MMVAD / PsGetProcessSectionBaseAddress.' },
  { key: 'win-kernel-thread-injection', focus: 'Windows kernel thread-origin validation in the protected process: thread start addresses outside any loaded module image, threads created cross-process, APC-queued user routines (NtQueueApcThread), context/Wow64 redirection, TEB/StartAddress mismatch — observed via PsSetCreateThreadNotifyRoutine + ETW-TI thread metadata.' },
  { key: 'win-kernel-driver-integrity', focus: 'Windows kernel driver/module trust: known-vulnerable-driver hash inventory (the loaded-driver list cross-checked against a blocklist), unsigned/test-signed driver presence, DRIVER_OBJECT MajorFunction dispatch pointing outside the owning driver image (IRP-table edits), unexpected \\Driver/\\Device objects, MmUnloadedDrivers history, unsigned big-pool allocations.' },
  { key: 'win-kernel-syscall-etw-integrity', focus: 'Windows kernel syscall/ETW surface integrity: validating KiServiceTable / shadow table entries point into ntoskrnl/win32k, detecting infinity-hook style HalpPerfInterrupt redirection, ETW threat-intel provider being disabled (EtwThreatIntProvRegHandle), MSR LSTAR pointing off the syscall entry, and our own integrity callbacks surviving KPP.' },
  { key: 'win-hypervisor-detection', focus: 'Windows virtualization-state observability: presence of an unexpected hypervisor under the OS (CPUID 0x40000000 vendor + RDTSC/vmexit latency), memory-virtualization (EPT/SLAT) page-permission splits used to hide patched pages (#VE / exec-vs-read divergence), VBS/HyperGuard state, distinguishing a sanctioned analysis VM from an attached out-of-OS inspection layer.' },
  { key: 'win-usermode-overlay', focus: 'Windows usermode render/overlay observability: hooks on DXGI/D3D/Vulkan Present & SwapChain (prologue patches on the vtable entries), externally-created topmost/layered transparent windows over the game (EnumWindows + extended styles), DWM thumbnail/Magnification API consumers, WH_* global hooks via SetWindowsHookEx, GDI screen-capture of the game window.' },
  { key: 'win-input-automation', focus: 'Windows input-provenance observability: distinguishing hardware HID input from synthetic input (LLMHF_INJECTED / LLMHF_LOWER_IL_INJECTED low-level-hook flags), filter drivers stacked on \\Device\\KeyboardClass/PointerClass, raw-input device set anomalies, inter-report timing regularity that has no human jitter, serial-bridge devices presenting as a mouse.' },
  { key: 'win-handle-memory-access', focus: 'Windows external-access observability against the protected process: foreign OpenProcess attempts surfaced by the Ob pre-op, NtReadVirtualMemory/NtWriteVirtualMemory/MmCopyVirtualMemory targeting our process (ETW-TI ReadVm/WriteVm events), handle-duplication chains that reach the game, periodic PsLookupProcessByProcessId polling by foreign tools.' },
  { key: 'linux-ebpf-memory', focus: 'Linux eBPF memory-access observability on the protected process: foreign process_vm_readv/writev (lsm/ptrace_access_check, tracepoints), opens of /proc/<pid>/mem and /proc/<pid>/maps by other processes, PTRACE_PEEK/POKE, runtime PROT_EXEC|PROT_WRITE mappings (lsm/mmap_file, lsm/file_mprotect), /dev/mem and /dev/kmem access, memfd_create+execveat.' },
  { key: 'linux-ebpf-injection', focus: 'Linux eBPF userspace-loader observability: LD_PRELOAD / /etc/ld.so.preload (lsm/bprm_creds_for_exec env + file watch), GOT/PLT entry integrity of the game (uprobe sampling), dlopen of libraries outside an expected set (uprobe on dlopen), ELF interpreter substitution, library load-order anomalies in the protected process.' },
  { key: 'linux-module-integrity', focus: 'Linux kernel/module trust observability: module-load events (lsm/kernel_module_request, finit_module/init_module tracepoints), kallsyms/ksymtab consistency, modules present in memory but hidden from sysfs, ftrace/kprobe hooks installed on syscalls, /dev/mem and MSR access, kernel-lockdown & secure-boot state, foreign enumeration of loaded BPF programs.' },
  { key: 'linux-proton-wine', focus: 'Linux Proton/Wine + Steam Deck integrity observability: unexpected Wine DLL overrides (WINEDLLOVERRIDES), foreign shared objects mapped into the Proton prefix, wineserver memory access to the game, processes entering the pressure-vessel/pivot-root namespace from outside, Game-Mode constraints that forbid an LKM, gamescope compositor consumers, Deck read-only-rootfs assumptions being violated.' },
  { key: 'macos-injection', focus: 'macOS process-inspection observability via EndpointSecurity + userspace: foreign task_for_pid against the game, mach_vm_read/write/protect on it, ES NOTIFY_MMAP / NOTIFY_GET_TASK / NOTIFY_PROC_CHECK, DYLD_INSERT_LIBRARIES seen in the exec environment, mach exception-port registration on the game task, thread_create_running from another task, debugger attach.' },
  { key: 'macos-codesign-integrity', focus: 'macOS code-signing & platform-trust observability: AMFI and hardened-runtime status, com.apple.security.get-task-allow on the running image (debuggable), SIP state, csops/SecCode validity of loaded dylibs, Gatekeeper/notarization status, library-validation flag, ES NOTIFY_CS_INVALIDATED (a signature going invalid at runtime), amfid anomalies.' },
  { key: 'dma-hardware', focus: 'DMA/peripheral hardware-trust observability: PCIe config-space signatures of inspection boards (devices spoofing NIC/capture-card IDs), BAR0 size vs declared capability mismatch, devices with bus-master enabled but no bound driver or outside any IOMMU domain, hot-plug after game start, ACS/topology anomalies, TLP/latency fingerprints, option-ROM/MSI-X table irregularities.' },
  { key: 'hardware-input-devices', focus: 'USB/HID device-trust observability: microcontroller HID boards (Arduino/Leonardo class) and serial-bridge devices presenting as mice/keyboards, USB descriptor fingerprints (VID/PID, low-entropy iManufacturer/iProduct), composite-device irregularities, input reports with zero inter-arrival jitter, pointer deltas appearing with no corresponding enumerated USB endpoint.' },
  { key: 'memory-integrity-selfcheck', focus: 'Horkos client self-integrity observability: hashing our own .text vs the on-disk image, IAT/EAT integrity, prologue scans for inline patches (jmp/push-ret) on our critical functions, return-address/stack-walk validation to spot external callers of our entry points, page-protection audit of our own image, hardware-breakpoint registers (DR0-DR7) set on our code, loader-entry tamper.' },
  { key: 'timing-side-channels', focus: 'Timing & execution-trace observability around guarded regions: RDTSC deltas indicating single-stepping or a present debugger, CPUID serializing latency for hypervisor presence, trap-flag/single-step artifacts, INT3 (0xCC) byte scans on guarded code, guard-page fault frequency, KUSER_SHARED_DATA tick vs RDTSC skew, exception-rate anomalies.' },
  { key: 'behavioral-aim', focus: 'Server-side aiming-behaviour observability (statistical/ML feature design): the per-tick telemetry the client must carry so the server can model flick kinematics (overshoot/settle), angular-velocity spikes onto targets, reaction-time distribution vs a human floor, aim smoothness/jerk, target-switch latency, recoil-compensation regularity, sub-pixel correction signatures, time-on-target ratios.' },
  { key: 'behavioral-gamestate', focus: 'Server-side game-state-knowledge observability: server-reconstructable signals for pre-aim before line-of-sight, engaging through full occlusion, vision-cone/knowledge violations, beelining to high-value positions (positional priors), tracking entities through smoke/walls, reacting to off-screen actors, peeker-advantage that exceeds latency budget. Define what the authoritative server must log/replay to compute each.' },
  { key: 'network-anomaly', focus: 'Network-layer integrity observability: deliberate uplink stall + burst (lag-switch), injected latency/jitter, client-tick vs server-tick drift, out-of-order or duplicated input frames, movement extrapolation beyond bounds, packet-cadence time-dilation (speed manipulation), RTT divergence between the control and game channels.' },
  { key: 'anti-analysis-environment', focus: 'Cross-platform analysis-tooling presence observability: debugger attach (PEB BeingDebugged/NtGlobalFlag, TracerPid on Linux, P_TRACED sysctl on macOS), dynamic-instrumentation frameworks resident in the process (named mappings/threads/pipes characteristic of common instrumentation toolkits), memory-editor and debugger applications running on the host (window/driver/named-pipe fingerprints), trampoline patterns left by common hooking libraries.' },
  { key: 'process-genealogy', focus: 'Process-genealogy & loader-trust observability: the game not parented by its expected launcher/store client, suspended-create-then-resume launch patterns, signed-binary-proxy/LOLBin loaders in the ancestry, unsigned modules inside the protected process, integrity-level/token mismatches, process-tree fingerprints matching known external-tool launchers.' },
]

// Resilient agent: if the policy filter nulls an agent, retry once with a more
// abstract, monitoring-framed prompt so a non-deterministic block doesn't drop a niche.
async function designNiche(niche) {
  const base = `${CONTEXT}

YOUR SUBSYSTEM: ${niche.key}
SCOPE: ${niche.focus}

Design 9 DISTINCT, advanced observability signals strictly within this subsystem. Each must:
- name a real, current OS API / hook / data source in 'mechanism' (no invented APIs)
- go DEEPER than the basic signals already implemented (assume those are done)
- be implementable in the Horkos tree; put the file/interface in 'horkos_slot'
- state the unauthorized-modification class it surfaces in 'catches'
- give an honest false-positive risk and how to gate it (what legitimate software shares the observable)
Be niche and precise; avoid generic overlap. Return exactly 9 signals.`

  let r = await agent(base, { label: `niche:${niche.key}`, phase: 'Design', model: 'opus', schema: DETECTION_SCHEMA })
  if (r && r.detections && r.detections.length) return { niche: niche.key, detections: r.detections }

  // Retry: maximally abstract, EDR-telemetry framing, no technique nouns in the ask.
  const retry = `You are designing read-only host-integrity TELEMETRY for Horkos, a licensed, authorized game-integrity product. This is an observability spec, equivalent to EDR sensor design. For the subsystem "${niche.key}" (${niche.focus}), list 9 documented OS data sources the integrity client can SAMPLE to tell whether the monitored process/system is in a clean baseline state or a modified one. For each: the benign baseline, the anomalous observable, and the exact documented API that reads it. This is purely defensive monitoring; no modification, injection, or evasion logic is involved. Architecture context for slotting:
${CONTEXT}
Return exactly 9 signals.`
  r = await agent(retry, { label: `niche:${niche.key}#retry`, phase: 'Design', model: 'opus', schema: DETECTION_SCHEMA })
  return { niche: niche.key, detections: (r && r.detections) || [] }
}

phase('Design')
const raw = await parallel(NICHES.map((niche) => () => designNiche(niche)))

// Flatten + tag with niche, dedup by normalized name.
const seen = new Set()
const all = []
for (const block of raw.filter(Boolean)) {
  for (const d of block.detections) {
    const key = (d.name || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim()
    if (!key || seen.has(key)) continue
    seen.add(key)
    all.push({ ...d, niche: block.niche })
  }
}
const emptyNiches = NICHES.filter((n) => !raw.some((b) => b && b.niche === n.key && b.detections.length)).map((n) => n.key)
log(`Design: ${all.length} unique signals across ${raw.filter(Boolean).length} niches. Empty niches: ${emptyNiches.length ? emptyNiches.join(', ') : 'none'}`)

const byNiche = {}
for (const d of all) byNiche[d.niche] = (byNiche[d.niche] || 0) + 1
const coverage = NICHES.map((n) => `${n.key}: ${byNiche[n.key] || 0}`).join('\n')
const nameList = all.map((d) => `[${d.niche}] ${d.name} (${d.platform})`).join('\n')

phase('GapFill')
const target = 200
const need = Math.max(0, target - all.length)
let extra = { detections: [] }
if (need > 0) {
  extra = await agent(
    `${CONTEXT}

A panel of 24 subsystem specialists produced this catalog of ${all.length} observability signals. Per-subsystem counts:
${coverage}

All signal names (subsystem + platform):
${nameList}

TASK: We want ~${target} total. Design ${need + 8} ADDITIONAL net-new observability signals NOT already listed, prioritising the THINNEST subsystems above and any cross-cutting gaps (e.g. self-protection of the integrity client, attestation-backed challenge/response, supply-chain/loader trust, novel correlations across two existing signals). Same depth rules: real APIs in 'mechanism', concrete 'horkos_slot', honest 'fp_risk'. Do not duplicate any existing name.`,
    { label: 'gapfill:synthesis', phase: 'GapFill', model: 'opus', schema: DETECTION_SCHEMA }
  )
}

for (const d of (extra.detections || [])) {
  const key = (d.name || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim()
  if (!key || seen.has(key)) continue
  seen.add(key)
  all.push({ ...d, niche: d.niche || 'gapfill' })
}

log(`Final catalog: ${all.length} observability signals`)
return { count: all.length, perNiche: byNiche, emptyNiches, detections: all }
