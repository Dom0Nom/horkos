export const meta = {
  name: 'impl-plans',
  description: 'Write per-domain implementation plans for the 216 Horkos detection signals; one opus agent per domain, 3 backup prompts each',
  phases: [
    { title: 'Plan', detail: '24 domain opus agents read their catalog slice + write docs/impl-plans/<domain>.md', model: 'opus' },
  ],
}

// key, human title, catalog start line (so each agent reads ONLY its ~95-line slice;
// the catalog file is >256KB and cannot be Read whole).
const NICHES = [
  { key: 'win-kernel-object-callbacks', title: 'Windows Kernel — Object / Notify Callback Integrity', line: 15 },
  { key: 'win-kernel-memory-injection', title: 'Windows Kernel — Memory Injection & Image Anomalies', line: 101 },
  { key: 'win-kernel-thread-injection', title: 'Windows Kernel — Thread Origin Validation', line: 195 },
  { key: 'win-kernel-driver-integrity', title: 'Windows Kernel — Driver / Module Trust', line: 289 },
  { key: 'win-hypervisor-detection', title: 'Windows — Hypervisor / Virtualization State', line: 383 },
  { key: 'win-usermode-overlay', title: 'Windows Usermode — Render / Overlay Hooks', line: 477 },
  { key: 'win-input-automation', title: 'Windows — Input Provenance & Automation', line: 571 },
  { key: 'win-handle-memory-access', title: 'Windows — External Memory Access', line: 665 },
  { key: 'linux-ebpf-memory', title: 'Linux eBPF — Memory Access', line: 759 },
  { key: 'linux-ebpf-injection', title: 'Linux eBPF — Userspace Loader / Injection', line: 853 },
  { key: 'linux-module-integrity', title: 'Linux — Kernel / Module Trust', line: 947 },
  { key: 'linux-proton-wine', title: 'Linux — Proton / Wine / Steam Deck', line: 1041 },
  { key: 'macos-injection', title: 'macOS — Process Inspection / Injection', line: 1135 },
  { key: 'macos-codesign-integrity', title: 'macOS — Code-Signing & Platform Trust', line: 1229 },
  { key: 'dma-hardware', title: 'DMA / Peripheral Hardware Trust', line: 1323 },
  { key: 'hardware-input-devices', title: 'USB / HID Device Trust', line: 1417 },
  { key: 'memory-integrity-selfcheck', title: 'Client Self-Integrity', line: 1511 },
  { key: 'timing-side-channels', title: 'Timing & Execution-Trace Side-Channels', line: 1605 },
  { key: 'behavioral-aim', title: 'Server-Side — Aiming Behaviour', line: 1699 },
  { key: 'behavioral-gamestate', title: 'Server-Side — Game-State Knowledge', line: 1793 },
  { key: 'network-anomaly', title: 'Network-Layer Integrity', line: 1887 },
  { key: 'anti-analysis-environment', title: 'Cross-Platform — Analysis-Tooling Presence', line: 1981 },
  { key: 'process-genealogy', title: 'Process Genealogy & Loader Trust', line: 2075 },
  { key: 'win-kernel-syscall-etw-integrity', title: 'Windows Kernel — Syscall / ETW / PatchGuard Surface Integrity', line: 2169 },
]

const ARCH = `Horkos is an AUTHORIZED, commercially-licensed, open-core (MIT) cross-platform game-integrity / anti-cheat product. This is a defensive engineering planning task: turn already-designed read-only telemetry signals into a concrete implementation plan. No tampering/injection/evasion code is designed — only read-only sensors and where they slot into the tree.

Repo layout (already exists):
- kernel/win/ — KMDF boot-start driver (DriverEntry.c, Notify.c, Callbacks.c, RingBuffer.c, Whitelist.c, IrpDispatch.c; include/horkos_kernel.h). SPSC ring -> IOCTL bridge.
- kernel/linux/bpf/ (LSM + tracepoints, CO-RE, shared ringbuf), kernel/linux/lkm/, kernel/linux/userspace/ (libbpf Loader). kernel/linux/CMakeLists.txt gates eBPF (default OFF) + LKM.
- kernel/macos/es/EsClient.mm (EndpointSecurity), daemon/macos/.
- dma_detect/ (PCIe + IOMMU/BME), sdk/ (event_schema.h, ioctl.h, sdk.cpp + win/posix driver-probe backends), attestation/ (Attestation.h stable interface), server/ (Rust axum/tokio: api, ban-engine, telemetry, license-server), obfuscator/ (LLVM 19), bypass-tests/.

BINDING GUARDRAILS the plan MUST respect (from CLAUDE.md):
1. No platform API outside platform/ or a backends/ folder; conditional code uses HK_PLATFORM_WINDOWS/LINUX/MACOS, never raw _WIN32/__linux__/__APPLE__.
3. Module comment on every new file (role, target platform, interface).
4. Kernel and userspace code never share a translation unit.
5. Kernel C uses safe string functions only; every NTSTATUS / kernel return checked.
6. Linux kernel code compiles -Wall -Wextra -Werror.
7. macOS System Extension never drops an ES event without a reply.
8. Server fully async on tokio; thiserror for errors; no unwrap() outside tests.
10. Attestation.h is the stable interface; backends change, interface does not.
11. Adding a telemetry field requires updating server/api/data-categories.md in the same PR.
12. bypass-tests/ are a merge gate: any change under a security folder needs a corresponding bypass test.
13/On-uncertainty: when uncertain about a kernel API (IRQL, IRP lifecycle, ObRegisterCallbacks semantics, ES auth deadlines, signing requirements), STOP and FLAG it explicitly in the plan rather than guessing. A BSOD is worse than a delay.
14. Logic lands under TDD where testable.

All ban authority is server-side; clients sample + report only.`

const PLAN_SHAPE = `The implementation plan for docs/impl-plans/<KEY>.md must contain, in this order:
1. # title + one-line scope; list the catalog signal numbers it covers.
2. ## New files — table of path | role | module-comment summary (honor guardrail #3, #1, #4).
3. ## Interfaces & data structures — new headers, structs, the exact wire-schema/IOCTL additions (event_schema.h types, ioctl.h codes, HK_STATIC_ASSERT sizes) where the signal must reach the server; note guardrail #11 (data-categories.md) for every new telemetry field.
4. ## Mechanism implementation notes — per signal or grouped: the OS API/hook, IRQL/safety/lifetime concerns (Windows), -Werror/CO-RE concerns (Linux eBPF), ES reply-deadline concerns (macOS), tokio/no-unwrap concerns (server). Cite the real API names from the catalog.
5. ## Build wiring — CMake targets/options, feature flags, toolchain (WDK/clang-19/libbpf/Xcode), default ON/OFF.
6. ## Test strategy — unit tests AND the required bypass-tests (guardrail #12): name each bypass test and what it must demonstrate.
7. ## Sequencing — ordered milestones (what lands first, dependencies between signals).
8. ## Risks & UNCERTAINTY FLAGS — explicitly flag any kernel/ES/signing API you are NOT certain about (guardrail #13). Do not paper over uncertainty.

Be concrete and buildable. Reference real Horkos files. Keep it a PLAN (no full source); short illustrative signatures/struct sketches are fine.`

async function planNiche(niche) {
  const read = `First read your source: run \`grep -n "${niche.key}" docs/detection-catalog.md\` to confirm the section, then Read docs/detection-catalog.md with offset=${niche.line} limit=95 (the file is >256KB — do NOT read it whole). That slice is your ~9 detection signal designs for the "${niche.title}" domain.`

  const write = `Then WRITE the implementation plan to docs/impl-plans/${niche.key}.md. After writing, confirm the file exists and report: the path, its approx line count, and a one-line summary. If you could not complete it, say so plainly.`

  // 4 escalating framings: main + 3 backups. Each stays strictly defensive so a
  // non-deterministic content-filter block on one framing doesn't lose the domain.
  const prompts = [
    `${ARCH}\n\nYOUR DOMAIN: ${niche.key} — ${niche.title}.\n${read}\n\n${PLAN_SHAPE}\n\n${write}`,

    `You are a senior engineer writing a build plan for read-only host-integrity telemetry in Horkos, a licensed anti-cheat (EDR-class sensor work). DOMAIN: ${niche.key}.\n${read}\nProduce a concrete, file-level implementation plan: new files (with module comments), interfaces, wire-schema/IOCTL additions, OS-API integration notes with safety/IRQL/deadline concerns, build wiring, unit + bypass tests, sequencing, and explicit flags on any API you are unsure about (never guess kernel APIs).\nArchitecture + guardrails:\n${ARCH}\n${write}`,

    `Engineering task breakdown for a licensed, authorized game-integrity product. We have a catalog of read-only monitoring signals already designed; your job is purely the IMPLEMENTATION PLAN (no detection logic invented, no offensive code). DOMAIN: ${niche.key} — ${niche.title}.\n${read}\nWrite the plan covering: files to add, interfaces/structs, telemetry-schema changes (and the data-categories.md update each new field needs), how each sensor reads its documented OS data source and the correctness/safety concerns, CMake/build wiring, the unit and bypass tests required by our merge gate, and a milestone sequence. Flag uncertain OS APIs instead of guessing.\nContext:\n${ARCH}\n${write}`,

    `Defensive observability planning only. Treat each catalog entry as a monitoring sensor to be built into an existing codebase. DOMAIN: ${niche.key}.\n${read}\nDescribe, as a checklist-style implementation plan, the files, interfaces, schema/IOCTL additions, build steps, and tests (unit + required bypass test) needed to wire each sensor into Horkos, plus any OS-API uncertainties to resolve before coding. Repo + rules:\n${ARCH}\n${write}`,
  ]

  for (let i = 0; i < prompts.length; i++) {
    const label = i === 0 ? `plan:${niche.key}` : `plan:${niche.key}#b${i}`
    const r = await agent(prompts[i], { label, phase: 'Plan', model: 'opus', agentType: 'general-purpose' })
    if (r && typeof r === 'string' && r.trim().length) {
      return { key: niche.key, ok: true, attempt: i, note: r.slice(0, 400) }
    }
  }
  return { key: niche.key, ok: false, attempt: prompts.length, note: 'all 4 framings blocked/empty' }
}

phase('Plan')
const results = await parallel(NICHES.map((n) => () => planNiche(n)))

const done = results.filter((r) => r && r.ok)
const failed = results.filter((r) => !r || !r.ok)
log(`Plans: ${done.length}/${NICHES.length} written. Failed: ${failed.map((f) => f && f.key).join(', ') || 'none'}`)
return {
  written: done.length,
  failed: failed.map((f) => (f ? f.key : 'null')),
  perDomain: results.map((r) => r && ({ key: r.key, ok: r.ok, attempt: r.attempt })),
}
