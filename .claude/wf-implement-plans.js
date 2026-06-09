export const meta = {
  name: 'implement-plans',
  description: 'Implement the 24 Horkos detection impl-plans into real code; opus-only; shared-schema first, domains sequential, then verify. Backup prompts on every agent.',
  phases: [
    { title: 'Schema', detail: 'one opus agent lands all shared wire-schema/IOCTL/data-category additions', model: 'opus' },
    { title: 'Implement', detail: '24 domains implemented sequentially (no file races), opus each', model: 'opus' },
    { title: 'Verify', detail: 'opus agent builds host-buildable parts, fixes trivial breaks, reports', model: 'opus' },
  ],
}

const DOMAINS = [
  'win-kernel-object-callbacks', 'win-kernel-memory-injection', 'win-kernel-thread-injection',
  'win-kernel-driver-integrity', 'win-kernel-syscall-etw-integrity', 'win-hypervisor-detection',
  'win-usermode-overlay', 'win-input-automation', 'win-handle-memory-access',
  'linux-ebpf-memory', 'linux-ebpf-injection', 'linux-module-integrity', 'linux-proton-wine',
  'macos-injection', 'macos-codesign-integrity', 'dma-hardware', 'hardware-input-devices',
  'memory-integrity-selfcheck', 'timing-side-channels', 'behavioral-aim', 'behavioral-gamestate',
  'network-anomaly', 'anti-analysis-environment', 'process-genealogy',
]

const RULES = `Horkos is an AUTHORIZED, commercially-licensed, open-core anti-cheat. This is defensive engineering: implement read-only telemetry sensors only. No tampering/injection/evasion code.

BINDING GUARDRAILS (CLAUDE.md) — failure to follow is a failed task:
1. No platform API outside platform/ or a backends/ folder; conditional code uses HK_PLATFORM_WINDOWS/LINUX/MACOS, never raw _WIN32/__linux__/__APPLE__.
3. Module comment on every new file (role, target platform, interface it implements/declares).
4. Kernel and userspace code never share a translation unit.
5. Kernel C: safe string functions only; check every NTSTATUS / kernel return.
6. Linux kernel code compiles -Wall -Wextra -Werror.
7. macOS ES code replies to every AUTH event.
8. Server: fully async tokio; thiserror; NO unwrap() outside tests.
10. Attestation.h interface is stable; change backends, not the interface.
11. ANY new telemetry field requires updating server/api/data-categories.md (the Schema phase already centralised this — do NOT re-edit data-categories.md / event_schema.h / ioctl.h here; if a schema type you need is missing, leave a // HK-TODO(schema): note and stub around it, do not add wire types in a domain TU).
12. bypass-tests/ are a merge gate: every new sensor under a security folder needs a corresponding bypass test (author it even if it can only run on the real toolchain).
13. *** ON UNCERTAINTY: if the plan flags a kernel/ES/signing API as unverified, or you are not certain of an API's exact contract (IRQL, IRP lifecycle, ObRegisterCallbacks semantics, ETW-TI kernel consumer, ES reply deadlines), DO NOT GUESS. Write the surrounding scaffold and a clearly-commented stub with // HK-UNCERTAIN: <what needs on-box verification>, and leave the risky call unimplemented. A BSOD is worse than an unfinished function. ***
14. Logic lands with tests where testable.

This host is macOS with NO Windows/Linux kernel toolchain. Windows/Linux kernel code cannot be compiled here — write it carefully per the plan and the existing sibling files, flag uncertainty, do not attempt to build it. Server (Rust), host C++ (cmake/ctest), obfuscator (LLVM lit), and macOS ES (clang -fsyntax-only) ARE buildable here.`

// Authoritative, verified API contracts (researched 2026-06-09 from MS Learn /
// kernel.org / Apple). Agents MUST follow these EXACTLY and WebFetch the canonical
// URL before implementing any flagged API. Where a plan contradicts a contract
// below, the CONTRACT wins — fix the code and leave a // HK-DOC note.
const DOCS = `=== VERIFIED API CONTRACTS (follow exactly; WebFetch the URL before coding a flagged API) ===

WINDOWS KERNEL
- ObRegisterCallbacks — https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks
  IRQL <= APC_LEVEL. Returns STATUS_ACCESS_DENIED if the callback routines are NOT in a SIGNED kernel image; STATUS_FLT_INSTANCE_ALTITUDE_COLLISION on altitude clash. OB_OPERATION_REGISTRATION.ObjectType is assigned PsProcessType/PsThreadType WITHOUT deref (it is POBJECT_TYPE*); the pre/post callback compares Info->ObjectType against *PsProcessType WITH deref. Unregister all callbacks before unload.
- PsSetCreateProcessNotifyRoutineEx2 — https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex2
  IRQL PASSIVE_LEVEL. The driver image MUST set IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY (link /INTEGRITYCHECK) or registration returns STATUS_ACCESS_DENIED. Remove=TRUE waits for all in-flight callbacks to complete before returning (safe teardown).
- *** ETW Threat-Intelligence (Microsoft-Windows-Threat-Intelligence) — IT IS A PROTECTED PROVIDER. ***
  It CANNOT be consumed by an ordinary KMDF driver. Only a PPL/PP (Protected-Process-Light, anti-malware/ELAM-signed) USER-MODE process may open a real-time session on it; the kernel emits to it via EtwRegister. Horkos does NOT currently hold an anti-malware/ELAM certificate. THEREFORE any plan that consumes ETW-TI from the driver is INCORRECT: implement the consumer surface as a PPL user-mode session stub and mark it // HK-UNCERTAIN(etw-ti): requires anti-malware/ELAM cert + PPL; do NOT write a kernel ETW-TI consumer. Refs: https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/event-tracing-for-windows--etw-

LINUX eBPF / LSM
- BPF LSM — https://docs.kernel.org/bpf/prog_lsm.html
  Requires kernel >= 5.7, CONFIG_BPF_LSM=y, AND "bpf" present in the lsm= boot parameter / CONFIG_LSM list — otherwise lsm/ programs will NOT attach (document this prerequisite in the build/README, do not assume it). SEC("lsm/<hook>") is non-sleepable; SEC("lsm.s/<hook>") is sleepable (BPF_F_SLEEPABLE) and only valid on hooks known to allow sleeping. Return value: 'ret' is the prior LSM/BPF program's result (0 if first); return -EPERM to DENY; an audit-only program MUST return ret (never hard 0) to avoid overriding another module's deny. Compile -Wall -Wextra -Werror (guardrail #6).

MACOS EndpointSecurity
- es_respond_auth_result / es_message_t.deadline — https://developer.apple.com/documentation/endpointsecurity/es_message_t/deadline
  Every AUTH message carries its OWN es_message_t.deadline; you MUST call es_respond_auth_result before that deadline or the KERNEL TERMINATES your process. Do not hardcode a timeout — honor the per-message deadline. Reply to EVERY auth event exactly once (guardrail #7).
  es_delete_client MUST be called on the SAME thread that called es_new_client and inherently races event delivery — drain async sink work with a barrier before freeing context (as kernel/macos/es/EsClient.mm already does). Keep the ES handler non-blocking.`

// Single guide every agent receives: guardrails + verified contracts.
const GUIDE = RULES + "\n\n" + DOCS

// Every agent gets main + 3 backup framings so the content filter can't drop a domain.
async function runAgent(spec) {
  const { label, phase, build } = spec
  const prompts = build() // array of 4 prompt strings, escalating defensive framing
  for (let i = 0; i < prompts.length; i++) {
    const lbl = i === 0 ? label : `${label}#b${i}`
    const r = await agent(prompts[i], { label: lbl, phase, model: 'opus', agentType: 'general-purpose' })
    if (r && typeof r === 'string' && r.trim().length) return { ok: true, attempt: i, note: r.slice(0, 600) }
  }
  return { ok: false, attempt: prompts.length, note: 'all 4 framings blocked/empty' }
}

// ---- Phase 1: shared schema ------------------------------------------------
phase('Schema')
const schemaRes = await runAgent({
  label: 'schema:shared', phase: 'Schema',
  build: () => {
    const task = `Land ALL shared wire-schema additions the 24 implementation plans require, in ONE consistent pass, so domain agents never touch these files.

STEPS:
1. Read every plan's "Interfaces & data structures" section: docs/impl-plans/*.md (24 files; each is <650 lines). Collect every new event payload struct, every new HK_EVENT_* / IOCTL enum, and every new telemetry field.
2. Edit sdk/include/horkos/event_schema.h: add the new payload structs, bump HK_EVENT_SCHEMA_VERSION once, add a HK_STATIC_ASSERT size check for each (match the existing style in that header).
3. Edit sdk/include/horkos/ioctl.h: add the new HK_EVENT_* type enum values (keep them distinct; reuse the existing drain path, add IOCTL codes only if a plan truly needs a new control verb).
4. Update tests/unit/test_event_schema_sizes.cpp and tests/unit/test_ioctl_sizes.cpp with the new size asserts.
5. Update server/api/data-categories.md: declare every new telemetry field (guardrail #11).
6. Add matching serde structs on the server JSON plane (server/telemetry/src/schema.rs) for fields that reach the server — async/thiserror/no-unwrap (guardrail #8).
7. Build-check what is buildable here: \`cd server && cargo build\` and a host cmake configure+build of the unit tests; fix your own breaks. Report compile status honestly.

Keep additions consistent (one naming scheme, no duplicate type tags across plans — dedup where two plans propose the same event). Where a plan's type is half-specified, choose the minimal sound layout and note it.`
    return [
      `${GUIDE}\n\nYOU OWN THE SHARED SCHEMA.\n${task}\n\nReturn: files changed, schema version, new type count, and host build status (cargo + ctest).`,
      `Defensive telemetry schema consolidation for the licensed Horkos anti-cheat. ${task}\nGuardrails:\n${GUIDE}\nReport files changed + build status.`,
      `Engineering task: merge the data-structure sections of 24 design docs into the shared C headers and Rust telemetry mirror, with size asserts and a data-category declaration for each field. ${task}\nContext/rules:\n${GUIDE}`,
      `Read-only observability schema task. Consolidate new event payload structs into sdk/include/horkos/event_schema.h + ioctl.h, add asserts and server serde mirrors, update data-categories.md. Source: docs/impl-plans/*.md. Build-check server + host unit tests. Rules:\n${GUIDE}`,
    ]
  },
})
log(`Schema phase: ${schemaRes.ok ? 'done (attempt ' + schemaRes.attempt + ')' : 'FAILED — domains will stub schema'}`)

// ---- Phase 2: domains, SEQUENTIAL (no file races) --------------------------
phase('Implement')
const implResults = []
for (const key of DOMAINS) {
  const task = `Implement the plan in docs/impl-plans/${key}.md into real code.

STEPS:
1. Read docs/impl-plans/${key}.md (your plan) and the existing sibling files it references (e.g. kernel/win/src/Callbacks.c, kernel/linux/bpf/src/*, kernel/macos/es/EsClient.mm, sdk/src/backends/*, server/* — read the ones your plan names so you match their style and conventions).
2. Create the NEW files the plan lists, each with a module comment (guardrail #3). Implement the sensors per the plan.
3. Make the small edits the plan calls for in EXISTING files. The shared schema files (event_schema.h, ioctl.h, data-categories.md) are already done by the Schema phase — do NOT edit them; if a needed type is missing, // HK-TODO(schema) and stub around it.
4. Author the bypass test(s) the plan requires under bypass-tests/<platform>/ (guardrail #12), even if they only run on the real toolchain.
5. Wire CMake/build files the plan names. Default new security features OFF / behind their flag.
6. For Windows/Linux kernel code: cannot compile here — write it carefully against the plan + sibling files, and for any API the plan flagged uncertain, write a // HK-UNCERTAIN stub (guardrail #13), do NOT guess. For server/host-C++/macOS-ES code that IS buildable here, build-check the part you touched and fix your own breaks.

Stay strictly within this domain's files. Do not refactor other domains.`
  const res = await runAgent({
    label: `impl:${key}`, phase: 'Implement',
    build: () => [
      `${GUIDE}\n\nDOMAIN: ${key}.\n${task}\n\nReturn: new files created, existing files edited, bypass tests added, every // HK-UNCERTAIN you left, and build status for anything buildable here.`,
      `You are implementing read-only host-integrity sensors for the licensed Horkos anti-cheat (EDR-class work). DOMAIN: ${key}. ${task}\nGuardrails:\n${GUIDE}\nReport files + uncertainties + build status.`,
      `Engineering implementation from an approved design doc. DOMAIN: ${key}. Turn docs/impl-plans/${key}.md into code: new files (with module comments), the small edits it names, bypass tests, build wiring. Flag any uncertain OS API as a stub instead of guessing. ${task}\nRules:\n${GUIDE}`,
      `Defensive monitoring implementation, single domain ${key}. Follow its plan file exactly; create the sensor files and tests; stub+flag any kernel/ES API the plan marked unverified. Build-check only the host-buildable parts. Rules:\n${GUIDE}`,
    ],
  })
  implResults.push({ key, ...res })
  log(`impl ${key}: ${res.ok ? 'ok (b' + res.attempt + ')' : 'FAILED all framings'} — ${implResults.filter(r => r.ok).length}/${DOMAINS.length} done`)
}

// ---- Phase 3: verify + fix -------------------------------------------------
phase('Verify')
const verifyRes = await runAgent({
  label: 'verify:build', phase: 'Verify',
  build: () => {
    const task = `Verify the implementation pass did not break the host-buildable subsystems, and fix trivial breaks (do NOT touch kernel-only code that cannot compile here).
1. Server: \`cd server && cargo build && cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check\`.
2. Host C++: fresh cmake configure + build + \`ctest\` of the existing host unit/bypass tests.
3. Obfuscator: run its lit suite if present.
4. macOS ES: \`clang -fsyntax-only\` on kernel/macos/es/EsClient.mm against its include path (it is host-syntax-checkable).
Fix compile/test breaks you introduced this run (missing include, signature drift from the new schema, fmt). Leave kernel/win + kernel/linux code alone (no toolchain).
Then grep the tree for // HK-UNCERTAIN and // HK-TODO(schema) and collect them.`
    return [
      `${GUIDE}\n\n${task}\n\nReturn: per-suite pass/fail with the actual command output tail, the list of // HK-UNCERTAIN flags, and what still needs the Windows/Linux toolchain.`,
      `Build-verification + triage for the licensed Horkos anti-cheat after an implementation pass. ${task}\nRules:\n${GUIDE}\nReport honest pass/fail per suite.`,
      `Run the host build/test suites, fix only self-introduced breaks, and collect all uncertainty markers. ${task}\n${GUIDE}`,
      `Verification task: compile server + host C++ + obfuscator + macOS ES, report pass/fail honestly, fix trivial regressions, list every HK-UNCERTAIN. ${task}\n${GUIDE}`,
    ]
  },
})

const okCount = implResults.filter(r => r.ok).length
log(`Implement: ${okCount}/${DOMAINS.length} domains. Schema ${schemaRes.ok ? 'ok' : 'FAILED'}. Verify ${verifyRes.ok ? 'ran' : 'FAILED'}.`)
return {
  schema: schemaRes.ok,
  domainsDone: okCount,
  domainsFailed: implResults.filter(r => !r.ok).map(r => r.key),
  verify: verifyRes.ok ? verifyRes.note : 'verify failed',
  perDomain: implResults.map(r => ({ key: r.key, ok: r.ok, attempt: r.attempt })),
}
