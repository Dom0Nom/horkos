# Handoff — What Is NOT Implemented Yet (2026-06-10)

Supersedes `HANDOFF-verify-0610.md` (deleted from the working tree; recover
via `git show fc0de65:docs/HANDOFF-verify-0610.md` if needed). That document's
"5 missing domains" are now all landed — anti-analysis (`c58015c`), HV
(`f024679`/`d6249c7`), mem-injection (`36735f0`/`0078c50`/`5cdd652`),
genealogy (`42b167e`/`b94cf47`/`3605981`), plus Win11 24H2 VAD offsets
(`18c0591`). This documents everything that remains unimplemented, stubbed,
or unverified as of HEAD `18c0591` on `auto/impl-detections-0609`.

Marker counts at HEAD: **`HK-UNCERTAIN` = 361**, **`HK-TODO(schema)` = 123**
(184 `HK-TODO` total).

## 1. Never compiled on a real target (largest risk)

| Tree | Toolchain needed | Where |
|---|---|---|
| `kernel/win/` (~8.3k lines, 45 files) | WDK/MSVC, KMDF | Windows box `admin@192.168.178.80` (Win 11 Pro 25H2) — see `docs/windows-build.md`, `docs/windows-signing.md` |
| `sdk/src/backends/win/` (~50 sensor files) | MSVC | same box |
| `kernel/linux/bpf/` (36 progs) + `userspace/` loader + `lkm/` | clang-bpf + libbpf + kernel headers | any Linux box / Steam Deck |

All commits touching these are explicitly tagged `(UNVERIFIED)`. Expect a
substantial fix pass on first build — none of this code has ever seen its
real compiler. The host-verifiable subset (cargo, 296 ctest, lit, ES
`-fsyntax-only`) was green as of `96761c6`; re-run after any change.

## 2. Whole subsystems that are stubs by design (later phases)

- **Attestation — all 6 backends return `NotImplemented`.**
  `attestation/backends/{win,linux}/` (tpm2-tss `Esys_Quote` not written),
  `macos/` (Secure Enclave `SecKeyCreateRandomKey` not written), 3 console
  stubs (NDA-gated). `Attestation.h` interface is frozen; only bodies missing.
- **DRM — `drm/src/drm.cpp`** `drm_validate` always returns
  `HK_DRM_NOT_IMPLEMENTED`; no licence logic exists anywhere.
- **License server — every route returns 501** (`server/license-server/`,
  Phase 2 stubs with typed `LicenseError::NotImplemented`).
- **Ban-engine rule-bundle signature verification** —
  `BundleLoader::verify()` returns `VerifierNotImplemented` in production;
  real Ed25519 verifier is a future TDD phase (dev-only placeholder behind
  `unverified_bundles_dev_only` with a `compile_error!` release guard).
- **ONNX/ort scoring is not wired.** `ort` is only a
  `PhantomData<ort::session::Session>` marker in `telemetry/src/lib.rs:119`.
  `aim_kinematics.rs` extracts features but produces no verdict; no model, no
  inference session, no training pipeline.
- **Telemetry ingest is validate-then-drop.** `lib.rs:109` `let _ = payload;`
  → 202. No persistence, no queue, and the 9 gamestate analyzers + per-domain
  decoders are NOT connected to the ingest path — they only run in tests.
  End-to-end pipeline (ingest → analyzers → ban-engine fusion → decision) does
  not exist as a running system.
- **Console SDK integration** — `console/*/stubs/` return
  `HK_*_NOT_AVAILABLE`; PlayStation and Nintendo stubs are essentially empty
  (NDA). Not in the default build.
- **macOS System Extension path** — gated on Apple ES entitlement
  (`-DHORKOS_MACOS_ES=ON`, syntax-checked only). The shipping path is the
  userspace daemon; SysExt swap is pending entitlement approval.

## 3. Schema debts (HK-TODO(schema) = 123)

- **Discriminant collision (must fix before any schema merge):**
  `ac/src/selfcheck/self_wire.h` defines local event types
  `HK_EVENT_SELF_* = 14u–22u`, but frozen `event_schema.h` v5 has since
  assigned 14–17 to the HV kernel records (`HK_EVENT_HV_SYNTH_MSR = 14` …)
  and 18 to `HK_EVENT_PROCESS_CREATE_EX`. self_wire is not live on the wire
  yet, so nothing misparses today, but the planned Schema-phase merge of
  signals 145–153 must renumber, and any code emitting self events on the
  main ring before that would corrupt decode.
- **Signal 155 (kernel freq-skew)** — same pre-schema status:
  `ac/src/timing/timing_kernel_correlate.cpp` drains a ring whose record type
  is not yet frozen in `event_schema.h`.
- **vm_access large-record blocker** — `hk_event_vm_access` (32 B) and
  `hk_event_handle_provenance` (24 B + header) exceed
  `HK_EVENT_PAYLOAD_MAX` (24); `tests/unit/test_vm_access_sizes.cpp`
  deliberately asserts this. They need a large-record plane like the
  mem-scan ring (`HK_IOCTL_DRAIN_MEM_EVENTS`); signals 64–72 currently have
  no transport.
- Remaining `HK-TODO(schema)` sites are field-name reconciliation between
  domain code and the consolidated headers — grep before trusting any wire
  struct.

## 4. HK-UNCERTAIN stubs (361 sites — deliberately unimplemented APIs)

Distribution: `kernel/win/src` 34 files, `sdk/src/backends` 33,
`kernel/linux/bpf` 26, `linux/userspace` 10, `ac/src/selfcheck` 9,
`daemon/macos/csops` 6, rest scattered. Every one emits nothing rather than
guessing (guardrail #13). The load-bearing clusters:

- **ETW-TI (largest):** the ThreatIntelligence provider is protected — needs
  a **PPL/ELAM-signed user-mode consumer**, not a kernel consumer.
  `kernel/win/src/EtwTiVmWatch.c` + `sdk/src/backends/win/EtwTiConsumer.cpp`
  are stubs for this reason. Signals 22–25 (VM-access watch) effectively
  dormant until the signing/ELAM story exists.
- **All 4 Windows HV kernel sensors** (signals 39/41/42/44:
  `HvEptProbe`, `HvSecureKernelLiveness`, `HvSyntheticMsr`,
  `HvApicIdtResidue`) are observe-only or default-OFF pending on-box
  confirmation; `TimingProbe.c` APERF/MPERF needs IRQL/CPU-pin confirmation.
- **VAD layout table covers exactly one build.** `vad_layout.h` has offsets
  for Win11 24H2 / NtBuildNumber 26100 only (Vergilius PDB-derived). Every
  other build fails closed (`HkVadLayoutForCurrentBuild` → NULL) — VAD/PEB
  scanners (signals 10–17) silently do nothing on 23H2/25H2/Server. Needs
  per-build rows + ideally symbol-server automation.
- **`CallbackSelfCheck.c`** (6 sites): Ob callback list walk, PS re-arm lock
  semantics, text-hash base resolution.
- **Linux BPF attach points** (~10 sites): BPF-LSM arity for
  `ptrace_access_check`/`ptrace_traceme`, fentry/fexit BTF availability for
  `process_vm_*`, `perf_event/hw_breakpoint` attach, IOMMU-fault kprobe
  signature, `CONFIG_BPF_LSM` not universal on SteamOS (genealogy 205).
- **macOS** (~12 sites): ES-client foreign task-port acquisition
  (`ExceptionPortAudit.mm` returns `HK_EXCPORT_RESULT_UNAVAILABLE`),
  `es_event_mmap_t` source-signing fields across ES versions, cdhash
  extraction, `SelfCheckRead.mm` self-read entitlement confirmation.
- **`ThreadProvenance.c`** carries a `VERIFIED-FALSE` note on the
  ex-thread-notify-startaddress assumption — re-derive before enabling.

## 5. Disabled / target-only bypass tests

The merge-gate suite is only partially armed:

- **macOS:** most of `bypass-tests/macos/` (dylib inject, csflags strip,
  cdhash swap, task_for_pid, exception-port hijack, etc.) is `[disabled]`
  until enforcement mode exists.
- **Windows:** behavioral-aim, overlay, input-filter, HID-spoof tests
  disabled pending kernel plane completion; all 50 win tests build only
  under `if(WIN32)` — never executed yet.
- **Linux:** ptrace-attach and uinput-provenance disabled; rest gated
  `if(UNIX AND NOT APPLE)` — never executed yet.
- Host-runnable today: dma_hardware (9), cross (partly), thread_origin
  correlator replay, server gamestate replay — these are in the 296 green.

## 6. Smaller known debts

- **`docs/ARCHITECTURE.md` is stale:** says JSON plane v4 and 315
  HK-UNCERTAIN; code is **TickPayload v6** (v5 anti_analysis, v6 hv) and 361.
  Also doesn't mention the genealogy/mem-scan additions to the build matrix.
- **`server/api/data-categories.md`**: regenerated and structurally checked,
  but the human/legal pass over retention + legal-basis columns has not
  happened. New v5/v6 fields and genealogy/mem-event fields should be
  re-audited against guardrail #11.
- **dma_detect module comments** still lack catalog signal IDs (127–134),
  so coverage audits false-flag them.
- **`docs/detection-research-codex.md`** holds ~90 unconsolidated research
  signals never merged into the 216-signal catalog.
- `.claude/scheduled_tasks.lock` is untracked junk in `git status`; no
  recurring cron remains from the 0609 run.

## 7. Code-review findings (2026-06-10 full-codebase review)

Six parallel subsystem reviews (read-only; Windows/Linux kernel code reviewed
without compiling). Severity: 🔴 = bug/security, 🟡 = risk, ❓ = design question.

### kernel/win (KMDF)

- 🔴 `MemScanWorker.c:243` — if `ObReferenceObjectByHandle` fails after
  `PsCreateSystemThread` succeeds, `g_WorkerThread` is NULL but the thread
  runs and `g_Armed` is TRUE; Disarm skips the wait → driver can unload under
  a live worker thread (executes freed pages). Fail the arm or wait on an
  event the worker signals.
- 🔴 `VadWalk.c:117` — no guard for torn VAD node with `end_vpn < start_vpn`;
  `region_size` underflows to ~2^64 and `ExecOrigin.c:31` range math wraps to
  empty. Return FALSE from `HkNormalizeVad` on inversion.
- 🔴 `HkIntegrityScan.c:249` — manual rescan IOCTL re-queues the same
  `IO_WORKITEM` the periodic timer DPC queues; double-queue of one work item
  is UB. Second work item or interlocked in-flight guard.
- 🟡 `SsdtIntegrity.c:61` — `desc->Base/Limit` read outside `__try` (the
  sibling `SyscallIntegrity.c` guards the same reads). Tampered descriptor →
  BSOD.
- 🟡 `ModuleMap.c:81` — 32-bit `bufLen = needed + needed/4 + 4096` can wrap;
  cap `needed` or widen before arithmetic.
- 🟡 `MemScanWorker.c:111` — `g_Armed` plain non-volatile BOOLEAN read from
  notify routines; make `volatile` like `g_Stop`.
- 🟡 `vad_layout.h:103` — offset `0x00` (legit for `Left`) is
  indistinguishable from an uninitialized table entry; add a distinct
  confirmed-zero sentinel.

### kernel/linux (eBPF + loader)

- 🔴 `genealogy.bpf.c:31` + `loader_trust.bpf.c:31` vs `Loader.cpp` —
  `HK_EVENT_LAUNCH_TRACED` (0x22) and `HK_EVENT_LOADER_TAINT` (0x23) have NO
  translate arm in `on_ringbuf_sample`; **all signal-205/206 events are
  silently dropped**. Add the arms.
- 🔴 `genealogy.bpf.c:68` — `tracer_pid = (u32)bpf_get_current_pid_tgid()`
  records TID, not TGID; use `>> 32`. Wrong value for multi-threaded tracers.
- 🔴 `fentry_proc_mem.bpf.c:103` — manual `container_of` via
  `offsetof(task_struct, pid_links)` is wrong unless PIDTYPE_PID is element 0
  at array base; use `bpf_task_from_pid` (already used in
  `fexit_process_vm.bpf.c`).
- 🟡 `proton_env.bpf.c:102` — strict `<` boundary misses `WINEDLLOVERRIDES=`
  keys starting in the last 16 bytes of a 256-byte chunk.
- 🟡 `Loader.cpp:645` — `memfd_join` map unbounded under memfd flood; O(n)
  eviction per insert → O(n²). Cap size before insert.
- 🟡 `Loader.cpp:848` — `ResolveFdIsMsr` readlinks `/proc/<pid>/fd/<fd>`
  post-event; PID/fd reuse TOCTOU → possible false positive (report-only).
- 🟡 `hw_breakpoint_census.bpf.c:109` — always-false keepalive call may be
  DCE'd by some clang-bpf versions, breaking the "referenced" guarantee.
- 🟡 `hk_bpf_shared.h:80` — `hk_fnv64` verifier-safe only with constant
  `len`; document or enforce.

### server (Rust)

- 🟡 `telemetry/src/lib.rs:54` — **no HTTP body size limit** on the router;
  axum 0.8 doesn't impose one and `tower_http::limit` is unwired. Unbounded
  `Vec<f32>`/`String` fields in TickPayload = memory DoS. Add
  `DefaultBodyLimit::max(N)`.
- 🟡 `stats.rs:250` — `dominant_peak` can return `snr = +∞` (single nonzero
  bin); passes `snr < FLOOR` gate and propagates into `SuspicionEvent.zscore`.
  Require `is_finite()`.
- 🟡 `analyzers/mod.rs:107` — `feed` aborts on first analyzer error with `?`,
  desyncing per-analyzer tick state. Run all, aggregate errors.
- 🟡 `schema.rs:297` — `tx_cadence_skew_ns` serde-defaults to 0 but doc says
  sentinel is `i64::MIN`; absent field becomes "genuine zero skew". Default
  to the sentinel.
- 🟡 `ban-engine/src/aim_kinematics.rs:315` — `(to_ns - from_ns) as f32`
  loses precision beyond ~16 ms gaps; compute in f64.
- ❓ analyzers — no reset path between sessions/matches; confirm
  one-instance-per-session lifecycle or add reset.

### ac/ + sdk/

- 🔴 `ac/src/hv/hv_vbs_attest.cpp:40` — BSTRs allocated before
  `CoInitializeEx` check; every `FAILED(hr)` path leaks `ns`/`query`/`lang`.
  Also `RPC_E_CHANGED_MODE` is treated as fatal though COM is usable. Per-call
  CoInit+ConnectServer ×2 should be one cached session.
- 🔴 `ac/src/selfcheck/pe_parse.cpp:134` — `e_lfanew`-derived `sect_table`
  pointer math unchecked for wrap before per-section guards; add explicit
  `e_lfanew + 4 + 20 + opt_size <= len` check.
- 🟡 `pe_parse.cpp:161,177` — `rva + virtual_size` and `raw_ptr + delta`
  uint32 overflow in `section_for_rva`/`rva_to_file_offset`.
- 🟡 `ac/src/timing/shared_data_clock_win.cpp:98` — unbounded
  `hi1 != hi2` seqlock spin in `read_ksystem_time`; infinite spin on
  suspended/migrating VM. Cap retries.
- 🟡 `sdk/src/backends/win/ancestry_walker.cpp:29` — one Toolhelp snapshot
  per ancestry level (≤32); widens PID-reuse window. Snapshot once, walk
  in-memory.
- 🟡 `MinifilterCensusWin.cpp:162` — `ERROR_INSUFFICIENT_BUFFER` ends the
  whole enumeration instead of skipping the oversized instance; census can
  miss a suspect filter.
- 🟡 `selfcheck.cpp:48` — `arm()` arms unconditionally even with
  `baseline.valid == false`; add the guard now.
- 🟡 `self_logic.cpp:164` — `tls_table_tampered` conflates "compared clean"
  with "could not compare" when a table pointer is null.
- 🟡 `token_check.cpp:37` — `HANDLE token` used uninitialized on the
  short-circuit failure path (benign with CloseHandle(NULL) but UB-shaped);
  initialize.
- ❓ `event_schema.h` — `hk_event_hv_synth_msr.ref_tsc_vs_rdtsc` declared
  `uint64_t` but commented "signed skew"; pick one before the server decoder
  pins it.

### macOS + dma_detect

- 🔴 `daemon/macos/horkosd.cpp:40` — **no audit-token / code-signing check on
  XPC connections**; any local process can talk to `com.horkos.daemon`.
  Validate `xpc_connection_get_audit_token` + SecTask requirement before
  resume.
- 🟡 `HKThreadIntegrity.cpp:150` — `task_threads` thread-port send rights
  never `mach_port_deallocate`d; leaks one right per thread per poll.
- 🟡 `EsClient.mm:553,649` — `sSinkQueue`/`sLog` leaked on both
  `es_new_client` and `es_subscribe` failure paths.
- 🟡 `dma_detect/.../ConfigSpaceForensics.cpp:177` —
  `dsn_oui_matches_vendor` polarity inverted vs name ("not provably wrong"
  encoded as 1); rename or flip before server logic consumes it.
- 🟡 `HotplugMonitor.cpp:54,86` — `strlen` past token boundary on NUL-free
  uevent; `recv` retry loop with no backoff can spin at 100% CPU.
- 🟡 `TlpLatencyProbe.cpp:87` — upper-median bias on even sample count;
  document or average the two middles.
- ❓ `forensics_report.cpp:99` — serializer field walk appears to produce 98
  bytes vs `DEVICE_WIRE_BYTES=100`; verify before the Rust decoder pins it.

### Cross-cutting (schema/obfuscator/PAL/tests)

- 🔴 `server/telemetry/src/kernel_events.rs:41` — Linux module-trust
  discriminants 5–14 collide with the now-frozen Windows mem-injection (5–13)
  + HV (14) ranges in `event_schema.h`. Second discriminant collision besides
  self_wire (§3). Rebase to ≥19.
- 🔴 `tests/unit/test_integrity_finding_size.cpp:60` — IOCTL test claims
  0x803 is free but `HK_IOCTL_DRAIN_MEM_EVENTS` already occupies 0x803 and
  the test never checks against it; collision invisible. Next free is 0x805.
- 🔴 `sdk/src/sdk_backend.h:19` — raw `_WIN32` outside `platform/`/
  `backends/` (guardrail #1 violation, self-acknowledged in comment).
- 🟡 `obfuscator StringEncryption.cpp:151` — ctor priority 0 has no defined
  order vs other priority-0 ctors; an earlier ctor reading an annotated
  string sees ciphertext. `usedOnlyInAnnotated` doesn't exclude
  ctor-reachable functions. Also single-byte XOR 0x5A is known-weak (accepted).
- 🟡 `ControlFlowFlattening.cpp:122` — pool blocks ending in `ReturnInst`
  silently bypass the dispatcher (correct but unflattened); document or handle.
- 🟡 `attestation/Attestation.h:42` — `quote()` has no nonce/freshness
  parameter → replayable quotes; add before the interface freeze bites
  (guardrail #10 makes later change expensive).
- ❓ `platform/platform.h:71` — macOS-only seams (`csr_active_config` etc.)
  declared unconditionally; confirm non-macOS links never reference them.

## Suggested order of attack

1. Windows build on `192.168.178.80` — compiles `kernel/win/` + win backends,
   converts the biggest UNVERIFIED mass into real code. Fix pass expected.
2. Linux/Deck build of eBPF + loader — second UNVERIFIED mass.
3. Schema phase: renumber + merge self_wire (145–153) and timing 155 into
   `event_schema.h`; add the large-record plane for vm_access (64–72); burn
   down `HK-TODO(schema)`.
4. HK-UNCERTAIN triage, starting with ETW-TI consumer architecture decision
   (PPL/ELAM signing) and vad_layout build coverage.
5. Wire the server pipeline end-to-end (ingest → analyzers → fusion) +
   persistence; then ONNX scoring; then bundle Ed25519 verification.
6. Attestation backends (tpm2-tss first), then DRM logic under `/tdd`.
7. Refresh `docs/ARCHITECTURE.md` + data-categories legal pass.

Standing rules: never push unprompted, never commit to `main`, no
Co-Authored-By trailers, never claim kernel code works until compiled on its
real target.
