# win-hypervisor-detection — Implementation Plan

**Scope:** Windows hypervisor / virtualization-state telemetry — read-only sensors that sample CPUID hypervisor leaves, vmexit timing, EPT exec/read split, VBS/HVCI attestation posture, secure-kernel liveness, Hyper-V synthetic MSRs, sanctioned-VM identity, APIC/IDT residue, and cross-vCPU TSC coherence. Clients sample and report only; all classification and ban authority is server-side.

**Catalog signals covered:** 37, 38, 39, 40, 41, 42, 43, 44, 45 (`docs/detection-catalog.md` §`win-hypervisor-detection`, lines 383–473).

Split by layer:
- **Usermode (`ac/src/hv/`):** 37 (TLFS leaves), 38 (vmexit latency), 40 (VBS attest), 43 (VM identity), 45 (TSC coherence).
- **Kernel (`kernel/win/src/`):** 39 (EPT split), 41 (secure-kernel liveness), 42 (synthetic MSR), 44 (APIC/IDT residue). Kernel sensors report over the existing SPSC ring → `HK_IOCTL_DRAIN_EVENTS` bridge; usermode correlators read kernel output and merge with their own samples before uploading to the server.

---

## New files

All usermode sensor `.cpp` live under `ac/src/hv/` (a `backends`-equivalent subtree for platform-specific sensors; guardrail #1 — every Windows-only API in these files is gated behind `HK_PLATFORM_WINDOWS`). Kernel sensors live under `kernel/win/src/` and never share a TU with userspace (guardrail #4). Every file opens with the role / target-platform / interface module comment (guardrail #3).

| Path | Role | Module-comment summary |
|---|---|---|
| `ac/include/horkos/hv_signals.h` | Declares the usermode HV sensor surface: one sampler function per signal returning a fixed POD result struct; a `hv_collect_all()` aggregator. | Role: usermode hypervisor-state sensor interface. Target: Windows (PC). Interface: this header IS the HV sensor surface; `ac/src/hv/*.cpp` implement it; consumed by `ac/src/ac.cpp`. |
| `ac/src/hv/hv_tlfs_leaves.cpp` | Signal 37 sensor: read CPUID 0x40000000–0x4000000A + OS VBS posture, emit full leaf vector. | Role: TLFS hypervisor-leaf sampler. Target: Windows. Interface: implements `hv_sample_tlfs_leaves()` from `hv_signals.h`. |
| `ac/src/hv/hv_vmexit_latency.cpp` | Signal 38 sensor: CPUID vmexit round-trip latency histogram with independent-clock cross-check. | Role: serialized-instruction vmexit latency sampler. Target: Windows. Interface: implements `hv_sample_vmexit_latency()`. |
| `ac/src/hv/hv_vbs_attest.cpp` | Signal 40 correlator: Win32_DeviceGuard WMI + IUM info vs TPM measured-boot via `Attestation.h`. | Role: VBS/HVCI enablement-vs-attestation correlator. Target: Windows. Interface: implements `hv_sample_vbs_attest()`; consumes `attestation/Attestation.h`. |
| `ac/src/hv/hv_vm_identity.cpp` | Signal 43 sensor: SMBIOS + device-tree + vTPM EK identity vs CPUID hypervisor-present bit. | Role: sanctioned-VM-identity-vs-covert-inspection sampler. Target: Windows. Interface: implements `hv_sample_vm_identity()`; reuses `attestation/backends` for the vTPM EK path. |
| `ac/src/hv/hv_tsc_coherence.cpp` | Signal 45 sensor: per-logical-processor RDTSCP skew vs invariant-TSC capability. | Role: cross-vCPU TSC coherence sampler. Target: Windows. Interface: implements `hv_sample_tsc_coherence()`. |
| `ac/src/hv/hv_kernel_correlate.cpp` | Drains kernel HV records (signals 39/41/42/44) via the SDK IOCTL bridge and folds them into the usermode report. | Role: kernel-HV-record correlator. Target: Windows. Interface: implements `hv_collect_kernel()`; consumes `sdk/include/horkos/ioctl.h`. |
| `kernel/win/src/HvSyntheticMsr.c` | Signal 42 kernel sensor: guarded `__readmsr` of Hyper-V synthetic MSR range, reference-TSC vs rdtsc coherence. | Role: Hyper-V synthetic-MSR / reference-TSC presence sensor. Target: Windows kernel (KMDF). Interface: declared in `kernel/win/include/horkos_kernel.h`; emits via `HkRingEmit`. |
| `kernel/win/src/HvEptProbe.c` | Signal 39 kernel sensor: exec-view vs data-read-view checksum of the game's signed sections; #VE expectation arming. | Role: EPT exec/read permission-split sensor. Target: Windows kernel (KMDF). Interface: declared in `horkos_kernel.h`; emits via `HkRingEmit`. |
| `kernel/win/src/HvSecureKernelLiveness.c` | Signal 41 kernel sensor: IUM/secure-kernel liveness counters vs VBS-running claim. | Role: HyperGuard/secure-kernel liveness sensor (observe-only). Target: Windows kernel (KMDF). Interface: declared in `horkos_kernel.h`; emits via `HkRingEmit`. |
| `kernel/win/src/HvApicIdtResidue.c` | Signal 44 kernel sensor: `__sidt` vs KPCR-authoritative IDT base; APIC access-exit timing. | Role: APIC/IDT virtualization-residue sensor (observe-only). Target: Windows kernel (KMDF). Interface: declared in `horkos_kernel.h`; emits via `HkRingEmit`. |
| `server/telemetry/src/hv.rs` | serde structs mirroring the HV report sub-payload on the per-tick/periodic ingest plane; validation (no `unwrap`). | Role: server-side HV-posture ingest contract. Target: server. Interface: `mod hv` under `server/telemetry`; mirrors `hv_signals.h` field names. |
| `bypass-tests/win/hv/*` | Bypass tests (one per merge-gated sensor). See Test strategy. | Role: HV-sensor bypass merge gate (guardrail #12). Target: Windows. Interface: drives `ac/src/hv` + kernel sensors. |

Header additions (not new files): new kernel event types/payloads in `sdk/include/horkos/event_schema.h`; new HV sub-payload fields in `server/telemetry/src/schema.rs` (or `hv.rs` submodule); new data-category rows in `server/api/data-categories.md`.

---

## Interfaces & data structures

### Usermode sensor surface (`ac/include/horkos/hv_signals.h`)

Plain POD result structs, fixed-size, no platform headers in the header itself (platform calls live in the `.cpp`). Sketch:

```c
typedef struct hv_tlfs_leaves {
    uint32_t leaf[11][4];        /* 0x40000000..0x4000000A, EAX/EBX/ECX/EDX */
    uint32_t cpuid1_ecx31_hv;    /* leaf 1 ECX[31] hypervisor-present */
    uint32_t os_vbs_running;     /* from SystemIsolatedUserModeInformation */
    uint32_t os_hv_present;      /* from SystemHypervisorDetailInformation */
    uint32_t reserved;
} hv_tlfs_leaves;

typedef struct hv_vmexit_latency {
    uint32_t hist[32];           /* CPUID round-trip latency buckets (cycles) */
    uint32_t cpu_model;          /* CPUID family/model/stepping */
    uint64_t qpc_span;           /* independent QPC span over the loop */
    uint64_t shared_interrupt_dt;/* KUSER_SHARED_DATA.InterruptTime delta */
} hv_vmexit_latency;
/* ... hv_vbs_attest, hv_vm_identity, hv_tsc_coherence analogous ... */

typedef struct hv_report {
    hv_tlfs_leaves      tlfs;        /* 37 */
    hv_vmexit_latency   vmexit;      /* 38 */
    hv_vbs_attest       vbs;         /* 40 */
    hv_vm_identity      identity;    /* 43 */
    hv_tsc_coherence    tsc;         /* 45 */
    hv_kernel_summary   kern;        /* 39/41/42/44 folded from kernel ring */
    uint32_t            sensors_ok;  /* bitmask: which samplers ran cleanly */
} hv_report;
```

Each `hv_sample_*` returns one of these by out-param plus an `HK_AC_*` status. The aggregator builds an `hv_report`; `ac/src/ac.cpp` serializes it to the server. **Server is the only classifier** — the client ships raw vectors/histograms, never a verdict.

### Kernel event-schema additions (`sdk/include/horkos/event_schema.h`)

Bump `HK_EVENT_SCHEMA_VERSION 2u → 3u`. Append event types (existing values never change):

```c
HK_EVENT_HV_SYNTH_MSR   = 5,  /* signal 42 */
HK_EVENT_HV_EPT_SPLIT   = 6,  /* signal 39 */
HK_EVENT_HV_SK_LIVENESS = 7,  /* signal 41 */
HK_EVENT_HV_APIC_IDT    = 8,  /* signal 44 */
```

**Payload-size constraint (load-bearing):** `ioctl.h` pins `HK_EVENT_PAYLOAD_MAX = 16` and `sizeof(hk_event_record) == 40`. New payloads must stay ≤ 16 bytes or `HK_EVENT_PAYLOAD_MAX`, the record size, and every `HK_STATIC_ASSERT` in `ioctl.h` must be bumped in lockstep — a wider record changes the wire size on both sides. Recommendation: keep each new payload at exactly 16 bytes (status word + one or two summary scalars); ship the *bulky* raw data (full leaf vectors, histograms) on the **usermode** report plane, not the kernel ring. The kernel records carry only a compact verdict-input summary plus a correlation token:

```c
typedef struct hk_event_hv_synth_msr {     /* 16 bytes */
    uint32_t flags;            /* HK_HV_MSR_* : cpuid_claims_hv, guest_os_id_ok,
                                  hypercall_msr_ok, ref_tsc_coherent, gp_faulted */
    uint32_t gp_fault_mask;    /* which MSR reads #GP'd (bit per MSR) */
    uint64_t ref_tsc_vs_rdtsc; /* signed skew sample, ns */
} hk_event_hv_synth_msr;
HK_STATIC_ASSERT(sizeof(hk_event_hv_synth_msr) == 16, "...");
```

`hk_event_hv_ept_split` (exec-view checksum, read-view checksum truncated to fit, flags), `hk_event_hv_sk_liveness` (ium_running, sk_image_loaded, transition_count_bucket), and `hk_event_hv_apic_idt` (sidt_base_low, kpcr_idt_base_low, mismatch flag, apic_exit_bucket) follow the same 16-byte discipline. If any payload genuinely cannot fit 16 bytes, that is an **explicit schema decision** — bump `HK_EVENT_PAYLOAD_MAX`, `hk_event_record` size, and all `HK_STATIC_ASSERT`s together, and update the Rust mirror; do not silently overflow.

### IOCTL additions (`sdk/include/horkos/ioctl.h`)

No new control code required — these events flow through the existing `HK_IOCTL_DRAIN_EVENTS` envelope (they are just new `hk_event_type` values in the same `hk_event_record` stream). One optional addition: a `HK_IOCTL_HV_PROBE` (next free function `0x803`) to *trigger* an on-demand EPT/MSR probe rather than relying on periodic emission, if a pull model is preferred. Default plan is push (periodic) via the existing drain, so `0x803` is deferred unless sequencing shows a need.

### Server ingest (`server/telemetry/src/hv.rs` + `schema.rs`)

The HV posture rides the telemetry JSON plane (independent from the C99 kernel wire schema, per `schema.rs` module note). Add an optional `hv: Option<HvReport>` to `TickPayload` (or a dedicated periodic endpoint) and bump `SCHEMA_VERSION`. `HvReport` mirrors `hv_report` field names: `tlfs_leaves: [[u32;4];11]`, `vmexit_hist: [u32;32]`, `vbs: VbsPosture`, etc. All deserialization fallible, validated, `thiserror` errors, **no `unwrap()` outside tests** (guardrail #8).

### data-categories.md (guardrail #11 — same PR)

Every new reported field is telemetry and MUST be declared. Add a new category section, e.g.:

> **### 5. Hypervisor / virtualization state**
>
> | Field | Source | Retention | Legal basis | Operator |
> |---|---|---|---|---|
> | `hv_tlfs_leaves` | CPUID 0x40000000–0x4000000A (`hv_tlfs_leaves.cpp`) | 90 days | Legitimate interest — anti-cheat | Horkos Service Operator |
> | `hv_vmexit_hist` | CPUID vmexit latency histogram | 90 days | Legitimate interest | … |
> | `hv_vbs_posture` | Win32_DeviceGuard WMI + IUM info | 90 days | Legitimate interest | … |
> | `hv_vm_identity` | SMBIOS / device-tree / vTPM EK digest | 90 days | Legitimate interest | … |
> | `hv_tsc_skew` | per-vCPU RDTSCP skew | 90 days | Legitimate interest | … |
> | `hv_synth_msr` / `hv_ept_split` / `hv_sk_liveness` / `hv_apic_idt` | kernel HV sensors (`event_schema.h` v3) | 90 days | Legitimate interest | … |

Note: the vTPM EK digest (signal 43) overlaps category 4 (Hardware identifiers) — reuse `tpm_ek_pubkey_sha256` semantics; declare any *new* EK-cert-chain field explicitly. The reviewer rejects undeclared fields.

---

## Mechanism implementation notes

### Usermode (Windows)

- **37 — TLFS leaves.** `__cpuid`/`__cpuidex` over `0x40000000`–`0x4000000A`; OS posture via `NtQuerySystemInformation(SystemHypervisorDetailInformation, SystemIsolatedUserModeInformation)`, cross-checked with `IsProcessorFeaturePresent`. Pure read-only CPUID, no IRQL concern (usermode). Ship the full leaf vector; the server models known-good nested-Hyper-V vectors (WSL2 / Sandbox / Cloud PC). `NtQuerySystemInformation` info classes are partially undocumented — see UNCERTAINTY FLAGS.
- **38 — vmexit latency.** `RDTSCP`/`__cpuid` timing loop, `SetThreadAffinityMask` pin + `SetThreadPriority(TIME_CRITICAL)`. Collect a **histogram**, not a delta. Independent clocks: `QueryPerformanceCounter` and `KUSER_SHARED_DATA.InterruptTime`. Require TSC-vs-independent-clock divergence before the server flags. Never a hardcoded threshold (FP risk: high — SpeedStep/turbo, SMM, noisy cloud).
- **40 — VBS attest.** Read `Win32_DeviceGuard` WMI (`VirtualizationBasedSecurityStatus`, `SecurityServicesRunning`, `CodeIntegrityPolicyEnforcementStatus`) + `SystemIsolatedUserModeInformation`/`SystemSecureBootInformation`, then call `Attestation::quote()` (`attestation/Attestation.h`, guardrail #10 — interface is stable). **Currently a `NotImplemented` stub** — do not enforce on this signal until a real TPM backend lands; report the contradiction, let the server decide. WMI is COM — initialize/uninitialize per call, handle `HRESULT` on every step.
- **43 — VM identity.** `GetSystemFirmwareTable('RSMB')` for SMBIOS; `SetupDiGetClassDevs`/`CM_Get_Device_ID` for the device tree; vTPM EK via `Tbsi_Get_TCG_Log`/`NCryptGetProperty` (reuse `attestation/backends`). Correlate with CPUID hypervisor-present bit (leaf 1 ECX[31]) to classify {bare-metal, honest-VM, covert-inspection}. Ship the full tuple; operators whitelist sanctioned fleets by attested vTPM EK server-side.
- **45 — TSC coherence.** Enumerate LPs via `GetLogicalProcessorInformationEx`, pin with `SetThreadAffinityMask`, sample `RDTSCP` (its `IA32_TSC_AUX` returns the CPU id — verify the pin actually took). Compare skew/monotonicity against the invariant-TSC bit `__cpuid(0x80000007) EDX[8]`. Server models skew distributions per CPU SKU; never a fixed tolerance.

All usermode platform calls gated behind `HK_PLATFORM_WINDOWS`; non-Windows builds compile a stub returning `HK_AC_NOT_IMPLEMENTED` (guardrail #1, no raw `_WIN32`).

### Kernel (Windows, KMDF) — safety

All kernel sensors: safe string functions only, **every `NTSTATUS`/kernel return checked** (guardrail #5). New TUs do not share with userspace (guardrail #4). Emit through the existing `HkRingEmit` → ring → drain path; the ring critical section runs at `DISPATCH_LEVEL` under `KSPIN_LOCK` (see `horkos_kernel.h`). Sample at `PASSIVE_LEVEL` from a work item or system thread; only the brief `HkRingPush` touches `DISPATCH_LEVEL`.

- **42 — synthetic MSR.** `__readmsr` of `HV_X64_MSR_GUEST_OS_ID (0x40000000)`, `HV_X64_MSR_HYPERCALL (0x40000001)`, `HV_X64_MSR_REFERENCE_TSC (0x40000021)` **inside a guarded `__try/__except` SEH block** — a bare-metal host #GPs on these and that must not bugcheck. **Gate the read by first confirming CPUID claims Hyper-V**; treat "no Hyper-V" as a distinct, expected state from "Hyper-V claimed but MSRs incoherent". This is the lowest-uncertainty kernel signal; land it first.
- **39 — EPT split.** Checksum the game's signed sections two ways: a data-read via `MmGetPhysicalAddress` + mapped read (`MmMapIoSpaceEx`), and an independent integrity hash of the on-disk/section image; arm `#VE` (`EXCEPTION_VIRTUALIZATION_FAULT`, `STATUS 0xC0000420`) expectations. Whitelist HVCI-managed regions via `NtQuerySystemInformation(SystemCodeIntegrityInformation)`; only flag splits over the game's own signed sections. `MmMapIoSpaceEx` lifetime/unmap and IRQL discipline must be exact — see UNCERTAINTY FLAGS.
- **41 — secure-kernel liveness.** Sample `SystemIsolatedUserModeInformation` + secure-kernel counters; observe `securekernel.exe`/`skci.dll` presence through the **already-collected** `PsSetLoadImageNotifyRoutine` records (do not add a second image-notify registration). **Observe-only, cohort-gated, weak corroborator** — flag to user before any enforcement wiring (guardrail #13; secure-kernel internals undocumented/version-volatile).
- **44 — APIC/IDT residue.** `__sidt` vs the authoritative IDT base from KPCR/`KIDTENTRY`; sample local-APIC access timing via HAL. **Observe-only, cohort-gated, low standalone weight** — genuine Hyper-V/VBS already virtualizes APIC and may relocate descriptors; per-CPU IDT differences are normal. Flag to user before wiring (guardrail #13).

### Server (tokio)

Fully async; `thiserror` error type for HV ingest/validation; **no `unwrap()` outside tests** (guardrail #8). HV classification (population modeling, per-SKU skew, known-good nested-Hyper-V vectors) is server-side and must not block the async runtime — any ONNX/heavy modeling runs off the async path (spawn_blocking or the existing ban-engine inference lane).

---

## Build wiring

- **Usermode:** extend `ac/CMakeLists.txt` to add `src/hv/*.cpp` to `hk_ac`. Keep `hk_ac` depending on `hk_platform`; add `attestation` as a link dependency for `hv_vbs_attest.cpp`/`hv_vm_identity.cpp`. Gate the HV sensor sources on a CMake option `HK_HV_SENSORS` (default **ON** for Windows builds, **OFF**/stub elsewhere). Toolchain: MSVC + Windows SDK (WMI/SetupAPI/CfgMgr32/NCrypt/Tbs link libs: `wbemuuid`, `setupapi`, `cfgmgr32`, `ncrypt`, `tbs`). clang-19/obfuscator only touches init/licence/integrity/attestation symbols (guardrail #9) — HV sensors that feed attestation may carry `__attribute__((annotate("hk_obfuscate")))` on their entry points; the hot game loop is untouched.
- **Kernel:** add `HvSyntheticMsr.c`, `HvEptProbe.c`, `HvSecureKernelLiveness.c`, `HvApicIdtResidue.c` to `kernel/win/horkos.vcxproj` and `kernel/win/CMakeLists.txt`. WDK toolchain, `-W4`/`/WX` per existing driver. Gate the higher-uncertainty sensors (41, 44) behind a build flag `HK_HV_KERNEL_EXPERIMENTAL` (default **OFF**) so a default driver ships only the well-understood 42 (and 39 once `MmMapIoSpaceEx` lifetime is confirmed). 42 default **ON**; 39 default **ON after review**; 41/44 default **OFF**.
- **Server:** add `mod hv` to `server/telemetry/src/lib.rs`; bump `SCHEMA_VERSION`. No new crate.
- **Schema:** bump `HK_EVENT_SCHEMA_VERSION` to 3; keep `HK_EVENT_PAYLOAD_MAX`/record-size asserts green (or bump all together with explicit justification).

---

## Test strategy

### Unit / integration tests
- **Schema pins:** the existing `HK_STATIC_ASSERT`s in `event_schema.h`/`ioctl.h` must stay green with the new 16-byte payloads — a compile failure is the test. Add asserts for each new `hk_event_hv_*` struct (== 16).
- **Server (`server/telemetry`):** round-trip serde tests for `HvReport` (valid, missing-optional, malformed → typed error, never panic). Reject undeclared/extra fields. Verify `SCHEMA_VERSION` bump.
- **Usermode samplers:** on a CI Windows runner, smoke-test each `hv_sample_*` returns a populated struct without crashing on bare-metal and on a Hyper-V guest (both are valid states; assert *shape*, not verdict).
- **Kernel:** driver-load + drain smoke test (extend `tests/integration/win/ioctl_smoke.cpp`) asserting new event types appear in the drain envelope without bugcheck. Critically verify the `__try/__except` MSR guard does **not** bugcheck on a bare-metal runner.

### Bypass tests (guardrail #12 — merge gate; any change under a security folder needs a corresponding bypass test)
One bypass test per sensor, each demonstrating the sensor *detects the evasion it claims to* (read-only; tests simulate/observe adversary conditions, they do not ship evasion code):
- `bypass-tests/win/hv/cpuid_vendor_spoof_only` — spoof only CPUID vendor leaf 0x40000000; signal **37** must report downstream-leaf inconsistency. (Drives `hv_tlfs_leaves`.)
- `bypass-tests/win/hv/tsc_clamp` — clamp/offset visible TSC; signal **38** must show TSC-vs-QPC/InterruptTime divergence, and **45** must show cross-vCPU skew anomaly.
- `bypass-tests/win/hv/vbs_flag_flip` — present contradictory VBS-on/unattested state; signal **40** must report the contradiction (gated on Attestation backend being implemented — until then the test asserts "contradiction surfaced, enforcement withheld").
- `bypass-tests/win/hv/bare_metal_identity_with_hv_cue` — bare-metal device identity + hypervisor-present cue; signal **43** must classify `covert-inspection`, and must classify a sanctioned GPU-passthrough VM as `honest-VM` (FP guard).
- `bypass-tests/win/hv/synth_msr_absent` — Hyper-V CPUID claimed but synthetic MSRs #GP/incoherent; signal **42** must flag incoherence **and** must not bugcheck on a true bare-metal host (the #GP-guard regression).
- `bypass-tests/win/hv/ept_read_exec_split` — exec-view ≠ read-view over a signed section; signal **39** must detect, and must **not** flag a legitimate HVCI-managed region (FP guard).
- `bypass-tests/win/hv/idt_relocation` — relocated/shadowed IDT; signal **44** must detect `__sidt` vs KPCR mismatch (observe-only; assert detection recorded, no enforcement).
- `bypass-tests/win/hv/sk_liveness_inert` — VBS-running claim with inert secure-kernel callout path; signal **41** must record the liveness gap (observe-only).

Each FP-guard assertion is as load-bearing as the detection assertion — these signals are high/medium FP and gate enforcement on server-side population modeling.

---

## Sequencing

1. **Schema + data-categories first.** Bump `HK_EVENT_SCHEMA_VERSION` → 3, add the four `hk_event_hv_*` 16-byte payloads + static asserts, add `HvReport` serde mirror + `data-categories.md` rows. Everything downstream depends on the wire contract. (Guardrails #11, schema asserts.)
2. **Server ingest** (`hv.rs`): deserialize + validate + tests. Independent of client; lands the receiving end.
3. **Usermode low-risk sensors:** 37 (TLFS), 45 (TSC), 38 (vmexit) — pure CPUID/RDTSCP/timing, no kernel, no Attestation dependency. Land with bypass tests.
4. **Kernel sensor 42 (synthetic MSR)** — lowest kernel uncertainty (guarded `__readmsr`, well-documented), default ON. Then `hv_kernel_correlate.cpp` to fold kernel records into the usermode report.
5. **Usermode 43 (VM identity)** — needs SetupAPI/NCrypt + vTPM EK path; reuse attestation backends.
6. **Usermode 40 (VBS attest)** — **blocked on a real Attestation backend** (currently `NotImplemented` stub). Land report-only now; enforcement deferred until TPM2 backend exists.
7. **Kernel 39 (EPT split)** — after `MmMapIoSpaceEx` lifetime/IRQL is confirmed (UNCERTAINTY FLAG); default ON only after review.
8. **Kernel 41 (secure-kernel liveness) and 44 (APIC/IDT residue)** — last, behind `HK_HV_KERNEL_EXPERIMENTAL` (default OFF); observe-only, cohort-gated, flagged to user before any enforcement wiring.

---

## Risks & UNCERTAINTY FLAGS

Per guardrail #13, the following are explicitly flagged as not-certain and must be confirmed before code lands — a BSOD in a dev VM is recoverable, a mis-wired kernel API is not:

- **FLAG (kernel, signal 39): `MmMapIoSpaceEx` lifetime, IRQL, and unmap discipline.** Mapping physical pages to read the data-view, the exact caller IRQL, cache-type argument, and guaranteed `MmUnmapIoSpace` on every path are security-critical. **Stop and confirm** the IRQL/lifetime contract before implementing; do not guess. The `#VE`/`EXCEPTION_VIRTUALIZATION_FAULT (0xC0000420)` arming semantics in a non-root partition are equally uncertain.
- **FLAG (kernel, signal 42): `__readmsr` #GP behavior under SEH in kernel mode.** Confirm a `__try/__except` around `__readmsr` actually catches the #GP on bare metal at the intended IRQL and does not itself bugcheck. The HV synthetic-MSR numbers are from public TLFS, but the guard mechanics need confirmation on real hardware (target PC at `admin@192.168.178.80`).
- **FLAG (kernel, signal 41): secure-kernel/HyperGuard internals are undocumented and version-volatile.** Counter sources and `SystemIsolatedUserModeInformation` sub-fields are not stable contracts. Observe-only, default OFF, cohort-gated, flagged to user before enforcement. Do not make a client trust decision on this.
- **FLAG (kernel, signal 44): KPCR/`KIDTENTRY` authoritative-IDT access and per-CPU IDT layout.** Reading the "known" IDT base from the processor control region is version- and CPU-specific and partly undocumented; APIC-access exit timing baselines differ across Hyper-V versions. Observe-only, default OFF, flagged.
- **FLAG (usermode, signals 37/40/41): `NtQuerySystemInformation` info classes** `SystemHypervisorDetailInformation`, `SystemIsolatedUserModeInformation`, `SystemSecureBootInformation`, `SystemCodeIntegrityInformation` are semi-documented and their struct layouts vary by Windows build. Treat returned layouts defensively (size-checked), cohort by OS build server-side.
- **FLAG (signal 40 dependency): Attestation backend is a `NotImplemented` stub.** VBS-vs-attestation enforcement is impossible until a real TPM2 backend lands (`attestation/backends/win/`). Plan ships signal 40 report-only; do not gate bans on it yet (guardrail #10 keeps the interface stable so the backend swap is transparent).
- **FP exposure (all signals):** every signal here is medium/high FP per the catalog (nested Hyper-V, WSL2, Sandbox, Cloud PC, GPU-passthrough VMs, multi-socket TSC skew, HVCI exec/read asymmetry, CET/shadow-stack). The plan ships raw vectors/histograms/tuples to the server for population-relative classification and **never a client-side verdict or hardcoded threshold** — consistent with "all ban authority is server-side".
- **Schema-size risk:** if any kernel HV payload cannot fit the 16-byte `HK_EVENT_PAYLOAD_MAX`, bumping `hk_event_record` is a wire-breaking change requiring lockstep updates to `ioctl.h` asserts and the Rust mirror — call it out in the PR, do not overflow silently.
