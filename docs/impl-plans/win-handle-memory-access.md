# Implementation Plan — Windows External Memory Access (`win-handle-memory-access`)

Covers catalog signals **#64–72**. Hand-authored (the automated planning pass was blocked on this domain by the content filter — cross-process memory-read telemetry reads as offensive to it even when the work is purely read-only observation).

Goal: detect *foreign* read/write/handle access against the protected game process. Two data planes:
- **Kernel plane** — ETW Threat-Intelligence (ETW-TI) consumer + the existing `ObRegisterCallbacks` filter, extended.
- **Userspace plane** — periodic SDK samplers that the kernel plane corroborates (most single samplers are high-FP and only fire when correlated with a kernel event).

All output is read-only telemetry reported to the server; nothing here blocks. Honors guardrails #1, #3, #4, #5, #8, #11, #12, #13.

---

## New files

| Path | Role | Module-comment summary |
|------|------|------------------------|
| `kernel/win/src/EtwTiVmWatch.c` | kernel | ETW-TI consumer for ReadVm/WriteVm/AllocVm/ProtectVm (local+remote) keywords; classifies target VA against cached PE section flags; assembles alloc→protect→write staging tuples. Declares `HkEtwTiArm`/`HkEtwTiDisarm`. (#64, #69, #72; VAD-walk helper for #71) |
| `kernel/win/src/CanaryProc.c` | kernel | Spawns + tracks a low-cost guard process and registers an Ob filter on its process object to externalize foreign PID-poll cadence. Declares `HkCanaryStart`/`HkCanaryStop`. (#68) |
| `sdk/src/backends/win/WorkingSetWatchWin.cpp` | userspace | `QueryWorkingSetEx` sampler correlating residency bursts with owning-thread CPU deltas. (#65) |
| `sdk/src/backends/win/SelfHandleAuditWin.cpp` | userspace | `NtQuerySystemInformation(SystemExtendedHandleInformation)` audit of who holds a Process handle to the game and with what access. (#70) |
| `sdk/src/backends/win/PageProtectAuditWin.cpp` | userspace | `VirtualQueryEx` audit of live page protection vs cached PE section flags on shipped code regions. (#71) |

Extended (not new):
- `kernel/win/src/Callbacks.c` — add `HkObPostCallback` (post-op granted-access delta, #67) and a duplicate-source provenance map in the existing `OB_OPERATION_HANDLE_DUPLICATE` branch (#66).
- `kernel/win/include/horkos_kernel.h` — declarations for the new arms; provenance-map + section-flag-cache structs in `HK_DEVICE_CONTEXT`.
- `sdk/include/horkos/event_schema.h`, `sdk/include/horkos/ioctl.h` — new event payloads (below).

Guardrail #4: every kernel `.c` here is a pure kernel TU; the SDK `.cpp` samplers are pure userspace. No shared TU.

---

## Interfaces & data structures

New wire-schema event payloads (`event_schema.h`, schema bump to v3; each gets a `HK_STATIC_ASSERT` size check in `tests/unit/test_event_schema_sizes.cpp`):

```c
typedef struct hk_event_vm_access {          /* #64, #69, #72 */
    uint32_t source_pid;
    uint32_t target_pid;                      /* == protected game pid */
    uint64_t target_va;
    uint32_t access_kind;                     /* HK_VM_READ|WRITE|ALLOC|PROTECT bitmask */
    uint32_t target_section_flags;            /* IMAGE_SCN_* of resolved VA, 0 if not in a module */
    uint32_t flags;                           /* HK_VM_REMOTE, HK_VM_STAGING_SEQ, HK_VM_ETWTI_SILENT */
} hk_event_vm_access;

typedef struct hk_event_handle_provenance {  /* #66, #67 */
    uint32_t requester_pid;
    uint32_t source_pid;                      /* DuplicateHandle source; ==requester for direct create */
    uint32_t target_pid;
    uint32_t original_desired_access;
    uint32_t granted_access;                  /* post-op; 0 on create path */
    uint32_t flags;                           /* HK_HND_DUP_LAUNDERED, HK_HND_GRANT_EXCEEDS_PREOP */
} hk_event_handle_provenance;

typedef struct hk_event_foreign_holder {     /* #70 userspace */
    uint32_t owner_pid;
    uint32_t granted_access;
    uint32_t flags;                           /* HK_HND_DANGEROUS_RIGHTS, HK_HND_UNSIGNED_OWNER */
} hk_event_foreign_holder;

typedef struct hk_event_protect_drift {      /* #71 */
    uint64_t region_base;
    uint32_t live_protect;                    /* MEMORY_BASIC_INFORMATION.Protect */
    uint32_t expected_protect;                /* from PE section characteristics */
    uint32_t flags;                           /* HK_PROT_WX_ON_SHIPPED, HK_PROT_FOREIGN_INITIATED */
} hk_event_protect_drift;
```

`ioctl.h`: add the matching `HK_EVENT_VM_ACCESS`, `HK_EVENT_HANDLE_PROVENANCE`, `HK_EVENT_FOREIGN_HOLDER`, `HK_EVENT_PROTECT_DRIFT` type enums; no new IOCTL codes (these flow over the existing drain path).

**Guardrail #11:** every field above is new telemetry → `server/api/data-categories.md` updated in the same PR (source/target PID, VA, access masks, owner PID). The server `telemetry` crate gets matching `serde` structs on the independent JSON plane.

---

## Mechanism implementation notes

- **ETW-TI consumer (#64, #69, #72):** register a kernel ETW consumer for `Microsoft-Windows-Threat-Intelligence` (provider GUID `EtwThreatIntProviderGuid`) with the `KERNEL_THREATINT_KEYWORD_{READVM,WRITEVM,ALLOCVM,PROTECTVM}_{LOCAL,REMOTE}` keywords. Filter to events whose `TargetProcessId` == the protected pid. For #64, resolve `BaseAddress` against the section-flag cache populated at `PsSetLoadImageNotifyRoutine` time (store per-module `[base,size)` + `IMAGE_SCN_MEM_EXECUTE` ranges). For #72, key an ordered `(SourcePid → {alloc,protect,write})` accumulator with a short tumbling window and emit one staging event. For #69, the correlation half: a working-set page-in (from #65) with **no** matching ReadVm event in the window sets `HK_VM_ETWTI_SILENT`.
- **Ob extensions (#66, #67):** wire `op[].PostOperation = HkObPostCallback` in `HkObArm` (currently `NULL`). Post-op reads `OB_POST_OPERATION_INFORMATION.GrantedAccess` and diffs against the pre-op-recorded mask for the same handle; emit only when `granted > preop` (#67). For #66, the DUPLICATE branch reads `DuplicateHandleInformation.SourceProcessId`; a driver-maintained ring of "who opened us" lets us flag dup chains whose root opener never appeared in the create log.
- **Canary (#68):** `HkCanaryStart` spawns a guard process and arms an Ob filter on *its* object. A single foreign opener hitting it at a fixed sub-second (frame-locked) cadence is the signal; system enumerators (taskmgr/procexp) are bursty and excluded.
- **Userspace samplers (#65, #70, #71):** `QueryWorkingSetEx` + `GetProcessTimes` correlation (#65); `NtQuerySystemInformation(SystemExtendedHandleInformation)` filtered to `Process`-type handles on the game pid, reading `GrantedAccess`/`UniqueProcessId` (#70); `VirtualQueryEx` `MEMORY_BASIC_INFORMATION.Protect` vs PE characteristics (#71). All three are noisy alone → reported with a low base confidence; the server weights them up only when a kernel VM/Ob event coincides.

IRQL/safety: ETW consumer callbacks run at `PASSIVE_LEVEL` — VAD walks and section-cache reads are fine there; do them off the event-delivery path via a work item if they grow. Ring writes use the existing lock-free emit. Guardrail #5: check every `NTSTATUS`; safe string/`RtlZeroMemory` only.

---

## Build wiring

- `kernel/win/CMakeLists.txt` — add `EtwTiVmWatch.c`, `CanaryProc.c` to the driver target. No new external deps (ETW-TI consumer uses in-box `EtwRegister`/`NtTraceControl`-class APIs from the WDK).
- `sdk/CMakeLists.txt` — add the three `backends/win/*.cpp` under the existing `HK_PLATFORM_WINDOWS` branch (guardrail #1 — they live in `backends/win/`, no raw `_WIN32`).
- Feature flag `HORKOS_WIN_VMWATCH` (default **OFF** until validated on a signed test driver, same posture as the Ob rights-strip policy). Samplers gate behind a runtime policy bit so they can ship dark.

---

## Test strategy

Unit (host-buildable, `tests/unit/`):
- `test_event_schema_sizes.cpp` — `HK_STATIC_ASSERT` on the four new payloads.
- Section-flag classifier: table test mapping a VA to expected `IMAGE_SCN_*` (pure function, no driver).
- #72 staging-sequence assembler: feed ordered/unordered/partial `(alloc,protect,write)` tuples, assert only the full ordered triad emits.
- #66/#67 mask logic: assert emit-on `granted > preop` only; assert reductions never emit.

Bypass-tests (**guardrail #12 merge gate**, `bypass-tests/win/`):
- `vm_read_external.cpp` — a harness process issues `ReadProcessMemory` against a target; assert an `HK_EVENT_VM_ACCESS` (ReadVm) is produced.
- `vm_write_codecave.cpp` — external `WriteProcessMemory` into a +X section; assert `#64` fires with the section-flag bit set.
- `handle_dup_launder.cpp` — open a handle in broker A, `DuplicateHandle` into B, assert `#66` `HK_HND_DUP_LAUNDERED`.
- `protect_flip.cpp` — external `VirtualProtectEx` RX→RWX on a shipped section, assert `#71` `HK_PROT_FOREIGN_INITIATED`.
- `staging_sequence.cpp` — alloc→protect→write-remote triad, assert single `#72` staging event.
- Whitelist FP guard: run RTSS/Steam-overlay-style self-injection, assert it does **not** fire (#64/#71 gating works).

These need a Windows VM with a test-signed driver — flagged as CI `win-driver` job, not host-runnable.

---

## Sequencing

1. **Schema + data-categories first** (#all): land the four payloads, size asserts, `data-categories.md`, server serde structs. Unblocks every downstream signal.
2. **Ob extensions** (#66, #67) — lowest risk, extends existing `Callbacks.c`, post-op is well-documented. Lands with its bypass tests.
3. **ETW-TI consumer** (#64, #72) — the high-value, lower-FP signals. Needs the section-flag cache wired into `Notify.c`'s load-image handler first.
4. **Userspace samplers** (#65, #70, #71) — independent, ship dark; only useful once #3 exists for correlation.
5. **Correlation signals** (#69) — depends on #3 + #65 both emitting.
6. **Canary** (#68) — standalone, last (it spawns a process; validate lifetime/cleanup carefully).

---

## Risks & uncertainty flags

- **⚠ ETW-TI kernel-consumer API (#64, #69, #72):** consuming `Microsoft-Windows-Threat-Intelligence` from kernel mode and the exact `KERNEL_THREATINT_KEYWORD_*` set/encoding is **not something I can confirm blind** — keyword names, the in-kernel consumer registration path, and whether a driver can subscribe (vs only a protected-process-light usermode ETW session) need WDK-header + on-box verification before any code. Per guardrail #13, do **not** implement until confirmed on the target build. This is the single biggest unknown in the domain.
- **⚠ `OB_POST_OPERATION_INFORMATION.GrantedAccess` semantics (#67):** confirm the post-op actually exposes the *final* granted mask after all callbacks, and that registering a post-op doesn't change dispatch behavior. Verify against the WDK sample before wiring `PostOperation`.
- **⚠ Section-flag cache lifetime:** mapping a runtime VA back to `IMAGE_SCN_*` requires the per-module range cache to survive image unload/reload races; needs careful interaction with `PsSetLoadImageNotifyRoutine` teardown. Flag for review.
- **High-FP samplers (#65, #70, #71):** documented in-catalog as `high`/`medium`; the plan gates them behind kernel-event correlation. If correlation proves too sparse, these stay dark — do not promote to standalone signals.
- **Canary process (#68):** spawning an AC-owned guard process has its own attack surface and cleanup/uninstall implications; treat as optional/experimental.
