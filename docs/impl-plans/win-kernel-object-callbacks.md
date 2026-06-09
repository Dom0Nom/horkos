# Windows Kernel — Object / Notify Callback Integrity (`win-kernel-object-callbacks`)

**Scope:** Self-integrity sensors that confirm Horkos's own kernel callback registrations (ObRegisterCallbacks handle filter, Ps* notify routines, CmRegisterCallbackEx registry filter) are still live, in-position, and un-patched — so the server can detect a cheat that silences Horkos's telemetry surface before tampering. All sensors are read-only; ban authority is server-side.

**Catalog signals covered:** 1–9 (Ob liveness self-poll; CallbackList entry walk; Ps* re-arm probe; notify-routine census; Cm registry-callback on protected keys; minifilter altitude census; Ob Enabled-flag drift Process vs Thread; driver image-section/.text hash of callback thunks; Cm altitude collision + census).

These split into three TUs by mechanism, all new, all kernel-private except signal #6's userspace half:
- **`CallbackSelfCheck.c`** — signals 1, 2, 3, 4, 7, 8 (Ob + Ps* self-integrity, one self-check timer).
- **`RegistryCallback.c`** — signals 5, 9 (Cm filter on our own keys + Cm census).
- **`MinifilterCensusWin.cpp`** (userspace SDK) + a thin `Whitelist.c` census hook — signal 6.

---

## New files

| Path | Role | Module-comment summary (guardrail #3) |
|---|---|---|
| `kernel/win/src/CallbackSelfCheck.c` | Periodic Ob/Ps self-integrity sensor: timer→work-item that runs the liveness self-poll, CallbackList walk, notify re-arm probe, notify census, per-type Enabled drift, and .text hash of callback thunks; emits self-integrity events to the ring. | Role: Horkos own-callback integrity self-check. Target: Windows kernel (KMDF). Interface: implements `HkObSelfPoll`/`HkSelfCheckArm`/`HkSelfCheckDisarm` declared in `kernel/win/include/horkos_kernel.h`; emits `hk_event_callback_integrity` / `hk_event_callback_census` from `sdk/include/horkos/event_schema.h`. |
| `kernel/win/src/RegistryCallback.c` | CmRegisterCallbackEx filter scoped to Horkos's own service/config/driver-image keys; emits RegNt* tamper events and the Cm-callback census/cookie-presence check. | Role: registry-tamper sensor on Horkos's own keys + Cm-callback census. Target: Windows kernel (KMDF). Interface: implements `HkCmArm`/`HkCmDisarm`/`HkCmCensus` declared in `horkos_kernel.h`; emits `hk_event_reg_tamper` / `hk_event_callback_census`. |
| `sdk/src/backends/win/MinifilterCensusWin.cpp` | Userspace minifilter altitude census via fltlib (`FilterFindFirst`/`FilterInstanceFindFirst`); flags filters at unallocated altitudes or with a failed Authenticode chain that sit altitude-adjacent-above Horkos. | Role: minifilter altitude-squat census (userspace backend). Target: Windows userspace (guardrail #1: lives under `backends/win/`). Interface: declared in `sdk/src/sdk_backend.h`; feeds the SDK report plane, not the kernel ring. |
| `bypass-tests/win/callback_unhook.cpp` | Merge-gate bypass test (guardrail #12): exercises Ob-deregister / Ps-notify-removal / .text-patch scenarios against the self-check sensor and asserts the integrity event fires. Phase 3 ships disabled (`HK_SELFCHECK_TEST_ENABLED` undefined), like `byovd_load.cpp`. | Role: bypass test for the object/notify self-integrity surface. Target: Windows only (built behind `if(WIN32)`). Interface: consumes `sdk/include/horkos/ioctl.h` + the integrity event surface. |

Guardrail #4 honored: all three `.c`/`.cpp` are separate TUs; kernel TUs (`CallbackSelfCheck.c`, `RegistryCallback.c`) never link the userspace `MinifilterCensusWin.cpp`. They share only the pure-C99 wire headers (`event_schema.h`, `ioctl.h`).

---

## Interfaces & data structures

### `horkos_kernel.h` additions

```c
/* ---- CallbackSelfCheck.c ---- */
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS HkSelfCheckArm(_In_ PHK_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL) void     HkSelfCheckDisarm(_In_ PHK_DEVICE_CONTEXT Ctx);
/* The Ob liveness self-poll target (signal 1): pre-callback stamps this nonce. */
_IRQL_requires_max_(DISPATCH_LEVEL) void HkObSelfPoll(_In_ PHK_DEVICE_CONTEXT Ctx);

/* ---- RegistryCallback.c ---- */
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS HkCmArm(_In_ PHK_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL) void     HkCmDisarm(_In_ PHK_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL) void     HkCmCensus(_In_ PHK_DEVICE_CONTEXT Ctx);
```

### `HK_DEVICE_CONTEXT` additions (baselines captured at arm time)

```c
typedef struct _HK_OB_BASELINE {            /* signals 2, 7 */
    BOOLEAN  Enabled[2];        /* [0]=PsProcessType, [1]=PsThreadType */
    ULONG    Operations[2];     /* CREATE|DUPLICATE bitmask we registered */
    PVOID    PreOpFnBaseline;   /* expected &HkObPreCallback */
    UCHAR    TextHash[32];      /* SHA-256 of callback .text range (signal 8) */
    BOOLEAN  Valid;
} HK_OB_BASELINE;

typedef struct _HK_CM_BASELINE {            /* signal 9 */
    LARGE_INTEGER Cookie;       /* our CmRegisterCallbackEx cookie */
    BOOLEAN       Present;
} HK_CM_BASELINE;

/* added to HK_DEVICE_CONTEXT */
HK_OB_BASELINE   ObBaseline;
HK_CM_BASELINE   CmBaseline;
KTIMER           SelfCheckTimer;
KDPC             SelfCheckDpc;
PIO_WORKITEM     SelfCheckWorkItem;
volatile LONG    SelfCheckHeartbeat;   /* DPC-incremented; distinguishes scheduler
                                          starvation from callback removal (signal 1 FP gate) */
volatile LONG64  ObSelfPollNonce;      /* stamped by HkObPreCallback, checked by self-poll */
volatile LONG    SelfCheckArmed;
LARGE_INTEGER    CmCookie;             /* live cookie, separate from baseline */
```

### Wire-schema additions (`sdk/include/horkos/event_schema.h`) — bump `HK_EVENT_SCHEMA_VERSION` 2 → 3

New event types appended (existing values unchanged, guardrail: append-only):

```c
HK_EVENT_CALLBACK_INTEGRITY = 5,   /* Ob/Ps/.text self-check verdict */
HK_EVENT_CALLBACK_CENSUS    = 6,   /* notify-routine + Cm count census */
HK_EVENT_REG_TAMPER         = 7,   /* RegNt* write to our own keys */
```

```c
/* 16 bytes — fits existing HK_EVENT_PAYLOAD_MAX, no record-size change. */
typedef struct hk_event_callback_integrity {
    uint32_t check_id;       /* HK_CB_CHECK_* (which signal: liveness/walk/rearm/drift/texthash) */
    uint32_t object_type;    /* 0=process 1=thread 2=image (for per-type drift, signal 7) */
    uint32_t result;         /* HK_CB_RESULT_OK / _MISSING / _DISABLED / _PTR_SWAP / _TEXT_PATCH */
    uint32_t consecutive;    /* consecutive-miss counter (FP gate: N misses, not one) */
} hk_event_callback_integrity;
HK_STATIC_ASSERT(sizeof(hk_event_callback_integrity) == 16, "size");

/* 16 bytes. */
typedef struct hk_event_callback_census {
    uint32_t notify_count;   /* populated Ps* notify slots (signal 4; cap PSP_MAX=64) */
    uint32_t cm_count;       /* registered Cm callbacks (signal 9; cap 100) */
    uint32_t own_present;    /* bit0 = our notify slot present, bit1 = our Cm cookie present */
    uint32_t floor;          /* per-host post-boot floor we compare against (signal 4 FP gate) */
} hk_event_callback_census;
HK_STATIC_ASSERT(sizeof(hk_event_callback_census) == 16, "size");

/* 16 bytes — writer identity + which protected value class was touched. */
typedef struct hk_event_reg_tamper {
    uint32_t writer_pid;     /* PsGetCurrentProcessId of the RegNt* requester */
    uint32_t value_class;    /* HK_REG_VAL_* (ImagePath/Start/Altitude/Policy) */
    uint32_t op;             /* HK_REG_OP_SET / _DELETE / _DELETEVALUE */
    uint32_t writer_is_system; /* 1 if requester token is SYSTEM/TrustedInstaller (FP gate) */
} hk_event_reg_tamper;
HK_STATIC_ASSERT(sizeof(hk_event_reg_tamper) == 16, "size");
```

`HK_EVENT_PAYLOAD_MAX` stays 16, so `hk_event_record` stays 40 bytes — **no IOCTL envelope change, no `hk_event_record`/`hk_drain_header` size-pin churn.** The existing `HK_STATIC_ASSERT(sizeof(hk_event_record)==40)` in `ioctl.h` still holds and gates drift on both sides (Step 3.5 contract).

`hk_status` (`ioctl.h`) gains two status flags (no struct growth — `flags` is already a `uint32_t` bitmask):
```c
#define HK_STATUS_FLAG_SELFCHECK_OK   0x00000008u
#define HK_STATUS_FLAG_CB_TAMPER_SEEN 0x00000010u
```

### Server mirror

Phase 2 server adds serde mirrors of the three structs (lockstep `HK_EVENT_SCHEMA_VERSION = 3`) when the kernel-event ingest plane lands; the three new types route into the ban-engine as high-weight self-integrity signals. No `unwrap()` (guardrail #8); deserialize via `thiserror`-typed errors.

### Guardrail #11 — `server/api/data-categories.md` (same PR)

New telemetry fields **must** be declared in the same PR. Add a section **"2b. Callback / self-integrity (Windows kernel)"** with rows:

| Field | Source |
|---|---|
| `check_id`, `object_type`, `result`, `consecutive` | `hk_event_callback_integrity` (Ob/Ps/.text self-check) |
| `notify_count`, `cm_count`, `own_present`, `floor` | `hk_event_callback_census` |
| `writer_pid`, `value_class`, `op`, `writer_is_system` | `hk_event_reg_tamper` (RegNt* on Horkos keys) |

Retention default 90 days, Legitimate interest — anti-cheat enforcement, Operator-of-record Horkos Service Operator (matching the existing §2a rows). `writer_pid` is a foreign-process identifier and carries the same basis as `requesting_pid` in §2a.

---

## Mechanism implementation notes

**Shared timing substrate (signals 1,2,3,4,7,8,9).** One `KeInitializeTimerEx`(NotificationTimer) + `KeSetTimerEx` periodic timer drives a `KDPC`. The DPC runs at DISPATCH_LEVEL: it does nothing but increment `SelfCheckHeartbeat` and `IoQueueWorkItem` a passive-level work item. **All actual checks run in the work item at PASSIVE_LEVEL** because they touch pageable structures, walk lists, hash pages, and (Cm/Ps) call routines that require PASSIVE. This mirrors the catalog's stated KTIMER/KDPC→work-item design and respects the same IRQL discipline the existing ring uses.

**Signal 1 — Ob liveness self-poll.** Work item zeroes `ObSelfPollNonce`, then `ZwOpenProcess` (kernel-mode caller) opens a sentinel target with a magic `DesiredAccess` bit pattern. `HkObPreCallback` (in `Callbacks.c`) is extended to recognize that magic mask and `InterlockedExchange64` a stamp into `ObSelfPollNonce`, then return SUCCESS without logging it as a real handle-open. Work item re-reads the nonce: set ⇒ callback fired. **FP gate:** require N consecutive missed polls AND confirm `SelfCheckHeartbeat` advanced (so scheduler starvation, which also stalls the work item, is distinguishable from a removed callback). Self-open by the driver must be excluded from the normal handle-open emit path so we don't pollute `hk_event_handle_open`.
- *Safety:* `ZwOpenProcess` from the system process context at PASSIVE only; check every `NTSTATUS` (guardrail #5). The sentinel handle is closed with `ZwClose` and the return checked.

**Signal 2 + 7 — CallbackList walk / per-type Enabled drift.** The catalog itself flags this as **undocumented internal layout** (`OBJECT_TYPE.CallbackList`, `OB_CALLBACK_ENTRY`). Per guardrail #13 this is an **UNCERTAINTY FLAG** (see Risks). The buildable, documented-only fallback we land first: compare against the baseline we *constructed ourselves* at arm time — Horkos owns the `OB_OPERATION_REGISTRATION[]` it passed to `ObRegisterCallbacks` and the returned handle, so signal 7's per-type, per-operation Enabled/Operations comparison is done against **our own recorded intent**, not by parsing kernel internals. The raw `CallbackList` walk (absolute neighbor order, foreign altitudes) is gated behind a per-build offset table and ships **OFF by default** until offsets are validated on each target build.

**Signal 3 — Ps* re-arm probe.** Call `PsSetCreateProcessNotifyRoutineEx`/`PsSetCreateThreadNotifyRoutine`/`PsSetLoadImageNotifyRoutine` with the SAME routine already registered. Documented behavior: a still-registered routine returns `STATUS_INVALID_PARAMETER` (duplicate). A `STATUS_SUCCESS` means we'd just re-registered a silently-removed routine — **immediately re-disarm the duplicate** (`...Routine(routine, TRUE)` remove form) to keep slot accounting correct, and emit an integrity event. **Serialize with `Notify.c` arm state:** take the same arm/disarm lock and skip the probe while `NotifyRoutinesArmed` is mid-transition (the only FP is our own disarm racing the probe). Every return checked (guardrail #5).

**Signal 4 — notify census.** No fully documented enumeration API exists for the populated count, so the census is maintained as **Horkos's own delta accounting** plus the documented hard cap (`PSP_MAX_CREATE_PROCESS_NOTIFY = 64`). Establish a per-host floor after boot settles; alert only on a sharp monotone drop that includes our own slot (own_present bit0 clear). Reading the global `PspCreateProcessNotifyRoutine` array directly is **undocumented** → UNCERTAINTY FLAG; ships OFF, behind the same per-build offset table as signal 2.

**Signal 5 — Cm filter on our own keys.** `CmRegisterCallbackEx` with our altitude; the callback handles `RegNtPreSetValueKey` / `RegNtPreDeleteKey` / `RegNtPreDeleteValueKey`. From `REG_SET_VALUE_KEY_INFORMATION` extract target key path + new data; `PsGetCurrentProcessId` for the writer. **Scope strictly to Horkos's own service/config/driver-image keys** to bound FP volume and load. FP gate: stamp `writer_is_system` (SYSTEM/TrustedInstaller during a servicing window = allow-list-leaning); non-elevated/game-adjacent writer = high weight. The Cm callback runs at PASSIVE; **return `STATUS_SUCCESS` to never block the write** (observe-only Phase 3) — and never drop a notification without returning, analogous to the ES never-drop rule. Use safe string functions only when copying the key path (guardrail #5).

**Signal 6 — minifilter altitude census (userspace).** `FilterFindFirst`/`FilterFindNext` (`FilterFullInformation`) + `FilterInstanceFindFirst`/`...Next` (`InstanceFullInformation` → Altitude) via `fltlib.lib`. Lives in `sdk/src/backends/win/` (guardrail #1: no platform API outside `backends/`). Flag only filters at an **unallocated** altitude OR with a failed Authenticode chain that sit numerically adjacent-above Horkos's load-order group — never altitude-occupancy alone (Defender 328010, OneDrive, Carbon Black are legitimate). Gate against Microsoft's published Allocated Altitudes + a signed-publisher allowlist. Feeds the SDK report plane (not the kernel ring).

**Signal 8 — .text hash of callback thunks.** At arm time, capture the addresses of `HkObPreCallback`/`HkProcessNotifyEx`/`HkLoadImageNotify`, resolve the owning image base via the loaded-module list, and SHA-256 the `.text` code range (exclude IAT/relocs). Re-hash on the self-check timer at PASSIVE; mismatch = inline patch even though the registration pointer is pristine. **Cross-check with attestation:** confirm the on-disk image matches (reuse the `Attestation.h` stable interface, guardrail #10) before trusting the in-memory baseline. Walking `PsLoadedModuleList` for the image base is partly undocumented → UNCERTAINTY FLAG (prefer a documented base-resolution path; see Risks).

**Server (guardrail #8).** New events deserialize on tokio async paths with `thiserror` error types, no `unwrap()` outside tests. The ban-engine treats `result != OK` / missing-own-slot / `cm_count` cookie-absent as high-weight self-integrity inputs; consecutive-miss gating already applied client-side keeps the server signal low-FP.

---

## Build wiring

- **`kernel/win/CMakeLists.txt`** — add `src/CallbackSelfCheck.c` and `src/RegistryCallback.c` to `HK_DRIVER_SRC`. They build under the existing `/kernel /GS /W4 /WX` flags (warnings-as-errors already on). No new kernel link libs needed (Cm/Ps/Ob/Ke/Mm/Zw exports come from `ntoskrnl.lib`). Mirror the same additions in `kernel/win/horkos.vcxproj` (the production signing source of truth).
- **Feature flags (kernel):** `HK_SELFCHECK_UNDOC_OFFSETS` (CMake `option`, default **OFF**) gates the undocumented `CallbackList`/`PspCreateProcessNotifyRoutine` paths (signals 2-walk, 4-array). With it OFF, only the documented self-baseline + re-arm-probe + census-delta + .text-hash + Cm paths compile in. `HK_SELFCHECK_TIMER_MS` (default e.g. 5000) is the self-check period.
- **`sdk/CMakeLists.txt`** — add `src/backends/win/MinifilterCensusWin.cpp` to the Windows backend sources; link `fltlib.lib` on `WIN32`.
- **`bypass-tests/win/CMakeLists.txt`** — add `hk_bypass_callback_unhook` target (`callback_unhook.cpp`), `add_test`, include `sdk/include`. Phase 3 builds it disabled.
- **Toolchain:** WDK (matching installed SDK) for the kernel TUs; standard MSVC + `fltlib` for the SDK backend. No clang-19/libbpf/Xcode here (Windows-only domain).

---

## Test strategy

**Unit / host-buildable:**
- Wire-schema pins: the new `HK_STATIC_ASSERT`s (each new payload == 16) compile on both the kernel C99 build and every userspace TU; `hk_event_record == 40` unchanged.
- Server serde round-trip tests for the three new structs (Rust, `#[cfg(test)]` may `unwrap`).
- FP-gate logic unit-tested where extractable: the "N consecutive misses AND heartbeat advanced" decision and the "census floor monotone-drop including own slot" decision factored into pure helpers testable on a host build.
- `MinifilterCensusWin.cpp`: unit-test the allocated-altitude/publisher-allowlist classifier against a fixture altitude table (no live FltMgr needed).

**Bypass tests (guardrail #12 — merge gate; any change under a security folder needs a corresponding bypass test):**
- **`bypass-tests/win/callback_unhook.cpp`** — the required gate file for this surface. Disabled in Phase 3 (compiled no-op reporting "DISABLED", returns 0, exactly like `byovd_load.cpp`), activated in a later enforcement phase. When enabled it must demonstrate, each as a sub-case:
  1. **Ob-deregister:** force `ObUnRegisterCallbacks` of Horkos's handle (or NOP the pre-op pointer) ⇒ assert signal-1 liveness emits `_MISSING` after N polls and the heartbeat confirms it isn't starvation.
  2. **Ps-notify removal:** remove a Horkos notify routine out from under it ⇒ assert signal-3 re-arm probe returns `STATUS_SUCCESS`, the duplicate is re-disarmed, and an integrity event fires; assert signal-4 census shows own_present bit0 cleared.
  3. **.text patch:** write a detour/`int3` over a callback prologue while leaving the registration pointer intact ⇒ assert signal-8 hash mismatch fires though table-walk signals stay green.
  4. **Cm-cookie removal:** `CmUnRegisterCallback` of our cookie ⇒ assert signal-9 census shows our cookie absent.
- The `byovd_load.cpp` gate is unaffected.

---

## Sequencing

1. **Schema + contract first.** Bump `HK_EVENT_SCHEMA_VERSION` to 3, add the three payload structs + `HK_STATIC_ASSERT`s in `event_schema.h`, add the two status flags in `ioctl.h`, update `server/api/data-categories.md` (§2b) — all in the same PR (guardrail #11). This unblocks both kernel and server in parallel and proves wire-size pins on both sides.
2. **`HK_DEVICE_CONTEXT` + self-check timer skeleton** (`CallbackSelfCheck.c`): timer→DPC→work-item plumbing, heartbeat, arm/disarm wired into `DriverEntry.c`/unload. No checks yet — just the substrate.
3. **Documented signals on the substrate:** signal 7 (self-baseline Enabled drift), signal 1 (Ob liveness self-poll, requires the `HkObPreCallback` nonce-stamp edit in `Callbacks.c`), signal 3 (Ps re-arm probe, serialized with `Notify.c` lock), signal 4 (census-delta accounting + floor), signal 8 (.text hash + attestation cross-check). These are independent and can land in any order once step 2 exists; signal 1 depends on the `Callbacks.c` edit.
4. **`RegistryCallback.c`** (signals 5, 9): `HkCmArm`/`HkCmDisarm` + Cm census, wired into DriverEntry/unload. Independent of the Ob/Ps work above.
5. **`MinifilterCensusWin.cpp`** (signal 6, userspace SDK) — fully parallel to all kernel work; only depends on the SDK backend interface.
6. **Undocumented-offset paths** (signal 2 full walk, signal 4 array scan) — **last**, behind `HK_SELFCHECK_UNDOC_OFFSETS=OFF`, only after per-build offset tables are validated. Do not block the rest on these.
7. **Bypass test** `callback_unhook.cpp` lands disabled alongside step 2 (gate requirement), activated when enforcement/fixture support exists.

---

## Risks & UNCERTAINTY FLAGS

Per guardrail #13 — these are explicitly flagged, not papered over. Stop and confirm before implementing the flagged items:

- **UNCERTAIN — `OBJECT_TYPE.CallbackList` / `OB_CALLBACK_ENTRY` internal layout (signals 2, 7-raw-walk).** Undocumented, version-fragile across Windows builds; the catalog says so itself. **Do not guess offsets.** Ships OFF behind `HK_SELFCHECK_UNDOC_OFFSETS`. The documented self-baseline comparison (compare against the `OB_OPERATION_REGISTRATION[]` Horkos itself passed) covers signal 7's high-weight case without touching internals; land that, flag the raw walk.
- **UNCERTAIN — `PspCreateProcessNotifyRoutine` array scan (signal 4 absolute census).** Undocumented global; the *populated-slot count* has no documented enumerator. Use Horkos's own delta accounting + the documented `PSP_MAX = 64` cap as the buildable path; the absolute array scan is OFF behind the same flag.
- **UNCERTAIN — `PsLoadedModuleList` walk for image base resolution (signal 8).** Partly undocumented. Prefer a documented base-resolution route for our own image if one is acceptable; if the loaded-module walk is required, flag the exact offset assumptions before coding. Hashing the wrong range risks false positives, not a BSOD — but the walk itself can fault if offsets drift.
- **IRQL discipline.** All checks must run in the PASSIVE work item, not the DISPATCH DPC. `ZwOpenProcess` (signal 1), Cm callback body (signal 5), `Ps*` re-arm (signal 3), and page hashing (signal 8) are PASSIVE-only. A DISPATCH-level call here is a bugcheck. This is documented and low-risk if the timer→DPC→work-item split is respected, but it is the single most important invariant in this domain.
- **Ps re-arm probe race (signal 3).** Re-registering then re-disarming a routine has a window where slot accounting is transiently off. Must hold the `Notify.c` arm lock across the probe; getting this wrong double-frees or leaks a notify slot. Confirm the exact lock semantics in `Notify.c` before wiring.
- **Cm callback never drops a notification.** Like the macOS ES never-drop rule, the registry callback must always return a status; observe-only Phase 3 returns `STATUS_SUCCESS`. Verify no path can early-return without a status.
- **Signal 6 FP surface.** Altitude-occupancy alone is never a verdict; only unallocated-altitude or failed-Authenticode adjacent-above. The allocated-altitude table and publisher allowlist must be kept current or legitimate AV/backup/cloud filters trigger noise.
- **Signing.** ObRegisterCallbacks already requires the object-callback signing EKU (see `Callbacks.c` `STATUS_ACCESS_DENIED` note). Cm/Ps registration do not add a new signing requirement, but production signing remains gated by `docs/windows-signing.md` — do not assume test-signing grants the Ob EKU.
