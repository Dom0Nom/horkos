# Windows Kernel — Thread Origin Validation (`win-kernel-thread-injection`)

**Scope:** Read-only thread-provenance sensors for the Windows client that validate where a newly created thread *came from* (creator lineage, kernel vs user start address, entry-page backing, session/desktop, hide-from-debugger, rate/stack) and ship the evidence to the server, which holds all ban authority. Clients sample and report only.

**Catalog signals covered:** 19, 20, 21, 22, 23, 24, 25, 26, 27.

Signal split by collection plane:

- **Kernel notify plane** (KMDF driver, `PsSetCreateThreadNotifyRoutineEx`): 19, 22, 23, 26 (creator provenance, WOW64 start, ETHREAD-vs-TEB capture, session). These need the *Ex* create-notify so the kernel captures `PS_CREATE_THREAD_NOTIFY_INFO.StartAddress` at create time and can resolve the creator TID.
- **Userspace ETW-TI plane** (protected SDK consumer, never a kernel TU): 20, 21, 27 (alloc/setcontext/resume causality, APC-routine target, creator-stack burst). No sanctioned kernel callback exposes remote VM-alloc, set-context, or APC enqueue; ETW Threat-Intelligence is the only documented source.
- **Userspace enrichment plane** (`ThreadProvenanceWin.cpp`): 22, 23, 24, 25 (the `ZwQueryInformationThread` / `ZwQueryVirtualMemory` comparisons and `ThreadHideFromDebugger` flag). Runs on demand against TIDs the kernel/ETW planes flagged, not as a blanket poll.

All scoring, thresholding, and rate modelling are **server-side** (signal 27 in particular reports raw events; the client never thresholds). The driver and SDK are capture-only.

---

## New files

| Path | Role | Module-comment summary |
|---|---|---|
| `kernel/win/src/ThreadProvenance.c` | Kernel: the `HkThreadNotifyEx` create-notify body — capture kernel `ETHREAD` StartAddress, creator TID/PID, session ids, WOW64 flag; emit `hk_event_thread_create`. Replaces the non-Ex stub path. | Role: Ex thread-create notify, kernel-side provenance capture into the ring. Target: Windows kernel (KMDF). Interface: implements `HkThreadProvenanceArm/Disarm` declared in `kernel/win/include/horkos_kernel.h`; emits records defined in `sdk/include/horkos/event_schema.h`. Guardrail #4: kernel TU only — no userspace headers. |
| `sdk/src/backends/win/EtwTiConsumer.cpp` | Userspace: protected (PPL/AM-signed) ETW-TI consumer for `Microsoft-Windows-Threat-Intelligence`; correlates ALLOCVM_REMOTE→SETTHREADCONTEXT→RESUMETHREAD and QUEUEUSERAPC_REMOTE, captures create-event stack walks; produces `hk_event_thread_inject` / `hk_event_apc_inject` records. | Role: ETW-TI consumer + cross-process causality correlation (signals 20, 21, 27). Target: Windows (userspace). Interface: implements `hk::sdk::etwti::start/stop` from `EtwTiConsumer.h`; emits event_schema.h records to the SDK report queue. Guardrail #1: all ETW Win32 API confined to this backends/ file. |
| `sdk/src/backends/win/EtwTiConsumer.h` | Userspace: SDK-internal interface for the ETW-TI consumer (start/stop, callback registration). | Role: declares the ETW-TI consumer lifecycle. Target: Windows (userspace). Interface: consumed by `sdk.cpp` Windows path. |
| `sdk/src/backends/win/ThreadProvenanceWin.cpp` | Userspace: on-demand thread enrichment — `ZwQueryInformationThread` Win32StartAddress vs kernel start (23), WOW64 64-bit start (22), entry-page MEM_IMAGE/MEM_PRIVATE + on-disk RVA byte compare for module-stomping (24), `ThreadHideFromDebugger` flag (25). Reuses the `dma_detect` page-hash helper. | Role: userspace thread-provenance enrichment for flagged TIDs. Target: Windows (userspace). Interface: implements `hk::sdk::threadprov::enrich(tid)` from `ThreadProvenanceWin.h`; reads kernel records, emits enriched `hk_event_thread_provenance`. Guardrail #1: NT query API confined to this backends/ file. |
| `sdk/src/backends/win/ThreadProvenanceWin.h` | Userspace: SDK-internal interface for the enrichment path. | Role: declares `threadprov::enrich`. Target: Windows (userspace). Interface: consumed by the ETW-TI consumer and `sdk.cpp`. |
| `server/telemetry/src/thread_inject.rs` | Server: serde mirror + feature extraction for the new kernel-event records (thread-create provenance, thread-inject causality, APC-inject, provenance enrichment). Feeds the rate/unbacked-stack model (signal 27). | Role: server-side decode + feature extraction for thread-origin events. Target: server. Interface: `#[repr(C)]`-mirrored decoders for the new event_schema.h structs; pure async, `thiserror`, no `unwrap()` (guardrail #8). |
| `bypass-tests/win/thread_origin/` (dir) | Bypass-test suite for this domain (guardrail #12). One test per evasion the catalog names. | Role: merge-gate bypass tests for thread-origin validation. Target: Windows test host + server decode. Interface: drives synthetic injectors / replays recorded ETW-TI traces; asserts the corresponding record is emitted and the spoof is not silently accepted. |

**Edited (not new):** `kernel/win/src/Notify.c` (drop the non-Ex `HkThreadNotify` stub, call into `ThreadProvenance.c`), `kernel/win/include/horkos_kernel.h` (declare the new kernel routines + ring-slot size bump), `sdk/include/horkos/event_schema.h` (new event types + payloads + `HK_EVENT_PAYLOAD_MAX` bump), `sdk/include/horkos/ioctl.h` (`hk_event_record` re-pin), `server/telemetry/src/schema.rs`/`lib.rs` (wire in the new module), `server/api/data-categories.md` (guardrail #11), `dma_detect/` (expose the page-hash helper for reuse).

---

## Interfaces & data structures

### Wire-schema additions (`sdk/include/horkos/event_schema.h`)

Bump `HK_EVENT_SCHEMA_VERSION` 2u → 3u. Append event types (existing values never change):

```c
HK_EVENT_THREAD_CREATE      = 5,  /* kernel Ex notify provenance        */
HK_EVENT_THREAD_INJECT      = 6,  /* ETW-TI causality (alloc/ctx/resume) */
HK_EVENT_APC_INJECT         = 7,  /* ETW-TI remote user APC             */
HK_EVENT_THREAD_PROVENANCE  = 8,  /* userspace enrichment (start/page)  */
```

**Critical wire change — record growth.** The catalog payloads carry 64-bit addresses (kernel StartAddress, Win32StartAddress, ApcRoutine, three creator/target TID/PID pairs, session ids, flag words). They exceed the current `HK_EVENT_PAYLOAD_MAX 16`. The largest below is `hk_event_thread_inject` at 56 bytes. Therefore:

```c
#define HK_EVENT_PAYLOAD_MAX 56u   /* was 16u — grown for thread-origin payloads */
```

This re-pins `hk_event_record` to `24 + 56 = 80` bytes and changes the ring-slot stride in `HK_RING.Slots[]`. The `HK_STATIC_ASSERT(sizeof(hk_event_record) == 40, ...)` in `ioctl.h` becomes `== 80`. The DRAIN envelope stays a flat array of the (now larger) record, so `IrpDispatch.c` needs no logic change, only the recompiled size. The ring capacity (`HK_RING_CAPACITY 4096`) doubles its non-paged-pool footprint (4096 × 80 = 320 KB); flag for review (see Risks).

Payload structs (sizes pinned with `HK_STATIC_ASSERT`, all fields fixed-width):

```c
/* HK_EVENT_THREAD_CREATE — 48 bytes. Captured at PsSetCreateThreadNotifyRoutineEx. */
typedef struct hk_event_thread_create {
    uint32_t tid;                  /* new thread TID                              */
    uint32_t pid;                  /* target (owning) PID                         */
    uint32_t creator_tid;          /* PsGetCurrentThreadId at callback            */
    uint32_t creator_pid;          /* PsGetThreadProcessId(creator)               */
    uint64_t kernel_start_address; /* PS_CREATE_THREAD_NOTIFY_INFO.StartAddress   */
    uint32_t target_session_id;    /* PsGetProcessSessionId(target)               */
    uint32_t creator_session_id;   /* PsGetProcessSessionId(creator)              */
    uint32_t flags;                /* HK_THREAD_FLAG_* (wow64 target, etc.)       */
    uint32_t reserved;             /* zero                                        */
    uint64_t create_time_ns;       /* KeQueryInterruptTime*100; boot epoch        */
} hk_event_thread_create;
HK_STATIC_ASSERT(sizeof(hk_event_thread_create) == 48, "thread_create size");

/* HK_EVENT_THREAD_INJECT — 56 bytes. ETW-TI alloc/setcontext/resume causality. */
typedef struct hk_event_thread_inject {
    uint32_t source_pid;           /* SETTHREADCONTEXT/RESUMETHREAD source        */
    uint32_t target_pid;
    uint32_t target_tid;
    uint32_t chain_flags;          /* HK_INJECT_CHAIN_* bits seen for this TID    */
    uint64_t alloc_base;           /* ALLOCVM_REMOTE base, 0 if not seen          */
    uint64_t alloc_size;
    uint64_t window_ns;            /* span first→last event in the chain          */
    uint64_t context_rip;          /* SETTHREADCONTEXT new RIP/EIP, 0 if none     */
    uint32_t source_session_id;
    uint32_t flags;                /* debugger-source / overlay-allowlisted bits  */
} hk_event_thread_inject;
HK_STATIC_ASSERT(sizeof(hk_event_thread_inject) == 56, "thread_inject size");

/* HK_EVENT_APC_INJECT — 40 bytes. ETW-TI QUEUEUSERAPC_REMOTE. */
typedef struct hk_event_apc_inject {
    uint32_t source_pid;
    uint32_t target_pid;
    uint32_t target_tid;
    uint32_t apc_flags;            /* special-user-APC bit, etc.                  */
    uint64_t apc_routine;          /* ApcRoutine address                          */
    uint32_t routine_region_type;  /* HK_REGION_* (image/private/mapped) resolved */
    uint32_t reserved;
    uint64_t event_time_ns;
} hk_event_apc_inject;
HK_STATIC_ASSERT(sizeof(hk_event_apc_inject) == 40, "apc_inject size");

/* HK_EVENT_THREAD_PROVENANCE — 48 bytes. Userspace enrichment result. */
typedef struct hk_event_thread_provenance {
    uint32_t tid;
    uint32_t pid;
    uint64_t user_start_address;   /* ThreadQuerySetWin32StartAddress (spoofable) */
    uint64_t entry_region_base;    /* MemoryBasicInformation base of start page   */
    uint32_t entry_region_type;    /* HK_REGION_IMAGE/PRIVATE/MAPPED              */
    uint32_t prov_flags;           /* HK_PROV_* (start mismatch, stomped, hidden, */
                                   /*   wow64-64bit-start, jit-allowlisted)       */
    uint64_t entry_page_disk_delta;/* #mismatching bytes vs on-disk RVA, MEM_IMAGE*/
    uint32_t backing_module_hash32;/* truncated hash id of backing module path    */
    uint32_t reserved;
} hk_event_thread_provenance;
HK_STATIC_ASSERT(sizeof(hk_event_thread_provenance) == 48, "thread_provenance size");
```

Flag/enum constants (appended, never renumbered):

```c
#define HK_THREAD_FLAG_WOW64_TARGET     0x00000001u
#define HK_THREAD_FLAG_CROSS_SESSION    0x00000002u  /* creator/target session differ */
#define HK_INJECT_CHAIN_ALLOCVM         0x00000001u
#define HK_INJECT_CHAIN_SETCONTEXT      0x00000002u
#define HK_INJECT_CHAIN_RESUME          0x00000004u
#define HK_INJECT_FLAG_SOURCE_DEBUGGER  0x00000008u  /* gate: registered debugger src */
#define HK_INJECT_FLAG_SOURCE_OVERLAY   0x00000010u  /* gate: signed-overlay allowlist */
#define HK_REGION_IMAGE                 1u
#define HK_REGION_PRIVATE               2u
#define HK_REGION_MAPPED                3u
#define HK_PROV_START_MISMATCH          0x00000001u  /* kernel start unbacked, user in-module (23 spoof sig) */
#define HK_PROV_ENTRY_STOMPED           0x00000002u  /* MEM_IMAGE but bytes != on-disk (24) */
#define HK_PROV_ENTRY_PRIVATE           0x00000004u  /* manual-map private RX (24) */
#define HK_PROV_HIDE_FROM_DEBUGGER      0x00000008u  /* ThreadHideFromDebugger (25) */
#define HK_PROV_WOW64_64BIT_START       0x00000010u  /* start > 4GB in wow64 proc (22) */
#define HK_PROV_JIT_ALLOWLISTED         0x00000020u  /* signed JIT host — FP suppressor */
```

### IOCTL additions (`sdk/include/horkos/ioctl.h`)

No new control code is required — the new kernel records flow through the existing `HK_IOCTL_DRAIN_EVENTS` envelope (only the record size grows, per above). The userspace ETW-TI and enrichment records do **not** transit the driver at all; they are produced in userspace and merged into the SDK report stream alongside drained kernel records. Re-pin the existing assert: `sizeof(hk_event_record) == 80`.

(Optional, deferred: an `HK_IOCTL_QUERY_THREAD` code so userspace can ask the kernel to re-read a still-live TID's ETHREAD start. Listed as a future code `0x803`; not implemented in this plan — the kernel emits the start at create time, which is the spoof-resistant capture.)

### Server mirror (`server/telemetry/src/thread_inject.rs`)

`#[repr(C)]` structs mirroring each payload by field name and size, decoded from the drained kernel-event byte stream. Feature extraction emits a normalized record for the ban-engine / ONNX model: per-TID chain completeness, creator-stack-unbacked ratio, start-mismatch boolean, cross-session boolean. Pure async, `thiserror` error type (extend `telemetry::error`), no `unwrap()` outside `#[cfg(test)]`.

### Guardrail #11 — `server/api/data-categories.md`

Every new field above is telemetry and **must** be declared in the same PR. Add a new subsection **"2b. Thread origin (Windows kernel + ETW-TI)"** with rows for: `tid`, `creator_tid`, `creator_pid`, `kernel_start_address`, `user_start_address`, `target_session_id`, `creator_session_id`, `entry_region_type`, `entry_region_base`, `apc_routine`, `alloc_base`/`alloc_size`, `context_rip`, `backing_module_hash32`, plus the `*_flags`/`prov_flags` bitmasks. Source = "thread-create notify (`hk_event_thread_create`) / ETW-TI consumer (`hk_event_thread_inject`,`hk_event_apc_inject`) / userspace enrichment (`hk_event_thread_provenance`)". Retention 90 days, legal basis legitimate interest, operator Horkos Service Operator (matching existing kernel-event rows). Note `kernel_start_address`/`context_rip`/`apc_routine` are in-process code addresses, not user content.

---

## Mechanism implementation notes

### Kernel plane (`ThreadProvenance.c`)

- **Arm with the Ex variant.** Replace `PsSetCreateThreadNotifyRoutine(HkThreadNotify)` with `PsSetCreateThreadNotifyRoutineEx(PsCreateThreadNotifyNonSystem, HkThreadNotifyEx)`. The Ex routine receives `PPS_CREATE_THREAD_NOTIFY_INFO`, whose `StartAddress` is the spoof-resistant kernel ETHREAD start (signal 23) and which is the documented carrier for signals 19/22/26 enrichment. **UNCERTAINTY FLAG (see Risks):** `PsSetCreateThreadNotifyRoutineEx` availability and the exact `PS_CREATE_THREAD_NOTIFY_INFO` field set are version-gated; confirm against the target WDK before coding.
- **IRQL.** Create-thread notify routines run at `PASSIVE_LEVEL` in the context of the creating thread. `PsGetCurrentThreadId`, `PsGetThreadProcessId`, `PsGetProcessSessionId`, `PsGetProcessWow64Process` are callable here. `HkRingPush`/`HkRingEmit` already take the ring spin lock and run safely up to `DISPATCH_LEVEL`, so emitting is fine. Do **not** call `ZwQueryInformationThread` / `ZwQueryVirtualMemory` from the notify routine — those are userspace-friendly NT calls that the catalog deliberately routes through the SDK enrichment plane; the kernel only captures what the callback hands it plus cheap `PsGet*` accessors.
- **Creator-region check (signal 19) is deferred to userspace.** The catalog's "creator region unbacked AND unsigned AND recently VirtualAlloc'd" test needs VAD/section walks that are unsafe and verbose in the notify routine. The kernel emits `creator_tid`/`creator_pid`; `ThreadProvenanceWin.cpp` performs the region classification against the creator. This keeps the kernel path short and bounded (guardrail #13 spirit: don't do risky VAD spelunking at notify time).
- **Safe strings / return checks (guardrails #5).** No string formatting in this path. Every `PsGet*` returns a value, not NTSTATUS; the one NTSTATUS path is `Ps...NotifyRoutineEx` arm/disarm — checked exactly like the existing `HkNotifyArm` does, with the same disarm-on-failure and bugcheck-on-disarm-failure discipline already in `Notify.c`.
- **WOW64 (signal 22) kernel half.** `PsGetProcessWow64Process(target) != NULL` sets `HK_THREAD_FLAG_WOW64_TARGET`. The actual "start address > 4 GB / non-wow64 CS" decision is userspace (needs `ThreadWow64Context`), but the kernel flag tells the enrichment plane to apply the WOW64 rule.
- **Session (signal 26).** `PsGetProcessSessionId(creator)` vs `PsGetProcessSessionId(target)`; set `HK_THREAD_FLAG_CROSS_SESSION` on mismatch. Session-0 allowlisting of signed service publishers is a **server-side** gate (the kernel has no signed-publisher DB), so the kernel reports the raw session ids and the flag.

### Userspace ETW-TI plane (`EtwTiConsumer.cpp`) — signals 20, 21, 27

- **Provider.** Subscribe to `Microsoft-Windows-Threat-Intelligence`. **Hard requirement:** this provider only delivers to a process running as PPL anti-malware-light (`PsProtectedSignerAntimalware`), which requires an ELAM-signed binary and the AM cert. **UNCERTAINTY FLAG:** exact PPL level, ELAM registration, and whether a real-time `OpenTrace`/`ProcessTrace` session vs a TraceLogging consumer is the supported path — confirm before implementing (Risks).
- **Causality window (20).** Correlate `KERNEL_THREATINT_TASK_ALLOCVM_REMOTE` → `KERNEL_THREATINT_TASK_SETTHREADCONTEXT` → `KERNEL_THREATINT_TASK_RESUMETHREAD` keyed on `TargetThreadId`/`TargetProcessId` within a bounded ms window. A per-target ring of recent events with a sliding timeout; emit `hk_event_thread_inject` when ≥2 of the three fire on the same TID with `source_pid != target_pid`. FP gates per catalog: drop if source is a registered debugger (`HK_INJECT_FLAG_SOURCE_DEBUGGER`) or in the signed-overlay allowlist (`HK_INJECT_FLAG_SOURCE_OVERLAY`); flags are *reported*, not used to suppress client-side — server decides.
- **APC (21).** `KERNEL_THREATINT_TASK_QUEUEUSERAPC_REMOTE` payload `ApcRoutine`/`TargetThreadId`/special-APC flag; resolve `ApcRoutine` against the target's module map (via `threadprov` region query) → `routine_region_type`. Emit `hk_event_apc_inject` only when source≠target (Windows' own I/O/thread-pool APCs are same-process and land in-ntdll).
- **Stack capture (27).** Enable stack-walk on the create event; walk `RtlWalkFrameChain`-style return addresses against the loaded-module map. Report raw events + the unbacked-stack ratio in `hk_event_thread_inject.chain_flags` adjacency; **no client thresholding** — the catalog is explicit that the ONNX model weighs rate vs unbacked-stack server-side.
- **Guardrail #1/#4.** All ETW Win32 API (`StartTrace`/`OpenTrace`/`ProcessTrace`/`EVENT_RECORD`) lives only in this `backends/win/` TU. It is userspace and shares no TU with the kernel.

### Userspace enrichment (`ThreadProvenanceWin.cpp`) — signals 22, 23, 24, 25

- **Start mismatch (23).** Compare `ZwQueryInformationThread(ThreadQuerySetWin32StartAddress)` (user-spoofable) against the kernel `kernel_start_address` from the drained `hk_event_thread_create`. Set `HK_PROV_START_MISMATCH` only on the spoof signature: kernel start unbacked while user start in-module (per catalog, *not* the reverse, and modulo the known ntdll `RtlUserThreadStart` shim delta).
- **Entry page (24).** `ZwQueryVirtualMemory(MemoryBasicInformation)` on the start address for `Type`/`AllocationProtect`; `MemoryMappedFilenameInformation` for the backing section. For `MEM_IMAGE`, read the on-disk file at the same RVA and byte-compare the entry page → `entry_page_disk_delta` / `HK_PROV_ENTRY_STOMPED`. `MEM_PRIVATE`/`MEM_MAPPED` RX → `HK_PROV_ENTRY_PRIVATE`. **Reuse the `dma_detect` page-hash helper** rather than re-rolling a hasher; expose it via a small header in `dma_detect/`.
- **WOW64 64-bit start (22).** When the kernel set `HK_THREAD_FLAG_WOW64_TARGET`: `ZwQueryInformationThread(ThreadWow64Context)` and the recorded start; a start > `0xFFFFFFFF` or non-wow64 CS selector → `HK_PROV_WOW64_64BIT_START`. Allowlist the wow64cpu/ntdll transition stubs by image path.
- **HideFromDebugger (25).** `ZwQueryInformationThread(ThreadHideFromDebugger)` (Win10 1607+ returns the flag) → `HK_PROV_HIDE_FROM_DEBUGGER`. Only meaningful as a *co-signal*: emit the flag; the server only treats it as adversarial combined with a non-image start AND not-in-signed-anti-tamper-set.
- **JIT FP suppression (19/24).** Maintain a signed-JIT-host allowlist (CLR, V8, JVM, .NET R2R); set `HK_PROV_JIT_ALLOWLISTED` so the server can discount unbacked-region threads from those hosts. The allowlist is a *report enrichment*, not a client-side drop.
- **Guardrail #13:** every `ZwQueryInformationThread` info class used here is documented-but-versioned (`ThreadHideFromDebugger`, `ThreadWow64Context` readability). Flagged in Risks.

### Server plane (`thread_inject.rs`) — signal 27 scoring + all decode

- Fully async on tokio; decode runs in the existing telemetry ingest task. `thiserror` error variant for short/garbage records (never panic on a malformed wire record — a malformed drained buffer must yield a typed error, not `unwrap()`). No `unwrap()`/`expect()` outside `#[cfg(test)]` (guardrail #8). The rate model and unbacked-stack weighting are features handed to the ban-engine's ONNX path; this module only extracts features, it does not ban.

---

## Build wiring

- **Kernel (`kernel/win/`):** `ThreadProvenance.c` joins the existing driver target in `kernel/win/CMakeLists.txt` / the `.vcxproj`. No new option — thread-origin capture is core to the driver and ships **ON**. Keeps `/INTEGRITYCHECK` (the Ex notify, like the process Ex notify, requires `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY`). Toolchain: WDK + MSVC, same as the rest of `kernel/win`.
- **SDK (`sdk/`):** `EtwTiConsumer.cpp` + `ThreadProvenanceWin.cpp` compile only under the Windows backend selector in `sdk/CMakeLists.txt` (alongside `DriverProbeWin.cpp`), gated by the existing `HK_PLATFORM_WINDOWS` path — never raw `_WIN32` (guardrail #1). New CMake option `HK_WIN_ETWTI` (**default OFF**): the ETW-TI consumer needs a PPL/ELAM-signed host, which dev builds don't have, so it's opt-in until signing lands; the kernel notify plane and the non-ETW enrichment (23/24/25 via the driver record) work **ON** without it. clang or MSVC per the SDK's existing toolchain.
- **dma_detect:** add a `dma_detect/include/.../page_hash.h` exporting the existing page-hash helper so `ThreadProvenanceWin.cpp` links it instead of duplicating; no new option.
- **Server (`server/`):** `thread_inject` module added to `server/telemetry/src/lib.rs`. No new crate, no new dependency (serde + existing decode). Feature-flagged behind nothing — decoding new event types is always compiled; unknown types already degrade gracefully.

---

## Test strategy

### Unit tests

- `event_schema.h`: the new `HK_STATIC_ASSERT` size pins (48/56/40/48) and the re-pinned `hk_event_record == 80` are compile-time gates — they fail the build on any layout drift, on both kernel and userspace sides (already the pattern in `ioctl.h`).
- `thread_inject.rs` (`#[cfg(test)]`): round-trip decode of each record from a fixed byte vector; malformed/short buffer yields the typed error (not a panic); chain-completeness and unbacked-stack-ratio feature extraction over a synthetic event sequence; cross-session and start-mismatch boolean derivation.
- `ThreadProvenanceWin.cpp`: unit-test the start-mismatch decision table (kernel-unbacked/user-in-module → flag; reverse → no flag; agreement-modulo-ntdll-shim → no flag) with injected query results behind a seam, so no live thread is needed.

### Bypass tests (guardrail #12 — merge gate; one per catalog evasion)

Under `bypass-tests/win/thread_origin/`:

- `bypass_manual_map_thread` (19, 24) — manual-mapped injector creates a thread from unbacked private RX; assert `HK_EVENT_THREAD_CREATE` with the creator flagged and `HK_PROV_ENTRY_PRIVATE` emitted; assert a signed-JIT host doing the same is `HK_PROV_JIT_ALLOWLISTED` (no false ban signal).
- `bypass_setcontext_resume` (20) — CreateRemoteThread-suspended / SetThreadContext / ResumeThread and Early-Bird APC sequences; assert the ALLOCVM→SETCONTEXT→RESUME chain is correlated into one `hk_event_thread_inject`; assert a debugger-sourced set-context sets `HK_INJECT_FLAG_SOURCE_DEBUGGER` (reported, not silently dropped).
- `bypass_remote_apc` (21) — `NtQueueApcThreadEx` special-user-APC into the target; assert `hk_event_apc_inject` with `apc_routine` resolved to a non-image region; assert same-process I/O-completion APCs produce no record.
- `bypass_heavens_gate_wow64` (22) — 64-bit shellcode thread in a WOW64 game; assert `HK_PROV_WOW64_64BIT_START`; assert legitimate wow64 transition stubs do not flag.
- `bypass_start_address_spoof` (23) — patch the queryable Win32StartAddress to a benign in-module value while real start is shellcode; assert `HK_PROV_START_MISMATCH` fires from the kernel-vs-user comparison (the userspace-only check would have been fooled).
- `bypass_module_stomp` (24) — overwrite a system-DLL page and start a thread there; assert `HK_PROV_ENTRY_STOMPED` with non-zero `entry_page_disk_delta`; assert a declared-packed game section does not flag.
- `bypass_hide_from_debugger` (25) — thread sets `ThreadHideFromDebugger`; assert `HK_PROV_HIDE_FROM_DEBUGGER` only co-fires with a non-image start (lone benign DRM thread with the flag does not produce an adversarial co-signal).
- `bypass_cross_session_injector` (26) — Session-0 service creates a thread into the interactive game; assert `HK_THREAD_FLAG_CROSS_SESSION`; assert an allowlisted signed Session-0 publisher is distinguishable server-side.
- `bypass_worker_burst` (27) — periodic tick-worker recreation from unbacked stack; assert raw events reported with creator-stack-unbacked set and **no client-side threshold** (the test asserts the client emits per-event, leaving rate scoring to the server).

Each bypass test asserts two things: (a) the sensor *emits the expected record*, and (b) the named evasion is **not silently accepted** (the spoof either flags or is faithfully reported with its FP-gate flag for server adjudication).

---

## Sequencing

1. **Schema + wire first.** Land `event_schema.h` additions, the `HK_EVENT_PAYLOAD_MAX`/record re-pin, `ioctl.h` assert update, and `data-categories.md` rows (guardrail #11) in one PR. Update the kernel `HK_RING` footprint review note. Nothing else compiles correctly until the record size is settled. Gate: static-asserts pass on both build sides.
2. **Kernel notify plane.** `ThreadProvenance.c` + `HkThreadNotifyEx`, swap out the stub in `Notify.c`, declare routines in `horkos_kernel.h`. Emits `hk_event_thread_create` (signals 19-capture / 22-flag / 23-capture / 26). Gate: driver loads with `/INTEGRITYCHECK`, status IOCTL shows the routine armed, DRAIN returns thread-create records.
3. **Server decode.** `thread_inject.rs` decoders + the static round-trip tests. Depends on step 1. Can land in parallel with step 2 (decoding a recorded byte stream).
4. **Userspace enrichment (no ETW-TI).** `ThreadProvenanceWin.cpp` for signals 23/24/25 (and 22 userspace half) driven off drained kernel records. Depends on steps 1–2. `HK_WIN_ETWTI` still OFF. Reuse the `dma_detect` page-hash helper (expose it first).
5. **ETW-TI consumer.** `EtwTiConsumer.cpp` for signals 20/21/27 behind `HK_WIN_ETWTI` (default OFF) — last, because it is blocked on PPL/ELAM signing (Risks). Bring-up path: replay recorded ETW-TI traces in the bypass tests so 20/21/27 are testable before live PPL works.
6. **Bypass-test suite** lands incrementally with each sensor (a sensor PR without its bypass test is rejected by guardrail #12).

---

## Risks & UNCERTAINTY FLAGS

**Flagged for confirmation before writing kernel/ETW code (guardrail #13):**

- **`PsSetCreateThreadNotifyRoutineEx` + `PS_CREATE_THREAD_NOTIFY_INFO`.** I am **not certain** the Ex thread-create notify exists with the `StartAddress`-bearing `PS_CREATE_THREAD_NOTIFY_INFO` on all supported Windows builds, nor of the exact struct field layout. The process-create Ex variant is well established; the *thread*-create Ex is the load-bearing assumption for signals 19/23 and must be verified against the target WDK. If it does not exist as assumed, signal 23's spoof-resistant kernel start capture has no sanctioned source and the design changes — **STOP and confirm.**
- **ETW-TI access / PPL / ELAM.** The `Microsoft-Windows-Threat-Intelligence` provider only emits to a PPL anti-malware-signed consumer (ELAM registration + AM cert). I am **not certain** of the exact protected-signer level, the registration sequence, or whether a real-time trace session vs. a different consumer API is the supported route. This blocks signals 20/21/27 in production; hence `HK_WIN_ETWTI` defaults OFF and bring-up uses replayed traces. **Signing/EKU is exactly the kind of requirement CLAUDE.md says not to guess on — confirm.**
- **`ThreadHideFromDebugger` / `ThreadWow64Context` readability.** `ThreadHideFromDebugger` is readable from Win10 1607+; `ThreadWow64Context` query semantics are version-sensitive. Confirm the exact info-class behavior on the target build before relying on the read for signals 22/25.
- **Ring footprint blowup.** Growing `HK_EVENT_PAYLOAD_MAX` 16→56 doubles+ the record (40→80 B) and the non-paged-pool ring (160 KB → 320 KB at capacity 4096). Non-paged pool is a constrained resource; review whether to (a) accept it, (b) shrink `HK_RING_CAPACITY`, or (c) split thread-origin records into a separate, smaller-capacity ring. **Decision needed at step 1 review.**
- **Module-stomping on-disk byte compare (24).** Reading the on-disk image at an RVA and comparing to mapped bytes has inherent FPs from legitimate self-modifying DRM (VMProtect/Themida/Denuvo) and hot-patch/Detours trampolines. The catalog's mitigation (signed module manifest of known-packed sections; only flag system DLLs the game never rewrites) is a **policy dependency** not yet built — without the manifest, signal 24 is medium-FP and should report-only, never auto-ban. Server-side adjudication is mandatory.
- **Signed-publisher / overlay / JIT allowlists** (signals 19/20/26 FP gates) are data dependencies (signed-overlay allowlist, Session-0 publisher allowlist, JIT-host allowlist). They live server-side; the client reports the raw flag. If these lists are absent, the affected signals are higher-FP and must remain report-only. Not a code blocker, but a correctness dependency to track.
- **Stack-walk on thread-create (27).** ETW-TI create-event stack-walk availability and depth are not guaranteed; if unavailable, signal 27 degrades to rate-only (weaker, per the catalog's own FP note). Confirm with the ETW-TI work in step 5.
