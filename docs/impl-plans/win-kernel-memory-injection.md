# Windows Kernel — Memory Injection & Image Anomalies

Scope: read-only kernel sampling of process address space (VAD tree, PTEs,
loader lists, image-section backing, thread/TLS origins) to surface
manually-mapped / stomped / hollowed / unbacked-executable code that the
existing `PsSet*NotifyRoutine` event plane never sees. The kernel emits raw
evidence; **all verdicts are server-side** (clients sample + report only).

Covers catalog signals **10–18**:

| # | Signal | Event |
|---|---|---|
| 10 | Unbacked executable VAD (no ControlArea) | `HK_EVENT_MEM_UNBACKED_EXEC` |
| 11 | PTE/VAD protection divergence (W^X flip) | `HK_EVENT_MEM_WX_DIVERGENCE` |
| 12 | On-disk vs in-memory .text mismatch (stomp) | `HK_EVENT_MEM_MODULE_STOMP` |
| 13 | Image VAD absent from PEB loader list (ghost) | `HK_EVENT_MEM_GHOST_IMAGE` |
| 14 | Oversized private executable commit | `HK_EVENT_MEM_PRIV_EXEC_COMMIT` |
| 15 | Large-page / VAD-rotate executable region | `HK_EVENT_MEM_EXOTIC_VAD` |
| 16 | Image VAD section-name vs path mismatch (hollow/doppelgang) | `HK_EVENT_MEM_HOLLOW_BACKING` |
| 17 | Entry-point / TLS-callback outside image VAD | `HK_EVENT_MEM_EXEC_ORIGIN_ANON` |
| 18 | Section backing file lacks signing/EKU provenance | `HK_EVENT_MEM_UNSIGNED_IMAGE` |

> **Structural decision that drives the whole plan.** All nine signals require
> attaching to a target with `KeStackAttachProcess` and walking *pageable*
> structures (VAD AVL tree, PEB, PTEs, on-disk file maps). That is
> **PASSIVE_LEVEL, single-threaded worker** work — NOT the DISPATCH_LEVEL
> notify-callback context that `Notify.c` / `Callbacks.c` run in. The existing
> ring producers (`HkRingEmit`) are `_IRQL_requires_max_(DISPATCH_LEVEL)`;
> none of the scan code may run there. The scan plane therefore lives in its
> own system worker thread (§4) and never shares a TU with the notify
> producers. Additionally these payloads carry hashes, ~260-char paths, diff
> RVAs and sizes — far larger than today's `HK_EVENT_PAYLOAD_MAX = 16`. Both
> facts are resolved in §3 (a second, large-record wire plane).

---

## New files

All new kernel TUs are Windows-kernel-only under `kernel/win/src/` (guardrail
#1: platform code stays in the platform tree; conditional code uses
`HK_PLATFORM_WINDOWS`, never raw `_WIN32`). Every file carries the mandated
module comment (guardrail #3). Kernel scan TUs never `#include` a userspace TU
and share only the pure-C99 wire headers (guardrail #4).

| Path | Role | Module-comment summary |
|---|---|---|
| `kernel/win/src/MemScanWorker.c` | Scan orchestrator: a system worker thread at PASSIVE_LEVEL, per-target attach/detach lifetime, scan cadence/budget, dispatch into the per-signal scanners, and the large-record emit path. | Win kernel mode (KMDF). Implements `HkMemScanArm/Disarm/EnqueueTarget` (declared in `mem_scan.h`); drives signals 10–18; asserts PASSIVE_LEVEL on entry. |
| `kernel/win/src/VadWalk.c` | Shared read-only VAD AVL-tree walk from `EPROCESS.VadRoot` while attached; yields a normalized `HK_VAD_NODE` per leaf. Single source of VAD traversal for signals 10,13,14,15,16. | Win kernel mode. Implements `HkVadEnumerate` (`mem_scan.h`). Read-only; layout via `vad_layout.h`. |
| `kernel/win/src/MemScanVad.c` | Signals **10**, **14**, **15**: classifies each `HK_VAD_NODE` — unbacked +X (10), private-exec commit size + aggregate (14), exotic VadType / large-page +X (15). | Win kernel mode. Consumes `HkVadEnumerate`; emits `HK_EVENT_MEM_UNBACKED_EXEC`, `_PRIV_EXEC_COMMIT`, `_EXOTIC_VAD`. |
| `kernel/win/src/MemScanPte.c` | Signal **11**: for committed pages of a VAD resolve the leaf PTE NX bit and compare against the VAD-declared protection mask. | Win kernel mode. Emits `HK_EVENT_MEM_WX_DIVERGENCE`. Sampled, not hot-polled. |
| `kernel/win/src/LdrCrosscheck.c` | Signal **13**: cross-reference image VADs against the three PEB `Ldr` lists; flag image +X VADs with no loader entry. Skips processes in exit. | Win kernel mode. Emits `HK_EVENT_MEM_GHOST_IMAGE`. |
| `kernel/win/src/ModuleStomp.c` | Signal **12** (and feeds **18**): map each signed module's backing file, normalize relocs + zero IAT thunks, diff code sections vs the live mapping; emit first-diff RVA + section hash. Also stages backing path+hash for the userspace signing verdict (18). | Win kernel mode. Emits `HK_EVENT_MEM_MODULE_STOMP`; stages evidence for `HK_EVENT_MEM_UNSIGNED_IMAGE`. |
| `kernel/win/src/HollowDetect.c` | Signal **16**: compare image-VAD `FILE_OBJECT` name vs Ldr-recorded path; probe `DeletePending`/transaction state of the backing. | Win kernel mode. Emits `HK_EVENT_MEM_HOLLOW_BACKING`. |
| `kernel/win/src/ExecOrigin.c` | Signal **17**: resolve each thread's Win32 start address and each module's TLS callbacks, map them through the VAD tree, flag anon/unbacked targets. | Win kernel mode. Emits `HK_EVENT_MEM_EXEC_ORIGIN_ANON`; correlates with the existing thread-notify path. |
| `kernel/win/include/mem_scan.h` | Kernel-private scan-plane interface: `HK_VAD_NODE`, scanner entry points, worker lifetime. NOT userspace-visible. | Win kernel mode header. Declares the scan worker + per-signal scanners; included only by kernel scan TUs. |
| `kernel/win/include/vad_layout.h` | **Versioned, documented struct-offset table** for `_MMVAD`/`_MMVAD_SHORT`/`_SUBSECTION`/`_CONTROL_AREA`/`_PEB_LDR_DATA`/`_LDR_DATA_TABLE_ENTRY`/`_ETHREAD` start-address, keyed by OS build, with a runtime build-gate. The one place undocumented layout lives, fenced behind a build allow-list (§8). | Win kernel mode header. Per-build offset constants; every offset cites its public-symbol/RE source. |
| `sdk/src/backends/win/ImageSigningWin.cpp` | Signal **18** userspace half: take the kernel-shipped backing path+hash, compute a `WinVerifyTrust` signer verdict, ship `HK_EVENT_MEM_UNSIGNED_IMAGE`. Only place the SDK touches `wintrust.h`. | Windows userspace. Implements `hk::sdk::verify_image_signing` (`sdk_backend.h`); guardrail #1 — Win32 confined to `backends/win`. |
| `server/telemetry/src/mem_events.rs` | Phase-2 serde mirror of the new memory-event wire structs; `#[serde(...)]` field names + sizes match `event_schema.h`; deserialized in the ban-engine ingest path. | Rust, tokio server. Mirrors the `hk_event_mem_*` structs; no `unwrap()` outside tests (guardrail #8). |
| `bypass-tests/win/manual_map_scan.cpp` | Merge-gate bypass test (guardrail #12) for signals 10/13/16/17: a fixture that manual-maps a benign DLL and asserts the scan plane raises the right events. | Windows only (built behind `if(WIN32)`). Consumes `sdk/include/horkos/ioctl.h` + the large-record drain. |
| `bypass-tests/win/module_stomp_scan.cpp` | Merge-gate bypass test (guardrail #12) for signals 11/12: stomp a benign module's `.text` and W^X-flip a region; assert `MODULE_STOMP` + `WX_DIVERGENCE` fire with correct first-diff RVA. | Windows only. |

---

## Interfaces & data structures

### 3.1 New wire plane for large records

The current ring is an array of fixed 40-byte `hk_event_record` (24-byte header
+ 16-byte payload). Memory-scan payloads exceed 16 bytes. **Do not widen
`HK_EVENT_PAYLOAD_MAX`** — that would bloat the 4096-slot ring 8–16× and break
every existing `HK_STATIC_ASSERT`. Instead add a *second* fixed-size record
type sized to the largest memory payload, drained via a new IOCTL. Both record
families keep the shared `hk_event_header` so the server demuxes on
`header.type`.

New constant + record in `sdk/include/horkos/ioctl.h`:

```c
#define HK_EVENT_MEM_PAYLOAD_MAX 320u  /* fits hk_event_mem_module_stomp (largest). */

typedef struct hk_event_mem_record {
    hk_event_header header;                        /* 24 bytes (shared). */
    uint8_t         payload[HK_EVENT_MEM_PAYLOAD_MAX];
} hk_event_mem_record;                             /* 344 bytes. */

HK_STATIC_ASSERT(sizeof(hk_event_mem_record) == 344, "hk_event_mem_record wire size drift");
```

A separate smaller ring (`HK_MEM_RING_CAPACITY 256u`, power of two) holds these
so the big slots don't dominate the device context. New IOCTL + scan trigger:

```c
#define HK_IOCTL_DRAIN_MEM_EVENTS \
    HK_CTL_CODE(HK_FILE_DEVICE_UNKNOWN, 0x803, HK_METHOD_BUFFERED, HK_FILE_ANY_ACCESS)
#define HK_IOCTL_SCAN_PROCESS \
    HK_CTL_CODE(HK_FILE_DEVICE_UNKNOWN, 0x804, HK_METHOD_BUFFERED, HK_FILE_ANY_ACCESS)

typedef struct hk_scan_request {     /* HK_IOCTL_SCAN_PROCESS input */
    uint32_t target_pid;
    uint32_t signal_mask;            /* bit per signal 10..18; 0 = all enabled. */
    uint32_t flags;                  /* reserved (e.g. force-resample). */
    uint32_t reserved;
} hk_scan_request;
HK_STATIC_ASSERT(sizeof(hk_scan_request) == 16, "hk_scan_request wire size drift");
```

`HK_IOCTL_DRAIN_MEM_EVENTS` reuses the existing `hk_drain_header` envelope but
strides `hk_event_mem_record`. `HkHandleDrain` in `IrpDispatch.c` is
parameterized by record size + ring pointer; a thin `HkHandleMemDrain` calls it
against the mem ring. `HK_IOCTL_SCAN_PROCESS` validates the PID and calls
`HkMemScanEnqueueTarget` (returns immediately; the worker does the attach).

### 3.2 New event types (appended in `event_schema.h`; bump schema → v3)

```c
/* appended to hk_event_type — existing values never change */
HK_EVENT_MEM_UNBACKED_EXEC    = 5,
HK_EVENT_MEM_WX_DIVERGENCE    = 6,
HK_EVENT_MEM_MODULE_STOMP     = 7,
HK_EVENT_MEM_GHOST_IMAGE      = 8,
HK_EVENT_MEM_PRIV_EXEC_COMMIT = 9,
HK_EVENT_MEM_EXOTIC_VAD       = 10,
HK_EVENT_MEM_HOLLOW_BACKING   = 11,
HK_EVENT_MEM_EXEC_ORIGIN_ANON = 12,
HK_EVENT_MEM_UNSIGNED_IMAGE   = 13,

#define HK_EVENT_SCHEMA_VERSION 3u   /* was 2u */
```

Payload structs (all begin pid + region base/size so the server can correlate
regions across signals; sizes pinned by `HK_STATIC_ASSERT`). Sketch of the
non-obvious / largest ones:

```c
/* Common region descriptor reused by 10,14,15. 32 bytes. */
typedef struct hk_mem_region {
    uint32_t pid;
    uint32_t vad_type;          /* normalized VadType enum (VadNone/Awe/...). */
    uint64_t region_base;       /* StartingVpn << PAGE_SHIFT. */
    uint64_t region_size;       /* (EndingVpn-StartingVpn+1) << PAGE_SHIFT. */
    uint32_t protection;        /* MM_EXECUTE* mask, normalized. */
    uint32_t flags;             /* unbacked / large-page / has-jit-owner bits. */
} hk_mem_region;
HK_STATIC_ASSERT(sizeof(hk_mem_region) == 32, "hk_mem_region wire size drift");

/* Signal 11 — W^X divergence. 40 bytes. */
typedef struct hk_event_mem_wx {
    hk_mem_region region;       /* 32 */
    uint32_t vad_says_exec;     /* 0/1 from VAD protection. */
    uint32_t pte_says_exec;     /* 0/1 from live PTE NX bit. */
} hk_event_mem_wx;

/* Signal 12 — module stomp. Largest payload (drives HK_EVENT_MEM_PAYLOAD_MAX). */
typedef struct hk_event_mem_module_stomp {
    uint32_t pid;
    uint32_t first_diff_rva;    /* RVA of first unexplained code byte. */
    uint64_t image_base;
    uint8_t  live_section_sha256[32];
    uint8_t  disk_section_sha256[32];
    uint16_t module_path_len;
    uint16_t section_name_len;
    uint8_t  module_path[208];  /* UTF-16→UTF-8 path, truncated; len above. */
    uint8_t  section_name[8];   /* e.g. ".text". */
} hk_event_mem_module_stomp;    /* <= 320 bytes; pins HK_EVENT_MEM_PAYLOAD_MAX. */

/* Signal 18 — unsigned image (kernel ships path+hash; userspace fills verdict). */
typedef struct hk_event_mem_unsigned_image {
    uint32_t pid;
    uint32_t signer_verdict;    /* HK_SIGN_* (filled by userspace WinVerifyTrust). */
    uint64_t image_base;
    uint8_t  file_sha256[32];
    uint16_t path_len;
    uint16_t reserved;
    uint8_t  file_path[208];
} hk_event_mem_unsigned_image;
```

Signals **13 / 16 / 17** reuse `hk_event_mem_unsigned_image`-style
{pid, base, path, flags} shapes (ghost image: base+path; hollow: base + a
backing-state bitmask for delete-pending/transacted/name-mismatch; exec-origin:
thread-id + start-address + resolved-vad-type). `HK_STATIC_ASSERT` pins each.

`signer_verdict` enum (`HK_SIGN_UNKNOWN/UNSIGNED/SELF/UNTRUSTED/TRUSTED`) is
the only field the kernel leaves zero and userspace fills before the record
reaches the server.

### 3.3 Guardrail #11 — every new telemetry field needs `data-categories.md`

The same PR that lands these structs **must** add to
`server/api/data-categories.md` a new category **"5. Memory & image anomalies
(Windows kernel scan)"** declaring each new field with source / retention /
legal basis / operator-of-record, mirroring the existing categories. Fields to
declare: `vad_type`, `region_base`, `region_size`, `protection`,
`region_flags`, `first_diff_rva`, `live_section_sha256`, `disk_section_sha256`,
`module_path`, `section_name`, `pte_says_exec`/`vad_says_exec`,
`file_sha256`, `file_path`, `signer_verdict`, `thread_start_address`,
`backing_state`. Reviewer rejects the PR if any field is undeclared.

The Rust mirror (`server/telemetry/src/mem_events.rs`) and the canonical
cross-reference line in `data-categories.md` ("Wire format source of truth:
`event_schema.h`") both apply.

---

## Mechanism implementation notes

### Scan plane lifetime & IRQL (applies to all signals)

- The worker is a `PsCreateSystemThread` thread (or a KMDF passive-level work
  item / `IoQueueWorkItem` with `DelayedWorkQueue`). It runs at **PASSIVE_LEVEL**
  exclusively. `HkMemScanWorker` asserts `KeGetCurrentIrql() == PASSIVE_LEVEL`
  on entry. The notify producers stay where they are — they only enqueue a PID
  (a non-blocking ring of pending targets) and never attach.
- Per target: take a **reference** on the EPROCESS via `PsLookupProcessByProcessId`
  (checked `NTSTATUS`), confirm not exiting (skip if exit),
  `KeStackAttachProcess`, do **all** reads, then `KeUnstackDetachProcess` and
  `ObDereferenceObject`. Attach/detach must be strictly paired on every exit
  path including error returns (guardrail #5: every kernel return checked; no
  early-return that skips detach).
- Reads of pageable target memory at PASSIVE_LEVEL can fault — wrap target-VA
  reads in `__try/__except` (SEH) or validate with `MmIsAddressValid`-class
  guards; a torn-down VAD during the walk must degrade to "skip node", never a
  bugcheck. **Do not** touch target memory at raised IRQL.
- Cadence: event-driven (scan on new-process / new-thread / suspicious image
  load) plus a slow round-robin resample. Budget per scan tick so a 10k-VAD
  process cannot monopolize the worker.

### Per-signal notes (real APIs from the catalog)

- **10 Unbacked +X VAD** (`MemScanVad.c`): walk `EPROCESS.VadRoot` AVL tree;
  per leaf read `VadType` and `Subsection->ControlArea->FilePointer`; flag
  leaves whose protection includes `MM_EXECUTE` / `MM_EXECUTE_READ` /
  `MM_EXECUTE_READWRITE` with NULL ControlArea/FilePointer. JIT gate: set a
  `has_jit_owner` flag if the region falls inside a loaded CLR/V8/Chakra/JVM
  module's owned range (server decides; kernel only annotates).
- **11 W^X divergence** (`MemScanPte.c`): after the VAD walk, for committed
  pages resolve the leaf PTE and read the NoExecute (NX) bit; compare against
  the VAD protection mask. Use the **documented** `MmGetPhysicalAddress` per
  sampled page. **Sample, do not hot-poll** — racing a legitimate
  `VirtualProtect` produces FPs. See §8 uncertainty flag on PTE translation.
- **12 Module stomp** (`ModuleStomp.c`): enumerate loaded modules via the PEB
  `Ldr` `InLoadOrderModuleList` (`PsGetProcessSectionBaseAddress` for the main
  image base). For each signed module, map the on-disk backing with
  `ZwCreateSection` + `ZwMapViewOfSection`, normalize relocations via
  `IMAGE_BASE_RELOCATION` (`IMAGE_DIRECTORY_ENTRY_BASERELOC`), zero IAT thunks
  (`IMAGE_DIRECTORY_ENTRY_IMPORT`/IAT), then SHA-256-compare each code section
  against the live mapping read while attached. **Emit raw first-diff RVA +
  both hashes — never a verdict** (FP risk is high: hotpatch, Detours overlays,
  Discord/Steam/RTSS). The relocation+IAT+/hotpatch-pad model must be exact.
- **13 Ghost image** (`LdrCrosscheck.c`): collect image VADs (non-NULL
  FilePointer + section name) from the walk; collect entries from all three
  `PEB.Ldr` lists (InLoadOrder/InMemoryOrder/InInitializationOrder); flag any
  image VAD whose base/path is in none. Require fully-committed +X and
  **skip processes in exit** (loader teardown races).
- **14 Oversized private +X commit** (`MemScanVad.c`): during the same walk sum
  committed bytes of private (`VadNone`) EXECUTE regions; emit per-region size
  and the process-wide aggregate. **Ship the number; no hard kernel threshold**
  — the server model baselines per title.
- **15 Exotic VAD** (`MemScanVad.c`): branch on `VadType`
  (`VadRotatePhysical` / `VadAwe` / `VadLargePages`) and the large-page flag in
  the MMVAD flags word; flag any with EXECUTE not owned by a signed
  graphics/AWE module. Strong signal — games lack `SeLockMemoryPrivilege`.
- **16 Hollow/doppelgang backing** (`HollowDetect.c`): read
  `ControlArea->FilePointer->FileName` and `FILE_OBJECT` flags; cross-check
  against the Ldr-recorded path; probe backing via `ZwQueryInformationFile`
  `FILE_STANDARD_INFORMATION` `DeletePending` + transaction state. Gate on
  EXECUTE + entry-point region + delete-pending/transacted **together**.
- **17 Exec origin anon** (`ExecOrigin.c`): read each thread's Win32 start
  address via the documented `ThreadQuerySetWin32StartAddress` path, and each
  module's `IMAGE_TLS_DIRECTORY` `AddressOfCallBacks`; map each target through
  the VAD tree; flag anon/unbacked resolutions. Correlate with signal 10 +
  JIT-owner attribution before the *server* alerts.
- **18 Unsigned image** (`ModuleStomp.c` kernel → `ImageSigningWin.cpp`
  userspace): kernel captures `FilePointer->FileName` + the file SHA-256 and
  emits with `signer_verdict = HK_SIGN_UNKNOWN`. The in-kernel `ci.dll` path
  (`CiCheckSignedFile` / `SeCodeIntegrityQueryInformation`) is **flagged
  uncertain** (§8); the bring-up path computes the verdict in **userspace** via
  `WinVerifyTrust` and overwrites `signer_verdict` before forwarding.
  Provenance enrichment only — never a standalone ban.

### Server (tokio) notes

- `mem_events.rs` deserializes each `hk_event_mem_*` with `thiserror` error
  types; **no `unwrap()` outside tests** (guardrail #8). Variable-length
  fields (`*_len` + fixed buffer) are bounds-checked before slicing — a
  truncated/oversized `path_len` is a typed `MemEventError`, not a panic.
- Ingest is fully async on the existing axum/tokio path; SHA-256 comparison is
  offloaded with `spawn_blocking` so it never blocks an async worker thread.

---

## Build wiring

- **`kernel/win/CMakeLists.txt`**: append the new TUs to `HK_DRIVER_SRC`
  (`MemScanWorker.c VadWalk.c MemScanVad.c MemScanPte.c LdrCrosscheck.c
  ModuleStomp.c HollowDetect.c ExecOrigin.c`). Same `/kernel /GS /W4 /WX`,
  `/INTEGRITYCHECK`, `/NODEFAULTLIB` flags as today. The `.vcxproj` stays the
  production source of truth (add the same files there).
- **Feature flag**: gate the scan plane behind a CMake option
  `HK_ENABLE_MEM_SCAN` (compile define `HK_MEM_SCAN`) — **default ON** on
  Windows. The per-build offset table (`vad_layout.h`) is itself gated by
  `HK_VAD_LAYOUT_BUILD_ALLOWLIST`; if the running OS build is not in the
  allow-list the worker stays armed but **refuses to dereference layout-
  dependent offsets** and emits only the layout-independent signals (§8).
- **`sdk/CMakeLists.txt`**: add `ImageSigningWin.cpp` to the Windows backend
  source list (behind the existing `if(WIN32)` branch) and link `wintrust.lib`.
- **`server/telemetry`**: add the `mem_events` module; `cargo` only, no new
  crate.
- **`bypass-tests/win/CMakeLists.txt`**: add `manual_map_scan` and
  `module_stomp_scan` targets, behind `if(WIN32)`, disabled-by-default like
  `byovd_load` (`HK_MEMSCAN_TEST_ENABLED` define gates the live body).
- Toolchain: WDK (matching installed SDK) for the driver; MSVC for the SDK
  backend; stable Rust + tokio for the server.

---

## Test strategy

### Unit tests (logic under TDD where testable — guardrail #14)

- **Pure-logic, host-buildable** (no kernel): factor the FP-free decision logic
  out of the kernel TUs into pure functions fed synthetic `HK_VAD_NODE` / PE
  fixtures, tested on the host:
  - VAD classifier (10/14/15): unbacked-+X detection, private-exec sum,
    exotic-VadType branch, JIT-owner gating.
  - Reloc/IAT normalizer (12): a crafted PE with relocations + IAT must diff
    **clean** against its relocated image; a single stomped byte must yield the
    correct `first_diff_rva`.
  - Ldr cross-check (13) and path/name compare (16) against synthetic list +
    FILE_OBJECT-name fixtures.
- **`server/telemetry`**: serde round-trip + bounds-check tests for every
  `hk_event_mem_*` struct, including malicious `*_len` values (must error, not
  panic). `cargo test`.
- **Wire pins**: the new `HK_STATIC_ASSERT`s compile-fail on any struct drift
  across kernel + userspace + tests (the existing Step-3.5 mechanism).

### Bypass tests (merge gate — guardrail #12)

Any change under `kernel/win/` (a security folder) requires a corresponding
bypass test. Two new fixtures, disabled-by-default (compile now, assert when
`HK_MEMSCAN_TEST_ENABLED` lands with the signed fixture harness):

- **`bypass-tests/win/manual_map_scan.cpp`** — manual-maps a benign signed DLL
  into a victim test process **without** `LdrLoadDll` (raw `NtCreateSection` +
  `NtMapViewOfSection`, plus a private-commit shellcode-stub variant), starts a
  thread in the mapped region, drains `HK_IOCTL_DRAIN_MEM_EVENTS`, and asserts:
  signal 10 (unbacked +X) for the private variant, signal 13 (ghost image) for
  the section-mapped variant, signal 17 (exec origin anon) for the thread, and
  signal 16 if the backing is deleted post-map. Demonstrates the scanner sees
  what `PsSetLoadImageNotifyRoutine` does not.
- **`bypass-tests/win/module_stomp_scan.cpp`** — overwrites a benign loaded
  module's `.text` (module stomping) and separately RW→RX-flips a region;
  asserts signal 12 fires with the correct `first_diff_rva`, that a pure
  relocation/IAT diff does **not** fire (FP guard), and signal 11 fires on the
  W^X flip. Demonstrates the reloc/IAT normalizer's FP resistance.

A negative/FP-suite fixture (CLR or V8 JIT host) asserts the kernel sets
`has_jit_owner` and the **server** does not alert — proving the
"kernel emits, server decides" contract.

---

## Sequencing

1. **Wire + schema first** (no logic): `event_schema.h` v3 types + structs,
   `ioctl.h` new records/IOCTLs/asserts, `data-categories.md` category 5,
   `mem_events.rs` mirror + serde tests. Lands green with all static asserts.
   Unblocks kernel and server work in parallel.
2. **Scan-plane skeleton**: `mem_scan.h`, `MemScanWorker.c` (worker lifetime,
   attach/detach, enqueue), the second ring + `HK_IOCTL_DRAIN_MEM_EVENTS` /
   `HK_IOCTL_SCAN_PROCESS` in `IrpDispatch.c`. Emits nothing yet; testable that
   attach/detach is balanced and the drain IOCTL round-trips empty.
3. **`vad_layout.h` + `VadWalk.c`**: the shared read-only walk + build-allow-list
   gate. Dependency for 10/13/14/15/16/17 — land before any classifier.
4. **Walk-based signals**: 10, 14, 15 (`MemScanVad.c`); then 13
   (`LdrCrosscheck.c`), 16 (`HollowDetect.c`), 17 (`ExecOrigin.c`).
5. **Heavier signals**: 12 (`ModuleStomp.c`, reloc/IAT model — most FP-prone),
   then 11 (`MemScanPte.c`, PTE translation — most API-uncertain), then 18
   (kernel hash capture + `ImageSigningWin.cpp` `WinVerifyTrust` verdict).
6. **Bypass tests + FP suite** activate alongside the signed fixture harness.

Dependencies: everything after step 1 needs the wire plane; everything
VAD-based needs step 3; signal 18 needs signal 12's path/hash capture.

---

## Risks & UNCERTAINTY FLAGS

Per guardrail #13 the following are **flagged, not guessed** — confirm against
current WDK docs / a kernel reviewer before code lands. Each is fenced behind
`vad_layout.h`'s build allow-list so an unverified build fails **closed** rather
than dereferencing a wrong offset (a BSOD risk):

- **UNCERTAIN — MMVAD / EPROCESS internal layout.** `_MMVAD`, `_MMVAD_SHORT`,
  `StartingVpn`/`EndingVpn`, `VadType`, the MMVAD flags word,
  `Subsection->ControlArea->FilePointer`, and `EPROCESS.VadRoot` are **not
  stable documented ABI**; offsets shift across Windows builds. Single biggest
  BSOD risk. Mitigation: per-build offset table, runtime build-gate allow-list,
  SEH-guarded reads, fail-closed on unknown builds. **Confirm offsets per
  target build before enabling.**
- **UNCERTAIN — leaf-PTE / NX-bit translation (signal 11).** Deriving the leaf
  PTE (`MiGetPteAddress`-equivalent) relies on the non-exported, build-varying
  PTE_BASE. Prefer documented `MmGetPhysicalAddress` per sampled page over a
  hand-rolled PTE walk. Confirm the NX-bit read is reachable through a
  documented path on the target builds; if not, signal 11 ships sampled-only or
  is deferred.
- **UNCERTAIN — `KeStackAttachProcess` read safety at scale.** Faulting on a
  concurrently-torn-down VAD or paged-out target memory at PASSIVE_LEVEL.
  Mitigation: SEH around every target read, EPROCESS reference held across the
  whole attach window, skip exiting processes. Confirm the SEH + reference
  pattern with a kernel reviewer before enabling on a populated machine.
- **UNCERTAIN — in-kernel signing path (signal 18).** `CiCheckSignedFile` /
  `SeCodeIntegrityQueryInformation` are **not cleanly documented public kernel
  APIs**. Bring-up uses userspace `WinVerifyTrust`; the in-kernel path stays a
  flagged TODO, not shipped on a guess.
- **UNCERTAIN — `ETHREAD` start-address offset (signal 17).** Prefer the
  documented `ZwQueryInformationThread(ThreadQuerySetWin32StartAddress)` over
  the raw `ETHREAD` field; the raw field is build-varying and goes in
  `vad_layout.h` only if the documented path is unavailable from the worker.
- **FP risk (server-side, not BSOD):** signal 12 (high — hotpatch / Detours /
  overlay injectors), signals 10/11/14/17 (medium — JIT). The kernel ships raw
  evidence + `has_jit_owner` annotations only; **no client-side ban**. The
  per-title baseline + allow-list (Discord/Steam/RTSS, CLR/V8/JVM hosts) lives
  in the server model.
- **`ZwCreateSection`/`ZwMapViewOfSection` file-mapping (signal 12):** confirm
  handle lifetime and that mapping a game-owned file from the system-worker
  context raises no sharing-violation or self-DoS before enabling broadly. The
  driver already builds `/INTEGRITYCHECK`; the scan plane adds no new signing
  requirement.