# Client Self-Integrity — Memory-Integrity Self-Check

Scope: read-only verification that the **Horkos AC binary's own image** (.text,
.rdata, IAT/GOT, unwind/VEH tables, TLS/init-array, loader structures, page
protections, debug registers) is unmodified at runtime. Each signal is a
self-sampling sensor: the AC reads its *own* image three ways (in-process VA,
kernel-side foreign read, on-disk file) and ships the divergence as raw
evidence. **No verdict on the client — all ban authority is server-side; the
client samples + reports only.** The kernel driver supplies a foreign,
non-spoofable read of the AC's address space; the AC never trusts its own
in-process view alone.

Covers catalog signals **145–153**:

| # | Signal | Event |
|---|---|---|
| 145 | Cross-view .text hash divergence (VA vs section-object vs disk) | `HK_EVENT_SELF_CROSSVIEW` |
| 146 | Per-page Dirty/CoW bit audit on read-only code pages | `HK_EVENT_SELF_PAGE_COW` |
| 147 | Return-address provenance / shadow-stack mismatch at our entry points | `HK_EVENT_SELF_RETADDR` |
| 148 | DR0–DR7 hardware-breakpoint audit across our threads (kernel context) | `HK_EVENT_SELF_HWBP` |
| 149 | IAT / delay-IAT resolution-target signature audit | `HK_EVENT_SELF_IAT_TARGET` |
| 150 | Exception/VEH & unwind-table hijack audit | `HK_EVENT_SELF_VEH_UNWIND` |
| 151 | Loader-structure consistency (LDR vs section object vs disk) | `HK_EVENT_SELF_LOADER` |
| 152 | Self-image W^X / PTE protection-drift audit | `HK_EVENT_SELF_WX_DRIFT` |
| 153 | TLS-callback & static-initializer table integrity | `HK_EVENT_SELF_TLS_INIT` |

> **Structural decisions that drive the whole plan.**
>
> 1. **The header the catalog names does not exist yet.** The catalog slots
>    reference `ac/include/horkos/selfcheck.h`; today only `ac/include/horkos/ac.h`
>    exists. This plan *creates* `selfcheck.h` as the new self-check interface
>    header and leaves `ac.h` as the public C surface (guardrail #10 spirit:
>    a stable interface, backends behind it).
> 2. **This is a userspace-primary domain.** The authoritative read of our own
>    image is the *kernel-side foreign read* of our VA (signals 145/146/148/152),
>    but the orchestration, PE/ELF/Mach-O parsing, IAT/VEH/TLS walks, and hashing
>    all live in the AC userspace TU (`ac/src/selfcheck/*`). The kernel adds one
>    new IOCTL family: "read these VA ranges of *the calling AC process* and
>    return bytes / page-share state / PTE bits / debug registers." It never
>    decides anything.
> 3. **Self-read must be cross-checked, never trusted alone.** Every byte-hash
>    signal (145) is meaningless if a hooked `NtReadVirtualMemory` lies on
>    self-read. The whole point is that the kernel foreign read (145 path B) and
>    the page-share / PTE / DR reads (146/148/152) **cannot be restored-on-read**
>    by a usermode hook, so they catch what self-hashing alone misses.
> 4. **New payloads exceed `HK_EVENT_PAYLOAD_MAX = 16`** (hashes, RVAs, module
>    paths, per-frame stacks). We reuse the **large-record wire plane** introduced
>    by `win-kernel-memory-injection.md` (`hk_event_mem_record`,
>    `HK_IOCTL_DRAIN_MEM_EVENTS`) rather than widening the 40-byte ring. If that
>    plan has not yet landed, this plan introduces the same large-record plane;
>    they must converge on **one** `HK_EVENT_MEM_PAYLOAD_MAX` (see §3.1).
> 5. **Obfuscation opt-in (guardrail #9).** Signal 147 entry guards and the
>    self-check init path are exactly the init/integrity/attestation symbols that
>    `__attribute__((annotate("hk_obfuscate")))` is *for*. The hot game loop is
>    never touched.

---

## New files

All userspace self-check TUs live under `ac/src/selfcheck/` and compile into the
existing `hk_ac` static library. Platform-specific reads route through
`platform/` backends or an `HK_PLATFORM_*` branch (guardrail #1 — never raw
`_WIN32`/`__linux__`/`__APPLE__`). Every file carries the mandated module
comment (guardrail #3). Userspace self-check TUs never `#include` a kernel TU and
share only the pure-C99 wire headers (guardrail #4).

| Path | Role | Module-comment summary |
|---|---|---|
| `ac/include/horkos/selfcheck.h` | The stable self-check interface the catalog names. Declares `hk::selfcheck` orchestrator (`SelfCheck::arm/run_once/report`), the per-signal sensor entry points, and the `HK_GUARD_ENTRY` macro for signal 147. Backends change; this header does not (guardrail #10). | Cross-platform C++ header. Declares the self-integrity sensor surface implemented across `ac/src/selfcheck/*`; included by `ac.cpp` and every selfcheck TU. |
| `ac/src/selfcheck/selfcheck.cpp` | Orchestrator: owns the scan cadence/budget, calls each sensor, batches raw evidence into the large-record drain path, and feeds `ac_get_last_flag`. Pure glue; no platform API. | Cross-platform. Implements `hk::selfcheck::SelfCheck` (`selfcheck.h`); dispatches signals 145–153; ships evidence, never verdicts. |
| `ac/src/selfcheck/image_baseline.cpp` | Shared on-disk header/section cache: parse our own backing file once at init (PE/ELF/Mach-O), record expected section ranges, on-disk SHA-256 of code sections, expected IAT/TLS/unwind table pointers (pre-ASLR), and signing identity. Single source of "what disk says." | Cross-platform (format dispatch via `HK_PLATFORM_*`). Implements `hk::selfcheck::ImageBaseline` (`selfcheck.h`); read-only file parse; feeds 145/149/150/151/153. |
| `ac/src/selfcheck/pe_parse.cpp` | Shared PE/EAT/IAT/unwind/TLS parser used by the Windows-format signals (149/150/151/153) and `image_baseline`. No Win32 calls — pure structure walk over a mapped buffer. | Cross-platform-buildable PE parser (plain struct walk, no `windows.h`). Implements `hk::selfcheck::pe::*`; consumed by 149/150/151/153 + baseline. |
| `ac/src/selfcheck/text_crossview.cpp` | Signal **145**: hash our `.text` via in-process VA, request the kernel foreign read of the same VA, re-read disk; emit the three SHA-256s + the matching matrix. | Cross-platform orchestration; kernel/daemon read via backend. Emits `HK_EVENT_SELF_CROSSVIEW`. |
| `ac/src/selfcheck/page_cow_audit.cpp` | Signal **146**: query per-page share / private-dirty / CoW state of our code pages (no byte hashing). | Cross-platform; per-OS page-state read via `platform::page_share_state()`. Emits `HK_EVENT_SELF_PAGE_COW`. |
| `ac/src/selfcheck/retaddr_provenance.cpp` | Signal **147**: at annotated critical-function prologues, capture the call stack, attribute each frame to a signed module, cross-check the CET shadow stack. `hk_obfuscate` applied here (guardrail #9). | Cross-platform unwind + module attribution. Implements `HK_GUARD_ENTRY` body; emits `HK_EVENT_SELF_RETADDR`. |
| `ac/src/selfcheck/dr_audit.cpp` | Signal **148**: request the kernel-side per-thread DR0–DR7 / DR7 read for our process and compare DR linear addresses against our `.text` range. | Cross-platform orchestration; trustworthy read is kernel-side only. Emits `HK_EVENT_SELF_HWBP`. |
| `ac/src/selfcheck/iat_target_audit.cpp` | Signal **149** (Windows): walk our IAT + delay-IAT, resolve each slot's target, attribute owning module, recompute expected export VA from that module's EAT, assert equality (or forwarder). Scoped to security-relevant imports. | Windows-format userspace; uses `pe_parse` + a signing backend. Emits `HK_EVENT_SELF_IAT_TARGET`. |
| `ac/src/selfcheck/got_target_audit.cpp` | Signal **149** (Linux/macOS): the `.got.plt`/`.rela.plt` (Linux) and `__la_symbol_ptr`/`__got` (macOS) analog — resolve via `dladdr`/dynsym, verify target inside the expected signed DSO/dylib. | POSIX userspace (`HK_PLATFORM_LINUX`/`MACOS` branch). Emits `HK_EVENT_SELF_IAT_TARGET`. |
| `ac/src/selfcheck/veh_unwind_audit.cpp` | Signal **150** (Windows): validate VEH-list ordering + re-parse our `.pdata` `RUNTIME_FUNCTION` table for critical functions vs on-disk unwind tables. | Windows userspace; `RtlLookupFunctionEntry` + VEH walk. Emits `HK_EVENT_SELF_VEH_UNWIND`. |
| `ac/src/selfcheck/sig_handler_audit.cpp` | Signal **150** (Linux/macOS): validate our `SIGTRAP`/`SIGSEGV` `sigaction` handlers resolve into our text and are not chained ahead of by an injected handler. | POSIX userspace. Emits `HK_EVENT_SELF_VEH_UNWIND` (same event, posix detail bits). |
| `ac/src/selfcheck/loader_consistency.cpp` | Signal **151**: cross-check our loader entry (PEB `Ldr` / `link_map` / `dyld_all_image_infos`) base/size/entrypoint/path against in-memory headers, the kernel section-object query, and disk. | Cross-platform orchestration; kernel image-file-name via backend. Emits `HK_EVENT_SELF_LOADER`. |
| `ac/src/selfcheck/wx_pte_audit.cpp` | Signal **152**: correlate usermode protection view (`VirtualQuery`/`/proc/self/maps`/`mach_vm_region`) with the kernel PTE write/NX read of the same VAs; flag disagreement. | Cross-platform orchestration; kernel PTE read via backend. Emits `HK_EVENT_SELF_WX_DRIFT`. |
| `ac/src/selfcheck/tls_init_audit.cpp` | Signal **153**: re-parse in-memory TLS callback array + CRT `.CRT$XC*` / `.init_array` / `__mod_init_func`; compare count + each rebased pointer vs the on-disk table; verify each resolves into our text. | Cross-platform (format via `HK_PLATFORM_*`). Emits `HK_EVENT_SELF_TLS_INIT`. |
| `platform/platform.h` (extend) | Add `page_share_state()` (146), `module_image_file_name()` (151), and `selfcheck_kernel_read()` request shim declarations. Interface only; backends implement. | Existing platform interface header; gains self-check read abstractions (guardrail #1). |
| `platform/platform_win.cpp` / `_linux.cpp` / `_macos.cpp` (extend) | Per-OS implementation of the new platform shims: Win = IOCTL to driver; Linux = `/proc/self/*` + eBPF/LKM read; macOS = `mach_vm_*` on our own task port via the daemon. | Existing platform backends; add self-check read implementations behind the matching CMake host branch. |
| `kernel/win/src/selfcheck_read.c` | Win kernel: handle `HK_IOCTL_SELF_READ_VA` — foreign-read the **calling** process's VA range (145), page-share state (146), PTE bits (152), and per-thread DRs (148). Reads only the caller's own image; validates caller identity. | Win kernel mode (KMDF). Implements `HkHandleSelfRead` (`horkos_kernel.h`); reads only the verified AC caller's address space. |
| `kernel/linux/bpf/src/selfcheck_read.bpf.c` | Linux eBPF: `bpf_probe_read_user` of the requested VA (145) + soft-dirty/private state (146) + `file_mprotect`/exec-VMA prot (152), keyed to the AC task. CO-RE, `-Wall -Wextra -Werror`. | Linux eBPF (CO-RE). Cooperates with the libbpf Loader; emits self-read replies for the AC task only. |
| `kernel/linux/bpf/src/hwbp_audit.bpf.c` | Linux eBPF: tracepoint on `arch_install_hw_breakpoint` / `perf_event_open` `HW_BREAKPOINT_X` targeting the AC's address space (148). CO-RE. | Linux eBPF. Emits hardware-breakpoint-install events scoped to the AC task. |
| `daemon/macos/SelfCheckRead.mm` | macOS daemon: `mach_vm_read_overwrite` (145), `mach_vm_region_recurse` share-mode/protection (146/152), `thread_get_state` DEBUG_STATE (148) over our own task port. Never touches an ES event (guardrail #7 N/A here — not an ES client path). | macOS userspace daemon. Implements the self-read backend over the AC's own task port; no ES auth path. |
| `server/telemetry/src/self_events.rs` | Phase-2 serde mirror of the new `hk_event_self_*` wire structs + the correlation logic that joins the three cross-views (145) and gates FP-prone signals (147/149/150) on a concurrent signature failure. Async, `thiserror`, no `unwrap()` outside tests. | Rust, tokio. Mirrors `hk_event_self_*`; correlates cross-views server-side (guardrail #8). |
| `bypass-tests/win/self_text_patch.cpp` | Merge-gate bypass test (145/146/152): inline-patch our own `.text` with a self-read-restoring hook; assert the **kernel** crossview/CoW/PTE path flags it even though self-hash is clean. | Windows only (`if(WIN32)`). Drives the large-record self-read drain. |
| `bypass-tests/win/self_iat_veh_hook.cpp` | Merge-gate bypass test (149/150/153): hook an IAT slot, install a VEH ahead of ours, append a TLS callback; assert 149/150/153 fire with correct RVAs and that a benign signed-overlay redirect does **not** fire (FP guard). | Windows only. |
| `bypass-tests/win/self_hwbp.cpp` | Merge-gate bypass test (148): set a hardware breakpoint on a critical function via `SetThreadContext`; assert the kernel-side DR read flags it where a usermode `GetThreadContext` would be spoofable. | Windows only. |
| `bypass-tests/linux/self_text_patch.cpp` | Merge-gate bypass test (145/146/152 Linux): `process_vm_writev`/`ptrace` patch of our `.text`; assert the eBPF foreign read + soft-dirty + exec-VMA prot path flags it. | Linux only (`if(UNIX AND NOT APPLE)`). |
| `bypass-tests/macos/self_text_patch.cpp` | Merge-gate bypass test (145/146/152 macOS): `mach_vm_write` patch of our `__TEXT`; assert the daemon `mach_vm_region_recurse` SM_COW + `mach_vm_read` path flags it. | macOS only (`if(APPLE)`). |

---

## Interfaces & data structures

### 3.1 Wire plane — reuse the large-record path

Self-check payloads carry 32-byte hashes, per-frame stack arrays, and ~260-char
module paths — far over `HK_EVENT_PAYLOAD_MAX = 16`. **Do not widen the 40-byte
ring.** Reuse the `hk_event_mem_record` large-record plane and
`HK_IOCTL_DRAIN_MEM_EVENTS` from `win-kernel-memory-injection.md`. If that plan
has not landed yet, this plan introduces the identical plane; the two **must
share one** `HK_EVENT_MEM_PAYLOAD_MAX` value (take the max of both domains'
largest payload). The self-check largest payload is `hk_event_self_crossview`
(below); confirm it fits the shared max or bump it once, with all
`HK_STATIC_ASSERT`s updated on both sides.

New IOCTL family for the **self-read** request path (kernel reads the calling AC
process's own VA — distinct from the memory-injection `HK_IOCTL_SCAN_PROCESS`
which scans *other* PIDs):

```c
/* appended in sdk/include/horkos/ioctl.h, next free function codes */
#define HK_IOCTL_SELF_READ_VA \
    HK_CTL_CODE(HK_FILE_DEVICE_UNKNOWN, 0x805, HK_METHOD_BUFFERED, HK_FILE_ANY_ACCESS)

/* What the AC asks the kernel to read about ITS OWN address space. The kernel
 * validates that the requesting PID == the FILE_OBJECT-owning AC process and
 * that [va_base, va_base+va_len) falls inside that process's image mapping —
 * it will not foreign-read arbitrary VAs for a caller. */
typedef enum hk_self_read_kind {
    HK_SELF_READ_BYTES      = 0,  /* 145: raw bytes of our .text range.        */
    HK_SELF_READ_PAGE_SHARE = 1,  /* 146: per-page share/CoW/dirty state.      */
    HK_SELF_READ_PTE_PROT   = 2,  /* 152: per-page kernel PTE write/NX bits.   */
    HK_SELF_READ_DEBUG_REGS = 3,  /* 148: per-thread DR0-DR7 + DR7.            */
    HK_SELF_READ_IMAGE_FILE = 4,  /* 151: kernel section-object FILE name.     */
} hk_self_read_kind;

typedef struct hk_self_read_request {
    uint32_t kind;        /* hk_self_read_kind. */
    uint32_t flags;       /* reserved. */
    uint64_t va_base;     /* start VA in the caller's own image. */
    uint64_t va_len;      /* length; bounded server-/kernel-side. */
} hk_self_read_request;
HK_STATIC_ASSERT(sizeof(hk_self_read_request) == 24, "hk_self_read_request wire size drift");
```

The reply rides the existing `hk_drain_header` envelope strided by
`hk_event_mem_record` (for `HK_SELF_READ_BYTES`/page-share/PTE/DR the kernel
fills a `hk_event_self_*` payload; for raw bytes the AC hashes the returned
buffer in userspace so the kernel ships bytes, not a hash it could be fooled
into trusting).

### 3.2 New event types (appended in `event_schema.h`; bump schema)

```c
/* appended to hk_event_type — existing values never change. Continues the
 * numbering after the memory-injection plan's block (which ends at 13); if
 * that block is not present yet, these still only *append*. */
HK_EVENT_SELF_CROSSVIEW   = 14,
HK_EVENT_SELF_PAGE_COW    = 15,
HK_EVENT_SELF_RETADDR     = 16,
HK_EVENT_SELF_HWBP        = 17,
HK_EVENT_SELF_IAT_TARGET  = 18,
HK_EVENT_SELF_VEH_UNWIND  = 19,
HK_EVENT_SELF_LOADER      = 20,
HK_EVENT_SELF_WX_DRIFT    = 21,
HK_EVENT_SELF_TLS_INIT    = 22,

#define HK_EVENT_SCHEMA_VERSION 4u  /* was 3u (or 2u→4u if mem plan not landed; bump once) */
```

Payload structs (each begins `pid` + our `image_base` so the server correlates
across signals; every size pinned by `HK_STATIC_ASSERT`). Sketches of the
non-obvious / largest:

```c
/* Signal 145 — cross-view hashes. Largest self payload → pins the shared max. */
typedef struct hk_event_self_crossview {
    uint32_t pid;
    uint32_t section_rva;       /* RVA of the .text range hashed. */
    uint64_t image_base;
    uint8_t  hash_inproc[32];   /* SHA-256 via our own VA read.        */
    uint8_t  hash_kernel[32];   /* SHA-256 via kernel foreign read.    */
    uint8_t  hash_disk[32];     /* SHA-256 of relocated on-disk bytes. */
    uint32_t match_matrix;      /* bit0 inproc==kernel, bit1 kernel==disk, bit2 inproc==disk. */
    uint32_t first_diff_rva;    /* first byte where the diverging pair differs, else 0. */
} hk_event_self_crossview;      /* 120 bytes; candidate for HK_EVENT_MEM_PAYLOAD_MAX. */

/* Signal 146 — page CoW/share audit. */
typedef struct hk_event_self_page_cow {
    uint32_t pid;
    uint32_t page_count;        /* pages covered by this report. */
    uint64_t image_base;
    uint64_t region_base;       /* first page VA. */
    uint32_t private_pages;     /* pages that became private/CoW (share-count dropped). */
    uint32_t dirty_pages;       /* soft-dirty / Private_Dirty count (Linux) / SM_PRIVATE (mac). */
} hk_event_self_page_cow;

/* Signal 147 — return-address provenance. Bounded frame array. */
#define HK_SELF_MAX_FRAMES 16u
typedef struct hk_event_self_retaddr {
    uint32_t pid;
    uint32_t guarded_fn_id;     /* which HK_GUARD_ENTRY site fired. */
    uint64_t frames[HK_SELF_MAX_FRAMES];     /* captured return addresses. */
    uint16_t frame_count;
    uint16_t unsigned_frame_idx; /* index of first frame in MEM_PRIVATE/unsigned, 0xFFFF if none. */
    uint32_t shadow_stack_mismatch; /* 0/1 from CET SSP cross-check when CET active. */
} hk_event_self_retaddr;

/* Signal 148 — hardware-breakpoint audit (kernel-context DR read). */
typedef struct hk_event_self_hwbp {
    uint32_t pid;
    uint32_t thread_id;
    uint64_t dr[4];             /* DR0-DR3 linear addresses. */
    uint32_t dr7;               /* enable bits. */
    uint32_t dr_in_text_mask;   /* bit i set if DRi lands inside our .text. */
} hk_event_self_hwbp;

/* Signal 149 — IAT/GOT target audit (one flagged slot per record). */
typedef struct hk_event_self_iat_target {
    uint32_t pid;
    uint32_t slot_rva;          /* RVA of the IAT/GOT slot. */
    uint64_t slot_target_va;    /* where the slot currently points. */
    uint64_t expected_va;       /* recomputed expected export VA. */
    uint32_t target_flags;      /* HK_SELF_TGT_* : private/unsigned/wrong-module/displaced. */
    uint32_t import_class;      /* Nt*/crypto/file/attestation bucket (scoped imports only). */
} hk_event_self_iat_target;
```

Signals **150 / 151 / 152 / 153** reuse compact {pid, image_base, table_rva,
expected_va, actual_va, flags} shapes (VEH/unwind: handler PC + ordering bits;
loader: which cross-reference broke as a bitmask + canonicalized path len;
wx_drift: per-page `usermode_prot` vs `kernel_prot`; tls_init: callback index +
expected vs actual rebased pointer). `HK_STATIC_ASSERT` pins each.

The kernel leaves `hash_kernel` / DR / PTE fields as the **authoritative**
values; `hash_inproc` / usermode-prot fields are the spoofable view. The server
flags only on **disagreement** (per the catalog FP gates), never on the
in-process view alone.

### 3.3 `selfcheck.h` interface sketch

```cpp
namespace hk { namespace selfcheck {

/* One critical-function entry guard for signal 147. Annotated for obfuscation
 * (guardrail #9) — only init/licence/integrity/attestation symbols. */
#define HK_GUARD_ENTRY(fn_id) ::hk::selfcheck::guard_entry((fn_id))
void guard_entry(uint32_t fn_id) __attribute__((annotate("hk_obfuscate")));

class SelfCheck {
public:
    int  arm(const ImageBaseline& baseline);  /* parse disk once; cache expected tables. */
    int  run_once();                          /* one budgeted pass over signals 145-153. */
    uint32_t last_flag() const;               /* feeds ac_get_last_flag (bypass tests). */
};

}} // namespace hk::selfcheck
```

### 3.4 Guardrail #11 — `data-categories.md` in the same PR

The same PR adds a new category **"5. Client self-integrity (AC image audit)"**
to `server/api/data-categories.md` declaring every new field with source /
retention / legal basis / operator-of-record. Fields to declare:
`section_rva`, `hash_inproc`, `hash_kernel`, `hash_disk`, `match_matrix`,
`first_diff_rva`, `private_pages`, `dirty_pages`, `frames[]`,
`unsigned_frame_idx`, `shadow_stack_mismatch`, `dr[]`, `dr7`, `dr_in_text_mask`,
`slot_rva`, `slot_target_va`, `expected_va`, `target_flags`, `import_class`,
plus the 150/151/152/153 fields. Source for all is "AC self-integrity sensor
(userspace) + Horkos kernel foreign read"; these are integrity hashes/addresses
of **our own binary**, not user content — but they are still collected from the
data subject's machine, so they are declared. Reviewer rejects undeclared fields.
Cross-reference line ("Wire format source of truth: `event_schema.h`") applies.

---

## Mechanism implementation notes

### Self-check orchestration (all signals)

- `selfcheck.cpp` runs on its own AC worker thread (or a low-priority timer),
  **not** on any kernel-callback context. Budget per pass so a large image scan
  cannot stall the AC. Cadence: a baseline pass at init (after `image_baseline`
  caches disk state), then a slow round-robin resample + event-driven re-checks
  on attestation challenge.
- The kernel-side reads (145/146/148/152) go through one IOCTL
  (`HK_IOCTL_SELF_READ_VA`); the AC issues them for its **own** VA ranges. The
  kernel validates caller identity and range containment (§8 — caller-identity
  proof is an uncertainty flag).

### 145 Cross-view .text hash (`text_crossview.cpp`)

- **View A (in-process):** read our `.text` via the parsed header range and
  SHA-256 in userspace.
- **View B (kernel foreign read):** `HK_SELF_READ_BYTES` → Win kernel uses
  `MmCopyVirtualMemory` (or `IoAllocateMdl` + `MmGetSystemAddressForMdlSafe` +
  `MmProbeAndLockPages`) against our process; Linux `bpf_probe_read_user` over
  the same VA; macOS `mach_vm_read_overwrite` on our task port. The kernel ships
  **bytes**, the AC hashes them — so a hooked self-`NtReadVirtualMemory` cannot
  forge view B.
- **View C (disk):** `ReadFile`/`pread` the backing image, relocate to the live
  base, hash the same RVA range. `image_baseline` already cached this.
- Emit all three hashes + `match_matrix` + `first_diff_rva`. **No verdict** —
  the catalog's signed-overlay allow-list (Steam/Discord/RTSS/GeForce/MSI AB)
  lives in the server, keyed on the patched RVA + trampoline target module.

### 146 Page Dirty/CoW audit (`page_cow_audit.cpp`)

- Windows: `QueryWorkingSetEx` over our `.text` range
  (`PSAPI_WORKING_SET_EX_BLOCK.Shared`/`ShareCount`/`Win32Protection`); the
  kernel half (`HK_SELF_READ_PAGE_SHARE`) corroborates via the PFN-database
  share-count / `MMPTE` CoW state. Linux: `/proc/self/pagemap` soft-dirty +
  `/proc/self/smaps` `Private_Dirty`/`Shared`, arming soft-dirty via
  `clear_refs`. macOS: `mach_vm_region_recurse` `share_mode == SM_COW/SM_PRIVATE`
  on `__TEXT`. Catches a frame the OS already split that no restore-on-read hook
  can un-private. FP gate (apphelp.dll shim, signed-overlay hotpatch) is
  server-side, correlated with 145.

### 147 Return-address provenance (`retaddr_provenance.cpp`)

- At annotated critical-function prologues (`HK_GUARD_ENTRY`), capture the stack:
  Win `RtlCaptureStackBackTrace` / `RtlVirtualUnwind` over `.pdata`, attribute
  each frame via `RtlPcToFileHeader`; when CET is active, read the shadow-stack
  pointer (`RDSSP`) and cross-check. Linux `_Unwind_Backtrace` +
  `dl_iterate_phdr`; macOS `backtrace()`/`__builtin_return_address` + `dladdr`.
- **FP risk is high** (overlays, VTune, JIT frames). Gate hard *in the sensor
  surface itself*: only sample at our own critical prologues (narrow surface),
  require the unsigned/private frame to be the **immediate** caller, and the
  server only alerts when correlated with a concurrent 145/149/150 signature
  failure. `hk_obfuscate` applied here (guardrail #9).

### 148 DR0–DR7 audit (`dr_audit.cpp`)

- The trustworthy read is **kernel-context only** — usermode `GetThreadContext`
  is spoofable. Win: `HK_SELF_READ_DEBUG_REGS` → driver enumerates our threads
  (`PsGetNextProcessThread`) and reads saved DRs from the thread context /
  `_KTRAP_FRAME`. Linux: the trustworthy path is the eBPF tracepoint on
  `arch_install_hw_breakpoint` / `perf_event_open` `HW_BREAKPOINT_X` targeting
  our address space (`hwbp_audit.bpf.c`), not `PTRACE_PEEKUSER`. macOS:
  `thread_get_state(x86_DEBUG_STATE64/ARM_DEBUG_STATE64)` over our task's
  threads in the daemon. Flag DR addresses landing in our `.text`. FP is
  essentially nil in retail; suppress on dev/test-signed builds reported via
  attestation. **See §8 — `_KTRAP_FRAME` DR offsets are build-varying.**

### 149 IAT/delay-IAT target audit (`iat_target_audit.cpp` / `got_target_audit.cpp`)

- Walk our `IMAGE_IMPORT_DESCRIPTOR` + `IMAGE_DELAYLOAD_DESCRIPTOR`; per
  `FirstThunk` slot resolve target VA, find owning module
  (`RtlPcToFileHeader`/`GetModuleHandleEx GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS`),
  confirm image-backed + Authenticode/cert-pinned (`WinVerifyTrust` in the
  signing backend), recompute expected export VA from that module's freshly
  parsed EAT and assert equality (or forwarder first-bytes). Linux: `.got.plt`/
  `.rela.plt` + `dladdr` + DSO dynsym. macOS: `__la_symbol_ptr`/`__got` +
  `dlsym` + dyld headers. **Scope to security-relevant imports only**
  (`Nt*`, crypto, file, attestation) per the catalog FP gate; server
  allow-lists signed-overlay redirects (GameOverlayRenderer/ReShade/RTSS/Reflex).

### 150 VEH & unwind audit (`veh_unwind_audit.cpp` / `sig_handler_audit.cpp`)

- Win: validate the VEH list — the hook-free approach is to **register our own
  VEH first and validate ordering** rather than traversing the undocumented
  `LdrpVectorHandlerList`/`RtlpCalloutEntryList` (§8). Independently re-parse our
  `IMAGE_DIRECTORY_ENTRY_EXCEPTION` (`.pdata`) via `RtlLookupFunctionEntry` per
  critical function and compare against the on-disk `RUNTIME_FUNCTION` array.
  Linux/macOS: validate our `sigaction(SA_SIGINFO)` `SIGTRAP`/`SIGSEGV` handlers
  resolve into our text and that no foreign handler is chained ahead on the
  signals we rely on. FP gate (CLR/CEF/Crashpad/ASAN): assert only that **our**
  critical-fn unwind entries are unmodified and no foreign handler is ordered
  ahead of ours — not the mere presence of other handlers.

### 151 Loader-structure consistency (`loader_consistency.cpp`)

- Win: read `PEB->Ldr` InLoad/InMemory/InInit lists (+ hash buckets) for our
  module; cross-check base/size/entrypoint/`TimeDateStamp` against the in-memory
  `IMAGE_NT_HEADERS` we re-parse, against the kernel section-object query
  (`HK_SELF_READ_IMAGE_FILE` → driver reports the `FILE_OBJECT` name + section
  for our VA), and against `ReadFile` of disk headers. Flag list-vs-list
  inconsistency (unlinking) or entrypoint mismatch. Linux: `link_map`(`r_debug`)
  vs `/proc/self/maps` vs DSO file. macOS: `dyld_all_image_infos` vs
  `mach_vm_region` vs file. Canonicalize the path via `GetFinalPathNameByHandle`
  and accept known virtualization layers (App-V/MSIX) — treat list-vs-list
  inconsistency, not path cosmetics, as the real signal.

### 152 W^X / PTE protection drift (`wx_pte_audit.cpp`)

- Correlate the usermode protection view (`VirtualQueryEx`
  `MEMORY_BASIC_INFORMATION.Protect` / `/proc/self/maps` r-xp / `mach_vm_region`
  cur+max prot) with the **kernel PTE** write/NX bits (`HK_SELF_READ_PTE_PROT` →
  driver reads the leaf PTE for our image VAs; Linux eBPF `security_file_mprotect`
  LSM hook on an exec VMA; macOS `mach_vm_region` `max_protection` gaining
  `VM_PROT_WRITE`). Flag **only on disagreement** for our image — legitimate
  software does not produce a kernel-says-writable / usermode-says-RX split on a
  foreign module. **See §8 — leaf-PTE translation is API-uncertain.**

### 153 TLS-callback & static-init integrity (`tls_init_audit.cpp`)

- Re-parse in-memory `IMAGE_TLS_DIRECTORY.AddressOfCallBacks` (walk to null
  terminator), compare count + each rebased pointer vs the on-disk table; verify
  each callback PC resolves (`RtlPcToFileHeader`) into our `.text`. Validate
  `.CRT$XCA..XCZ`. Linux: `.init_array`/`DT_INIT_ARRAY`. macOS:
  `__DATA,__mod_init_func`. Catches early-execution injection invisible to
  `.text` byte-hashing (it tampers data-directory pointers). FP gate: suppress
  on instrumented/sanitizer build flavors reported via attestation.

### Server (tokio) notes

- `self_events.rs` deserializes each `hk_event_self_*` with `thiserror`; **no
  `unwrap()` outside tests** (guardrail #8). The 145 correlation (join three
  hashes), 147/149/150 FP gating (require a concurrent signature failure), and
  the signed-overlay allow-list all live here, async on the existing axum/tokio
  path. SHA-256 comparison and any heavy parse is offloaded with `spawn_blocking`
  so it never blocks an async worker thread. Bounded `frames[]` / `*_len` fields
  are bounds-checked before slicing — a malicious length is a typed
  `SelfEventError`, not a panic.

---

## Build wiring

- **`ac/CMakeLists.txt`**: add the `selfcheck/*.cpp` TUs to `hk_ac`. The
  Windows-format TUs (`iat_target_audit.cpp`, `veh_unwind_audit.cpp`) compile
  everywhere (pure struct walks) but their live bodies are `HK_PLATFORM_WINDOWS`-
  guarded; the POSIX analogs (`got_target_audit.cpp`, `sig_handler_audit.cpp`)
  are `HK_PLATFORM_LINUX`/`MACOS`-guarded. `hk_ac` already links `hk_platform`;
  add a link to the signing backend (`WinVerifyTrust` on Win, `dladdr`/dyld on
  POSIX) through `platform/`.
- **Feature flag**: gate the self-check plane behind a CMake option
  `HK_ENABLE_SELFCHECK` (compile define `HK_SELFCHECK`) — **default ON** on all
  platforms (the self-check is core AC functionality, not optional like the
  cross-process mem scan). Signal 147's obfuscation is opt-in per symbol via the
  `hk_obfuscate` annotation, consumed by the LLVM-19 pass (guardrail #9); the
  pass runs only when the obfuscator toolchain build is selected.
- **`kernel/win/CMakeLists.txt` + `.vcxproj`**: add `selfcheck_read.c` to
  `HK_DRIVER_SRC` and the vcxproj. New IOCTL handled in `IrpDispatch.c`
  (`HkHandleSelfRead`). Same `/kernel /GS /W4 /WX /INTEGRITYCHECK /NODEFAULTLIB`.
- **`kernel/linux/bpf/CMakeLists.txt`**: add `selfcheck_read.bpf.c` and
  `hwbp_audit.bpf.c` to the eBPF object list. eBPF stays **default OFF** (locked
  decision 3); the LKM build flag provides the self-read path for non-Deck
  self-hosted servers. CO-RE, `clang-19`, `-Wall -Wextra -Werror` at the kernel
  warning level (guardrail #6).
- **`daemon/macos`**: add `SelfCheckRead.mm` to the daemon target (Xcode/clang).
  This is the bring-up path; no ES entitlement needed for self-task `mach_vm_*`.
- **`server/telemetry`**: add the `self_events` module; `cargo` only, no new
  crate.
- **`bypass-tests/{win,linux,macos}/CMakeLists.txt`**: add the new targets behind
  the matching host branch, disabled-by-default (live body gated by a
  `HK_SELFCHECK_TEST_ENABLED` define + signed fixture harness, mirroring
  `byovd_load`).
- Toolchain: WDK (driver), MSVC (Win SDK backend), `clang-19` + libbpf (Linux
  eBPF), Xcode (macOS daemon), stable Rust + tokio (server), LLVM-19 obfuscator
  (opt-in, never shipped — locked decision 5).

---

## Test strategy

### Unit tests (logic under TDD where testable — guardrail #14)

- **Host-buildable pure logic** (no kernel, no live image): factor the
  divergence/attribution decision logic out of the sensor TUs into pure functions
  fed synthetic fixtures:
  - `pe_parse` / `image_baseline`: a crafted PE/ELF/Mach-O with known IAT, TLS,
    `.pdata`, sections; assert parsed ranges + relocation math are exact (a clean
    relocated diff must be byte-identical; one stomped byte → correct
    `first_diff_rva`).
  - 145 correlation: synthetic (inproc, kernel, disk) hash triples → correct
    `match_matrix`; the inline-patch case (inproc diverges, kernel==disk) is
    classified distinctly from the COW-redirect case.
  - 149 IAT classifier: a slot pointing at the right module/RVA passes; a
    displaced/wrong-module/private target sets the right `target_flags`; a real
    forwarder does not false-positive.
  - 150/153: VEH-ordering + TLS-count/pointer compare against synthetic tables.
  - 147: frame-attribution logic over synthetic {frame VA, module range,
    signed?} sets — immediate-unsigned-caller rule fires, deep JIT frames do not.
- **`server/telemetry`**: serde round-trip + bounds-check tests for every
  `hk_event_self_*` struct, including malicious `frame_count`/`*_len`/`page_count`
  (must error, not panic), and the FP-gate correlation logic (147/149/150 do not
  alert without a concurrent signature failure). `cargo test`.
- **Wire pins**: new `HK_STATIC_ASSERT`s compile-fail on any struct drift across
  kernel + userspace + tests (the existing Step-3.5 mechanism).

### Bypass tests (merge gate — guardrail #12)

Any change under `ac/src/selfcheck/`, `kernel/`, `platform/` (security folders)
requires a corresponding bypass test. Five fixtures, disabled-by-default
(compile now; assert when `HK_SELFCHECK_TEST_ENABLED` lands with the signed
fixture harness):

- **`bypass-tests/win/self_text_patch.cpp`** — inline-patch our own `.text` and
  install a self-read-restoring `NtReadVirtualMemory` hook. Must demonstrate:
  signal 145 `hash_inproc` looks clean but `hash_kernel`/`hash_disk` diverge
  (the kernel foreign read defeats the hook); signal 146 shows the page went
  private/CoW; signal 152 shows the kernel PTE write-bit / usermode-RX
  disagreement. Proves self-hashing alone is insufficient and the kernel path
  catches the restore-on-read hook.
- **`bypass-tests/win/self_iat_veh_hook.cpp`** — hook a scoped IAT slot, install
  a VEH ahead of ours, append a TLS callback. Must demonstrate: 149 fires with
  the slot RVA + displaced target; 150 fires on the ordered-ahead VEH; 153 fires
  on the extra TLS callback; **and** a benign signed-overlay-style IAT redirect
  whose target resolves into an allow-listed module does **not** fire (FP guard).
- **`bypass-tests/win/self_hwbp.cpp`** — set a hardware breakpoint on a critical
  function via `SetThreadContext`, then spoof usermode `GetThreadContext` to read
  back clean. Must demonstrate: the kernel-side DR read (148) flags the DR
  landing in our `.text` where the usermode view was lied to.
- **`bypass-tests/linux/self_text_patch.cpp`** — `process_vm_writev`/`ptrace`
  patch of our `.text`. Must demonstrate the eBPF foreign read (145) + soft-dirty
  (146) + exec-VMA `mprotect` (152) path flags it.
- **`bypass-tests/macos/self_text_patch.cpp`** — `mach_vm_write` patch of our
  `__TEXT`. Must demonstrate the daemon `mach_vm_region_recurse` `SM_COW` (146) +
  `mach_vm_read` divergence (145) path flags it.

An FP-suite fixture (a process running under a benign signed overlay + a CLR/V8
JIT host loaded into the AC's space) asserts the sensors emit raw evidence but
the **server** does not alert — proving the "client emits, server decides"
contract.

---

## Sequencing

1. **Interface + wire first** (no sensor logic): create `selfcheck.h`,
   `event_schema.h` self events + structs, `ioctl.h` `HK_IOCTL_SELF_READ_VA` +
   `hk_self_read_request` + asserts, `data-categories.md` category 5,
   `self_events.rs` mirror + serde/bounds tests. Reconcile
   `HK_EVENT_MEM_PAYLOAD_MAX` with the memory-injection plan (one value). Lands
   green with all static asserts; unblocks userspace + kernel + server in
   parallel.
2. **Shared parsers**: `pe_parse.cpp` + `image_baseline.cpp` with host unit
   tests. Dependency for 145/149/150/151/153 — land before those sensors.
3. **Self-read kernel/daemon plane**: `selfcheck_read.c` (Win), the platform
   shims (`page_share_state`, `module_image_file_name`, `selfcheck_kernel_read`),
   eBPF `selfcheck_read.bpf.c` / `hwbp_audit.bpf.c`, daemon `SelfCheckRead.mm`,
   and the `HK_IOCTL_SELF_READ_VA` handler in `IrpDispatch.c`. Testable that a
   self-read round-trips our own bytes and is **refused** for a non-AC caller or
   an out-of-image VA (the caller-identity gate, §8).
4. **Userspace-only sensors** (no kernel dependency): 149 (`iat_target_audit` /
   `got_target_audit`), 150 (`veh_unwind_audit` / `sig_handler_audit`), 151
   (`loader_consistency`), 153 (`tls_init_audit`). These need only steps 1–2.
5. **Kernel-corroborated sensors**: 145 (`text_crossview`), 146
   (`page_cow_audit`), 152 (`wx_pte_audit`), 148 (`dr_audit`) — need step 3.
6. **Signal 147** (`retaddr_provenance`) + the `hk_obfuscate` annotation; land
   last because the obfuscation pass interaction (guardrail #9) and the
   immediate-caller FP gate need 149/150 already emitting for server correlation.
7. **Bypass tests + FP suite** activate alongside the signed fixture harness.

Dependencies: everything after step 1 needs the wire plane; format sensors need
step 2; kernel-corroborated sensors need step 3; 147's FP gate consumes
149/150 server-side.

---

## Risks & UNCERTAINTY FLAGS

Per guardrail #13 the following are **flagged, not guessed** — confirm against
current WDK / kernel / ES / signing docs (or a kernel reviewer) before code
lands. Kernel-offset-dependent reads fail **closed** (refuse the read) on an
unrecognized build rather than dereferencing a wrong offset (BSOD risk).

- **UNCERTAIN — caller-identity proof for `HK_IOCTL_SELF_READ_VA`.** The driver
  must prove the requesting process IS the legitimate AC (not malware asking the
  driver to foreign-read another process under cover of "self"). The intended
  gate is: validate the IRP-issuing `FILE_OBJECT`/PID against the AC image
  identity established at driver load, and bound `[va_base, va_len)` inside that
  process's own image mapping. **The exact secure binding mechanism (signed
  IOCTL, per-session token, image-hash check at open) is not settled — confirm
  before exposing a foreign-read IOCTL at all.** A foreign-read primitive is a
  privilege boundary; mis-scoping it is worse than shipping fewer signals.
- **UNCERTAIN — `MmCopyVirtualMemory` vs MDL foreign read at IRQL (145).** Which
  documented path is correct for reading the caller's own pageable image from the
  IOCTL dispatch context, and the IRQL/locking requirements
  (`MmProbeAndLockPages` SEH, `MmGetSystemAddressForMdlSafe` failure handling).
  Confirm the read happens at PASSIVE_LEVEL with the target referenced; SEH-guard
  every probe.
- **UNCERTAIN — leaf-PTE / NX-bit read (152).** Deriving the leaf PTE
  (`MiGetPteAddress`-equivalent) relies on the non-exported, build-varying
  PTE_BASE. Prefer a documented path (`MmGetPhysicalAddress` per sampled page) if
  it exposes the protection bits we need; if the NX/write bits are not reachable
  through a documented API on a target build, 152 ships **sampled-only** or is
  deferred. Do not hand-roll a PTE walk on a guess.
- **UNCERTAIN — `_KTRAP_FRAME` / thread-context DR offsets (148).** Saved debug
  registers in the thread context are not stable documented ABI; offsets vary by
  build. Prefer a documented context-capture path; the raw `_KTRAP_FRAME` field
  goes behind a per-build offset allow-list (fail closed) only if no documented
  path exists. Confirm before enabling.
- **UNCERTAIN — VEH list traversal (150).** `LdrpVectorHandlerList` /
  `RtlpCalloutEntryList` are undocumented internals. The plan's **primary**
  approach is hook-free (register our own VEH first, validate ordering), which
  avoids the undocumented walk entirely; the raw-list traversal is a fallback
  flagged uncertain and gated behind the same build allow-list. Do not traverse
  the undocumented list on a guess.
- **UNCERTAIN — CET shadow-stack SSP read (147).** Reading the shadow-stack
  pointer (`RDSSP`) and interpreting it requires CET to be active and the right
  privilege/instruction availability; confirm the documented usermode path and
  that absence of CET degrades to "shadow-stack check skipped," never a fault.
- **UNCERTAIN — macOS self-task `mach_vm_*` without ES (145/146/148/152).**
  Confirm the daemon can `mach_vm_read_overwrite` / `mach_vm_region_recurse` /
  `thread_get_state` over the AC's **own** task port without an EndpointSecurity
  entitlement (this is the bring-up path; the SysExt swap is a separate locked
  decision). If self-task introspection needs `task_for_pid` privilege or an
  entitlement, flag it before relying on it. (Guardrail #7 does not apply — this
  is not an ES auth-event path, so there is no reply-deadline concern here.)
- **UNCERTAIN — Linux eBPF foreign-read scope (145/146/152).**
  `bpf_probe_read_user` reads the **current** task's user memory in the probe
  context; reading the AC task's memory from an unrelated context, and the
  soft-dirty/`security_file_mprotect` LSM availability, depend on kernel config
  and the eBPF-vs-LKM split (locked decision 3). Confirm the read is reachable
  for the AC task on the target kernels; the LKM path is the fallback for
  self-hosted/non-Deck.
- **FP risk (server-side, not BSOD):** 147 (high — overlays/profilers/JIT),
  145/146/149/150/152 (medium — signed overlays, hotpatch, App-V/MSIX,
  CLR/CEF/Crashpad), 148/151/153 (low). The client ships **raw evidence only**;
  the signed-overlay allow-list, the immediate-caller rule (147), and the
  require-a-concurrent-signature-failure correlation (147/149/150) all live in
  `self_events.rs`. **No client-side ban.**
- **Obfuscation interaction (guardrail #9).** The `hk_obfuscate` annotation on
  147's guard and the self-check init path must not bleed into the GAME hot loop.
  Confirm the LLVM-19 pass honors the per-symbol opt-in and that obfuscating the
  self-check code does not break the `.pdata`/unwind self-parse it relies on
  (150 re-parses our own unwind tables — obfuscation must keep them consistent
  with what we cached on disk).
