# Linux eBPF — Userspace Loader / Injection — Implementation Plan

**Scope:** read-only detection sensors for userspace library-injection on Linux,
driven by eBPF uprobes/uretprobes/LSM + a userspace correlation loader, reporting
to the server which holds all ban authority. Clients sample and report only.

**Catalog signals covered:** 82, 83, 84, 85, 86, 87, 88, 89, 90 (the nine
`linux-ebpf-injection` signals, detection-catalog.md §853–943).

All work here is sensor-only: every BPF program returns its inbound LSM decision
unchanged (audit-only, like the existing `lsm/file_open`); no syscall is blocked,
no memory is written, no process is killed on-host. Scoring and banning are
server-side.

---

## 1. Signal → mechanism map (orientation)

| # | Short name | Primary hook | Userspace correlator |
|---|---|---|---|
| 82 | DT_NEEDED vs runtime DSO divergence | uretprobe `_dl_map_object` | `DsoProvenance.cpp` |
| 83 | GOT slot outside resolving DSO | uprobe sampler on hot game fn | `GotPltMap.cpp` |
| 84 | PT_INTERP / loader build-id mismatch | tracepoint `sched_process_exec` (reused) + uprobe loader entry | `InterpCheck.cpp` |
| 85 | ld.so.preload / preload-env transient | `lsm/bprm_creds_for_exec` + inotify | `PreloadWatch.cpp` |
| 86 | dlopen of deleted/memfd/anon DSO | uprobe `dlopen`/`_dl_open` | `DlopenBacking.cpp` |
| 87 | DSO load-order inversion | uretprobe `_dl_map_object` (shared w/ 82) | `LinkMapOrder.cpp` |
| 88 | `_r_debug` r_brk / RELRO divergence | uprobe-triggered `_r_debug` sample | `RDebugCheck.cpp` |
| 89 | LD_AUDIT rtld-audit activation | `lsm/bprm_creds_for_exec` (shared w/ 85) + uprobe `_dl_audit_symbind` | (env capture shared) |
| 90 | text page COW-broken / not file-backed | uprobe trigger + `/proc/pid/{smaps,pagemap}` | `TextPageBacking.cpp` |

Common architecture: the **BPF side** never parses ELF, never reads
`/proc/pid/{maps,mem,smaps,pagemap}` (those require userspace fd lifetime and are
not BPF-safe at scale). BPF programs only fire lightweight events (a DSO mapped,
a dlopen happened, an exec carried an env var, a sample tick). The **userspace
loader** does all ELF/`/proc` parsing, maintains the per-PID VMA + link_map
model, applies the signed allowlist gating, and emits `hk_event_record`s to the
server via the existing `HkEventSink` (Loader.h). This keeps each BPF TU tiny
(verifier-friendly) and keeps kernel and userspace code in separate TUs
(guardrail #4).

---

## 2. New files

All BPF `.bpf.c` files are pure kernel eBPF TUs (no userspace headers, guardrail
#4); all `.cpp`/`.h` are Linux userspace. None use raw `__linux__` — the whole
subtree is Linux-gated by CMake (`CMAKE_SYSTEM_NAME STREQUAL "Linux"`), satisfying
guardrail #1 (platform code confined to the Linux backend folder). Every file
carries the role/platform/interface module comment (guardrail #3).

### BPF programs — `kernel/linux/bpf/src/`

| Path | Role | Module-comment summary |
|---|---|---|
| `dl_map_object.bpf.c` | uretprobe on glibc `_dl_map_object`; emits one record per DSO the loader maps (link_map append order index, soname ptr, load bias). Feeds signals 82 + 87. | Role: capture loader DSO-map events for provenance/order analysis. Platform: Linux eBPF (uprobe, kernel ≥ 4.17). Interface: shares `hk_ringbuf` with existing programs; userspace `DsoProvenance.cpp`/`LinkMapOrder.cpp` consume. |
| `got_sample.bpf.c` | uprobe on a benign frequently-called game fn; on fire, `bpf_probe_read_user`s a small batch of `.got.plt` slot values at offsets supplied by userspace via a config map. Feeds signal 83. | Role: sample GOT/PLT slot pointers under an event-driven cadence. Platform: Linux eBPF (uprobe). Interface: reads `hk_got_cfg` map (slot offsets), writes slot snapshots to `hk_ringbuf`. |
| `dlopen_uprobe.bpf.c` | uprobe on `dlopen`/`dlmopen`/`_dl_open`; reads the path arg via `bpf_probe_read_user_str`. Feeds signal 86. | Role: report each dlopen path for backing-store resolution. Platform: Linux eBPF (uprobe). Interface: `hk_ringbuf`; userspace `DlopenBacking.cpp`. |
| `bprm_env.bpf.c` | `lsm/bprm_creds_for_exec`; scans `linux_binprm->envp`/`argv` for `LD_PRELOAD`/`LD_AUDIT`/`LD_LIBRARY_PATH` presence at exec, stamps event. Feeds signals 85 + 89. | Role: detect dynamic-loader env injection at exec time. Platform: Linux eBPF (BPF LSM, kernel ≥ 5.7). Interface: `hk_ringbuf`; always returns inbound `ret` (audit-only). |
| `interp_entry.bpf.c` | uprobe on the mapped loader's `_start`/entry to confirm which ld.so actually serviced relocation; correlates with PT_INTERP. Feeds signal 84. | Role: confirm the live interpreter identity at first relocation. Platform: Linux eBPF (uprobe). Interface: `hk_ringbuf`; userspace `InterpCheck.cpp`. |
| `dl_audit.bpf.c` | uprobe on glibc `_dl_audit_symbind`; reports that rtld-audit callbacks are firing for a watched PID. Feeds signal 89. | Role: detect active rtld-audit instrumentation. Platform: Linux eBPF (uprobe). Interface: `hk_ringbuf`; env capture shared with `bprm_env.bpf.c`. |
| `rdebug_sample.bpf.c` | uprobe-triggered sample that reports the watched PID needs an `_r_debug` r_brk/RELRO re-check (the actual `/proc/pid/mem` read is userspace). Feeds signal 88. | Role: cadence trigger for loader-bookkeeping integrity sampling. Platform: Linux eBPF (uprobe). Interface: `hk_ringbuf`; userspace `RDebugCheck.cpp`. |
| `text_sample.bpf.c` | uprobe on a hot game fn providing event-driven cadence for the userspace smaps/pagemap text-integrity scan. Feeds signal 90. | Role: cadence trigger for executable-page COW/back-store scan. Platform: Linux eBPF (uprobe). Interface: `hk_ringbuf`; userspace `TextPageBacking.cpp`. |

Note: `rdebug_sample.bpf.c`, `text_sample.bpf.c`, and `got_sample.bpf.c` are all
"cadence trigger" programs attached to game functions; they could share one
`sample.bpf.c` with a tag. Kept separate initially for independent attach/detach
and per-signal feature-flag gating (§5); consolidation is a later refactor.

### Userspace correlators — `kernel/linux/userspace/`

| Path | Role | Module-comment summary |
|---|---|---|
| `DsoProvenance.cpp` / `.h` | Parse the static DT_NEEDED closure of `/proc/<pid>/exe` once at attach; for each `_dl_map_object` event, flag DSOs absent from the closure and outside the signed runtime/lib allowlist (signal 82). | Role: DT_NEEDED-closure vs runtime-DSO divergence. Platform: Linux userspace. Interface: consumes `dl_map_object` ringbuf events; emits `hk_event_dso_provenance` via `HkEventSink`. |
| `GotPltMap.cpp` / `.h` | Compute `.got.plt` slot offsets from ELF section headers + load bias; resolve each sampled slot pointer against the live VMA map; flag IFUNC-excluded slots landing in anon/RWX/foreign DSO (signal 83). | Role: GOT/PLT redirection detection. Platform: Linux userspace. Interface: maintains VMA map from `dl_map_object`; consumes `got_sample`; emits `hk_event_got_anomaly`. |
| `InterpCheck.cpp` / `.h` | Read PT_INTERP + NT_GNU_BUILD_ID from `/proc/<pid>/exe`; identify mapped interpreter from `/proc/<pid>/maps`; resolve expected interpreter through container manifest (Flatpak/Steam pressure-vessel) before scoring (signal 84). | Role: PT_INTERP vs mapped-loader build-id check. Platform: Linux userspace. Interface: consumes `sched_process_exec` + `interp_entry`; emits `hk_event_interp_mismatch`. |
| `PreloadWatch.cpp` / `.h` | inotify-watch `/etc/ld.so.preload` (`IN_MODIFY|IN_CLOSE_WRITE|IN_DELETE`); correlate steady-state file content vs the at-exec env/file state from `bprm_env`; attribute env-setting ancestor PID (signal 85). | Role: transient preload (env/file) divergence detection. Platform: Linux userspace. Interface: consumes `bprm_env`; emits `hk_event_preload_anomaly`. |
| `DlopenBacking.cpp` / `.h` | On each dlopen event, stat the resolved path/fd and inspect the matching `/proc/<pid>/maps` line for `(deleted)`, `memfd:`, or anon-exec backing; require executable + later-called symbols before scoring (signal 86). | Role: fileless/memfd dlopen backing resolution. Platform: Linux userspace. Interface: consumes `dlopen_uprobe`; emits `hk_event_dlopen_backing`. |
| `LinkMapOrder.cpp` / `.h` | Build the per-PID link_map order from `_dl_map_object` insertion sequence; for security-relevant exported symbols (malloc, recv, glXSwapBuffers, vkQueuePresentKHR, time, rand) flag a non-allowlisted DSO preceding the canonical provider (signal 87, corroborating-only). | Role: load-order symbol-interposition detection. Platform: Linux userspace. Interface: shares `dl_map_object` stream with `DsoProvenance.cpp`; emits `hk_event_loadorder_inversion`. |
| `RDebugCheck.cpp` / `.h` | Locate `_r_debug` via PT_DYNAMIC DT_DEBUG at the load-biased address (read through `/proc/<pid>/mem`); range-check `r_brk` against ld.so VMA and read RELRO page perms from maps; suppress when a ptrace tracer is attached (signal 88). | Role: `_r_debug` r_brk / RELRO integrity check. Platform: Linux userspace. Interface: consumes `rdebug_sample`; emits `hk_event_rdebug_anomaly`. |
| `TextPageBacking.cpp` / `.h` | Read `/proc/<pid>/smaps_rollup`, per-VMA `/proc/<pid>/smaps` (Private_Dirty) and `/proc/<pid>/pagemap` (file-backed bit) for r-xp file-backed mappings; flag exec pages gone private-dirty/anonymous outside documented IFUNC/reloc spans (signal 90). | Role: in-memory inline-hook / COW-broken text detection. Platform: Linux userspace. Interface: consumes `text_sample` cadence; emits `hk_event_text_patch`. |
| `ElfModel.cpp` / `.h` | Shared ELF/`/proc` helper: DT_NEEDED closure, section-header/load-bias math, NT_GNU_BUILD_ID extraction, VMA-map snapshot, container-manifest resolution. Used by all correlators above. | Role: shared read-only ELF + `/proc` parsing utilities. Platform: Linux userspace. Interface: pure helper library, no BPF headers. |
| `OverlayAllowlist.cpp` / `.h` | Load and query the server-signed soname+build-id allowlist (overlay/layer/allocator ecosystem), scoped per distro/Steam-runtime. Verifies signature before use. | Role: signed-allowlist gating to suppress legitimate interposers. Platform: Linux userspace. Interface: queried by every correlator before scoring. |

`ElfModel` and `OverlayAllowlist` are the FP-control backbone; nearly every
signal's catalog entry gates on "outside the signed allowlist" and/or "no
DT_NEEDED provenance," so this logic is built once and shared.

---

## 3. Interfaces & data structures

### 3.1 New schema event types (`sdk/include/horkos/event_schema.h`)

Schema bump: **`HK_EVENT_SCHEMA_VERSION` 2 → 3** (additive; the Rust mirror in
`server/telemetry` and any kernel-event serde bump in lockstep). Append-only —
existing enum values unchanged (guardrail: no renames, deprecated→reserved).

```c
typedef enum hk_event_type {
    /* ... existing 0..4 unchanged ... */
    HK_EVENT_DSO_PROVENANCE     = 5,  /* signal 82 */
    HK_EVENT_GOT_ANOMALY        = 6,  /* signal 83 */
    HK_EVENT_INTERP_MISMATCH    = 7,  /* signal 84 */
    HK_EVENT_PRELOAD_ANOMALY    = 8,  /* signals 85, 89 (LD_AUDIT shares) */
    HK_EVENT_DLOPEN_BACKING     = 9,  /* signal 86 */
    HK_EVENT_LOADORDER_INVERT   = 10, /* signal 87 */
    HK_EVENT_RDEBUG_ANOMALY     = 11, /* signal 88 */
    HK_EVENT_TEXT_PATCH         = 12, /* signal 90 */
} hk_event_type;
```

These payloads carry a 20-byte **build-id** and a free-form **soname/path**
that exceed the current `HK_EVENT_PAYLOAD_MAX` of 16 bytes. Two options; the plan
chooses **(B)**:

- **(A)** widen `HK_EVENT_PAYLOAD_MAX` and `hk_event_record` — breaks the
  `sizeof(hk_event_record)==40` pin shared with the Windows IOCTL path and bloats
  every record. Rejected.
- **(B)** keep the fixed C record carrying only fixed-width scalars + a build-id
  digest (truncated to a `uint64_t` "build-id prefix" for the kernel record), and
  send the **full soname/path/build-id string out-of-band on the userspace→server
  JSON plane** (the same plane as `TickPayload`, `server/telemetry`). The Linux
  loader already runs in userspace and forwards over HTTP/JSON, so variable-length
  strings ride the JSON ingest, not the C wire record. **Chosen.**

New fixed payloads (each ≤ 16 bytes so `HK_EVENT_PAYLOAD_MAX` is unchanged and the
40-byte `hk_event_record` pin in `ioctl.h` holds — these Linux events reuse the
same record envelope even though they never traverse the Windows IOCTL):

```c
/* signal 82 / 87 — DSO provenance + load-order. 16 bytes. */
typedef struct hk_event_dso_anomaly {
    uint32_t pid;
    uint32_t flags;            /* HK_DSO_FLAG_* (no DT_NEEDED edge, order-inversion,
                                  outside-allowlist, memfd/deleted) */
    uint64_t buildid_prefix;   /* first 8 bytes of NT_GNU_BUILD_ID; full id via JSON */
} hk_event_dso_anomaly;
HK_STATIC_ASSERT(sizeof(hk_event_dso_anomaly) == 16, "hk_event_dso_anomaly size");

/* signal 83 — GOT/PLT redirect. 16 bytes. */
typedef struct hk_event_got_anomaly {
    uint32_t pid;
    uint32_t got_flags;        /* HK_GOT_FLAG_RWX_TARGET, _ANON_TARGET, _FOREIGN_DSO */
    uint64_t slot_target;      /* the offending resolved pointer (VA) */
} hk_event_got_anomaly;
HK_STATIC_ASSERT(sizeof(hk_event_got_anomaly) == 16, "hk_event_got_anomaly size");

/* signals 84 / 85 / 88 / 90 — loader/interp/text integrity. 16 bytes each,
   one struct reused with a discriminating `kind` field to limit enum sprawl: */
typedef struct hk_event_loader_integrity {
    uint32_t pid;
    uint32_t kind_flags;       /* HK_LI_INTERP_MISMATCH | _PRELOAD_TRANSIENT |
                                  _RDEBUG_FOREIGN | _RELRO_WRITABLE |
                                  _TEXT_COW_BROKEN | _LD_AUDIT_ACTIVE */
    uint64_t detail;           /* offset / r_brk VA / dirty-page VA per kind */
} hk_event_loader_integrity;
HK_STATIC_ASSERT(sizeof(hk_event_loader_integrity) == 16,
                 "hk_event_loader_integrity size");
```

`access_mask` reuse for ptrace already exists in data-categories §2a (Linux
truncated ptrace request code); the RDebug suppression depends on the existing
`sys_enter_ptrace` tracepoint, no new field for that gate.

### 3.2 BPF-side records & config map

Following the existing pattern in `lsm_file_open.bpf.c`, each BPF TU defines its
own compact `hk_bpf_*` struct (NOT `event_schema.h` types — that header pulls
`stdint.h`, forbidden under `-nostdinc`), tagged with `HK_SCHEMA_VERSION 3u`
(mirrors the bumped `HK_EVENT_SCHEMA_VERSION`). The loader translates to
`hk_event_record`. New internal BPF tags (analogous to `HK_EVENT_FILE_OPEN 0x10`):
`HK_EVENT_DL_MAP 0x20`, `HK_EVENT_GOT_SAMPLE 0x21`, `HK_EVENT_DLOPEN 0x22`,
`HK_EVENT_BPRM_ENV 0x23`, `HK_EVENT_INTERP 0x24`, `HK_EVENT_DL_AUDIT 0x25`,
`HK_EVENT_RDEBUG_TICK 0x26`, `HK_EVENT_TEXT_TICK 0x27`.

New BPF map for signal 83 (GOT slot offsets handed kernel-side by userspace):

```c
/* Per-PID array of .got.plt slot offsets to sample, populated by userspace
   after it parses the ELF. BPF_MAP_TYPE_HASH keyed by pid. */
struct { __uint(type, BPF_MAP_TYPE_HASH);
         __uint(max_entries, 4096);
         __type(key, __u32); __type(value, struct hk_got_cfg); } hk_got_cfg SEC(".maps");
```

`hk_got_cfg` carries a bounded array of offsets (e.g. 32) + count; the BPF
program loops with a `#pragma unroll`/bounded loop to stay verifier-legal.

### 3.3 data-categories.md additions (guardrail #11 — same PR)

Every new telemetry field above MUST be added to `server/api/data-categories.md`
**in the same PR**. New rows required:

- **§2 Module information:** `dso_buildid` (NT_GNU_BUILD_ID, full + prefix),
  `dso_soname`, `dso_provenance_flags`, `dlopen_backing_kind`
  (deleted/memfd/anon), `link_map_order_index`.
- **§2b (new) Loader / injection integrity (Linux eBPF):** `got_slot_target`,
  `got_flags`, `interp_buildid` + `interp_path`, `preload_env_value` (LD_PRELOAD/
  LD_AUDIT/LD_LIBRARY_PATH value, raw string — flag for DPIA: may contain a user
  path), `preload_ancestor_pid`, `rdebug_r_brk_va`, `relro_page_perms`,
  `text_dirty_page_va`, `ld_audit_module_buildid`.
- Note `preload_env_value` is the highest-sensitivity field (can embed a home
  directory path); record retention default 90 days, legal basis legitimate
  interest, and call out in the PR that it needs the DPIA reviewer's sign-off.

The plan does NOT itself edit data-categories.md (this is a plan, not the PR), but
the implementing PR is gated on it.

---

## 4. Mechanism implementation notes

General eBPF/CO-RE constraints (guardrail #6, `-Wall -Wextra -Werror`,
matching the existing BPF CMake flags): all kernel-struct access via `BPF_CORE_READ`;
all user-memory reads via `bpf_probe_read_user`/`bpf_probe_read_user_str` (uprobes
read **user** addresses — using the kernel variant is a silent fault). Bounded
loops only; `-O2` required (verifier complexity). Every ringbuf reserve checked
for NULL (drop-on-overflow, never block). LSM programs return the inbound `ret`
(audit-only) — never a hard 0.

**Signal 82 — DT_NEEDED divergence.** uretprobe on glibc `_dl_map_object`
(`SEC("uretprobe/...")` attached by soname+symbol via libbpf
`bpf_program__attach_uprobe` with `func_offset` resolved from the target's
`/proc/pid/maps` libc path). BPF emits `{pid, link_map_index, soname_uptr}`.
Userspace `DsoProvenance.cpp` parses the DT_NEEDED transitive closure once at
attach from `/proc/<pid>/exe` `.dynamic`, then diffs each mapped soname; gate on
build-id unknown to `OverlayAllowlist` AND path outside Steam-runtime/system lib
dirs (catalog FP gate). Concern: `_dl_map_object` is a glibc-internal symbol —
its presence/signature varies by libc (glibc vs musl); **see UNCERTAINTY §8**.

**Signal 83 — GOT outside resolving DSO.** uprobe on a benign hot game fn
(symbol supplied per-title via config). On fire, BPF reads a batch of `.got.plt`
slot values via `bpf_probe_read_user` at offsets from `hk_got_cfg` (computed
userspace-side from section headers + load bias). Userspace `GotPltMap.cpp`
compares each pointer against the VMA snapshot; **skip IFUNC slots**
(`R_*_IRELATIVE`), allowlist signed-overlay targets, score only anon/RWX/foreign.
Concern: GOT slot offsets are per-build; userspace must recompute on every
`_dl_map_object` (relocation may be lazy — a slot may still hold the PLT stub
until first call, which is legitimate, not a hook; the comparator must treat
"points into own PLT" as benign).

**Signal 84 — PT_INTERP mismatch.** Reuses the existing
`tracepoint/sched/sched_process_exec` (already in `tracepoints.bpf.c`) to learn
of the protected exec; `interp_entry.bpf.c` uprobes the mapped loader entry to
confirm which ld.so serviced relocation. Userspace `InterpCheck.cpp` reads
PT_INTERP + the mapped interpreter's NT_GNU_BUILD_ID and resolves the *expected*
interpreter through the container manifest (Flatpak metadata / Steam
pressure-vessel soldier/sniper build-id list) before scoring — patchelf/Nix/Steam
legitimately rewrite PT_INTERP (catalog FP gate). Concern: locating the loader
entry symbol reliably across ld.so builds — **UNCERTAINTY §8**.

**Signal 85 — transient preload.** `lsm/bprm_creds_for_exec`
(`bprm_env.bpf.c`) reads `linux_binprm->envp` for `LD_PRELOAD`/`LD_AUDIT`/
`LD_LIBRARY_PATH`. envp is a user-space pointer array at exec; reading it in BPF
means walking `bprm->envp` with bounded `bpf_probe_read_user` loops — **bounded
and capped** (e.g. scan first N=64 env entries, M=512 bytes each) to satisfy the
verifier; a longer env simply isn't fully scanned (acceptable: we only need
presence of the three keys). Userspace `PreloadWatch.cpp` inotify-watches
`/etc/ld.so.preload` and reports the at-exec vs steady-state disagreement,
attributing the env-setting ancestor PID. Concern: `bprm_creds_for_exec` vs
`bprm_committing_creds` availability differs by kernel — **UNCERTAINTY §8**.

**Signal 86 — fileless dlopen.** uprobe on `dlopen`/`dlmopen` (and internal
`_dl_open`) in the target's libc; `bpf_probe_read_user_str` the path arg.
Userspace `DlopenBacking.cpp` stats the resolved fd/path and inspects the maps
line for `(deleted)`/`memfd:`/anon-exec. Gate: require executable AND
later-called exported symbols; whitelist known JIT runtimes by ancestor+build-id
(catalog FP gate). Concern: `dlopen` is a PLT export (stable) but `_dl_open` is
internal — prefer the public `dlopen`/`dlmopen` symbols for the uprobe;
internal `_dl_open` only as a fallback (UNCERTAINTY §8).

**Signal 87 — load-order inversion.** Shares `dl_map_object.bpf.c` events with
signal 82. `LinkMapOrder.cpp` builds the per-PID link_map insertion order and,
for a fixed set of hookable symbols (malloc, recv, glXSwapBuffers,
vkQueuePresentKHR, time, rand), flags a non-allowlisted DSO preceding the
canonical provider. Catalog marks this **highest-FP**: gate hard (outside signed
allowlist AND no DT_NEEDED provenance AND interposes a security-relevant symbol)
and emit as **corroborating-only** — the server must never ban on signal 87
standalone; this is encoded as a low standalone weight server-side, not enforced
on-host.

**Signal 88 — `_r_debug` r_brk / RELRO.** `rdebug_sample.bpf.c` provides the
cadence trigger only. `RDebugCheck.cpp` locates `_r_debug` via PT_DYNAMIC
DT_DEBUG at the load-biased address read through `/proc/<pid>/mem`, range-checks
`r_brk` against ld.so's VMA, and reads RELRO page perms from maps (expected
`r--p`). Suppress when a ptrace tracer is attached (corroborate with the existing
`sys_enter_ptrace` signal) and allowlist the distro ld.so's expected r_brk
offset (catalog FP gate). `/proc/pid/mem` reads require matching the target's
address space and careful fd lifetime — userspace-only, never BPF.

**Signal 89 — LD_AUDIT.** Env capture shares `bprm_env.bpf.c` (signal 85).
`dl_audit.bpf.c` uprobes glibc `_dl_audit_symbind` to detect la_symbind firing
for a watched PID. Anomaly = firing la_symbind with no recorded/allowlisted
LD_AUDIT at exec. Catalog notes near-zero FP on the consumer Steam Deck path.
Concern: `_dl_audit_symbind` is glibc-version-specific and may be inlined/renamed
— **UNCERTAINTY §8**.

**Signal 90 — text COW-broken.** `text_sample.bpf.c` gives the event-driven
cadence; `TextPageBacking.cpp` reads `/proc/<pid>/smaps_rollup`, per-VMA `smaps`
(`Private_Dirty`) and `/proc/<pid>/pagemap` (file-backed bit) for r-xp
file-backed mappings; flags exec pages gone private-dirty/anonymous outside
documented IFUNC/reloc prologue spans. Suppress when a tracer is attached. Concern:
`/proc/pid/pagemap` file-backed/soft-dirty bit semantics changed across kernels
and reading it needs `CAP_SYS_ADMIN`/appropriate caps — **UNCERTAINTY §8**.

**Server side (guardrail #8).** The Linux loader forwards the variable-length
JSON (soname/path/build-id strings) to a new ingest route under
`server/api/src/routes` (mirror of the telemetry ingest). All handlers async on
tokio, `thiserror` error types, **no `unwrap()` outside tests**. Scoring weights
(especially signal 87 corroborating-only, signal 85 ancestor-attribution) live in
`server/ban-engine`; fail-closed posture as in the existing engine. The server
holds all ban authority — the client never acts.

---

## 5. Build wiring

**eBPF (`kernel/linux/bpf/CMakeLists.txt`).** Register the eight new programs via
the existing `bpf_program(name)` macro:

```cmake
bpf_program(dl_map_object)
bpf_program(got_sample)
bpf_program(dlopen_uprobe)
bpf_program(bprm_env)
bpf_program(interp_entry)
bpf_program(dl_audit)
bpf_program(rdebug_sample)
bpf_program(text_sample)
```

Add their `hk_bpf_*_skel` targets to the `hk_bpf_generated` INTERFACE target's
`add_dependencies`. Toolchain unchanged: clang ≥ 14 BPF backend, bpftool ≥ 6.0,
`-target bpf -O2 -g -Wall -Wextra -Werror -mcpu=v3 -nostdinc` (already enforced).
vmlinux.h generated on the build host (uncommitted, CI step).

**Feature flags.** Add a CMake option group so each signal can ship dark:
```cmake
option(HK_BPF_INJECTION_DSO      "Signals 82/87 (DSO provenance/order)"   ON)
option(HK_BPF_INJECTION_GOT      "Signal 83 (GOT/PLT)"                    OFF)
option(HK_BPF_INJECTION_INTERP   "Signal 84 (PT_INTERP)"                  ON)
option(HK_BPF_INJECTION_PRELOAD  "Signals 85/89 (preload/LD_AUDIT)"       ON)
option(HK_BPF_INJECTION_DLOPEN   "Signal 86 (fileless dlopen)"           ON)
option(HK_BPF_INJECTION_RDEBUG   "Signal 88 (_r_debug)"                  OFF)
option(HK_BPF_INJECTION_TEXT     "Signal 90 (text COW)"                  OFF)
```
Defaults: low-FP signals (82/84/85/86/89) **ON**; high-FP or
performance-sensitive sampling signals (83 GOT, 87 inherits 82's program but its
*scoring* is corroborating-only, 88 RDebug via `/proc/pid/mem`, 90
pagemap/smaps) **OFF** until field-validated. The existing top-level
`kernel/linux/CMakeLists.txt` already gates eBPF default-OFF; these are
sub-options under it.

**Userspace (`kernel/linux/userspace/CMakeLists.txt`).** Add the new
`.cpp` correlators + `ElfModel.cpp` + `OverlayAllowlist.cpp` to the
`hk_bpf_loader` STATIC library sources. Keep `-Wall -Wextra -Werror`,
`cxx_std_17`. New link deps: `libelf` (DT_NEEDED/section parsing — `pkg_check_modules(LIBELF REQUIRED libelf)`) and an Ed25519/ECDSA verify lib for the signed allowlist (reuse whatever attestation already links; otherwise libsodium). inotify is libc, no new dep.

**Server.** New ingest route module under `server/api/src/routes` + scoring in
`server/ban-engine`; standard cargo workspace member, no new toolchain.

---

## 6. Test strategy

### 6.1 Unit tests (TDD, guardrail #14)

- `ElfModel` (userspace, gtest): DT_NEEDED closure of a fixture ELF with a known
  needed graph; section-offset/load-bias math against a fixture with known
  `.got.plt`; NT_GNU_BUILD_ID extraction; maps-line parsing for `(deleted)`,
  `memfd:`, anon-exec, `r--p` RELRO.
- `OverlayAllowlist`: signature-verify accept/reject; soname+build-id lookup;
  per-distro scoping; tamper → reject.
- Each correlator: feed a synthetic BPF event + a fixture `/proc` snapshot
  (injected via a `ProcReader` seam so tests don't need a live PID) and assert
  the emitted `hk_event_record` flags. Includes the FP-suppression paths
  (allowlisted overlay → no event; IFUNC slot → no event; tracer-attached →
  suppressed for 88/90; patchelf'd PT_INTERP resolved via manifest → no event).
- Schema: extend the existing wire-size pin test — `HK_STATIC_ASSERT` for the
  three new payload structs (==16) and an `HK_EVENT_SCHEMA_VERSION == 3` mirror
  assert on the Rust side (`server/telemetry` / kernel-event serde).
- Server (cargo, `rust-test` TDD, no `unwrap` outside tests): JSON ingest
  round-trip for each new event; ban-engine asserts signal 87 alone does NOT
  reach ban threshold (corroborating-only); ancestor-attribution for signal 85.

### 6.2 Bypass tests (guardrail #12 — merge gate, one per mechanism class)

These live under `bypass-tests/linux/` (alongside the existing
`ptrace_attach.cpp`), built disabled-by-default like the current gate, each
`add_test`-registered. Each must demonstrate the sensor fires (or, for the
allowlist path, correctly *suppresses*):

| Bypass test | Demonstrates |
|---|---|
| `ldpreload_inject` | LD_PRELOAD a no-provenance DSO → signal 82 + 85 fire; same DSO added to a (test) signed allowlist → suppressed (proves the FP gate). |
| `got_hook` | Overwrite a `.got.plt` slot to a RWX trampoline → signal 83 fires; an IFUNC slot left alone → no event (proves IFUNC exclusion). |
| `interp_shim` | Launch via a patched ld.so path → signal 84 fires; a patchelf'd PT_INTERP resolvable via the (mock) container manifest → suppressed. |
| `memfd_dlopen` | `memfd_create` + `dlopen("/proc/self/fd/N")` an exec DSO → signal 86 fires; file-backed gconv-style dlopen → no event. |
| `loadorder_interpose` | Preload a malloc-interposer ahead of libc with no provenance → signal 87 flagged corroborating; jemalloc-style allowlisted preload → suppressed. |
| `rdebug_hook` | Repoint `_r_debug.r_brk` outside ld.so VMA (no tracer) → signal 88 fires; with a ptrace tracer attached → suppressed. |
| `text_inline_hook` | Patch a byte in a loaded DSO's `.text` (break COW) → signal 90 fires; an IFUNC-prologue dirty page → no event. |
| `ld_audit_inject` | Launch with LD_AUDIT pointing at a no-provenance module → signal 89 fires (la_symbind observed); allowlisted audit module → suppressed. |

The suppression half of each test is the load-bearing part — it proves the FP
gates the catalog demands actually work, not just that the sensor is trigger-happy.

---

## 7. Sequencing

1. **M0 — Foundations (no signal yet).** Schema v3 bump in `event_schema.h`
   (new enum + 3 payload structs + static-asserts), Rust mirror bump, and the
   data-categories.md rows (guardrail #11). Build `ElfModel` + `OverlayAllowlist`
   + the `ProcReader` test seam with full unit coverage. Nothing scores yet.
   *Everything downstream depends on M0.*
2. **M1 — DSO provenance (signals 82, 87).** `dl_map_object.bpf.c` +
   `DsoProvenance.cpp` + `LinkMapOrder.cpp`. 82 lands first (ON); 87 reuses the
   same BPF program, lands as corroborating-only scoring. Bypass:
   `ldpreload_inject`, `loadorder_interpose`.
3. **M2 — Exec-time env (signals 85, 89).** `bprm_env.bpf.c` (LSM) +
   `PreloadWatch.cpp` + `dl_audit.bpf.c`. Shares env capture. Bypass:
   `ldpreload_inject` (env half), `ld_audit_inject`.
4. **M3 — dlopen + interp (signals 86, 84).** `dlopen_uprobe.bpf.c` +
   `DlopenBacking.cpp`; `interp_entry.bpf.c` + `InterpCheck.cpp` (reuses existing
   `sched_process_exec`). Bypass: `memfd_dlopen`, `interp_shim`.
5. **M4 — Memory-integrity samplers (signals 83, 88, 90).** `got_sample.bpf.c` +
   `GotPltMap.cpp` (+ `hk_got_cfg` map); `rdebug_sample.bpf.c` + `RDebugCheck.cpp`;
   `text_sample.bpf.c` + `TextPageBacking.cpp`. All default-OFF (perf + FP). These
   depend on the VMA-map model from M1. Bypass: `got_hook`, `rdebug_hook`,
   `text_inline_hook`.
6. **M5 — Server ingest + scoring.** New `server/api` route + `server/ban-engine`
   weights (87 corroborating-only, 85 ancestor attribution). Fail-closed.

Dependency spine: M0 → M1 (VMA model) → {M3, M4}. M2 is independent of the VMA
model and can land in parallel with M1. M5 trails as each event type lands.

---

## 8. Risks & UNCERTAINTY FLAGS

Per guardrail #13, the following are **flagged, not guessed** — confirm against
the live target glibc/kernel before implementing the attach:

- **glibc internal symbol stability (signals 82, 84, 87, 89).** `_dl_map_object`,
  `_dl_open`, `_dl_audit_symbind`, and the loader entry point are glibc-internal
  and **not part of the stable ABI**. Their names, signatures, and even existence
  vary across glibc versions and are absent on musl (Alpine, some Deck flatpaks).
  Offsets must be resolved per-target at attach via BTF/symbol tables, and the
  uprobe must **fail gracefully (skip the signal, log) when the symbol is absent**
  rather than failing the whole loader. Prefer public exports (`dlopen`,
  `dlmopen`) over internals where the signal allows. **Confirm the exact symbol
  set on the shipping Steam Deck glibc before M1/M3 attach code.**
- **`bprm_creds_for_exec` vs `bprm_committing_creds` (signal 85).** The catalog
  lists both as candidate LSM hooks. Which exists, and whether `linux_binprm->envp`
  is safely readable at that hook, is kernel-version-dependent and **not verified
  here**. envp at exec is a user pointer array that may not yet be fully populated
  in the new mm — reading it in BPF needs confirmation it is valid and bounded at
  the chosen hook. **Flag: confirm hook availability + envp validity on the target
  kernel (Deck 6.x) before writing `bprm_env.bpf.c`.**
- **`/proc/pid/pagemap` semantics + caps (signal 90).** The file-backed /
  soft-dirty bit layout changed across kernels and reading pagemap of another
  process requires `CAP_SYS_ADMIN` (tightened in recent kernels). **Not verified**
  that the loader's capability set (currently CAP_BPF/CAP_PERFMON for LSM) suffices
  for cross-process pagemap. **Flag before M4.**
- **`/proc/pid/mem` read of `_r_debug` (signal 88).** Reading another process's
  `/proc/pid/mem` at a load-biased address has the same ptrace-access-mode gating
  as a debugger; whether the loader can do this without itself becoming a ptrace
  tracer (which would then self-suppress signal 88!) is **unconfirmed**. There is a
  potential self-interference between the read mechanism and the suppression gate.
  **Flag before M4.**
- **uprobe perf cost on hot game functions (signals 83, 90).** Attaching uprobes
  to frequently-called game functions for sampling cadence adds a trap per call;
  on a Steam Deck this could measurably regress frame time. **Not benchmarked.**
  Default-OFF mitigates, but the per-title "benign hot fn" choice and sampling
  rate need profiling before enabling. Consider a timer/`perf`-based cadence as an
  alternative to uprobe cadence — flagged as a design open question.
- **FP severity of signal 87 (load-order inversion).** Catalog rates it
  **highest-FP**. Even with the triple gate, the legitimate-interposer ecosystem
  (jemalloc/tcmalloc/MangoHud/ASan/libfaketime) is large and distro-variable. Plan
  keeps it corroborating-only server-side; do **not** let it raise standalone ban
  weight. Allowlist coverage is an ongoing operational burden, not a one-time task.
- **Signed-allowlist provenance.** The entire FP-control story rests on a current,
  correctly-signed soname+build-id allowlist scoped per distro/Steam-runtime.
  Stale allowlist → mass false positives on a Steam runtime update. Flag as an
  operational dependency: the allowlist must be server-pushed and versioned, not
  baked into the client.

No on-host enforcement, memory writes, or syscall blocking are introduced by any
signal here — all sensors are read-only and audit-only, consistent with the
existing `lsm/file_open` posture and the project's "all ban authority is
server-side" rule.
