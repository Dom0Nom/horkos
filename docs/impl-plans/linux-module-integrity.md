# Linux — Kernel / Module Trust

Scope: read-only host-integrity telemetry over the running Linux kernel's module
trust surface — kallsyms-vs-section drift, module-enumeration cross-view diffs,
ftrace/kprobe hook ownership, in-memory-vs-on-disk `.ko` integrity, lockdown /
signature-enforcement posture, foreign eBPF instrumentation of the protected
process, and module-less kernel-memory access (`/dev/mem`, MSR writes). Every
sensor is **audit-only**: existing LSM programs return the prior `ret` and never
deny; new BPF programs only read and emit; the LKM extension makes **no text
writes** and only reads kernel symbol-table accessors. The client samples and
reports; **all ban authority is server-side** (CLAUDE.md). Most signals here are
trust-tier *weights*, not standalone ban evidence — that gating is explicit per
signal and re-stated in §6.

Covers catalog signals **91–99**:

| # | Signal | Layer | BPF/proc tag → server event |
|---|---|---|---|
| 91 | kallsyms text-address drift vs `.text` section bounds | userspace (proc/sysfs) | `HK_EVENT_KSYM_DRIFT` |
| 92 | module in kobject tree but absent from `/proc/modules` (or vice versa) | eBPF iter + userspace diff | `HK_EVENT_MODULE_VIEW_DIFF` |
| 93 | ftrace handler ownership audit on syscall-entry functions | userspace (tracefs) | `HK_EVENT_FTRACE_HOOK` |
| 94 | kprobe/kretprobe on credential/exec/sig-verify symbols | userspace (debugfs/tracefs) | `HK_EVENT_KPROBE_SENSITIVE` |
| 95 | ksymtab-CRC / build-id mismatch vs on-disk `.ko` | LKM (gated) + userspace | `HK_EVENT_MODULE_DISK_DRIFT` |
| 96 | kernel lockdown level + module-sig-enforcement posture | userspace (securityfs/efivarfs) | `HK_EVENT_KERNEL_POSTURE` |
| 97 | foreign eBPF program enumeration on the game's hook points | userspace (BPF syscall) | `HK_EVENT_FOREIGN_BPF` |
| 98 | `/dev/mem`, `/dev/kmem`, `/dev/port` open/mmap on live kernel | eBPF (extend `lsm_file_open` + tracepoints) | `HK_EVENT_DEVMEM_ACCESS` |
| 99 | MSR write to LSTAR/SYSENTER_EIP/debug MSRs | eBPF (extend tracepoints) | `HK_EVENT_MSR_WRITE_SENSITIVE` |

> **Three structural decisions drive the whole plan.**
>
> 1. **Most of this domain is userspace, not kernel.** Seven of nine signals are
>    procfs/sysfs/debugfs/securityfs reads or BPF-syscall enumeration that the
>    *userspace loader process* performs on a timer — they are not hot-path BPF
>    hooks. Only signals 98 and 99 extend existing `.bpf.c` programs; only signal
>    95's memory-vs-disk CRC compare needs the (gated) LKM. This keeps the kernel
>    attack surface unchanged and most logic testable in plain userspace TUs.
>
> 2. **Payloads exceed today's `HK_EVENT_PAYLOAD_MAX = 16`.** Drift/hook payloads
>    carry a 64-bit address + a 64-bit owner-id + a small string. As established
>    in `linux-ebpf-memory.md` §intro, the BPF→server plane (`Loader.cpp`) does
>    **not** use the fixed `hk_event_record`; it translates each record and calls
>    the sink with `(hk_event_header, payload_ptr)`. New payload structs only need
>    to fit `hk_event_header` + their own size on the Loader sink path. They are
>    added to `event_schema.h` with their own `HK_STATIC_ASSERT`. The Windows
>    IOCTL `hk_event_record` / `HK_EVENT_PAYLOAD_MAX` (40-byte DRAIN plane) is
>    **not** widened. Stated so a reviewer does not reject the schema for
>    "exceeding payload max".
>
> 3. **The userspace sensors do not belong in `Loader.cpp`.** `Loader.cpp` is the
>    BPF poll/translate TU. The periodic proc/sysfs auditors are independent
>    userspace modules that emit through the *same* `HkEventSink` callback type
>    (Loader.h). A new aggregator (`HostIntegritySensors`) owns a timer thread and
>    drives them, so `Loader.cpp` stays a pure ring-buffer pump. This matches the
>    catalog's "reported via Loader.cpp ringbuf bridge" intent without bloating
>    that TU.

---

## 1. New and modified files

### 1.1 New userspace sensor TUs (`kernel/linux/userspace/`)

All are pure Linux userspace TUs (guardrail #4 — no BPF/kernel headers), compile
`-Wall -Wextra -Werror` (guardrail #6 applies to kernel code; we hold userspace
to the same bar as `Loader.cpp` already does), carry the role/platform/interface
module comment (guardrail #3), and use only procfs/sysfs/debugfs reads — no
platform `#ifdef` (guardrail #1; Linux isolation is by directory + CMake
`CMAKE_SYSTEM_NAME STREQUAL "Linux"`).

| Path | Signal | Module-comment summary |
|---|---|---|
| `KallsymsAudit.cpp` / `.h` | 91 | Parse `/proc/kallsyms`; cross-check each sensitive symbol's address against `_stext`/`_etext` (from `/proc/iomem` "Kernel code") and per-module `.text` bounds (`/sys/module/<m>/sections/.text`); detect collisions and out-of-bounds resolution; emit `HK_EVENT_KSYM_DRIFT`. |
| `ModuleViewDiff.cpp` / `.h` | 92 | Diff three module enumerations: `/proc/modules`, `/sys/module/*`, and the eBPF module-iterator view; debounce transient COMING/GOING; emit `HK_EVENT_MODULE_VIEW_DIFF` on a stable single-source discrepancy. |
| `FtraceAudit.cpp` / `.h` | 93 | Read `/sys/kernel/tracing/enabled_functions` (+ `touched_functions` on ≥5.18); attribute each ftrace_ops owner address against the loaded-module text map; flag callbacks on the sensitive function set with an unattributable owner; emit `HK_EVENT_FTRACE_HOOK`. |
| `KprobeAudit.cpp` / `.h` | 94 | Read `/sys/kernel/debug/kprobes/list` + `/sys/kernel/tracing/kprobe_events`; resolve probe addrs to symbols; match against the sensitive-symbol set; flag module-less / unsigned-module probes; emit `HK_EVENT_KPROBE_SENSITIVE`. |
| `LockdownPosture.cpp` / `.h` | 96 | Read `/sys/kernel/security/lockdown`, `/sys/module/module/parameters/sig_enforce`, `/proc/sys/kernel/tainted`, and the efivarfs `SecureBoot` variable; emit `HK_EVENT_KERNEL_POSTURE` (a posture weight, never standalone evidence). |
| `BpfEnumerate.cpp` / `.h` | 97 | Walk loaded BPF objects via `BPF_PROG_GET_NEXT_ID` + `BPF_OBJ_GET_INFO_BY_FD`, and links via `BPF_LINK_GET_NEXT_ID`; flag programs whose attach target is the game/client's own symbols/uprobes and whose tag is not the client's; emit `HK_EVENT_FOREIGN_BPF`. |
| `ModuleDiskDrift.cpp` / `.h` | 95 (userspace half) | Read `/sys/module/<m>/notes/.note.gnu.build-id`; parse the on-disk `.ko` build-id from `/lib/modules/$(uname -r)`; compare; for the in-memory CRC half, consume the LKM-exported per-module CRC view (see §1.3). Emit `HK_EVENT_MODULE_DISK_DRIFT`. |
| `SymbolMap.cpp` / `.h` | shared | Builds the once-per-cycle loaded-module text-bounds map (`_stext.._etext`, per-module `.text`/symbol ranges) consumed by signals 91/93/94. Single source so three auditors do not each re-parse kallsyms. |
| `HostIntegritySensors.cpp` / `.h` | orchestration | Owns the audit timer thread; invokes each sensor on its cadence (§5); emits all events through the shared `HkEventSink`. Does **not** poll the BPF ring buffer (that stays in `Loader.cpp`). |

> **Capability flag.** Several reads require elevated capability (`CAP_SYSLOG`
> for non-zero kallsyms addresses; tracefs/debugfs/securityfs mounts;
> `CAP_BPF`/`CAP_SYS_ADMIN` for BPF enumeration). Each sensor must degrade
> gracefully: a permission/`ENOENT`/unmounted-fs failure emits a single
> `HK_EVENT_SENSOR_UNAVAILABLE` (signal-id in payload) once per cycle, **not** a
> false positive. A sensor that cannot read its source is a *coverage gap to
> report to the server as a trust-tier input*, not evidence of tampering. This is
> a hard requirement — treating "can't read" as "detected" is the dominant FP
> failure mode for this whole domain.

### 1.2 Extended BPF TUs (`kernel/linux/bpf/src/`)

| Path | Signal | Change |
|---|---|---|
| `lsm_file_open.bpf.c` | 98 | Add a devmem/kmem/port/kcore device-node match (major 1, minor 1/2/4; kcore by dentry name under proc) in the existing `lsm/file_open` program; emit a new `HK_EVENT_DEVMEM_ACCESS`-tagged ring record carrying opener pid + a write-intent flag derived from `file->f_mode` (FMODE_WRITE). Audit-only; still returns `ret`. |
| `tracepoints.bpf.c` | 98 + 99 | (a) Add a `sys_enter_mmap` tracepoint correlating PROT_WRITE mmaps of an msr/devmem fd. (b) Add `sys_enter_write` / `sys_enter_pwrite64` programs filtered to fds resolving under `/dev/cpu/N/msr`, decoding the file offset (= MSR index) and flagging writes to the sensitive MSR set (LSTAR `0xC0000082`, SYSENTER_EIP `0x176`, debug/feature-control MSRs). Emit `HK_EVENT_MSR_WRITE_SENSITIVE`. |

> **fd→path resolution is the hard part of 98/99 and is split kernel/userspace.**
> Inside BPF, mapping an fd to "this is `/dev/cpu/3/msr`" robustly is non-trivial
> (you would walk `task->files->fdt->fd[fd]->f_path` via CO-RE, then match
> dentry/inode against the msr/devmem device). The lower-risk split: the BPF
> program emits the raw `(pid, fd, inode_major, inode_minor, file_offset,
> write_intent)` and **userspace** (`Loader.cpp` translate path, or a small
> `MsrPathResolver` helper) resolves the device identity and decides
> sensitivity. The BPF side stays simple and verifier-friendly; the policy lives
> in userspace where it is unit-testable. **FLAGGED for review (§7-A):** confirm
> we read `f_mode`/`inode` via CO-RE rather than assuming a fixed offset.

### 1.3 LKM extension (`kernel/linux/lkm/horkos.c`, behind `HORKOS_LINUX_LKM`)

Signal 95's *in-memory* half needs `struct module->crcs` / `->syms` / `->num_syms`,
which are kernel-internal and not reachable from userspace or (portably) from a
CO-RE BPF program. The LKM gains a **read-only** module-CRC export:

- New file `kernel/linux/lkm/module_crc.c` (+ `module_crc.h`) compiled into the
  existing module; `horkos.c` calls its init/exit. Keeping it a separate TU keeps
  `horkos.c` focused (it is the tracepoint TU) and matches the catalog slot
  "`horkos.c` (extend)".
- It exposes the per-module symbol-version CRC snapshot to userspace through a
  **read-only** interface — chosen carefully (§7-B): a `debugfs` seq_file under
  `horkos/module_crcs` is the simplest rmmod-safe read-only surface and needs no
  new IOCTL. It iterates the module list under the module mutex and emits
  `(name, build_id_or_crc_digest)` lines. **No text writes, no symbol patching.**
- Every kernel return is checked (guardrail #5); only safe string helpers
  (`scnprintf`, `strscpy`) are used (guardrail #5); `-Wall -Wextra -Werror` via
  the existing Makefile `ccflags-y` (guardrail #6).

> **FLAGGED (§7-B):** module-list iteration locking. Walking the module list and
> reading `struct module` fields must be done under the correct lock
> (`module_mutex`) or via the appropriate RCU accessor, and `struct module`
> internals (`crcs`, `syms`, `num_syms`, `state`, `core_layout`/`mem[]`) have
> **changed across kernel versions** (e.g. `module_layout` → `module_memory[]`
> around 6.4). Do **not** guess these. Confirm the locking discipline and the
> per-version field layout against the target kernel(s) before writing field
> reads. A wrong lock or a stale field offset is a deadlock/oops, not a logic
> bug — guardrail #13 applies: stop and flag, which this does.

### 1.4 New BPF TU for signal 92 (`kernel/linux/bpf/src/module_iter.bpf.c`)

A `SEC("iter/...")` BPF program providing the *third* independent module view for
the cross-enumeration diff (signal 92). Catalog names `bpf_iter` / module kset
walk.

> **FLAGGED (§7-C):** there is no stable, documented `bpf_iter` over the kernel
> *module* list in the way there is for tasks/vmas. The catalog references
> `bpf_for_each_kernel_symbol` and a "modules kset" walk; the exact iter target
> name and whether kfuncs for module iteration exist depends on kernel version
> and may require `bpf_iter` registration that is not upstream-stable. Do **not**
> author this program by guessing the iter section/struct. Two acceptable
> fallbacks if the iter is unavailable on the target kernel: (i) drop to a
> two-view diff (`/proc/modules` vs `/sys/module/*`), which already catches the
> classic `list_del` self-unlink (the sysfs kobject usually survives), and report
> reduced coverage; (ii) use the LKM's module-list walk (§1.3) as the third view.
> **Decision required before implementation.** Until resolved, ship signal 92
> with the two userspace views and the LKM view (when the LKM is built); the BPF
> iter is a later upgrade.

### 1.5 Schema additions (`sdk/include/horkos/event_schema.h`)

New event types appended to `hk_event_type` (existing values never change;
guardrail: additive only, bump `HK_EVENT_SCHEMA_VERSION` 2 → 3):

```
HK_EVENT_KSYM_DRIFT            = 5,
HK_EVENT_MODULE_VIEW_DIFF      = 6,
HK_EVENT_FTRACE_HOOK           = 7,
HK_EVENT_KPROBE_SENSITIVE      = 8,
HK_EVENT_MODULE_DISK_DRIFT     = 9,
HK_EVENT_KERNEL_POSTURE        = 10,
HK_EVENT_FOREIGN_BPF           = 11,
HK_EVENT_DEVMEM_ACCESS         = 12,
HK_EVENT_MSR_WRITE_SENSITIVE   = 13,
HK_EVENT_SENSOR_UNAVAILABLE    = 14,   /* coverage gap, not a detection */
```

New payload structs (each with its own `HK_STATIC_ASSERT`; each 8-byte aligned;
fixed size). These travel only the Loader sink plane, **not** the IOCTL record:

| Payload struct | Key fields | Size |
|---|---|---|
| `hk_event_ksym_drift` | `resolved_addr` (u64), `expected_lo`/`expected_hi` (u64×2), `reason` (u32: OOB / collision / shadow), `reserved` (u32) | 32 |
| `hk_event_module_view_diff` | `present_mask` (u32: bit0 procmodules, bit1 sysfs, bit2 bpf/lkm), `module_state` (u32), `name_hash` (u64) | 16 |
| `hk_event_ftrace_hook` | `func_addr` (u64), `ops_owner_addr` (u64), `owner_attributed` (u32: 0/1), `func_id` (u32: index into sensitive-set) | 24 |
| `hk_event_kprobe_sensitive` | `probe_addr` (u64), `symbol_id` (u32), `flags` (u32: OPTIMIZED/DISABLED/MODULELESS), `owner_signed` (u32), `reserved` (u32) | 24 |
| `hk_event_module_disk_drift` | `name_hash` (u64), `reason` (u32: BUILDID_MISMATCH / CRC_MISMATCH / NO_DISK_KO), `reserved` (u32) | 16 |
| `hk_event_kernel_posture` | `lockdown_level` (u32), `sig_enforce` (u32), `secure_boot` (u32), `taint_flags` (u32) | 16 |
| `hk_event_foreign_bpf` | `prog_id` (u32), `prog_type` (u32), `attach_target_id` (u32: game/client symbol index), `prog_tag_lo`/`_hi` would overflow → use `prog_tag_hash` (u64) | 16 |
| `hk_event_devmem_access` | `requesting_pid` (u32), `dev_minor` (u32), `write_intent` (u32), `mmap_prot_write` (u32) | 16 |
| `hk_event_msr_write` | `requesting_pid` (u32), `msr_index` (u32), `sensitive` (u32), `reserved` (u32) | 16 |
| `hk_event_sensor_unavailable` | `signal_id` (u32), `errno_value` (u32) | 8 |

> Field names use the established convention (`requesting_pid` etc.). No strings
> in payloads — names are hashed to a u64 (`name_hash`) and the raw name, when an
> operator needs it, is carried out-of-band in a side table keyed by hash, to keep
> payloads fixed-size and PII-minimal. Symbol/function identities are interned to
> a small enum index (`func_id`, `symbol_id`, `attach_target_id`) shared with the
> server.

### 1.6 Server mirror (`server/telemetry/`)

The kernel-event plane is mirrored server-side per the existing pattern. Add a
`server/telemetry/src/kernel_events.rs` (if not already present from a sibling
plan) with serde structs mirroring the new payloads, `#[repr(C)]` byte-compatible
where the ingest is binary, plus a `KernelEventKind` enum mirroring
`hk_event_type`. Bump the kernel-event mirror version in lockstep with
`HK_EVENT_SCHEMA_VERSION` 3. `thiserror` for any new error type; no `unwrap()`
outside `#[cfg(test)]` (guardrail #8). The ban/trust-scoring logic stays in
`server/ban-engine/`; telemetry only ingests and validates.

> **Cross-plane note:** signals 96/97/etc. are *posture weights*. The server must
> treat `HK_EVENT_KERNEL_POSTURE` and `HK_EVENT_SENSOR_UNAVAILABLE` as trust-tier
> inputs, **never** as standalone ban evidence (catalog FP guidance, signals 96
> = high FP, 98/99 = gated). The ban-engine rule for this domain requires
> corroboration (e.g. posture-weak AND an unattributed ftrace hook on
> `commit_creds`). Encode that as a rule, not as client logic.

---

## 2. Interfaces

### 2.1 Userspace sensor interface (new `kernel/linux/userspace/HostIntegritySensors.h`)

```c
/* Each sensor is a function with this shape; the aggregator calls them on a
 * cadence and forwards emitted events through the shared HkEventSink (Loader.h).
 * Return 0 on a completed cycle (even if it emitted "unavailable"); negative
 * errno only on an unrecoverable internal error. Sensors never block. */
typedef int (*HkHostSensorFn)(const struct HkSymbolMap *map, HkEventSink sink);

int  hk_host_integrity_start(HkEventSink sink);   /* spawns the timer thread   */
void hk_host_integrity_stop(void);               /* same thread-safety contract
                                                     as the Loader: stop on the
                                                     owning thread, flag first  */
```

`HkSymbolMap` (from `SymbolMap.h`) is the shared, refreshed-per-cycle view of
`_stext`/`_etext` + per-module text bounds, built once and passed to 91/93/94 so
they do not each re-parse kallsyms.

`HkEventSink` is **reused unchanged** from `Loader.h` (guardrail #10 spirit: the
event-emission contract is stable; sensors are new backends behind it). The
sink callback signature `(const hk_event_header*, const void* payload)` already
carries everything these payloads need.

### 2.2 BPF↔userspace contract for 98/99

The new BPF ring records (`HkBpfDevmemEvent`, `HkBpfMsrEvent`) are redeclared in
`Loader.cpp` exactly as the existing `HkBpf*Event` structs are (guardrail #4 —
the BPF structs are mirrored, not shared via a common header), with new BPF-side
tags `kBpfTagDevmem = 0x30`, `kBpfTagMsrWrite = 0x31`. `Loader.cpp`'s
`on_ringbuf_sample` switch gains two arms translating these to
`HK_EVENT_DEVMEM_ACCESS` / `HK_EVENT_MSR_WRITE_SENSITIVE`. The fd→device
resolution for 99 happens here (or in `MsrPathResolver`), not in BPF (§1.2).

### 2.3 No IOCTL change

These are Linux signals. The Windows IOCTL contract (`sdk/include/horkos/ioctl.h`)
is **untouched** — its `hk_event_record` / `HK_EVENT_PAYLOAD_MAX` / DRAIN
envelope is the Windows KMDF plane only. The Linux events ride the Loader sink →
server HTTP path, never the IOCTL DRAIN buffer. (Re-stated to forestall a
reviewer widening the IOCTL record.) If the LKM ever needs a userspace channel
beyond debugfs, that is a separate chardev decision flagged at that time, not in
this plan.

---

## 3. OS-API integration notes (safety / capability / version concerns)

| API / source | Concern | Mitigation |
|---|---|---|
| `/proc/kallsyms` | Addresses are `0000…` without `CAP_SYSLOG` and `kptr_restrict`. Zeroed addresses make drift detection impossible. | Detect zeroed addrs → emit `SENSOR_UNAVAILABLE(91)`, do not false-positive. Require the loader run with `CAP_SYSLOG`. |
| `/proc/iomem` "Kernel code" | Same `kptr_restrict` gating; resource names stable but ordering is not. | Match by resource name, not index. Degrade to `SENSOR_UNAVAILABLE` if zeroed. |
| `/sys/kernel/tracing/*` | tracefs may be unmounted; `touched_functions` only ≥5.18. | Probe mount; fall back to `enabled_functions` alone on <5.18; never assume mounted. |
| `/sys/kernel/debug/kprobes/list` | debugfs often not mounted on hardened/gaming hosts; format has DISABLED/OPTIMIZED flag columns that vary. | Mount-probe; parse defensively (column-count tolerant); on absence emit unavailable. |
| `/sys/kernel/security/lockdown`, efivarfs SecureBoot | securityfs/efivarfs may be absent; efivar GUID `8be4df61-93ca-11d2-aa0d-00e098032b8c`. | Treat absence as "unknown posture" weight, not "insecure". |
| BPF syscall enumeration (`BPF_PROG_GET_NEXT_ID` etc.) | Needs `CAP_BPF`/`CAP_SYS_ADMIN`; iterating others' progs may be blocked by `kernel.unprivileged_bpf_disabled` / LSM. | Degrade to unavailable; never infer tampering from an enumeration denial. |
| **eBPF 98/99 — IRQL/preempt analog** | BPF programs run in (soft)irq/tracepoint context; only bounded loops, no sleeping helpers, must pass the verifier. fd→path walk via CO-RE risks verifier complexity blowups. | Keep BPF side minimal (emit raw fd/inode/offset); resolve in userspace. `-O2`, `-mcpu=v3` as existing. |
| **LKM module-list walk (95)** | Wrong lock = deadlock/oops; `struct module` layout changed across versions. | **FLAGGED §7-B.** Read-only, correct lock, per-version field guards, or do not ship the in-memory CRC half (build-id-only via userspace still works). |
| `bpf_iter` module view (92) | Iter target may not exist / not be stable. | **FLAGGED §7-C.** Ship two-view + LKM-view diff; BPF iter is an upgrade. |

### Audit-only invariant (guardrails #7 analog for Linux LSM)

The extended `lsm/file_open` program for signal 98 **must still return `ret`**
(never a hard 0, never a deny) — exactly as the existing program does. Adding the
devmem match must not change the return path. A bypass test asserts the return
value is unchanged.

---

## 4. Build wiring

- **`kernel/linux/userspace/CMakeLists.txt`** — add the new sensor `.cpp` files to
  a new `hk_host_integrity` static library (sibling to `hk_bpf_loader`), or to the
  existing `hk_bpf_loader` target. Prefer a **separate `hk_host_integrity`
  library** so the userspace auditors build and unit-test without the BPF
  skeleton/`libbpf` dependency (signals 91/93/94/95-userspace/96 need no
  `libbpf`; only 97 `BpfEnumerate` links `libbpf`). This lets the proc/sysfs
  parsers be tested on any Linux CI box without a BPF toolchain. `97` and the
  Loader translate-path stay in the `libbpf`-linked target.
- Both libraries keep `-Wall -Wextra -Werror` and `cxx_std_17`, matching
  `hk_bpf_loader`.
- **`kernel/linux/bpf/CMakeLists.txt`** — register `module_iter` via the existing
  `bpf_program(module_iter)` macro *only once §7-C is resolved*; until then, do
  not add it (a non-compiling guessed iter would break the gated CI build).
  `lsm_file_open` and `tracepoints` edits need no CMake change (same files).
- **`kernel/linux/lkm/` Makefile + CMakeLists** — add `module_crc.c` to the
  Kbuild `obj-m` object list; debugfs requires `CONFIG_DEBUG_FS=y` (probe at init,
  fail gracefully if absent). Keep behind `HORKOS_LINUX_LKM` (default OFF).
- **`server/telemetry`** — `kernel_events.rs` added to the crate; `Cargo.toml`
  unchanged (serde already present). `cargo test` gate.
- **`server/api/data-categories.md`** — updated in the **same PR** (guardrail #11,
  §8 below). This is a merge blocker.

---

## 5. Sequencing & cadence

Audit cadence is deliberately slow — these are not per-event hot paths and the
sources are expensive to parse:

1. **SymbolMap refresh** — every 60 s (or on a module-load/unload eBPF wake from
   the existing exec/module plane, future optimization). Prereq for 91/93/94.
2. **91 / 93 / 94** — every 60 s, consuming the fresh SymbolMap.
3. **92 (view diff)** — every 30 s with the catalog's mandated 500 ms
   re-sample debounce: two consecutive snapshots must agree before emitting, to
   absorb insmod/rmmod races and `MODULE_STATE_COMING/GOING`.
4. **95 (disk drift)** — every 5 min (on-disk `.ko` parsing is heavy); build-id
   half always, CRC half only when the LKM debugfs view is present.
5. **96 (posture)** — once at startup + every 10 min (rarely changes).
6. **97 (foreign BPF)** — every 60 s.
7. **98 / 99** — event-driven via the BPF ring buffer (no timer); already on the
   Loader poll loop.

Implementation order (each lands under `/tdd` where testable — guardrail #14):

1. Schema additions + `HK_STATIC_ASSERT`s + server mirror (§1.5/§1.6) — pure data,
   fully testable, unblocks everything.
2. `SymbolMap` + `KallsymsAudit` (91) — establishes the proc/sysfs parsing +
   fixture-test pattern reused by 93/94.
3. `FtraceAudit` (93), `KprobeAudit` (94), `LockdownPosture` (96) — same pattern.
4. `ModuleViewDiff` (92, two-view + LKM-view) and `ModuleDiskDrift` (95
   build-id half).
5. `BpfEnumerate` (97).
6. BPF extensions 98/99 + Loader translate arms.
7. LKM `module_crc.c` (95 CRC half) — **only after §7-B resolved.**
8. `module_iter.bpf.c` (92 BPF view) — **only after §7-C resolved.**

---

## 6. FP gating (per signal, from catalog)

The catalog FP guidance is binding and lives mostly **server-side** (clients
report raw evidence; the server applies allowlists and trust weighting):

- **91:** allowlist livepatch module prefixes (`klp_*`, `kpatch_*`); confirm
  relocation target lands in a signed `/sys/module` entry. Drift outside that =
  signal.
- **92:** 500 ms debounce + ignore `MODULE_STATE_COMING/GOING`.
- **93:** attribute each `ftrace_ops` owner to a signed module / registered tracer
  PID; flag only the credential/exec/ptrace-shadow function set, not all
  instrumented functions. Falco/Tetragon/Datadog/bpftrace/livepatch allowlisted
  server-side.
- **94:** allowlist probes owned by known signed EDR/observability modules; flag
  only anonymous/unsigned/module-less probes on the sensitive set.
- **95:** trust the **on-disk `.ko` build-id as the reference** (not a central
  baseline) so DKMS rebuilds (NVIDIA/VBox/ZFS/v4l2loopback) don't trip; flag only
  same-file memory-vs-disk divergence or no-backing-`.ko`.
- **96 (high FP):** posture **weight only**, never standalone. Arch/self-built/Deck
  with unsigned out-of-tree modules is normal.
- **97:** flag by **attach-target** (game/client own symbols), not mere presence;
  allowlist systemd-unit-loaded / known-bffs-pinned programs.
- **98:** flag **write-intent** opens (`O_RDWR`/`O_WRONLY`) and `PROT_WRITE`
  mmaps, not read-only DMI scans; allowlist short-lived read-only tool comms
  (dmidecode, flashrom, hwinfo).
- **99:** gate by **MSR index** — power/perf MSRs (`0x150`, `0x199`, `0x1A0`)
  benign; LSTAR/SYSENTER_EIP/debug MSRs not; exclude read-only `rdmsr`.

All allowlists are server-side data (rule bundle), not hardcoded in the client —
so they update without a client redeploy and cannot be read out of the binary.

---

## 7. Items FLAGGED — STOP before coding (guardrail #13)

- **§7-A (98/99 BPF fd→device resolution).** Confirm the CO-RE path for reading
  `file->f_mode` (FMODE_WRITE) and the device `inode` major/minor at the
  `lsm/file_open` / mmap hook, vs. resolving in userspace. Lower-risk default
  (chosen above): BPF emits raw fields, userspace resolves. Confirm before
  authoring the BPF edits.
- **§7-B (LKM `struct module` access for 95).** Module-list locking
  (`module_mutex` vs RCU) and the per-version field layout (`crcs`/`syms`/
  `num_syms`/`state`; `module_layout` → `module_memory[]` ~6.4). **Do not guess.**
  Verify against the target kernel(s). If unresolved, ship build-id-only (no LKM
  CRC half) — still detects substitution.
- **§7-C (BPF module iterator for 92).** No confirmed stable `bpf_iter` over the
  module list / kset. Decide: ship two-view + LKM-view diff now (recommended),
  add the BPF iter later once the iter target is confirmed for the target kernel.
- **General:** any sensor whose source FS is unmounted or `CAP_*`-denied emits
  `SENSOR_UNAVAILABLE`, never a detection. This is the single most important
  correctness rule in the domain and is asserted by tests in §8.

These are flagged, not coded — consistent with "a BSOD/oops is worse than a delay."

---

## 8. Tests

### 8.1 Unit tests (`/tdd`, fixture-driven, no live kernel needed)

The proc/sysfs/debugfs parsers are tested against **captured text fixtures**
(checked into `kernel/linux/userspace/tests/fixtures/`), so CI needs no special
kernel:

- `kallsyms_audit_test` — fixtures: clean kallsyms, an out-of-bounds symbol, a
  two-symbol address collision, a livepatch-prefixed relocation (must NOT flag),
  and a zeroed-address (`kptr_restrict`) capture (must emit `SENSOR_UNAVAILABLE`,
  not a drift).
- `ftrace_audit_test` — fixtures: clean `enabled_functions`, a hook on
  `commit_creds` owned by an unattributable ops (flag), a hook owned by a signed
  tracer module (no flag), a pre-5.18 capture without `touched_functions`.
- `kprobe_audit_test` — module-less probe on `commit_creds` (flag); signed-EDR
  probe (no flag); OPTIMIZED-flag parsing.
- `module_view_diff_test` — sysfs-present/procmodules-absent (flag after
  debounce); transient COMING-state single-source (no flag); agreement (no flag).
- `lockdown_posture_test` — SecureBoot-on + lockdown=none (posture weight emitted,
  no detection); all-absent FS (unknown weight).
- `module_disk_drift_test` — build-id match (no flag); mismatch (flag); DKMS
  rebuild scenario via differing-but-self-consistent build-ids (no flag);
  no-backing-`.ko` (flag).
- `bpf_enumerate_test` — mock `bpf_prog_info` set: foreign prog on game symbol
  (flag); client's own tag (no flag); systemd-loaded allowlisted (no flag).
- `msr_path_resolver_test` — offset 0xC0000082 → sensitive; 0x150 → benign;
  rdmsr/read-only → ignored.
- Schema: `HK_STATIC_ASSERT` sizes compile; server serde round-trip for each new
  payload; kernel-mirror version == `HK_EVENT_SCHEMA_VERSION`.

### 8.2 Bypass tests (`bypass-tests/` — MERGE GATE, guardrail #12)

Any change under `kernel/linux/` and the new schema requires corresponding bypass
tests. These assert the **evasion the signal is designed to catch is in fact
caught**, and that the audit-only invariant holds:

- `bypass-tests/linux/module_unlink_hidden.sh` — load a benign test module that
  `list_del`-unlinks itself from `/proc/modules` while keeping its sysfs kobject;
  assert signal 92 emits `MODULE_VIEW_DIFF` after debounce. (Test module is a
  research artifact under `bypass-tests/`, not shipped.)
- `bypass-tests/linux/ftrace_hook_commit_creds.sh` — attach a benign ftrace hook
  to `commit_creds` from an unsigned module; assert 93 flags it and does **not**
  flag the same hook when owned by an allowlisted signed module.
- `bypass-tests/linux/devmem_write_open.sh` — open `/dev/mem` `O_RDWR`; assert 98
  emits with `write_intent=1`; open read-only → no write-intent flag; **assert
  `lsm/file_open` still returned `ret` (audit-only invariant)**.
- `bypass-tests/linux/msr_lstar_write.sh` — write to `/dev/cpu/0/msr` at the LSTAR
  offset (in a throwaway VM); assert 99 flags it; write a power MSR → no flag.
- `bypass-tests/linux/sensor_unavailable.sh` — run sensors with tracefs unmounted
  / `kptr_restrict=2`; assert `SENSOR_UNAVAILABLE`, **zero false detections**.

Bypass tests that require a live kernel are gated to the BPF/LKM CI runner (same
runner that enables `HORKOS_LINUX_EBPF`); the unmounted-fs and parser bypass
tests run anywhere.

---

## 9. data-categories.md update (same PR — guardrail #11)

Add a new section **"5. Kernel / module trust telemetry (Linux)"** declaring every
new reported field with source, retention, legal basis, operator-of-record —
mirroring the existing table style. Fields: `resolved_addr`/`expected_lo`/`_hi`,
`func_addr`/`ops_owner_addr`, `probe_addr`/`symbol_id`, `name_hash`,
`lockdown_level`/`sig_enforce`/`secure_boot`/`taint_flags`, `prog_id`/
`prog_type`/`prog_tag_hash`, `dev_minor`/`write_intent`, `msr_index`,
`signal_id`/`errno_value`. Retention default 90 days (legitimate interest —
anti-cheat enforcement), except posture fields which are session-lifetime trust
inputs. Note explicitly that `name_hash` is a non-reversible digest (no raw
module/file names persisted in the event plane). **This file MUST change in the
same PR or the reviewer rejects it.**

---

## 10. Guardrail compliance summary

| # | How this plan satisfies it |
|---|---|
| 1 | No raw platform macros; Linux isolation by directory + CMake `CMAKE_SYSTEM_NAME`. |
| 3 | Every new file carries role/platform/interface module comment (§1 tables specify each). |
| 4 | Kernel (`.bpf.c`, LKM) and userspace TUs never share a TU; BPF structs mirrored, not shared-header. |
| 5 | LKM uses `scnprintf`/`strscpy` only; every kernel return checked; read-only, no text writes. |
| 6 | All kernel code (`.bpf.c`, LKM) `-Wall -Wextra -Werror`; userspace held to same bar. |
| 7 | (Windows ES analog) Linux LSM stays audit-only — `lsm/file_open` returns `ret`; asserted by bypass test. |
| 8 | Server additions fully async on tokio, `thiserror`, no `unwrap()` outside tests. |
| 10 | `Attestation.h` untouched; the `HkEventSink` emission contract reused unchanged. |
| 11 | `data-categories.md` updated same PR (§9) — merge blocker. |
| 12 | `bypass-tests/` added for every security-folder change (§8.2) — merge gate. |
| 13 | Three kernel-API uncertainties FLAGGED and explicitly not coded (§7). |
| 14 | Logic lands under `/tdd`; scaffolding-only files carry comments, behavior is test-driven (§5 order). |
