# Linux eBPF — Memory Access

Scope: read-only eBPF sensors over the protected game process's address space and
the kernel choke points an external/in-process memory cheat must cross —
ptrace authorization, `process_vm_writev`/`readv`, `/proc/<pid>/mem`, W^X /
RWX mappings, fileless `memfd`→exec, foreign mmap of the game's inode, periodic
VMA-inventory drift, and `PTRACE_TRACEME` self-arm. Every program is **audit-only**
(LSM hooks return the prior `ret`, never deny); the kernel emits raw evidence and
**all verdicts are server-side** (clients sample + report only).

Covers catalog signals **73–81**:

| # | Signal | BPF tag → server event |
|---|---|---|
| 73 | `ptrace_access_check` authorization-context capture (LSM) | `HK_EVENT_PTRACE_ACCESS` |
| 74 | `process_vm_writev`/`readv` foreign-writer fexit byte accounting | `HK_EVENT_VM_WRITE` / `HK_EVENT_VM_READ` |
| 75 | `/proc/<pid>/mem` foreign opener via fentry on `mem_open` | `HK_EVENT_PROC_MEM_OPEN` |
| 76 | RWX / W^X-violation mapping inside the protected mm | `HK_EVENT_RWX_MAP` / `HK_EVENT_WX_FLIP` |
| 77 | `memfd_create`→`execveat(AT_EMPTY_PATH)` fileless-exec correlation | `HK_EVENT_MEMFD_CREATE` / `HK_EVENT_FILELESS_EXEC` |
| 78 | `/dev/mem`, `/dev/kmem`, `/proc/kcore` physical-memory window opens | `HK_EVENT_PHYSMEM_OPEN` |
| 79 | Foreign mmap of the game's own file-backed text/data inode | `HK_EVENT_FOREIGN_MAP` |
| 80 | VMA-iterator executable-region inventory drift (`iter/task_vma`) | `HK_EVENT_VMA_DRIFT` |
| 81 | `PTRACE_TRACEME` self-debug pre-arm (LSM) | `HK_EVENT_PTRACE_TRACEME` |

> **Two structural decisions drive the whole plan.**
>
> 1. **Protected-target gating is a shared kernel map, not per-program logic.**
>    All nine signals fire only when the *protected* tgid/mm/inode is the subject.
>    That set is populated from userspace (attestation backend) into one pinned
>    `BPF_MAP_TYPE_HASH` (`hk_protected`) that every new `.bpf.c` reads. Without
>    it, signals 74/75/76/79/80 are unfilterable firehoses that blow the FP budget.
>
> 2. **Payloads exceed today's `HK_EVENT_PAYLOAD_MAX = 16`.** Several payloads
>    carry two pids + a 64-bit byte count or (dev,inode,vm_start,vm_end,flags).
>    The existing BPF→server plane (Loader.cpp) does **not** use `hk_event_record`;
>    it translates each BPF record and calls the sink with `(hk_event_header,
>    payload_ptr)`. So new payload structs only have to fit `hk_event_header` +
>    their own size on the Loader sink path — they do **not** touch the Windows
>    IOCTL `HK_EVENT_PAYLOAD_MAX` 40-byte record. New payloads are added to
>    `event_schema.h` with their own `HK_STATIC_ASSERT`; the IOCTL `hk_event_record`
>    array is **not** widened (it is the Windows DRAIN plane only). This is called
>    out in §3 so a reviewer does not reject the schema for "exceeding payload max".

---

## New files

All new BPF TUs are Linux-eBPF-only, live under `kernel/linux/bpf/src/`, are gated
by the existing `kernel/linux/bpf/CMakeLists.txt` Linux check (guardrail #1: no
raw `__linux__`; platform isolation is by directory + CMake `CMAKE_SYSTEM_NAME`),
are pure kernel TUs with no userspace headers (guardrail #4), and compile
`-Wall -Wextra -Werror` (guardrail #6). Every file carries the module comment
(guardrail #3: role / target platform / interface), matching the existing
`lsm_file_open.bpf.c` header style.

| Path | Role | Module-comment summary |
|---|---|---|
| `kernel/linux/bpf/src/lsm_ptrace.bpf.c` | Signals 73 + 81 | LSM programs `lsm/ptrace_access_check` and `lsm/ptrace_traceme`; capture cred/mode/ret context for inbound attach and self-arm; audit-only (return `ret`); read `hk_protected` map; emit to `hk_ringbuf`. |
| `kernel/linux/bpf/src/fexit_process_vm.bpf.c` | Signal 74 | `fexit/process_vm_writev` + `fexit/process_vm_readv` (TRACING/BTF); resolve target task→mm, compare to protected mm, read `long` bytes-transferred return; emit write/read events. |
| `kernel/linux/bpf/src/fentry_proc_mem.bpf.c` | Signal 75 | `fentry/mem_open` (fs/proc/base.c) — recover target pid from `proc_inode->pid`, compare tgid to protected set, flag cross-tgid opener; path-independent. |
| `kernel/linux/bpf/src/lsm_mmap_mprotect.bpf.c` | Signals 76 + 79 | LSM `lsm/mmap_file` + `lsm/file_mprotect`; detect RWX / text→writable flips in protected mm (76) and foreign-tgid mmap of the protected (dev,inode) (79); audit-only. |
| `kernel/linux/bpf/src/memfd_exec.bpf.c` | Signal 77 | tracepoint `sys_enter_memfd_create` (record fd+flags into per-task LRU map) + `lsm/bprm_creds_for_exec`; emit create + fileless-exec tags; final join in Loader.cpp. |
| `kernel/linux/bpf/src/lsm_devmem.bpf.c` | Signal 78 | `lsm/file_open` filtered by `i_rdev` (MEM major 1: /dev/mem=1, /dev/kmem=2) + kcore proc inode; cross-checks `security_locked_down`; emit physmem-open. |
| `kernel/linux/bpf/src/iter_task_vma.bpf.c` | Signal 80 | `iter/task_vma` BPF iterator (kernel ≥ 5.13), userspace-triggered; emit `(vm_start, vm_end, vm_flags, dev, inode, anon)` per `VM_EXEC` VMA of the protected task for snapshot/diff. |
| `kernel/linux/bpf/include/hk_protected.bpf.h` | Shared (all 9) | BPF-side header declaring the `hk_protected` `BPF_MAP_TYPE_HASH` map + the `struct hk_protected_val { __u64 dev; __u64 inode; ... }` and `hk_is_protected_tgid()` static inline. Pure BPF TU header (vmlinux.h types only; no stdint/libc). |
| `kernel/linux/userspace/ProtectedSet.h` / `ProtectedSet.cpp` | Userspace | Populates/updates the `hk_protected` map from the attestation backend's recorded (tgid, mm-via-pidfd, dev, inode); userspace-only TU (guardrail #4). Declares `hk_protected_set_pid()` / `hk_protected_clear()`. |
| `bypass-tests/linux/vm_write_attach.cpp` | Merge gate (12) | Standalone tool that issues `process_vm_writev` against a victim pid; asserts signal 74 fires. |
| `bypass-tests/linux/proc_mem_open.cpp` | Merge gate (12) | Opens `/proc/<victim>/mem` cross-tgid; asserts signal 75 fires. |
| `bypass-tests/linux/wx_flip.cpp` | Merge gate (12) | mmaps RW then `mprotect`s to RX inside its own mm; asserts signal 76 W^X flip fires. |
| `bypass-tests/linux/memfd_exec.cpp` | Merge gate (12) | `memfd_create`→write ELF→`execveat(AT_EMPTY_PATH)`; asserts signal 77 correlation fires. |
| `bypass-tests/linux/devmem_open.cpp` | Merge gate (12) | Attempts `/dev/mem` / `/proc/kcore` open; asserts signal 78 fires (skips with `GTEST_SKIP`-equivalent if lockdown denies the open). |

`Loader.cpp` and `Loader.h` are **edited, not added** (new tag constants, new
BPF-side structs, new translation arms, the `memfd`↔`exec` correlation LRU, and
the `iter/task_vma` snapshot/diff trigger). `event_schema.h`, `kernel/linux/bpf/CMakeLists.txt`,
`server/api/data-categories.md` are edited (see below).

---

## Interfaces & data structures

### event_schema.h additions

Bump `HK_EVENT_SCHEMA_VERSION` to `3u` (additive; no renames; the BPF-side
`HK_SCHEMA_VERSION` mirrors must bump in lockstep, as the existing files note).

New enum values appended (existing values never change):

```c
HK_EVENT_PTRACE_ACCESS  = 5,   /* signal 73 */
HK_EVENT_PTRACE_TRACEME = 6,   /* signal 81 */
HK_EVENT_VM_WRITE       = 7,   /* signal 74 (read direction = same struct, type 8) */
HK_EVENT_VM_READ        = 8,
HK_EVENT_PROC_MEM_OPEN  = 9,   /* signal 75 */
HK_EVENT_RWX_MAP        = 10,  /* signal 76 mmap */
HK_EVENT_WX_FLIP        = 11,  /* signal 76 mprotect */
HK_EVENT_MEMFD_CREATE   = 12,  /* signal 77 stage A */
HK_EVENT_FILELESS_EXEC  = 13,  /* signal 77 stage B (post-correlation) */
HK_EVENT_PHYSMEM_OPEN   = 14,  /* signal 78 */
HK_EVENT_FOREIGN_MAP    = 15,  /* signal 79 */
HK_EVENT_VMA_DRIFT      = 16,  /* signal 80 */
```

New fixed-size payload structs (each gets its own `HK_STATIC_ASSERT`; all
`<stdint.h>`-typed, no padding ambiguity — explicit `reserved` words):

```c
/* 73 / 81 — ptrace authorization context */
typedef struct hk_event_ptrace {
    uint32_t caller_pid;     /* requester tgid (73) or would-be tracer (81) */
    uint32_t target_pid;     /* protected tgid */
    uint32_t mode;           /* PTRACE_MODE_* bits (73); 0 for traceme (81)  */
    uint32_t caller_uid;     /* caller cred uid                              */
    int32_t  lsm_ret;        /* LSM-stack decision (0 = granted)             */
    uint32_t reserved;
} hk_event_ptrace;                          /* 24 bytes */

/* 74 — cross-mm vm read/write */
typedef struct hk_event_vm_access {
    uint32_t caller_pid;     /* writer/reader tgid                           */
    uint32_t target_pid;     /* protected tgid                               */
    int64_t  bytes;          /* fexit return: bytes transferred (<0 = errno) */
} hk_event_vm_access;                       /* 16 bytes */

/* 75 — /proc/<pid>/mem foreign open */
typedef struct hk_event_proc_mem_open {
    uint32_t caller_pid;
    uint32_t target_pid;     /* tgid backing the opened mem inode            */
} hk_event_proc_mem_open;                   /* 8 bytes */

/* 76 / 79 — mapping anomaly (RWX map, W^X flip, foreign inode map) */
typedef struct hk_event_map_anomaly {
    uint32_t caller_pid;
    uint32_t prot;           /* requested PROT_* bits                        */
    uint32_t vm_flags;       /* existing VMA VM_* (mprotect/foreign-map path) */
    uint32_t reserved;
    uint64_t dev;            /* backing super_block s_dev (0 = anon)         */
    uint64_t inode;          /* backing i_ino (0 = anon)                     */
} hk_event_map_anomaly;                     /* 32 bytes */

/* 77 — memfd create + fileless exec */
typedef struct hk_event_memfd {
    uint32_t pid;
    uint32_t mfd_flags;      /* MFD_CLOEXEC / MFD_ALLOW_SEALING              */
    uint64_t inode;          /* anon shmem inode of the memfd               */
} hk_event_memfd;                           /* 16 bytes */

/* 78 — physical-memory window open */
typedef struct hk_event_physmem_open {
    uint32_t caller_pid;
    uint32_t rdev;           /* i_rdev of opened node (MEM major/minor)      */
    uint32_t locked_down;    /* security_locked_down state at open          */
    uint32_t reserved;
} hk_event_physmem_open;                    /* 16 bytes */

/* 80 — one executable VMA row in a drift snapshot */
typedef struct hk_event_vma_row {
    uint32_t pid;
    uint32_t vm_flags;       /* VM_EXEC | VM_WRITE | ...                     */
    uint64_t vm_start;
    uint64_t vm_end;
    uint64_t dev;            /* 0 = anonymous                                */
    uint64_t inode;
} hk_event_vma_row;                         /* 40 bytes */
```

**IOCTL note:** these payloads are **not** added to the Windows `hk_event_record`
union and do **not** require widening `HK_EVENT_PAYLOAD_MAX` in `ioctl.h`. The
Linux path delivers them via the `Loader.cpp` sink `(hk_event_header*, void*)`,
which has no fixed payload-size ceiling. If a later phase routes these over the
Windows DRAIN plane, that PR — not this one — bumps `HK_EVENT_PAYLOAD_MAX` to 40
(largest is `hk_event_vma_row`) and re-pins the `hk_event_record` static assert.

### BPF-side wire structs (in each .bpf.c, mirrored in Loader.cpp)

Following the existing pattern (`struct hk_bpf_*_event` in the `.bpf.c`,
redeclared in `Loader.cpp` to keep guardrail #4), every BPF record begins with
`{ __u32 schema_version; __u32 event_tag; __u64 timestamp_ns; }` then the
signal-specific fields. New BPF-side tags (BPF-internal, not the schema enum;
loader maps them):

```
0x30 HK_BPF_PTRACE_ACCESS   0x31 HK_BPF_PTRACE_TRACEME
0x40 HK_BPF_VM_WRITE        0x41 HK_BPF_VM_READ
0x50 HK_BPF_PROC_MEM_OPEN
0x60 HK_BPF_RWX_MAP         0x61 HK_BPF_WX_FLIP        0x62 HK_BPF_FOREIGN_MAP
0x70 HK_BPF_MEMFD_CREATE    0x71 HK_BPF_FILELESS_EXEC
0x80 HK_BPF_PHYSMEM_OPEN
0x90 HK_BPF_VMA_ROW
```

### Shared protected-set map (`hk_protected.bpf.h`)

```c
struct hk_protected_val {
    __u64 dev;        /* main-executable backing dev   */
    __u64 inode;      /* main-executable backing inode */
    __u64 load_done_ns; /* ktime after dynamic linker settled (signals 76/80) */
};
/* key = protected tgid (u32) */
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 64);
         __type(key, __u32); __type(value, struct hk_protected_val); } hk_protected SEC(".maps");
```

`load_done_ns` lets signals 76/79/80 separate post-link patches from loader
activity (catalog calls this out explicitly).

### data-categories.md (guardrail #11)

Every new telemetry field above is a new category row. Add under a new
**"### 2b. Memory-access events (Linux eBPF)"** section: `caller_pid`,
`target_pid`, `mode`, `caller_uid`, `lsm_ret`, `bytes`, `prot`, `vm_flags`,
`dev`, `inode`, `mfd_flags`, `rdev`, `locked_down`, `vm_start`, `vm_end` — each
with Source = "Linux eBPF memory hooks", Retention 90 days, Legal basis
"Legitimate interest — anti-cheat enforcement", Operator "Horkos Service Operator".
`caller_uid` is the only one with personal-data weight; flag it for the DPIA.
**This file is edited in the same PR as event_schema.h or the reviewer rejects it.**

---

## Mechanism implementation notes

**Common (all Linux eBPF):** CO-RE only (`BPF_CORE_READ` / `bpf_core_read`); no
fixed offsets, no `vmlinux.h` version pinning beyond BTF (kernel ≥ 5.4). Every
program reads `hk_protected` and bails early if the subject is not protected, to
hold the verifier instruction budget and the FP budget. LSM programs are
**audit-only**: they return the incoming `int ret` unchanged (the existing
`lsm_file_open.bpf.c` documents why a hard `0` would override another module's
deny). `-Wall -Wextra -Werror` is enforced by CMake — unused-arg warnings from
`BPF_PROG` wrappers are silenced by `(void)` per the existing convention.

**Signal 73 — `lsm/ptrace_access_check`** (`lsm_ptrace.bpf.c`):
`SEC("lsm/ptrace_access_check")`, `BPF_PROG(_, struct task_struct *child,
unsigned int mode, int ret)`. Read `mode` (`PTRACE_MODE_ATTACH` vs
`PTRACE_MODE_READ`), caller cred via `bpf_get_current_task_btf()->cred->uid`,
compare `child->tgid` to `hk_protected`. Emit only when child is protected and
`mode & PTRACE_MODE_ATTACH` and caller tgid ∉ game's own tree. **CO-RE concern:**
`security_ptrace_access_check`'s BPF-LSM signature exposes `(child, mode)` — the
attach name is `ptrace_access_check`; confirm the exact arg arity against the
target kernel's BTF (some trees added an arg). Flagged in §8.

**Signal 81 — `lsm/ptrace_traceme`** (same TU): `BPF_PROG(_, struct task_struct
*parent, int ret)`. Fires when `current` requests `PTRACE_TRACEME`. Record
`current==protected`, parent tgid/exe (would-be tracer), `ret`. Emit `mode=0`.

**Signal 74 — `fexit/process_vm_writev` + `fexit/process_vm_readv`**
(`fexit_process_vm.bpf.c`): `SEC("fexit/process_vm_writev")`,
`BPF_PROG(_, pid_t pid, ... , long ret)`. Resolve target task from `pid` via
`bpf_task_from_pid()` (or pidfd-less lookup) → `task->mm`, compare to protected
mm; `ret` is bytes transferred. Writer = `bpf_get_current_task_btf()`. **fexit
concern:** attaching fexit to `process_vm_writev` (the syscall wrapper) vs the
internal `process_vm_rw(vm_write=1)` differs by kernel; prefer fexit on the
exported syscall fn if BTF exposes it, else kprobe `process_vm_rw`. Flagged in §8.
Reads are a separate lower-severity tag (`HK_EVENT_VM_READ`) per the catalog.

**Signal 75 — `fentry/mem_open`** (`fentry_proc_mem.bpf.c`):
`SEC("fentry/mem_open")` (`fs/proc/base.c`). Recover the target task from the
proc inode (`proc_inode->pid` → `pid_task`/`get_proc_task`), compare its tgid to
protected; caller = `bpf_get_current_pid_tgid() >> 32`; same-tgid self-open is
benign. Path-independent (survives bind-mounts/chroot). **Concern:** `mem_open`
is `static` in some kernels — `fentry` needs it in BTF/kallsyms; if absent, fall
back to `lsm/file_open` + `i_rdev`/inode match. Flagged in §8.

**Signal 76 — `lsm/mmap_file` + `lsm/file_mprotect`** (`lsm_mmap_mprotect.bpf.c`):
filter `current->mm == protected mm`. On `mmap_file`, flag `prot &
(PROT_WRITE|PROT_EXEC)` (RWX map). On `file_mprotect`, read the target VMA's
`vm_flags` (currently `VM_EXEC`) vs requested `prot & PROT_WRITE` (text→writable
flip). Compare `bpf_ktime_get_ns()` to `hk_protected.load_done_ns` so post-link
patches separate from loader activity. Audit-only.

**Signal 79 — `lsm/mmap_file` foreign inode** (same TU as 76): read
`file->f_inode` `i_ino` and `i_sb->s_dev`, compare to protected `(dev,inode)`;
flag when mapping tgid ≠ protected tgid. Distinguish `MAP_SHARED`/`MAP_PRIVATE`
and `PROT_READ`-only from `PROT_WRITE`. Shares the mmap hook with 76 (one
program, two emit paths) to avoid double-attaching the same hook.

**Signal 77 — `sys_enter_memfd_create` + `lsm/bprm_creds_for_exec`**
(`memfd_exec.bpf.c`): tracepoint records `(tgid, fd, MFD_* flags, anon inode)`
into a `BPF_MAP_TYPE_LRU_HASH` keyed by `(tgid)`; the LSM exec hook detects an
exec whose `bprm->file` backing inode has no dentry path / is anon-shmem and
matches a recorded memfd inode. **Cross-hook join** is finished in Loader.cpp by
`(tgid, inode)` (the catalog specifies the join lives in the consumer). Emit
`HK_EVENT_MEMFD_CREATE` always (cheap) and `HK_EVENT_FILELESS_EXEC` only after
the join. `memfd_create` alone is common/benign — gate the *exec-of-memfd*.

**Signal 78 — `lsm/file_open` by `i_rdev`** (`lsm_devmem.bpf.c`):
`BPF_CORE_READ(file, f_inode, i_rdev)`; match MEM major 1 (minor 1=/dev/mem,
2=/dev/kmem) and the kcore proc inode. Read `security_locked_down` state (via a
companion `lsm/locked_down` probe or `bpf_lookup`) to record whether the open
should even be possible. Low FP on modern Wayland/KMS boxes.

**Signal 80 — `iter/task_vma`** (`iter_task_vma.bpf.c`):
`SEC("iter/task_vma")` BPF iterator (kernel ≥ 5.13), driven on a userspace timer
trigger from Loader.cpp. Walk the protected task's VMAs, emit one
`hk_event_vma_row` per `VM_EXEC` region `(vm_start, vm_end, vm_flags, dev, inode,
anon)`. Userspace diffs against the baseline snapshot taken at `load_done_ns`.
State-based ground truth orthogonal to the edge-triggered hooks.

**Loader.cpp / Loader.h (userspace, guardrail #8 N/A — C++; async is server-side):**
Add the new BPF-side structs (redeclared, not shared), the new tag constants, a
translation arm per tag, the `memfd`↔`exec` correlation LRU (a
`std::unordered_map<std::pair<tgid,inode>, timestamp>` with TTL eviction), and
`hk_bpf_loader_trigger_vma_scan()` to kick the iterator. The sink stays
non-blocking (runs inside `ring_buffer__poll`). No `goto`-leak regressions: new
skeletons follow the existing open→reuse_fd(hk_ringbuf)→load→attach sequence and
are torn down in `hk_bpf_loader_stop()` in reverse order.

**Server (Rust, guardrails #8):** the telemetry/api crates gain serde structs
mirroring the new `event_schema.h` payloads (field names + sizes in lockstep,
per the schema-version mirroring test). Fully async on tokio; `thiserror` for any
new error variants (e.g. unknown event type); **no `unwrap()` outside tests** —
deserialization of an unrecognized `type` returns a typed error, not a panic.

---

## Build wiring

- `kernel/linux/bpf/CMakeLists.txt`: register the new programs with the existing
  `bpf_program(...)` macro and add them to the `hk_bpf_generated` INTERFACE
  dependency list:
  ```
  bpf_program(lsm_ptrace)
  bpf_program(fexit_process_vm)
  bpf_program(fentry_proc_mem)
  bpf_program(lsm_mmap_mprotect)
  bpf_program(memfd_exec)
  bpf_program(lsm_devmem)
  bpf_program(iter_task_vma)
  ```
  and append each `hk_bpf_<name>_skel` to `add_dependencies(hk_bpf_generated ...)`.
  No new toolchain: reuses the existing `clang -target bpf -O2 -g -mcpu=v3
  -Wall -Wextra -Werror -nostdinc` + `bpftool gen skeleton` path. The new
  `include/hk_protected.bpf.h` lands under the already-configured `BPF_INCLUDE_DIR`.
- **Feature flag:** add CMake option `HK_BPF_MEMORY_ACCESS` **default ON** (this
  is core AC on Linux). Keep the eBPF master gate (`HK_ENABLE_EBPF`, default OFF
  per Locked Decision 3) as the parent — memory-access programs build only when
  eBPF is enabled. The LKM fallback path does **not** implement these signals in
  this PR (eBPF-only; flagged in §8 for self-hosted/non-Deck servers).
- `kernel/linux/userspace/CMakeLists.txt`: add `ProtectedSet.cpp` to the loader
  target and the new skel deps.
- `bypass-tests/linux/CMakeLists.txt`: add the five new executables + `add_test`
  entries (gated, like the existing `hk_bypass_ptrace`, behind the
  not-yet-enabled enforcement flag — they compile in CI and run when the loader
  test harness lands).
- Toolchain: clang ≥ 14 + bpftool ≥ 6.0 (already required); `iter/task_vma`
  needs a kernel ≥ 5.13 **at runtime** (compile-time only needs BTF) — CMake
  cannot check the runtime kernel, so the loader probes feature availability and
  degrades (signal 80 disabled, others continue).

---

## Test strategy

**Unit / loader tests (host, no privilege):**
- `Loader.cpp` translation: feed synthetic ring records for each new BPF tag,
  assert the emitted `hk_event_header.type` + payload fields. Extends the existing
  loader translation tests.
- `memfd`↔`exec` correlation: unit-test the LRU join in isolation (TTL eviction,
  `(tgid,inode)` match, no false join across unrelated tgids).
- Schema mirror: extend the Phase 2 server mirroring test so every new
  `event_schema.h` struct size/field is matched by the Rust serde struct; fails
  the build on drift (the schema files reference this test).
- `HK_STATIC_ASSERT` size pins compile on the C99 kernel build and the C++ build.

**Bypass tests (guardrail #12 merge gate — one per offensive technique):**
- `hk_bypass_vm_write` (`vm_write_attach.cpp`): issues `process_vm_writev` into a
  victim; **must demonstrate** signal 74 emits `HK_EVENT_VM_WRITE` with correct
  caller/target pids and `bytes > 0`.
- `hk_bypass_proc_mem` (`proc_mem_open.cpp`): cross-tgid `open("/proc/<v>/mem")`;
  **must demonstrate** signal 75 fires and a same-tgid self-open does **not**.
- `hk_bypass_wx_flip` (`wx_flip.cpp`): `mmap(RW)`→`mprotect(RX)` in own mm inside
  a "protected" test process; **must demonstrate** signal 76 `HK_EVENT_WX_FLIP`,
  and that a pre-`load_done_ns` flip is suppressed (baseline gating works).
- `hk_bypass_memfd_exec` (`memfd_exec.cpp`): `memfd_create`→write tiny static
  ELF→`execveat(AT_EMPTY_PATH)`; **must demonstrate** the joined
  `HK_EVENT_FILELESS_EXEC`, not just the create.
- `hk_bypass_devmem` (`devmem_open.cpp`): open `/dev/mem` / `/proc/kcore`; **must
  demonstrate** signal 78 fires, or cleanly skips when lockdown denies the open
  (skip ≠ pass-silently; it reports "denied by lockdown" so the gate stays honest).
- The existing `hk_bypass_ptrace` is **extended** to assert signal 73's
  `HK_EVENT_PTRACE_ACCESS` (mode=ATTACH, correct `lsm_ret`) in addition to the
  current tracepoint, and a `traceme` variant asserts signal 81.

All bypass tests require root + a loaded eBPF set, so they run in the
privileged-VM CI lane, not the unit lane; they are still the merge gate for any
change under `kernel/linux/bpf/`.

---

## Sequencing

1. **Foundations (no signals yet):** `hk_protected.bpf.h` map +
   `ProtectedSet.{h,cpp}` populated from the Linux attestation backend; bump
   `HK_EVENT_SCHEMA_VERSION=3`, add all payload structs + asserts to
   `event_schema.h`; update `data-categories.md` in the **same** commit
   (guardrail #11); add Rust serde mirrors + extend mirroring test. Nothing fires
   until the map is populated — safe to land first.
2. **ptrace pair (73, 81):** lowest-risk, reuses the existing ptrace bypass test
   and known LSM patterns. Validates the protected-set gating end-to-end.
3. **proc_mem (75) + devmem (78):** open-path hooks, low FP, independent.
4. **vm_access (74):** depends only on the protected mm in step 1; verify the
   fexit-vs-kprobe attach decision (§8) on the CI kernel before merge.
5. **mmap/mprotect (76) + foreign-map (79):** one TU, shares the mmap hook; needs
   `load_done_ns` from step 1; highest FP — lands with the baseline/allow-list
   plumbing.
6. **memfd→exec (77):** two-hook correlation + the Loader.cpp LRU; depends on the
   exec-LSM hook also used conceptually by 77; lands after the single-hook signals.
7. **iter/task_vma (80):** last — needs the kernel ≥ 5.13 runtime probe, the
   userspace timer trigger, and the baseline snapshot from step 1; orthogonal
   state-based detector, safe to defer.

Steps 2–7 each land with their bypass test (the merge gate) and their
`data-categories.md` rows already present from step 1.

---

## Risks & UNCERTAINTY FLAGS

Per guardrail #13, the following are **flagged, not guessed** — confirm against
the target kernel's BTF / source before writing the hook:

1. **`lsm/ptrace_access_check` arg arity (signal 73).** The BPF-LSM signature is
   commonly `(struct task_struct *child, unsigned int mode)`, but some kernel
   trees added/changed args on `security_ptrace_access_check`. **Verify the exact
   BPF_PROG arg list against the CI kernel's BTF before coding.** Wrong arity =
   verifier reject or wrong-field reads.
2. **`fexit` target for `process_vm_writev` (signal 74).** Whether to fexit the
   syscall entry, an inner `process_vm_rw(..., vm_write=1)`, or kprobe is
   kernel-version-dependent and the inner fn may be `static`/inlined (no BTF).
   **Verify the attachable symbol before committing to fexit vs kprobe.**
3. **`mem_open` attachability (signal 75).** `fs/proc/base.c:mem_open` may be
   `static` and absent from kallsyms/BTF on some configs; `fentry` then fails to
   attach. Fallback to `lsm/file_open` + proc-mem inode match must be designed in,
   not bolted on. **Flag: confirm `mem_open` is in BTF on the target kernels.**
4. **`security_locked_down` readability from BPF (signal 78).** Reading the
   lockdown state from a BPF program (vs a dedicated `lsm/locked_down` hook that
   only fires on a query) is uncertain; the `locked_down` field may have to be
   sampled from userspace (`/sys/kernel/security/lockdown`) and merged in the
   loader rather than read in-kernel. **Flag before relying on an in-kernel read.**
5. **`iter/task_vma` kernel floor (signal 80).** Requires kernel ≥ 5.13 at
   runtime; Steam Deck and older self-hosted kernels may lack it. The loader must
   probe and disable signal 80 gracefully — do not assume availability.
6. **LKM fallback gap.** Locked Decision 3 keeps an LKM behind a build flag for
   non-Deck/self-hosted servers, but **none of these nine signals are implemented
   in the LKM in this PR** (eBPF-only). On a kernel without `CONFIG_BPF_LSM` or
   `lsm=bpf`, signals 73/76/77/79 (the LSM ones) do not load. This is a coverage
   gap to call out to the user, not silently accept.
7. **FP budget on signals 76/79/80 (JIT-heavy titles).** Mono/IL2CPP/LuaJIT/V8,
   Proton's code emission, and dlopen'd plugins legitimately create RWX/W→X→W and
   grow `VM_EXEC` VMAs. These three signals are **not** shippable as
   auto-ban inputs until per-title baselining + the signed allow-list plumbing
   (server side) exists. They emit evidence; the server must treat them as
   low-confidence until baselined. Flagged so a reviewer does not wire them to the
   fail-closed ban path prematurely.
8. **`caller_uid` is personal data (guardrail #11 + GDPR).** Recording the caller
   uid raises the DPIA weight of the 2b category; confirm the retention/legal-basis
   row with the data-categories owner before merge.
