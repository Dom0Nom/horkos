# Linux eBPF Anti-Cheat Detection Techniques - Deep Dive

> **Audience**: Experienced Linux kernel / eBPF developers. Assumes familiarity with
> BPF program types, CO-RE, BTF, and kernel data structures.
> **Scope**: Linux 5.10+ (Ubuntu 22.04 LTS, Fedora 38+, SteamOS 3.x / Steam Deck).
> Kernel config requirements called out per technique.

---

## 1. Memory Mapping Analysis via eBPF

### 1.1 Walking vm_area_struct from task_struct

```
task_struct->mm (struct mm_struct*)
  -> mmap (struct vm_area_struct*)  - head of the VMA linked list
  -> mm_rb (struct rb_root)         - red-black tree of VMAs
```

Key vm_area_struct fields:

```c
struct vm_area_struct {
    unsigned long vm_start;          // Start address (inclusive)
    unsigned long vm_end;            // End address (exclusive)
    struct vm_area_struct *vm_next;  // Linked list
    struct mm_struct *vm_mm;         // Owning mm_struct
    pgprot_t vm_page_prot;           // Access permissions (encoded)
    unsigned long vm_flags;          // VM_READ, VM_WRITE, VM_EXEC, VM_SHARED, etc.
    struct file *vm_file;            // Backing file (NULL for anonymous)
    unsigned long vm_pgoff;          // Offset into backing file (in pages)
    const struct vm_operations_struct *vm_ops;
};
```

Key vm_flags:

```
VM_READ       0x00000001
VM_WRITE      0x00000002
VM_EXEC       0x00000004
VM_SHARED     0x00000008
VM_MAYEXEC    0x00000010
VM_MAYSHARE   0x00000080
VM_GROWSDOWN  0x00000100   // Stack-like growth
VM_GROWSUP    0x00000200   // Heap-like growth (rare)
VM_DONTCOPY   0x00000400   // Don't copy across fork
VM_DONTDUMP   0x00400000   // Exclude from core dump
```

### 1.2 eBPF Program: Enumerate VMAs for a Target PID

```c
// BPF_PROG_TYPE_KPROBE attached to kprobe/do_mmap
// Requires: CONFIG_KPROBES, CONFIG_BPF_KPROBE_OVERRIDE

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define VM_EXEC   0x00000004
#define VM_WRITE  0x00000002
#define VM_READ   0x00000001

struct vma_event {
    __u32 pid;
    __u64 vm_start;
    __u64 vm_end;
    __u64 vm_flags;
    __u64 vm_pgoff;
    char  pathname[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} vma_events SEC(".maps");

// Map to hold the target PID (set by userspace)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_pid_map SEC(".maps");

SEC("kprobe/do_mmap")
int BPF_KPROBE(do_mmap_hook,
    struct file *file, unsigned long addr,
    unsigned long len, unsigned long prot,
    unsigned long flags, unsigned long pgoff)
{
    struct vma_event *evt;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid_map, &key);
    if (!tpid || *tpid != pid)
        return 0;

    evt = bpf_ringbuf_reserve(&vma_events, sizeof(*evt), 0);
    if (!evt) return 0;

    evt->pid = pid;
    evt->vm_start = addr;
    evt->vm_end = addr + len;
    evt->vm_flags = (prot & 0xF) | (flags & 0xFFFFFFFF0);
    evt->vm_pgoff = pgoff;

    if (file) {
        struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
        if (dentry) {
            struct qstr d_name = BPF_CORE_READ(dentry, d_name);
            bpf_probe_read_kernel_str(evt->pathname, sizeof(evt->pathname),
                                      d_name.name);
        }
    } else {
        evt->pathname[0] = '\\0';
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}
```

### 1.3 Detecting RWX Anonymous Mappings

```c
// The single most reliable injection indicator on Linux.
// In kprobe or BPF iterator that walks existing VMAs:

bool is_suspicious_vma(struct vm_area_struct *vma) {
    unsigned long flags = BPF_CORE_READ(vma, vm_flags);
    bool rwx = (flags & VM_READ) && (flags & VM_WRITE) && (flags & VM_EXEC);
    bool anonymous = (BPF_CORE_READ(vma, vm_file) == NULL);
    if (rwx && anonymous) return true;       // classic shellcode injection
    if (anonymous && (flags & VM_EXEC))      // anonymous + EXEC
        return !is_known_jit_process();       // flag if not known JIT
    return false;
}
```

### 1.4 Detecting Modified Text Segments

```c
// BPF_PROG_TYPE_KPROBE on kprobe/do_mprotect_pkey
// Catches mprotect(PROT_WRITE) on regions that were previously PROT_EXEC only
// - a sign the cheat is patching .text

SEC("kprobe/do_mprotect_pkey")
int BPF_KPROBE(mprotect_hook,
    unsigned long start, size_t len, unsigned long prot, int pkey)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_target_pid(pid)) return 0;

    struct mm_struct *mm = BPF_CORE_READ(
        (struct task_struct *)bpf_get_current_task(), mm);
    if (!mm) return 0;

    struct vm_area_struct *vma = BPF_CORE_READ(mm, mmap);
    while (vma) {
        unsigned long vm_start = BPF_CORE_READ(vma, vm_start);
        unsigned long vm_end   = BPF_CORE_READ(vma, vm_end);
        if (start >= vm_start && start < vm_end) {
            unsigned long old_flags = BPF_CORE_READ(vma, vm_flags);
            bool was_rx  = (old_flags & VM_EXEC) && !(old_flags & VM_WRITE);
            bool now_rw  = (prot & PROT_WRITE);
            if (was_rx && now_rw)
                report_text_segment_tamper(pid, start, len, prot);
            break;
        }
        vma = BPF_CORE_READ(vma, vm_next);
    }
    return 0;
}
```

### 1.5 Detecting IAT/GOT Hooking

```c
// When a cheat writes to a shared library's GOT in the game process:
// - The GOT is in .got.plt, mapped from a shared library file
// - It should be RW- (read-write, no exec)
// - If mprotect adds PROT_EXEC to a library-backed region → GOT hooking

// In the mprotect kprobe, check if the VMA is file-backed by a .so:
if (vma->vm_file) {
    const char *path = get_vma_path(vma);
    if (strstr(path, ".so") || strstr(path, ".so.")) {
        if ((prot & PROT_EXEC) && !(old_flags & VM_EXEC))
            report_got_hook_attempt(pid, start, path);
    }
}
```

---

## 2. Reflective Loading Detection

### 2.1 The memfd_create → ftruncate → mmap Chain

Reflective loading avoids writing the cheat ELF to disk:

```
1. memfd_create("random_name", MFD_CLOEXEC | MFD_ALLOW_SEALING)  → fd
2. ftruncate(fd, elf_size)
3. write(fd, elf_data, elf_size)         → raw ELF into memfd
4. mmap(NULL, elf_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE, fd, 0)
5. memfd_seal(fd, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE)
6. ELF header parsing → dynamic linking → entry point execution
```

### 2.2 eBPF: memfd_create with Suspicious Names

```c
// BPF_PROG_TYPE_TRACEPOINT on tracepoint/syscalls/sys_enter_memfd_create
SEC("tracepoint/syscalls/sys_enter_memfd_create")
int hk_tp_memfd_create(struct trace_event_raw_sys_enter *ctx)
{
    struct memfd_event *evt;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    evt = bpf_ringbuf_reserve(&memfd_events, sizeof(*evt), 0);
    if (!evt) return 0;

    evt->pid = pid;
    evt->timestamp_ns = bpf_ktime_get_ns();

    const char *name = (const char *)BPF_CORE_READ(ctx, args[0]);
    bpf_probe_read_user_str(evt->name, sizeof(evt->name), name);
    evt->flags = (__u32)BPF_CORE_READ(ctx, args[1]);

    // Suspicious: empty/random name, MFD_ALLOW_SEALING flag, non-JIT process
    bpf_ringbuf_submit(evt, 0);
    return 0;
}
```

### 2.3 Correlating memfd_create with Subsequent mmap

```c
// BPF map: track memfd_create → fd number
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);    // pid
    __type(value, __u32);  // fd number
} pending_memfds SEC(".maps");

// kretprobe/memfd_create to capture the return value (fd):
SEC("kretprobe/memfd_create")
int BPF_KRETPROBE(memfd_create_ret, long ret)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (ret < 0) return 0;
    __u32 fd = (__u32)ret;
    bpf_map_update_elem(&pending_memfds, &pid, &fd, BPF_ANY);
    return 0;
}

// In the mmap kprobe: check if fd matches a pending memfd
SEC("kprobe/do_mmap")
int BPF_KPROBE(do_mmap_check_memfd, struct file *file, ...)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 *fd = bpf_map_lookup_elem(&pending_memfds, &pid);
    if (fd && is_memfd_fd(file, *fd)) {
        if (prot & PROT_EXEC)
            report_reflective_load(pid, *fd, addr, len);
    }
    return 0;
}
```

### 2.4 Detecting memfd Sealing (Post-Load Hiding)

```c
// kprobe/fcntl - F_ADD_SEALS = 1033
// Seal flags: F_SEAL_SEAL=0x0001, F_SEAL_SHRINK=0x0002,
//             F_SEAL_GROW=0x0004, F_SEAL_WRITE=0x0008

SEC("kprobe/fcntl")
int BPF_KPROBE(fcntl_seal_check, unsigned int fd, unsigned int cmd, unsigned long arg)
{
    if (cmd != 1033) return 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 *mfd = bpf_map_lookup_elem(&pending_memfds, &pid);
    if (mfd && *mfd == fd)
        report_memfd_seal(pid, fd, arg);
    return 0;
}
```

---

## 3. Ptrace Internals

### 3.1 PTRACE_ATTACH vs PTRACE_SEIZE

```
PTRACE_ATTACH (16):
  - Sends SIGSTOP to target
  - Target's parent gets SIGCHLD with CLD_TRAPPED
  - /proc/pid/status TracerPid is set
  - Classic, easily detected

PTRACE_SEIZE (0x4206):
  - Does NOT send SIGSTOP
  - Does NOT change TracerPid
  - Stealthier - preferred by modern cheats
  - Available since Linux 3.4
```

### 3.2 eBPF: Distinguishing PTRACE_SEIZE from PTRACE_ATTACH

```c
// In the sys_enter_ptrace tracepoint (already in Horkos):
SEC("tracepoint/syscalls/sys_enter_ptrace")
int hk_tp_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    long request = (long)BPF_CORE_READ(ctx, args[0]);
    long pid_arg = (long)BPF_CORE_READ(ctx, args[1]);
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    switch (request) {
    case PTRACE_ATTACH:  // 16
        report_ptrace_attach(caller_pid, pid_arg, false);
        break;
    case PTRACE_SEIZE:   // 0x4206 - stealth attach
        report_ptrace_attach(caller_pid, pid_arg, true);
        break;
    case PTRACE_PEEKDATA:  // 2
    case PTRACE_POKETEXT:  // 4
    case PTRACE_POKEDATA:  // 5
        if (!is_known_debugger(caller_pid))
            report_ptrace_memory_op(caller_pid, pid_arg, request);
        break;
    case PTRACE_GETREGS:   // 12
    case PTRACE_SETREGS:   // 13
        report_ptrace_register_op(caller_pid, pid_arg, request);
        break;
    case PTRACE_CONT:      // 7
    case PTRACE_SINGLESTEP: // 9
        report_ptrace_execution_control(caller_pid, pid_arg, request);
        break;
    }
    return 0;
}
```

### 3.3 Detecting Self-Attach Anti-Anti-Debug

```c
// Self-attach blocks PTRACE_ATTACH from any other process
if (pid_arg == caller_pid && request == PTRACE_TRACEME)
    report_self_ptrace(caller_pid);
```

### 3.4 PTRACE_POKE Frequency Analysis

```c
// BPF map: per-PID ptrace operation counter
struct ptrace_counter { __u64 peek_count; __u64 poke_count; __u64 last_reset_ns; };

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct ptrace_counter);
} ptrace_counters SEC(".maps");

// In ptrace tracepoint: increment counters
// In a timer BPF program: check if any PID exceeds threshold (e.g., 100 pokes/sec)
```

---

## 4. process_vm_writev Detection

### 4.1 Why This Matters

`process_vm_writev` is the Linux equivalent of Windows `WriteProcessMemory`. Every memory editor (GameGuardian, Cheat Engine Linux, GameCIH) uses it. Direct cross-process memory write that bypasses `/proc/pid/mem`.

### 4.2 eBPF: Inspecting the iovec Array

```c
// BPF_PROG_TYPE_TRACEPOINT on tracepoint/syscalls/sys_enter_process_vm_writev
SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int hk_tp_process_vm_writev(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    pid_t target_pid = (pid_t)BPF_CORE_READ(ctx, args[2]);

    if (!is_target_pid(target_pid)) return 0;

    const struct iovec *remote_iov = (const struct iovec *)
        BPF_CORE_READ(ctx, args[3]);
    unsigned long riovlen = (unsigned long)BPF_CORE_READ(ctx, args[4]);

    struct iovec iov[4];
    unsigned long count = riovlen < 4 ? riovlen : 4;
    bpf_probe_read_user(iov, sizeof(iov[0]) * count, remote_iov);

    for (int i = 0; i < count; i++) {
        __u64 dest_addr = (__u64)iov[i].iov_base;
        __u64 write_len = (__u64)iov[i].iov_len;
        // Flag: writes to .text segment, known data structures, large blocks (>4KB)
        report_vm_write(pid, target_pid, dest_addr, write_len);
    }
    return 0;
}
```

### 4.3 Detecting GOT/PLT Hooking via process_vm_writev

```c
// In userspace loader after receiving vm_write event:
// Parse /proc/pid/maps, check if dest_addr falls within a known library's GOT
void handle_vm_write(__u32 src_pid, __u32 dst_pid, __u64 addr, __u64 len) {
    auto& maps = get_process_maps(dst_pid);
    for (auto& region : maps) {
        if (region.perms == 'rwx' || region.perms == 'rw-') {
            if (region.pathname.find(".so") != std::string::npos) {
                if (addr >= region.start && addr < region.end) {
                    if (is_got_region(region))
                        report_got_hook(src_pid, dst_pid, addr, region.pathname);
                }
            }
        }
    }
}
```

---

## 5. Namespace Evasion Detection

### 5.1 The Namespace Attack

Cheats run the game (or themselves) in a separate namespace to isolate memory access:

```
CLONE_NEWUSER  - different UID/GID mappings
CLONE_NEWPID   - different PID space (game sees itself as PID 1)
CLONE_NEWNET   - different network stack
CLONE_NEWNS    - different mount points (hide /proc entries)
CLONE_NEWIPC   - different IPC namespace
CLONE_NEWUTS   - different hostname
CLONE_NEWCGROUP - different cgroup view
```

### 5.2 eBPF: Reading Namespace IDs

```c
// task_struct->nsproxy → struct nsproxy
// nsproxy contains: uts_ns, ipc_ns, mnt_ns, pid_ns_for_children, net_ns, cgroup_ns, time_ns
// Each namespace has a unique inode number in /proc/pid/ns/

SEC("kprobe/finish_task_switch")
int check_namespaces(struct pt_regs *ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 pid = BPF_CORE_READ(task, pid);
    if (!is_target_pid(pid)) return 0;

    struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
    if (!nsproxy) return 0;

    struct pid_namespace *pid_ns = BPF_CORE_READ(nsproxy, pid_ns_for_children);
    if (pid_ns) {
        int level = BPF_CORE_READ(pid_ns, level);
        if (level > get_expected_pid_level())
            report_namespace_evasion(pid, "pid_ns", level);
    }
    return 0;
}
```

### 5.3 Detecting Container-Based Evasion

```c
// Check cgroup path - containers have distinct cgroup hierarchies
// In BPF: read task_struct->cgroups->dfl_cgrp->id
// In userspace: read /proc/pid/cgroup - if it contains "docker", "lxc", "podman", "flatpak"

struct cgroup *cgrp = BPF_CORE_READ(task, cgroups, dfl_cgrp);
if (cgrp) {
    u64 cgrp_id = BPF_CORE_READ(cgrp, id);
    if (cgrp_id != expected_cgroup_id)
        report_cgroup_mismatch(pid, cgrp_id);
}
```

---

## 6. Seccomp Circumvention

### 6.1 The Attack

Cheats may relax the game's seccomp filter to allow ptrace, memfd_create, process_vm_writev:

```c
// Cheat code:
prctl(PR_SET_SECCOMP, SECCOMP_MODE_DISABLED);       // Disable entirely
prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);  // Install weaker filter
```

### 6.2 eBPF: Detecting prctl SECCOMP Changes

```c
// BPF_PROG_TYPE_KPROBE on kprobe/prctl
// prctl args: int option, unsigned long arg2, arg3, arg4, arg5

SEC("kprobe/prctl")
int BPF_KPROBE(prctl_seccomp_check, int option, unsigned long arg2, ...)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_target_pid(pid)) return 0;

    // PR_SET_SECCOMP = 22
    if (option == 22) {
        if (arg2 == 0)  // SECCOMP_MODE_DISABLED
            report_seccomp_disabled(pid);
        else if (arg2 == 2)  // SECCOMP_MODE_FILTER
            report_seccomp_filter_change(pid);
    }

    // PR_SET_NO_NEW_PRIVS = 38 - cheats may disable to allow priv escalation
    if (option == 38 && arg2 == 0)
        report_no_new_privs_disabled(pid);

    return 0;
}
```

### 6.3 Detecting seccomp Filter Content

```c
// When arg2 == SECCOMP_MODE_FILTER, arg3 = pointer to struct sock_fprog
struct sock_fprog prog;
bpf_probe_read_user(&prog, sizeof(prog), (void *)arg3);

// Read first few instructions to check for dangerous allowances
struct sock_filter insns[8];
unsigned short count = prog.len < 8 ? prog.len : 8;
bpf_probe_read_user(insns, sizeof(insns[0]) * count, prog.filter);

// Check if filter allows ptrace (syscall 101), memfd_create (319), etc.
// Requires a mini BPF interpreter in eBPF - complex but doable for
// simple allow-all patterns.
```

---

## 7. FTrace / BPF Trampoline Hook Detection

### 7.1 The Attack

Sophisticated cheats use ftrace or BPF trampolines to hook kernel functions:

```
ftrace:  Modify kernel function prologue to jump to handler.
         Cheats register ftrace ops on sys_ptrace, sys_mprotect, etc.
         to hide their activity from Horkos's tracepoints.

BPF trampoline: eBPF programs attached via fentry/fexit
         (BPF_PROG_TYPE_TRAMPOLINE). A cheat with CAP_SYS_ADMIN
         can attach a BPF program that filters out its own
         ptrace/mprotect calls from Horkos's visibility.
```

### 7.2 Detection: Walking ftrace_ops List (LKM only)

```c
// ftrace_ops is a linked list (ftrace_ops_list)
// Requires LKM - eBPF cannot walk ftrace_ops_list (not in BTF)

struct ftrace_ops *ops;
mutex_lock(&ftrace_lock);
for (ops = ftrace_ops_list; ops != NULL; ops = ops->next) {
    if (!is_known_ftrace_module(ops->func))
        report_unknown_ftrace_hook(ops->func, ops->flags);
}
mutex_unlock(&ftrace_lock);
```

### 7.3 Detection: BPF Program Enumeration (userspace)

```c
// Use bpf_prog_get_next_id() to enumerate all BPF programs
// For each: bpf_prog_get_fd_by_fd() + bpf_obj_get_info_by_fd()
// Get: prog_type, jited_prog_len, jited_prog_insns, map_ids, name

// Flag:
// - BPF_PROG_TYPE_KPROBE on sys_ptrace, sys_mprotect, etc.
// - BPF_PROG_TYPE_TRACEPOINT on syscall tracepoints
// - Programs with names like "hide_ptrace", "filter_anticheat"
// - Programs loaded by non-root, non-game PIDs
```

### 7.4 Detecting BPF Trampoline on Critical Functions (LKM)

```c
// Check if critical syscall functions have ftrace/BPF trampoline attached
unsigned char *ptrace_syscall_addr =
    (unsigned char *)kallsyms_lookup_name("__x64_sys_ptrace");
if (ptrace_syscall_addr) {
    // Check for JMP or indirect JMP at function prologue
    if (ptrace_syscall_addr[0] == 0xE9 ||  // JMP rel32
        (ptrace_syscall_addr[0] == 0xFF && ptrace_syscall_addr[1] == 0x25))
        report_syscall_hook("__x64_sys_ptrace", ptrace_syscall_addr);
}
```

---

## 8. eBPF Verifier Constraints for Anti-Cheat

### 8.1 Bounded Loops

```c
// REJECTED by verifier:
for (int i = 0; i < n; i++) { ... }  // n is runtime value

// ACCEPTED:
for (int i = 0; i < 64; i++) { ... }  // compile-time constant

// ACCEPTED (kernel 5.3+ with BPF_F_TIMER):
bpf_loop(n, my_callback, &ctx, 0);  // runtime-bounded via helper
```

### 8.2 Bounded Memory Reads

```c
// REJECTED: unbounded read
bpf_probe_read_kernel(buf, len, ptr);  // len is runtime

// ACCEPTED: compile-time constant size
bpf_probe_read_kernel(buf, 256, ptr);

// ACCEPTED: bpf_probe_read_kernel_str with sizeof(buf)
long ret = bpf_probe_read_kernel_str(buf, sizeof(buf), ptr);
// ret > 0: success, ret bytes read (including NUL)
// ret < 0: error
// ret == sizeof(buf): string was truncated
```

### 8.3 Stack Size Limit

eBPF programs have a **512-byte stack limit**. Large structs must use ringbuf or per-cpu maps:

```c
// REJECTED: struct too large for stack
struct big_event evt;  // 512+ bytes
bpf_probe_read_kernel(&evt, sizeof(evt), ptr);

// ACCEPTED: use ringbuf
struct big_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
if (evt) {
    bpf_probe_read_kernel(evt, sizeof(*evt), ptr);
    bpf_ringbuf_submit(evt, 0);
}

// ACCEPTED: per-cpu array for temporary storage
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct big_event);
} scratch SEC(".maps");
```

### 8.4 CO-RE Field Access Patterns

```c
// REJECTED: direct field access without CO-RE
unsigned long flags = vma->vm_flags;

// ACCEPTED: BPF_CORE_READ macro
unsigned long flags = BPF_CORE_READ(vma, vm_flags);

// ACCEPTED: BPF_CORE_READ_STR_INTO for strings
BPF_CORE_READ_STR_INTO(buf, task, comm);

// DEFENSIVE: check field existence
if (bpf_core_field_exists(struct vm_area_struct, vm_flags))
    flags = BPF_CORE_READ(vma, vm_flags);
```

### 8.5 Helper Function Availability by Program Type

```
                    KPROBE  TRACEPOINT  LSM  PERF_EVENT  TRAMPOLINE
bpf_probe_read      +       +          +    +           +
bpf_probe_read_str  +       +          +    +           +
bpf_ktime_get_ns    +       +          +    +           +
bpf_ringbuf_reserve  +       +          +    +           +
bpf_probe_read_user  +       +          -    +           +
bpf_override_return  +       -          -    -           +
bpf_send_signal      +       -          -    -           -
bpf_perf_event_output -      -          -    +           -
```

---

## 9. Process Hiding Detection

### 9.1 The Attack: list_del_init on task_struct->tasks

```c
// Rootkit code:
list_del_init(&task->tasks);  // Remove from task list
// Process still runs but doesn't appear in ps, top, /proc iteration
```

### 9.2 Detection: PID ↔ task_struct Consistency

```c
// eBPF approach: use kprobe on schedule() to record all seen PIDs
// Compare against /proc iteration done in userspace.
// Missing PIDs = hidden processes.

// LKM approach:
// 1. Enumerate all PIDs via for_each_pid() (uses pid_hash)
// 2. For each PID, try find_task_by_pid_ns()
// 3. If PID exists but task not in init_task.tasks list → hidden
```

### 9.3 Detecting /proc Hiding via filldir Interception

```c
// Rootkits intercept getdents64 on /proc to filter out their PID.
// Detection in userspace daemon:
// 1. Read /proc via readdir → list A
// 2. Read BPF map of PIDs seen by kernel (from kprobe on schedule) → list B
// 3. PIDs in B but not in A = hidden processes
```

---

## 10. BPF CO-RE for Cross-Kernel Compatibility

### 10.1 Generating vmlinux.h

```bash
# Generate from target kernel's BTF
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# For Steam Deck: copy from target device
# For CI: generate per target kernel version
```

### 10.2 Handling Struct Field Renames

```c
// task_struct->state renamed to task_struct->__state in 5.14
// CO-RE handles relocation automatically if vmlinux.h matches target

// For fields that may not exist in older kernels:
if (bpf_core_field_exists(struct task_struct, __state))
    state = BPF_CORE_READ(task, __state);
else
    state = BPF_CORE_READ(task, state);  // fallback
```

### 10.3 Handling __data_loc Fields

```c
// Tracepoint contexts use __data_loc for variable-length data:
// __data_loc char[] filename → (offset << 16) | length
// Same pattern already used in Horkos's tracepoints.bpf.c

unsigned int fname_off = (unsigned int)(ctx->__data_loc_filename & 0xFFFFu);
const char *fname_ptr = (const char *)ctx + fname_off;
bpf_probe_read_kernel_str(buf, sizeof(buf), fname_ptr);
```

### 10.4 Per-Kernel Build Strategy

```cmake
# CMakeLists.txt - compile separate .bpf.o per target kernel
set(BPF_TARGET_KERNELS "5.15" "6.1" "6.6")
foreach(kernel ${BPF_TARGET_KERNELS})
    set(VMLINUX_H "vmlinux-${kernel}.h")
    set(OUTPUT "horkos-${kernel}.bpf.o")
    add_custom_command(
        OUTPUT ${OUTPUT}
        COMMAND clang-19 -g -O2 -target bpf -D__TARGET_ARCH_x86
                -I${CMAKE_CURRENT_SOURCE_DIR}/vmlinux/${kernel}
                -c bpf/src/tracepoints.bpf.c -o ${OUTPUT}
        DEPENDS ${VMLINUX_H}
    )
endforeach()
# At runtime, Loader.cpp selects correct .bpf.o based on uname().release
```

---

## 11. Netlink Tampering

### 11.1 The Attack

Cheats use NETLINK_CONNECTOR or NETLINK_GENERIC sockets to query kernel process tables and race against anti-cheat detection:

```c
struct sockaddr_nl sa = { .nl_family = AF_NETLINK, .nl_groups = CN_IDX_PROC };
int fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
bind(fd, (struct sockaddr *)&sa, sizeof(sa));
// Listen for PROC_EVENT_FORK, PROC_EVENT_EXEC - real-time process notifications
// Used to hide child processes before Horkos scans
```

### 11.2 eBPF: Detecting NETLINK_CONNECTOR Usage

```c
// BPF_PROG_TYPE_KPROBE on kprobe/__sys_socket
SEC("kprobe/__sys_socket")
int BPF_KPROBE(socket_detect, int family, int type, int protocol)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (family == AF_NETLINK && protocol == NETLINK_CONNECTOR)
        report_netlink_connector(pid);
    if (family == AF_NETLINK && protocol == NETLINK_GENERIC)
        report_netlink_generic(pid);
    return 0;
}
```

### 11.3 Detecting NETLINK_CONNECTOR Event Subscription

```c
// kprobe/bind - inspect sockaddr_nl for process event subscription
struct sockaddr_nl sa;
bpf_probe_read_user(&sa, sizeof(sa), (void *)addr);
if (sa.nl_family == AF_NETLINK) {
    // CN_IDX_PROC = 0x1 - process event subscription
    if (sa.nl_groups & (1 << (CN_IDX_PROC - 1)))
        report_proc_event_subscription(pid);
}
```

---

## 12. Kernel-Level Timer Abuse

### 12.1 The Attack

Cheats use high-frequency timers for aimbots, speedhacks, or DMA timing:

```
hrtimer:     High-resolution timer (nanosecond precision) - aimbot timing
timerfd:     Timer file descriptor - event-loop-based cheats
posix_timer: POSIX timer_create - signal-based timing
```

### 12.2 eBPF: Detecting hrtimer Abuse

```c
// BPF_PROG_TYPE_KPROBE on kprobe/hrtimer_start
SEC("kprobe/hrtimer_start")
int BPF_KPROBE(hrtimer_check, struct hrtimer *timer,
    ktime_t tim, const enum hrtimer_mode mode)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_target_pid(pid)) return 0;

    ktime_t expires = BPF_CORE_READ(timer, _softexpires);
    enum hrtimer_restart (*callback)(struct hrtimer *) =
        BPF_CORE_READ(timer, function);

    if (!is_known_timer_callback(callback))
        report_suspicious_hrtimer(pid, callback, expires);
    return 0;
}
```

### 12.3 Detecting timerfd Abuse

```c
// tracepoint/syscalls/sys_enter_timerfd_create
SEC("tracepoint/syscalls/sys_enter_timerfd_create")
int hk_tp_timerfd_create(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_target_pid(pid)) return 0;
    int clockid = (int)BPF_CORE_READ(ctx, args[0]);
    int flags = (int)BPF_CORE_READ(ctx, args[1]);
    report_timerfd_create(pid, clockid, flags);
    return 0;
}

// tracepoint/syscalls/sys_enter_timerfd_settime - check the interval
SEC("tracepoint/syscalls/sys_enter_timerfd_settime")
int hk_tp_timerfd_settime(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_target_pid(pid)) return 0;

    struct itimerspec new_val;
    bpf_probe_read_user(&new_val, sizeof(new_val),
                        (void *)BPF_CORE_READ(ctx, args[2]));

    __u64 interval_ns = new_val.it_interval.tv_sec * 1000000000ULL
                      + new_val.it_interval.tv_nsec;
    if (interval_ns > 0 && interval_ns < 1000000)
        report_high_frequency_timer(pid, interval_ns);  // sub-ms = suspicious
    return 0;
}
```

---

## 13. Kernel Config Requirements Matrix

```
Technique                          | Required Kernel Config
-----------------------------------|------------------------------------------
BPF_PROG_TYPE_TRACEPOINT           | CONFIG_BPF, CONFIG_BPF_SYSCALL, CONFIG_TRACEPOINTS
BPF_PROG_TYPE_KPROBE               | CONFIG_BPF, CONFIG_BPF_SYSCALL, CONFIG_KPROBES, CONFIG_BTF
BPF_PROG_TYPE_LSM                  | CONFIG_BPF, CONFIG_BPF_SYSCALL, CONFIG_BPF_LSM, CONFIG_SECURITY
BPF_PROG_TYPE_RAW_TRACEPOINT       | CONFIG_BPF, CONFIG_BPF_SYSCALL, CONFIG_TRACEPOINTS
BPF iterators (task, task_file)    | CONFIG_BPF, CONFIG_BPF_SYSCALL, CONFIG_BTF (kernel 5.8+)
BPF ring buffer                    | CONFIG_BPF, CONFIG_BPF_SYSCALL (kernel 5.8+)
BPF CO-RE                          | CONFIG_BPF, CONFIG_BPF_SYSCALL, CONFIG_DEBUG_INFO_BTF
BPF trampoline (fentry/fexit)      | CONFIG_BPF, CONFIG_BPF_SYSCALL, CONFIG_BTF, CONFIG_FUNCTION_TRACER
kprobe on syscall entry            | CONFIG_KPROBES, CONFIG_BTF (for CO-RE)
LSM hooks (bprm_check_security)    | CONFIG_BPF_LSM, CONFIG_SECURITY_NETWORK
Process namespace detection        | CONFIG_NAMESPACES, CONFIG_UTS_NS, CONFIG_PID_NS, CONFIG_NET_NS
cgroup detection                   | CONFIG_CGROUPS
```

**Steam Deck (SteamOS 3.x) specific:**
- Kernel 5.13 (SteamOS 3.4) - CONFIG_BPF_LSM=n by default
- Kernel 6.1+ (SteamOS 3.5+) - CONFIG_BPF_LSM=y
- CONFIG_DEBUG_INFO_BTF=y on both
- CONFIG_KPROBES=y on both
- **Recommendation:** Use tracepoints + kprobes on Steam Deck; LSM hooks only on 3.5+

---

## 14. BPF Program Type Selection Guide

```
Detection Need                     | Best BPF Type           | Why
-----------------------------------|-------------------------|----------------------------------
Syscall entry/exit monitoring      | TRACEPOINT              | Stable ABI, no BTF needed, low overhead
Syscall with return value          | KRETPROBE               | Only way to get return value
Kernel function entry (any)        | KPROBE + CO-RE          | Flexible, needs BTF
Kernel function entry (stable)     | TRACEPOINT              | Preferred when available
File access monitoring             | LSM (file_open)         | Can DENY, AUTH semantics
Exec monitoring                    | LSM (bprm_check_security)| Can DENY execution
Memory protection change           | KPROBE (do_mprotect)    | No LSM hook for mprotect on all kernels
Periodic scanning                  | TIMER (kernel 5.15+)    | Timer-based BPF, or userspace-triggered
Process enumeration                | BPF_ITERATOR (task)     | Walk all tasks from BPF
Cross-process memory write          | TRACEPOINT (sys_enter)  | Stable tracepoint
I/O monitoring                     | KPROBE / TRACEPOINT     | Depends on specific subsystem
```

---

## 15. Implementation Checklist

- [ ] **vmlinux.h per target kernel**: Generate separate vmlinux.h for SteamOS 3.4 (5.13), SteamOS 3.5 (6.1), Ubuntu 22.04 (5.15), Fedora 38 (6.4)
- [ ] **CO-RE field guards**: Use `bpf_core_field_exists()` for all fields that may not exist on older kernels
- [ ] **Stack overflow prevention**: Never allocate structs > 512 bytes on BPF stack; use ringbuf or per-cpu maps
- [ ] **Verifier-friendly loops**: All loops must have compile-time-constant bounds; use `bpf_loop()` for runtime bounds
- [ ] **Bounded string reads**: Always use `bpf_probe_read_kernel_str` with `sizeof(buf)` - never a runtime length
- [ ] **LSM availability check**: At load time, verify `CONFIG_BPF_LSM` is available before attaching LSM programs; fall back to kprobes
- [ ] **BTF at runtime**: Verify `/sys/kernel/btf/vmlinux` exists on the target; if not, CO-RE won't work
- [ ] **Ringbuf vs perfbuf**: Use ringbuf (BPF_MAP_TYPE_RINGBUF) for all new programs; perfbuf is deprecated
- [ ] **Userspace correlation**: Many detections (reflective load, GOT hooking) require correlating multiple BPF events in userspace - design the event schema accordingly
- [ ] **Rate limiting**: Don't emit events for every syscall; use BPF maps to count and only emit when thresholds are exceeded
- [ ] **False positive testing**: Test against legitimate software (debuggers, IDEs, browsers with JIT, game engines) before enabling enforcement
- [ ] **Graceful degradation**: If eBPF program load fails (wrong kernel, missing config), fall back to userspace-only detection rather than failing entirely
