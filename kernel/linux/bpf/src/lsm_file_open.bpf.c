/*
 * Role: BPF LSM program for the lsm/file_open hook.  On every file-open
 *       decision it pushes a compact event record to the shared ring buffer
 *       so the userspace loader (kernel/linux/userspace/Loader.cpp) can
 *       convert it to an hk_event_record and forward it to the server.
 * Target platform: Linux eBPF (BPF LSM, kernel ≥ 5.7 for BPF_PROG_TYPE_LSM).
 * Interface: implements the lsm/file_open attach point declared in vmlinux.h;
 *            shares the hk_ringbuf map with tracepoints.bpf.c via the
 *            hk_ringbuf map pinned under the horkos namespace.
 *
 * Kernel struct layouts (file, inode, dentry, qstr) are accessed via CO-RE
 * (BPF_CORE_READ) which relocates offsets at load time using BTF, so no
 * vmlinux.h version pinning is needed beyond BTF availability (kernel ≥ 5.4).
 *
 * API references:
 *   - BPF LSM:    https://docs.kernel.org/bpf/prog_lsm.html
 *   - CO-RE:      https://docs.ebpf.io/linux/concepts/CO-RE/
 *   - ringbuf:    https://docs.kernel.org/bpf/ringbuf.html
 *   - BPF_PROG_TYPE_LSM / SEC("lsm/"):
 *                 https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_LSM/
 *
 * Guardrail compliance:
 *   #1  No raw platform macros — this file is Linux-only by build gating.
 *   #3  This module comment covers role/platform/interface.
 *   #4  Pure kernel eBPF TU — no userspace headers.
 *   #6  Compiled -Wall -Wextra -Werror (enforced in CMakeLists.txt).
 */

/* vmlinux.h is generated on the build host via:
 *   bpftool btf dump file /sys/kernel/btf/vmlinux format c > \
 *       kernel/linux/bpf/include/vmlinux.h
 * It provides all kernel type definitions for CO-RE without pulling in
 * kernel headers that carry GPL-incompatible or version-tied declarations. */
#include "vmlinux.h"

/* libbpf-dev helpers — safe to include after vmlinux.h because they guard
 * against double inclusion of conflicting type definitions. */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

/* ---- Wire-format constants (must stay in sync with event_schema.h) --------
 *
 * We cannot include event_schema.h here: it uses stdint.h which is a libc
 * header forbidden in eBPF C (-nostdinc).  The BPF side uses its own compact
 * struct; the userspace loader re-maps this to hk_event_record.
 * The magic/version literals are duplicated intentionally — any schema change
 * must update both sides (enforced by the Phase 2 server mirroring test).
 *
 * HK_SCHEMA_VERSION mirrors HK_EVENT_SCHEMA_VERSION from event_schema.h. */
#define HK_SCHEMA_VERSION   2u
#define HK_EVENT_FILE_OPEN  0x10u   /* internal BPF-side tag, not in schema enum;
                                       loader maps this to HK_EVENT_HANDLE_OPEN */
#define HK_PATH_MAX         256     /* truncated filename written to ring buffer */

/* ---- Shared ring buffer --------------------------------------------------- */
/*
 * BPF_MAP_TYPE_RINGBUF: lock-free, multi-producer, single-consumer.
 * Kernel ≥ 5.8.  max_entries is the ring size in bytes (must be page-aligned
 * power-of-two).  Shared across all BPF programs in this project; tracepoints
 * declare it as extern to reference the same map.
 * Reference: https://docs.kernel.org/bpf/ringbuf.html
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);   /* 1 MiB */
} hk_ringbuf SEC(".maps");

/* ---- Ring-buffer event layout -------------------------------------------- */
/*
 * This struct is the on-wire BPF-side record.  It is distinct from
 * hk_event_record in event_schema.h: the loader translates between them.
 * Kept small to minimise ringbuf pressure; CO-RE handles variable layouts.
 */
struct hk_bpf_file_open_event {
    __u32 schema_version;           /* HK_SCHEMA_VERSION */
    __u32 event_tag;                /* HK_EVENT_FILE_OPEN */
    __u64 timestamp_ns;             /* bpf_ktime_get_ns() — boot epoch */
    __u32 pid;
    __u32 reserved;                 /* padding; zero */
    char  filename[HK_PATH_MAX];    /* truncated path; NUL-terminated */
};

/* ---- LSM hook: lsm/file_open --------------------------------------------- */
/*
 * SEC("lsm/file_open") attaches to the file_open LSM hook.
 * The return value controls the allow/deny decision: 0 = allow, negative = deny.
 * We always return 0 (allow) — this program is audit-only.
 *
 * BPF LSM programs require CAP_BPF + CAP_PERFMON at load time (kernel ≥ 5.8)
 * or CAP_SYS_ADMIN on older kernels.  The loader must run with appropriate
 * capabilities or as root.
 *
 * Reference: https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_LSM/
 *            kernel/security/bpf.c — bpf_lsm_file_open
 */
/* The trailing `int ret` is the decision from the prior LSM in the stack. An
 * lsm/* program MUST propagate it: returning a hard 0 would override a real deny
 * from another module. This program is audit-only, so it always returns `ret`. */
SEC("lsm/file_open")
int BPF_PROG(hk_lsm_file_open, struct file *file, int ret)
{
    struct hk_bpf_file_open_event *evt;
    struct dentry *dentry;
    struct qstr   dname;

    /* Reserve space in the ring buffer. Flag 0 = libbpf's default adaptive
     * wakeup, which the epoll-based userspace poller handles fine. */
    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return ret;   /* drop on overflow — never override the prior decision */

    evt->schema_version = HK_SCHEMA_VERSION;
    evt->event_tag      = HK_EVENT_FILE_OPEN;
    evt->timestamp_ns   = bpf_ktime_get_ns();
    evt->pid            = bpf_get_current_pid_tgid() >> 32;
    evt->reserved       = 0;

    /* Read the filename via CO-RE.
     * file->f_path.dentry->d_name is a struct qstr { hash_len, name }.
     * BPF_CORE_READ_INTO copies through CO-RE relocation; bpf_probe_read_kernel_str
     * then copies the NUL-terminated string into the event buffer.
     *
     * f_path.dentry is guaranteed for regular file opens but may be NULL for
     * some special file types; the NULL check below is belt-and-suspenders. */
    dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry) {
        evt->filename[0] = '\0';
    } else {
        BPF_CORE_READ_INTO(&dname, dentry, d_name);
        /* bpf_probe_read_kernel_str: copies up to size bytes, guarantees NUL
         * termination, returns length or negative errno.
         * Reference: https://docs.ebpf.io/linux/helper-function/bpf_probe_read_kernel_str/ */
        long rc = bpf_probe_read_kernel_str(evt->filename,
                                            sizeof(evt->filename),
                                            (const void *)(unsigned long)dname.name);
        if (rc < 0)
            evt->filename[0] = '\0';
    }

    bpf_ringbuf_submit(evt, 0);
    return ret;   /* audit-only: preserve the prior LSM decision */
}

/* ===========================================================================
 * Signal 98 — /dev/mem, /dev/kmem, /dev/port write-intent opens.
 *
 * This is a SEPARATE lsm/file_open program from hk_lsm_file_open above; multiple
 * BPF LSM programs may attach to the same hook and run in sequence. It is also
 * distinct from lsm_devmem.bpf.c's signal-78 sensor: 78 reports the bare physmem
 * OPEN (read paths into raw memory); 98 specifically carries the WRITE-INTENT
 * flag (FMODE_WRITE) and adds /dev/port, which is the discriminator the catalog
 * FP gate needs (flag write-intent opens, not read-only DMI scans — §6).
 *
 * fd→device resolution is deliberately SPLIT (§1.2 / §7-A): this program emits
 * the raw (pid, dev major/minor, write_intent) and userspace (Loader.cpp) decides
 * device identity/sensitivity. We read f_mode and i_rdev via CO-RE.
 *
 * §7-A CONFIRMED-DEFAULT: read file->f_mode (FMODE_WRITE 0x2) and the inode
 * i_rdev via BPF_CORE_READ (CO-RE relocates the offsets); do NOT assume fixed
 * offsets. FMODE_WRITE is a stable UAPI-adjacent bit (include/linux/fs.h) but the
 * STRUCT FIELD offset is relocated by CO-RE.
 *
 * Audit-only: returns the incoming `ret` on every path (asserted by the
 * devmem_write_open bypass test).
 * ===========================================================================*/

/* 0xA0: module-trust devmem-write-intent tag. 0x30/0x31 are already taken by the
 * memory-access ptrace tags in Loader.cpp; the module-trust domain uses the 0xA0
 * range to avoid a translate-arm collision. */
#define HK_BPF_DEVMEM_ACCESS 0xA0u   /* loader maps to HK_EVENT_DEVMEM_ACCESS */

/* MEM char-device major + the devmem/kmem/port minors (drivers/char/mem.c). */
#define HK_MEM_MAJOR2   1u
#define HK_DEVMEM_MINOR 1u   /* /dev/mem  */
#define HK_DEVKMEM_MIN  2u   /* /dev/kmem */
#define HK_DEVPORT_MIN  4u   /* /dev/port */

/* FMODE_WRITE from include/linux/fs.h. The VALUE is stable; the f_mode FIELD
 * offset is CO-RE-relocated. */
#define HK_FMODE_WRITE  0x2u

static __always_inline __u32 hk98_major(__u32 dev) { return (dev >> 20) & 0xfffu; }
static __always_inline __u32 hk98_minor(__u32 dev) { return dev & 0xfffffu; }

/* Mirrored in Loader.cpp as HkBpfDevmemEvent. */
struct hk_bpf_devmem_event {
    __u32 schema_version;
    __u32 event_tag;        /* HK_BPF_DEVMEM_ACCESS */
    __u64 timestamp_ns;
    __u32 requesting_pid;
    __u32 dev_minor;        /* opened node minor (1/2/4) */
    __u32 write_intent;     /* 1 if FMODE_WRITE set at open */
    __u32 reserved;
};

SEC("lsm/file_open")
int BPF_PROG(hk_lsm_devmem_writeintent, struct file *file, int ret)
{
    struct hk_bpf_devmem_event *evt;
    __u32 rdev;
    __u32 major, minor;
    unsigned int fmode;

    if (!file)
        return ret;

    rdev = (__u32)BPF_CORE_READ(file, f_inode, i_rdev);
    major = hk98_major(rdev);
    minor = hk98_minor(rdev);

    if (major != HK_MEM_MAJOR2 ||
        (minor != HK_DEVMEM_MINOR && minor != HK_DEVKMEM_MIN &&
         minor != HK_DEVPORT_MIN))
        return ret;   /* not a physmem/port node — nothing to report */

    fmode = (unsigned int)BPF_CORE_READ(file, f_mode);

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return ret;   /* drop on overflow — never override the prior decision */

    evt->schema_version = HK_SCHEMA_VERSION;
    evt->event_tag      = HK_BPF_DEVMEM_ACCESS;
    evt->timestamp_ns   = bpf_ktime_get_ns();
    evt->requesting_pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    evt->dev_minor      = minor;
    evt->write_intent   = (fmode & HK_FMODE_WRITE) ? 1u : 0u;
    evt->reserved       = 0;

    bpf_ringbuf_submit(evt, 0);
    return ret;   /* audit-only: preserve the prior LSM decision */
}

char _license[] SEC("license") = "GPL";
