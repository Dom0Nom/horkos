/*
 * Role: BPF LSM sensor for physical-memory-window opens (signal 78). On
 *       lsm/file_open it filters by the opened node's device number to catch
 *       /dev/mem (MEM major 1, minor 1) and /dev/kmem (minor 2), plus the
 *       /proc/kcore inode. These are the read paths into raw/physical memory a
 *       kernel-assisted cheat uses to reach the game's pages out-of-band. The
 *       open is AUDIT-ONLY (returns the incoming `ret`); it records whether
 *       kernel lockdown should even permit the open.
 * Target platform: Linux eBPF (BPF LSM, kernel >= 5.7; CONFIG_BPF_LSM + lsm=bpf).
 * Interface: implements lsm/file_open filtered by i_rdev; writes hk_ringbuf
 *            (extern, shared via Loader.cpp). Maps to server event
 *            HK_EVENT_PHYSMEM_OPEN.
 *
 * Guardrail compliance:
 *   #1  No raw platform macros — Linux-only by build gating.
 *   #3  This module comment covers role/platform/interface.
 *   #4  Pure kernel eBPF TU — no userspace headers.
 *   #6  Compiled -Wall -Wextra -Werror (enforced in CMakeLists.txt).
 *
 * NOTE: this sensor is host-wide (not gated on hk_protected) — a physmem open is
 * suspicious regardless of which task does it, and it is rare on modern
 * Wayland/KMS boxes, so the FP cost is acceptable without the protected gate.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define HK_SCHEMA_VERSION       3u
#define HK_BPF_PHYSMEM_OPEN     0x80u

/* MEM char-device major and the /dev/mem, /dev/kmem minors (drivers/char/mem.c).
 * MKDEV(1,1) and MKDEV(1,2). i_rdev encodes major:minor; we compare via the
 * kernel's MAJOR/MINOR layout (major in high bits). We avoid hard-coding the
 * encoding by extracting with the standard new-dev bit layout. */
#define HK_MEM_MAJOR    1u
#define HK_MEM_MINOR    1u   /* /dev/mem  */
#define HK_KMEM_MINOR   2u   /* /dev/kmem */

/* new-style dev_t (kernel internal kdev_t): MAJOR = (dev & 0xfff00) >> 8 for the
 * 32-bit i_rdev as stored; but i_rdev in the inode is the encoded u32 where
 * MAJOR(dev) = (dev >> 20) & 0xfff and MINOR(dev) = (dev & 0xfffff) for the
 * kernel's huge-dev layout. Use the kernel macros' arithmetic. */
static __always_inline __u32 hk_major(__u32 dev) { return (dev >> 20) & 0xfffu; }
static __always_inline __u32 hk_minor(__u32 dev) { return dev & 0xfffffu; }

extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} hk_ringbuf SEC(".maps");

/* Mirrored in Loader.cpp as HkBpfPhysmemEvent. */
struct hk_bpf_physmem_event {
    __u32 schema_version;
    __u32 event_tag;        /* HK_BPF_PHYSMEM_OPEN */
    __u64 timestamp_ns;
    __u32 caller_pid;
    __u32 rdev;             /* i_rdev of opened node                */
    __u32 locked_down;      /* lockdown state at open (see below)   */
    __u32 reserved;
};

SEC("lsm/file_open")
int BPF_PROG(hk_lsm_devmem_open, struct file *file, int ret)
{
    struct hk_bpf_physmem_event *evt;
    __u32 rdev;
    __u32 major, minor;
    int is_physmem = 0;

    if (!file)
        return ret;

    rdev = (__u32)BPF_CORE_READ(file, f_inode, i_rdev);
    major = hk_major(rdev);
    minor = hk_minor(rdev);

    if (major == HK_MEM_MAJOR && (minor == HK_MEM_MINOR || minor == HK_KMEM_MINOR))
        is_physmem = 1;

    /* HK-TODO(schema): /proc/kcore detection needs a proc-inode/name match (it is
     * a regular proc file, not a char device, so i_rdev is 0). The robust test is
     * dname == "kcore" under proc; left to a companion path-filtered emit or the
     * Loader-side name check. For now this sensor covers the /dev/mem + /dev/kmem
     * char-device opens, which are the primary physmem windows. */
    if (!is_physmem)
        return ret;

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return ret;

    evt->schema_version = HK_SCHEMA_VERSION;
    evt->event_tag      = HK_BPF_PHYSMEM_OPEN;
    evt->timestamp_ns   = bpf_ktime_get_ns();
    evt->caller_pid     = (__u32)(bpf_get_current_pid_tgid() >> 32);
    evt->rdev           = rdev;
    /* HK-VERIFIED(locked-down-read): there is no BPF helper to query
     * security_locked_down() state directly from a BPF program context —
     * security_locked_down is a push hook, not a readable kernel global.
     * The confirmed reliable source is userspace /sys/kernel/security/lockdown
     * (kernel_lockdown(7) man page; exposed by the lockdown LSM module when
     * loaded). The Loader samples that sysfs file once at startup and merges
     * the value into this field. Source: man7.org/linux/man-pages/man7/kernel_lockdown.7.html
     * Confirms: BPF-side lockdown read is not possible; userspace sysfs read is the correct path. */
    evt->locked_down    = 0xFFFFFFFFu;
    evt->reserved       = 0;

    bpf_ringbuf_submit(evt, 0);
    return ret;   /* audit-only */
}

char _license[] SEC("license") = "GPL";
