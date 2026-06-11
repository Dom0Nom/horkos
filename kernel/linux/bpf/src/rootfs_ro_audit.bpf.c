/*
 * kernel/linux/bpf/src/rootfs_ro_audit.bpf.c
 * Role: Signal 105 — read-only rootfs invariant audit (SteamOS/immutable distro).
 *       Stable arm: lsm/sb_mount (a mount operation on the root SB). Uncertain
 *       arm: lsm/sb_remount (catching the precise MS_RDONLY->RW transition) is a
 *       stub pending on-target s_flags CO-RE test (lsm/sb_remount IS defined in
 *       lsm_hook_defs.h and BPF-attachable — HK-VERIFIED(sb-remount-hook) below).
 *       The protected-subvol CREATE/WRITE file-open arm reuses the cheap dentry
 *       read. Baseline RO state, frzr/rauc update-window and the immutable-distro
 *       gate are userspace (DeckRootfsBaseline.cpp).
 * Target platform: Linux eBPF (BPF LSM).
 * Interface: shares hk_ringbuf; emits HK_BPF_PW_ROOTFS_RW -> HK_EVENT_ROOTFS_RW.
 *
 * Guardrail compliance: #1 Linux-only by gating; #3 module comment; #4 pure BPF
 *   TU; #6 -Wall -Wextra -Werror; lsm/* returns inbound `ret`. #13: the
 *   sb_remount arm is a flagged stub.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "hk_bpf_shared.h"

extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} hk_ringbuf SEC(".maps");

/* SB_RDONLY / MS_RDONLY (fs.h / mount.h). The VALUE is stable UAPI; the s_flags
 * FIELD offset is CO-RE-relocated. */
#ifndef SB_RDONLY
#define SB_RDONLY 1u
#endif
#ifndef MS_RDONLY
#define MS_RDONLY 1u
#endif
#ifndef MS_REMOUNT
#define MS_REMOUNT 32u
#endif

static __always_inline void
hk_emit_rootfs_rw(__u32 flags, __u64 path_hash)
{
    struct hk_bpf_pw_rootfs_rw *evt;
    __u64 now = bpf_ktime_get_ns();

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return;

    evt->schema_version  = HK_PW_SCHEMA_VERSION;
    evt->event_tag       = HK_BPF_PW_ROOTFS_RW;
    evt->timestamp_ns    = now;
    evt->actor_tgid      = (__u32)(bpf_get_current_pid_tgid() >> 32);
    evt->flags           = flags;   /* UPDATE_WINDOW/IMMUTABLE_DISTRO set userspace */
    evt->target_path_hash = path_hash;
    evt->event_time_ns   = now;

    bpf_ringbuf_submit(evt, 0);
}

/*
 * lsm/sb_mount(const char *dev_name, const struct path *path,
 *              const char *type, unsigned long flags, void *data) -> int ret
 * STABLE arm: a mount carrying MS_REMOUNT without MS_RDONLY is a candidate
 * RO->RW remount of an immutable rootfs. We emit on that shape; userspace
 * confirms the target is the protected root SB and applies the update-window /
 * immutable-distro gates. Audit-only.
 */
SEC("lsm/sb_mount")
int BPF_PROG(hk_lsm_sb_mount,
             const char *dev_name, const struct path *path,
             const char *type, unsigned long flags, void *data, int ret)
{
    (void)dev_name; (void)path; (void)type; (void)data;

    /* A remount that does NOT re-assert read-only is the RO-loss candidate. */
    if ((flags & MS_REMOUNT) && !(flags & MS_RDONLY)) {
        hk_emit_rootfs_rw(HK_PW_ROOTFS_REMOUNT_RW, 0);
    }
    return ret;   /* audit-only */
}

/*
 * HK-VERIFIED(sb-remount-hook): lsm/sb_remount IS defined in
 * include/linux/lsm_hook_defs.h as
 *   LSM_HOOK(int, 0, sb_remount, struct super_block *sb, void *mnt_opts)
 * All hooks in lsm_hook_defs.h are BPF-attachable via the standard lsm/<hook>
 * mechanism (docs.kernel.org/bpf/prog_lsm.html; github.com/torvalds/linux/blob/
 * master/include/linux/lsm_hook_defs.h). The hook fires BEFORE the remount
 * applies, so sb->s_flags still reflects the pre-remount value — correct for the
 * SB_RDONLY->RW detection.
 * Confirms: lsm/sb_remount is BPF-attachable; signature is (struct super_block *,
 * void *mnt_opts, int ret). The sb_remount arm below is safe to implement.
 * Per guardrail #13 the arm is still left as a stub until tested on the target
 * to confirm SB_RDONLY detection via s_flags CO-RE read. Intended shape:
 *   SEC("lsm/sb_remount")
 *   int BPF_PROG(hk_lsm_sb_remount, struct super_block *sb, void *mnt_opts, int ret) {
 *       u64 fl = BPF_CORE_READ(sb, s_flags);
 *       if (!(fl & SB_RDONLY)) hk_emit_rootfs_rw(HK_PW_ROOTFS_REMOUNT_RW, 0);
 *       return ret;
 *   }
 *
 * HK-TODO(schema): the protected-subvol CREATE/WRITE file_open arm (impl-plan
 * §105) extends the existing lsm/file_open audit in lsm_file_open.bpf.c. It is
 * NOT added here to avoid a second lsm/file_open program racing the existing one;
 * the dentry-path hash + protected-subvol filter belongs alongside the canonical
 * file_open hook. Left for the file_open arm owner to wire (it needs the
 * protected-subvol path set, which is a userspace-populated map). Emitting the
 * REMOUNT arm above already covers the primary "steamos-readonly disable" vector
 * the bypass test drives.
 */

char _license[] SEC("license") = "GPL";
