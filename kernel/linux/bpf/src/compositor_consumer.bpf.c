/*
 * kernel/linux/bpf/src/compositor_consumer.bpf.c
 * Role: Signal 106 — gamescope frame-consumer / DRM-lease siphon audit. Two arms:
 *       sys_enter_connect (AF_UNIX connect, hashes the sun_path) and
 *       sys_enter_ioctl filtered to DRM lease/PRIME ioctls. Emits the connecting/
 *       importing tgid + an identity hash; the gamescope/pipewire/portal/Steam-
 *       stream allowlist is userspace (GamescopeConsumerBaseline.cpp). HIGH FP —
 *       explicitly a low-weight server-side corroborator, never standalone.
 * Target platform: Linux eBPF (BPF_PROG_TYPE_TRACEPOINT).
 * Interface: shares hk_ringbuf; emits HK_BPF_PW_FRAME_CONSUMER ->
 *            HK_EVENT_FRAME_CONSUMER.
 *
 * Guardrail compliance: #1 Linux-only by gating; #3 module comment; #4 pure BPF
 *   TU; #6 -Wall -Wextra -Werror.
 *
 * API references:
 *   - sys_enter_connect / sys_enter_ioctl: syscall tracepoints.
 *   - DRM ioctl numbers: include/uapi/drm/drm.h (DRM_IOCTL_MODE_CREATE_LEASE,
 *     DRM_IOCTL_PRIME_FD_TO_HANDLE).
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

/* AF_UNIX from socket.h; the value is stable UAPI. */
#ifndef AF_UNIX
#define AF_UNIX 1
#endif

/* DRM ioctl request numbers. These are fixed UAPI _IOWR encodings from
 * include/uapi/drm/drm.h:
 *   DRM_IOCTL_MODE_CREATE_LEASE  = _IOWR('d', 0xC6, struct drm_mode_create_lease)
 *   DRM_IOCTL_PRIME_FD_TO_HANDLE = _IOWR('d', 0x2E, struct drm_prime_handle)
 * We match on the (dir,type,nr) discriminant only (the size is struct-dependent
 * and not needed for the audit). 'd' == 0x64. */
#define HK_DRM_IOC_TYPE 0x64u
#define HK_DRM_NR_CREATE_LEASE  0xC6u
#define HK_DRM_NR_PRIME_FD2HND  0x2Eu

/* _IOC_NR / _IOC_TYPE extraction (asm-generic/ioctl.h bit layout). */
#define HK_IOC_NRBITS    8u
#define HK_IOC_TYPEBITS  8u
#define HK_IOC_NRSHIFT   0u
#define HK_IOC_TYPESHIFT (HK_IOC_NRSHIFT + HK_IOC_NRBITS)
static __always_inline __u32 hk_ioc_nr(__u32 cmd)   { return (cmd >> HK_IOC_NRSHIFT)   & 0xFFu; }
static __always_inline __u32 hk_ioc_type(__u32 cmd) { return (cmd >> HK_IOC_TYPESHIFT) & 0xFFu; }

static __always_inline void
hk_emit_frame_consumer(__u32 flags, __u64 identity_hash)
{
    struct hk_bpf_pw_frame_consumer *evt;
    __u64 now = bpf_ktime_get_ns();

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return;

    evt->schema_version  = HK_PW_SCHEMA_VERSION;
    evt->event_tag       = HK_BPF_PW_FRAME_CONSUMER;
    evt->timestamp_ns    = now;
    evt->consumer_tgid   = (__u32)(bpf_get_current_pid_tgid() >> 32);
    evt->flags           = flags;   /* OFF_ALLOWLIST added userspace */
    evt->socket_or_fb_hash = identity_hash;
    evt->event_time_ns   = now;

    bpf_ringbuf_submit(evt, 0);
}

/*
 * sys_enter_connect arg layout: args[0]=fd, args[1]=sockaddr*, args[2]=addrlen.
 * We read the sockaddr family; for AF_UNIX we hash the sun_path. The allowlist
 * decision (is this the gamescope display socket, and is the caller gamescope?)
 * is userspace.
 */
SEC("tracepoint/syscalls/sys_enter_connect")
int hk_tp_connect(struct trace_event_raw_sys_enter *ctx)
{
    const void *uaddr = (const void *)BPF_CORE_READ(ctx, args[1]);
    struct sockaddr_un un = {};
    __u16 family = 0;

    if (!uaddr)
        return 0;
    if (bpf_probe_read_user(&family, sizeof(family), uaddr) != 0)
        return 0;
    if (family != AF_UNIX)
        return 0;   /* only AF_UNIX connects are siphon-relevant for 106 */

    if (bpf_probe_read_user(&un, sizeof(un), uaddr) != 0)
        return 0;

    /* sun_path is up to 108 bytes; hash a bounded copy (abstract-socket names
     * start with a NUL — hk_fnv64 over the leading bytes still yields a stable
     * identity key for the same socket). */
    __u64 h = hk_fnv64(un.sun_path, sizeof(un.sun_path));
    hk_emit_frame_consumer(HK_PW_FRAME_WAYLAND, h);
    return 0;
}

/*
 * sys_enter_ioctl arg layout: args[0]=fd, args[1]=cmd, args[2]=arg.
 * We match the DRM lease/PRIME-import requests. The fd is NOT resolved to a DRM
 * node in-kernel (verifier cost); userspace confirms the fd is a /dev/dri node.
 * The cmd discriminant alone is a cheap, low-FP prefilter.
 */
SEC("tracepoint/syscalls/sys_enter_ioctl")
int hk_tp_ioctl(struct trace_event_raw_sys_enter *ctx)
{
    __u32 cmd = (__u32)(BPF_CORE_READ(ctx, args[1]) & 0xFFFFFFFFULL);

    if (hk_ioc_type(cmd) != HK_DRM_IOC_TYPE)
        return 0;   /* not a DRM ioctl */

    __u32 nr = hk_ioc_nr(cmd);
    __u32 flags;
    if (nr == HK_DRM_NR_CREATE_LEASE)
        flags = HK_PW_FRAME_DRM_LEASE;
    else if (nr == HK_DRM_NR_PRIME_FD2HND)
        flags = HK_PW_FRAME_PRIME;
    else
        return 0;   /* a DRM ioctl we do not audit */

    /* Hash the cmd as the identity key — userspace correlates the DRM object via
     * the fd. Using the cmd keeps this arm allocation-free and verifier-cheap. */
    hk_emit_frame_consumer(flags, (__u64)cmd);
    return 0;
}

char _license[] SEC("license") = "GPL";
