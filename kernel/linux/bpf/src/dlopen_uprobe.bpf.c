/*
 * kernel/linux/bpf/src/dlopen_uprobe.bpf.c
 * Role: uprobe on the PUBLIC glibc exports dlopen/dlmopen. On entry it reads the
 *       path argument (a user pointer) via bpf_probe_read_user_str and emits a
 *       compact record so the userspace correlator DlopenBacking.cpp (signal 86)
 *       can stat the resolved path/fd and inspect the matching /proc/<pid>/maps
 *       line for (deleted)/memfd:/anon-exec backing. No /proc or ELF parsing
 *       happens here (guardrail #4).
 * Target platform: Linux eBPF (uprobe, kernel >= 4.17; shared ringbuf >= 5.8).
 * Interface: shares hk_ringbuf with lsm_file_open.bpf.c (extern); Loader.cpp
 *            translates the HK_EVENT_DLOPEN record to hk_event_record.
 *
 * Guardrail compliance: #1 (no raw macros), #3 (module comment), #4 (pure eBPF
 * TU), #6 (-Wall -Wextra -Werror).
 *
 * API note: uprobes read USER addresses — the path arg MUST be read with
 * bpf_probe_read_user_str, never the _kernel_ variant (a silent fault otherwise).
 *
 * HK-UNCERTAIN(glibc-internal): the PUBLIC `dlopen`/`dlmopen` exports are stable
 * ABI (preferred here). The argument register carrying the `const char *file`
 * first argument is resolved by bpf_tracing.h's PT_REGS_PARM1 against the host
 * arch (set via -D__TARGET_ARCH_* in CMake). The glibc-INTERNAL `_dl_open`
 * (different signature, internal) is intentionally NOT attached here; if a future
 * title statically inlines dlopen, fall back to _dl_open only after confirming
 * its arg layout on the target glibc. Resolve the dlopen/dlmopen offsets per
 * target at attach in Loader.cpp and skip gracefully when absent.
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define HK_SCHEMA_VERSION   3u
#define HK_EVENT_DLOPEN     0x22u   /* loader maps to HK_EVENT_DLOPEN_BACKING */
#define HK_DLPATH_MAX       256

extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} hk_ringbuf SEC(".maps");

struct hk_bpf_dlopen_event {
    __u32 schema_version;
    __u32 event_tag;
    __u64 timestamp_ns;
    __u32 pid;
    __u32 reserved;
    char  path[HK_DLPATH_MAX];   /* dlopen() file arg; "" for dlopen(NULL) */
};

/* ---- uprobe: dlopen(const char *file, int mode) -------------------------- */
SEC("uprobe")
int BPF_KPROBE(hk_uprobe_dlopen, const char *file)
{
    struct hk_bpf_dlopen_event *evt;

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->schema_version = HK_SCHEMA_VERSION;
    evt->event_tag      = HK_EVENT_DLOPEN;
    evt->timestamp_ns   = bpf_ktime_get_ns();
    evt->pid            = bpf_get_current_pid_tgid() >> 32;
    evt->reserved       = 0;
    evt->path[0]        = '\0';

    if (file) {
        /* USER pointer — must use the _user_ helper. Bounded by sizeof(path);
         * a longer path is truncated (userspace re-resolves via /proc maps). */
        long rc = bpf_probe_read_user_str(evt->path, sizeof(evt->path), file);
        if (rc < 0)
            evt->path[0] = '\0';
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
