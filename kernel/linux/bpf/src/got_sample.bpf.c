/*
 * Role: uprobe on a benign, frequently-called game function (symbol supplied
 *       per-title via config). On fire it reads a bounded batch of .got.plt slot
 *       VALUES via bpf_probe_read_user at offsets supplied by userspace in the
 *       hk_got_cfg map (offsets are computed userspace-side from ELF section
 *       headers + load bias), and forwards the resolved pointers so the
 *       userspace correlator GotPltMap.cpp (signal 83) can compare each against
 *       the live VMA map (skip IFUNC slots; flag anon/RWX/foreign targets).
 * Target platform: Linux eBPF (uprobe, kernel >= 4.17; ringbuf >= 5.8).
 * Interface: reads hk_got_cfg (per-PID slot offsets), writes slot snapshots to
 *            hk_ringbuf (extern); Loader.cpp translates HK_EVENT_GOT_SAMPLE.
 *
 * Guardrail compliance: #1, #3, #4, #6. Bounded loop only (verifier).
 *
 * API note: GOT slots live in the TARGET process address space — reads are USER
 * reads (bpf_probe_read_user), never kernel reads.
 *
 * HK-UNCERTAIN(uprobe-perf): attaching a uprobe to a hot game function adds a
 * trap per call and may measurably regress frame time on a Steam Deck. Signal 83
 * is default-OFF (CMake) and the per-title "benign hot fn" + sample rate need
 * profiling before enabling. A timer/perf-based cadence is a flagged alternative.
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define HK_SCHEMA_VERSION    3u
#define HK_EVENT_GOT_SAMPLE  0x21u   /* loader maps to HK_EVENT_GOT_ANOMALY */
#define HK_GOT_MAX_SLOTS     32      /* bounded per-fire batch (verifier-legal) */

extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} hk_ringbuf SEC(".maps");

/* Per-PID array of .got.plt slot ADDRESSES (load-biased VAs) to sample,
 * populated by userspace after it parses the ELF. */
struct hk_got_cfg {
    __u32 count;                          /* number of valid entries in slot_va */
    __u32 reserved;
    __u64 slot_va[HK_GOT_MAX_SLOTS];      /* user VAs of each .got.plt slot */
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct hk_got_cfg);
} hk_got_cfg SEC(".maps");

struct hk_bpf_got_sample_event {
    __u32 schema_version;
    __u32 event_tag;
    __u64 timestamp_ns;
    __u32 pid;
    __u32 slot_count;                     /* number of valid entries below */
    __u64 slot_target[HK_GOT_MAX_SLOTS];  /* resolved pointer value at each slot */
};

/* ---- uprobe: benign hot game fn (cadence) -------------------------------- */
SEC("uprobe")
int BPF_KPROBE(hk_uprobe_got_sample)
{
    struct hk_bpf_got_sample_event *evt;
    struct hk_got_cfg *cfg;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 n, i;

    cfg = bpf_map_lookup_elem(&hk_got_cfg, &pid);
    if (!cfg)
        return 0;   /* not a sampled PID — nothing to do */

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->schema_version = HK_SCHEMA_VERSION;
    evt->event_tag      = HK_EVENT_GOT_SAMPLE;
    evt->timestamp_ns   = bpf_ktime_get_ns();
    evt->pid            = pid;

    n = cfg->count;
    if (n > HK_GOT_MAX_SLOTS)
        n = HK_GOT_MAX_SLOTS;

    /* Bounded loop: the compile-time HK_GOT_MAX_SLOTS bound keeps the verifier
     * happy; the runtime `i < n` guard limits work to the configured count. */
#pragma unroll
    for (i = 0; i < HK_GOT_MAX_SLOTS; i++) {
        evt->slot_target[i] = 0;
        if (i < n) {
            __u64 va = cfg->slot_va[i];
            /* USER read of the slot's stored pointer value. */
            __u64 val = 0;
            if (bpf_probe_read_user(&val, sizeof(val), (const void *)va) == 0)
                evt->slot_target[i] = val;
        }
    }
    evt->slot_count = n;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
