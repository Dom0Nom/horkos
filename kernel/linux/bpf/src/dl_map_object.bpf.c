/*
 * Role: uretprobe on the glibc dynamic loader's _dl_map_object. Emits one
 *       compact record per DSO the loader maps (a link-map append index, the
 *       soname user pointer, and the load bias) so the userspace correlators
 *       DsoProvenance.cpp (signal 82) and LinkMapOrder.cpp (signal 87) can build
 *       the per-PID DT_NEEDED-vs-runtime model and the link-map insertion order.
 *       This program parses NO ELF and reads NO /proc — it only forwards a
 *       lightweight event; all ELF/proc work is userspace (guardrail #4).
 * Target platform: Linux eBPF (uprobe/uretprobe, kernel >= 4.17 for uprobes,
 *                  >= 5.8 for the shared BPF_MAP_TYPE_RINGBUF).
 * Interface: shares hk_ringbuf with lsm_file_open.bpf.c (declared extern here);
 *            Loader.cpp repoints the map via bpf_map__reuse_fd before load and
 *            translates the HK_EVENT_DL_MAP record to hk_event_record.
 *
 * Guardrail compliance:
 *   #1 No raw platform macros — Linux-only by build gating.
 *   #3 This module comment covers role/platform/interface.
 *   #4 Pure kernel eBPF TU — no userspace headers.
 *   #6 Compiled -Wall -Wextra -Werror (enforced in CMakeLists.txt).
 *
 * HK-UNCERTAIN(glibc-internal): `_dl_map_object` is a glibc-INTERNAL symbol, not
 * part of the stable ABI. Its name/signature/existence varies across glibc
 * versions and it is ABSENT on musl (Alpine, some Deck flatpaks). The attach
 * offset MUST be resolved per-target at attach time from the libc in
 * /proc/<pid>/maps via BTF/symbol tables, and the uprobe MUST fail gracefully
 * (skip signals 82/87, log) when the symbol is missing rather than failing the
 * whole loader. The argument register carrying the `struct link_map *` (PT_REGS
 * return value of the uretprobe) and the soname accessor offset are likewise
 * version-specific: confirm against the shipping Steam Deck glibc before wiring
 * the real link_map field reads. Until verified on-box, the link_map field
 * extraction below is left as a guarded stub (emits the event with zeroed
 * link-map detail) so userspace still receives the "a DSO was mapped" cadence.
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

/* ---- Wire-format constants (mirror lsm_file_open.bpf.c) ------------------ */
#define HK_SCHEMA_VERSION   3u
#define HK_EVENT_DL_MAP     0x20u   /* BPF-side tag; loader maps to HK_EVENT_DSO_PROVENANCE */
#define HK_SONAME_MAX       256

/* ---- Shared ring buffer (defined in lsm_file_open.bpf.c) ----------------- */
extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} hk_ringbuf SEC(".maps");

/* ---- Ring-buffer event layout -------------------------------------------- */
struct hk_bpf_dl_map_event {
    __u32 schema_version;       /* HK_SCHEMA_VERSION */
    __u32 event_tag;            /* HK_EVENT_DL_MAP */
    __u64 timestamp_ns;         /* bpf_ktime_get_ns() */
    __u32 pid;                  /* tgid of the loader (== protected game) */
    __u32 link_map_index;       /* monotonic per-PID append index (0 = unset) */
    __u64 load_bias;            /* l_addr load bias, 0 if not yet resolvable */
    char  soname[HK_SONAME_MAX];/* truncated soname; userspace re-resolves */
};

/* Per-PID monotonic link-map append counter. Userspace also derives order from
 * the event stream sequence; this is a kernel-side hint that survives reorder. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} hk_dl_seq SEC(".maps");

/* ---- uretprobe: glibc _dl_map_object ------------------------------------- */
/*
 * SEC name is a placeholder; the real attach is BY OFFSET in Loader.cpp via
 * bpf_program__attach_uprobe (retprobe=true) against the resolved libc path +
 * _dl_map_object symbol, NOT by this section string. libbpf permits attaching a
 * uprobe program regardless of the SEC suffix when attach_uprobe is used
 * explicitly. The "uretprobe//proc/self/exe:func" form here documents intent.
 */
SEC("uretprobe")
int BPF_KRETPROBE(hk_uret_dl_map_object, void *link_map_ret)
{
    struct hk_bpf_dl_map_event *evt;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 *seqp;
    __u32 seq = 0;

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return 0;   /* drop on overflow — never block */

    evt->schema_version = HK_SCHEMA_VERSION;
    evt->event_tag      = HK_EVENT_DL_MAP;
    evt->timestamp_ns   = bpf_ktime_get_ns();
    evt->pid            = pid;
    evt->load_bias      = 0;
    evt->soname[0]      = '\0';

    /* Maintain a per-PID monotonic append index. */
    seqp = bpf_map_lookup_elem(&hk_dl_seq, &pid);
    if (seqp) {
        seq = *seqp + 1u;
    }
    evt->link_map_index = seq;
    bpf_map_update_elem(&hk_dl_seq, &pid, &seq, BPF_ANY);

    /* HK-UNCERTAIN(glibc-internal): the returned `struct link_map *` layout
     * (l_addr load bias, l_name soname pointer) is glibc-version-specific and
     * NOT in vmlinux BTF (it is a userspace struct). Reading l_name would require
     * a hardcoded, per-glibc field offset + bpf_probe_read_user_str on a USER
     * pointer. Left unimplemented until the offsets are confirmed on the shipping
     * Steam Deck glibc; userspace resolves the soname from its own link_map walk
     * keyed by pid+index. We deliberately do NOT guess the offset (a wrong offset
     * reads arbitrary user memory). The `link_map_ret` pointer is forwarded as a
     * presence signal only via the event cadence. */
    (void)link_map_ret;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
