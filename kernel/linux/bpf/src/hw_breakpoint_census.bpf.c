/*
 * Role: Signal 158 — hardware-breakpoint census on guarded symbols (timing-side-
 *       channels, Linux). Counts PERF_TYPE_BREAKPOINT perf events whose owning task is
 *       OUTSIDE the game's thread group (and absent from an allowlisted-tracer set),
 *       observed at the breakpoint install / #DB handler path. The census is the raw
 *       signal; the loader keys it to the game tgid and ships counts — never a local
 *       ban. AUDIT-ONLY on Steam Deck Game Mode (locked decision: Game Mode requires
 *       eBPF, no LKM).
 * Target platform: Linux eBPF (CO-RE). Default OFF (locked decision 3; this whole
 *       subtree is behind the parent HORKOS_LINUX_EBPF gate, and the sensor is behind
 *       its own HORKOS_LINUX_EBPF_HWBP_CENSUS sub-option).
 * Interface: shares hk_ringbuf (extern); the loader maps the census event into the
 *       timing report path. Mirrors event_schema.h field-name conventions (loader
 *       translates the kernel-private tag into the wire record once Schema lands).
 *
 * Guardrail compliance: #1, #3, #4, #6 (-Wall -Wextra -Werror at the kernel warning
 * level — every CO-RE read is relocatable; the uncertain attach point is a documented
 * stub, not a guess, so the verifier-clean program still builds with -Werror).
 *
 * BPF-LSM / attach prerequisite (document, do not assume): the breakpoint-install
 * observation requires either a kprobe on the install path or a tracepoint that exposes
 * perf_event_attr.type — see the HK-UNCERTAIN block. No lsm/* hook is used here, so the
 * lsm= boot-parameter prerequisite does NOT apply to THIS program.
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define HK_SCHEMA_VERSION       3u
#define HK_EVENT_HWBP_CENSUS    0x2Cu  /* loader maps to the timing census record */

/* PERF_TYPE_BREAKPOINT is 5 in the UAPI (perf_type_id). We compare the observed
 * perf_event_attr.type against it rather than relying on a vmlinux.h enum that may not
 * expose the UAPI constant. */
#define HK_PERF_TYPE_BREAKPOINT 5u

extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} hk_ringbuf SEC(".maps");

/* The game's tgid (set by the loader). Census counts breakpoint events whose owner is
 * OUTSIDE this thread group — a foreign tracer arming a HW breakpoint on the game. */
const volatile __u32 hk_game_tgid = 0;

/* Census event: one record per observed foreign breakpoint install targeting the game. */
struct hk_bpf_hwbp_census_event {
    __u32 schema_version;
    __u32 event_tag;
    __u64 timestamp_ns;
    __u32 owner_pid;     /* tgid that installed/owns the breakpoint (the foreign tracer) */
    __u32 owner_tid;
    __u32 target_pid;    /* the game tgid the breakpoint targets */
    __u32 bp_type;       /* PERF_TYPE_BREAKPOINT census discriminant (==5) */
};

/*
 * HK-UNCERTAIN(hwbp-census-attach): the exact attach point + CO-RE field path for the
 * "a PERF_TYPE_BREAKPOINT event was created targeting the game's address space" signal
 * is version-sensitive and must be confirmed against the target kernel BTF (Deck-class)
 * before it is relied on. Candidate attach points:
 *   - fexit/ksys_perf_event_open or a kprobe on perf_event_alloc, reading
 *     perf_event_attr.type == PERF_TYPE_BREAKPOINT and the attr's bp_addr/target task;
 *   - a tracepoint on the arch breakpoint install (arch_install_hw_breakpoint) plus a
 *     task-ownership read.
 * The attr.type / bp_addr / owning-task CO-RE paths differ across kernels, and reading
 * the CREATOR's tgid vs the TARGET task tgid requires care (perf events can target a
 * different task than the creator). Per guardrail #13 the real attach + reads are NOT
 * guessed: this raw_tracepoint body compiles verifier-clean (no unrelocated reads) and
 * emits NOTHING until the attach point + field paths are confirmed. The structure
 * (game-tgid scoping, foreign-owner gate, census record) is in place so activation is a
 * localized change once the BTF is validated.
 * (docs: PERF_TYPE_BREAKPOINT == 5 is a UAPI constant from
 * include/uapi/linux/perf_event.h; perf_event_attr.bp_addr is UAPI-stable per
 * perf_event_open(2). The internal kernel struct perf_event and how to navigate
 * creator-vs-target pid is NOT documented in public BPF API — still needs on-target)
 */
SEC("raw_tracepoint/sys_enter")
int hk_hwbp_census_probe(struct bpf_raw_tracepoint_args *ctx)
{
    __u64 pid_tgid;
    __u32 tgid;

    (void)ctx;  /* the perf_event_open arg decode + attr.type filter is the stub above */

    if (hk_game_tgid == 0u)
        return 0; /* loader has not armed the game tgid yet */

    pid_tgid = bpf_get_current_pid_tgid();
    tgid = (__u32)(pid_tgid >> 32);

    /* Only a FOREIGN owner (outside the game's thread group) is census-relevant. The
     * game tracing its own threads (e.g. a legitimate in-process profiler) is not a
     * signal; the loader additionally allowlists known tracers. */
    if (tgid == hk_game_tgid)
        return 0;

    /* HK-UNCERTAIN(hwbp-census-attach): until the real attach decodes a confirmed
     * PERF_TYPE_BREAKPOINT-targeting-the-game event, do not emit — emitting on every
     * foreign sys_enter would be a flood, not a census. Hold the emit. */
    return 0;
}

/* The emit path, kept reachable so it is type-checked and verifier-visible until
 * the real attach point is confirmed. noinline + __attribute__((used)) prevents
 * the compiler from removing it as dead code under -Werror even while the probe
 * body holds it at an inert return. */
static __attribute__((used)) __noinline int hk_emit_census(__u32 owner_pid, __u32 owner_tid)
{
    struct hk_bpf_hwbp_census_event *evt;

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->schema_version = HK_SCHEMA_VERSION;
    evt->event_tag      = HK_EVENT_HWBP_CENSUS;
    evt->timestamp_ns   = bpf_ktime_get_ns();
    evt->owner_pid      = owner_pid;
    evt->owner_tid      = owner_tid;
    evt->target_pid     = hk_game_tgid;
    evt->bp_type        = HK_PERF_TYPE_BREAKPOINT;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* Keepalive probe: references hk_emit_census through a verifier-visible,
 * runtime-variable guard (the volatile hk_game_tgid config map read) so the
 * call site is never constant-folded away by the compiler. The sentinel value
 * 0xFFFFFFFFu is never written by the loader, so this path is inert at runtime
 * while still being verifier-visible. */
SEC("raw_tracepoint/sys_exit")
int hk_hwbp_census_keepalive(struct bpf_raw_tracepoint_args *ctx)
{
    (void)ctx;
    if (hk_game_tgid == 0xFFFFFFFFu)  /* never true; hk_game_tgid is volatile */
        return hk_emit_census(0u, 0u);
    return 0;
}

char _license[] SEC("license") = "GPL";
