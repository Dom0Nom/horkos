/*
 * ac/src/timing/sibling_watchdog.cpp
 * Role: Signal 156 — sibling-thread RDTSCP watchdog. A watchdog thread (pinned
 *       best-effort to a sibling core via the platform/ affinity seam) keeps a
 *       lock-free atomic TSC slot fresh; the sampler reads an in-section __rdtscp and
 *       the freshest slot value, diffs the two clocks, and folds the IA32_TSC_AUX
 *       core-id cross-check. Windows/Linux hard-pin the watchdog; macOS gives only
 *       affinity hints (best-effort, weighted lower server-side — plan FLAG 156).
 * Target platforms: cross. The clock + affinity intrinsics route exclusively through
 *       hk::platform::{rdtscp_aux, pin_thread_to_core, unpin_thread} (guardrail #1);
 *       this TU touches NO raw intrinsic or OS affinity API.
 * Interface: implements ac/include/horkos/timing/watchdog.h. Pure decision math
 *       (divergence/usable-window) lives in timing_logic.cpp.
 */

#include "horkos/timing/watchdog.h"
#include "horkos/timing/timing_signals.h"
#include "platform.h"

#include <atomic>
#include <thread>
#include <cstring>

namespace hk {
namespace timing {

namespace {

/* The lock-free slot the watchdog refreshes. The packed value is the watchdog's last
 * __rdtscp reading; aux is its last IA32_TSC_AUX. Relaxed ordering is sufficient — we
 * only need a recent value, not a happens-before with the sampler (the divergence is a
 * statistical signal over many windows, and a torn read is discarded by the
 * usable-window gate, not trusted). */
std::atomic<uint64_t> g_slot_tsc{0};
std::atomic<uint32_t> g_slot_aux{0};
std::atomic<bool>     g_running{false};
std::thread           g_watchdog;

void watchdog_loop() {
    /* Best-effort pin to core 1 (a sibling of the typical main-thread core 0). On
     * macOS this returns false and the loop runs unpinned — the aux core-id check
     * (and the lower server-side weight) compensate. */
    (void)hk::platform::pin_thread_to_core(1u);
    while (g_running.load(std::memory_order_relaxed)) {
        uint32_t aux = 0u;
        const uint64_t tsc = hk::platform::rdtscp_aux(&aux);
        g_slot_tsc.store(tsc, std::memory_order_relaxed);
        g_slot_aux.store(aux, std::memory_order_relaxed);
        /* Yield rather than spin-burn a whole core; the slot only needs to be
         * "recent" relative to the in-section window. */
        std::this_thread::yield();
    }
    hk::platform::unpin_thread();
}

} // namespace

bool timing_watchdog_start() noexcept {
    bool expected = false;
    if (!g_running.compare_exchange_strong(expected, true)) {
        return true; /* already running */
    }
    try {
        g_watchdog = std::thread(watchdog_loop);
    } catch (...) {
        /* No exceptions out of this seam; a failed thread spawn means the sampler
         * simply reports not-collected. */
        g_running.store(false, std::memory_order_relaxed);
        return false;
    }
    return true;
}

void timing_watchdog_stop() noexcept {
    if (!g_running.exchange(false)) {
        return;
    }
    if (g_watchdog.joinable()) {
        g_watchdog.join();
    }
}

bool timing_sample_watchdog(timing_watchdog* out) noexcept {
    if (out == nullptr) {
        return false;
    }
    std::memset(out, 0, sizeof(*out));

    if (!g_running.load(std::memory_order_relaxed)) {
        return false; /* watchdog not started — not collected */
    }

    /* Two in-section reads bracket the watchdog observation so we measure an actual
     * in-thread interval, and pair it with the watchdog's advance over (about) the
     * same span. */
    uint32_t aux_in0 = 0u;
    const uint64_t in0 = hk::platform::rdtscp_aux(&aux_in0);
    const uint64_t watch0 = g_slot_tsc.load(std::memory_order_relaxed);

    /* A small bounded busy interval so both clocks advance measurably. */
    volatile uint64_t spin = 0u;
    for (uint32_t i = 0u; i < 4096u; ++i) {
        spin += i;
    }
    (void)spin;

    uint32_t aux_in1 = 0u;
    const uint64_t in1 = hk::platform::rdtscp_aux(&aux_in1);
    const uint64_t watch1 = g_slot_tsc.load(std::memory_order_relaxed);
    const uint32_t aux_watch = g_slot_aux.load(std::memory_order_relaxed);

    const uint64_t in_delta    = (in1 > in0) ? (in1 - in0) : 0u;
    const uint64_t watch_delta = (watch1 > watch0) ? (watch1 - watch0) : 0u;

    /* HK-TODO(ctx-switch): a GetThreadTimes-derived context-switch flag (Windows) /
     * getrusage nivcsw delta (POSIX) would let us discard windows where the scheduler
     * preempted us mid-measurement. The cross-platform seam for that is not yet wired,
     * so ctx_switch_seen is left 0 here and the aux core-id migration check is the
     * only window-discard gate for now (the divergence is a many-sample statistic, so
     * a few unflagged switches do not move the server's percentile threshold). */
    const uint32_t ctx_switch_seen = 0u;

    out->in_section_tsc_delta = in_delta;
    out->watchdog_tsc_delta   = watch_delta;
    out->aux_core_in          = aux_in0;
    out->aux_core_watch       = aux_watch;
    out->ctx_switch_seen      = ctx_switch_seen;
    out->divergence_pct       = watchdog_divergence_pct(in_delta, watch_delta);

    /* A migration of the IN-SECTION thread between the two reads also corrupts the
     * window; fold that into the usable-window decision alongside the in/watch aux
     * comparison. */
    const bool in_migrated = (aux_in0 != 0u && aux_in1 != 0u && aux_in0 != aux_in1);
    if (in_migrated) {
        return false;
    }
    return watchdog_window_usable(ctx_switch_seen, aux_in0, aux_watch);
}

} // namespace timing
} // namespace hk
