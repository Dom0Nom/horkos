/*
 * Role: Anti-cheat client lifecycle (ac.h). Owns the start/stop state machine
 *       and the latched detection-flag store that sensors report into and the
 *       bypass tests read back (ac_get_last_flag). Thread-safe (atomic state);
 *       no platform API here — the per-OS sensor wiring attaches through
 *       hk_ac_report_flag, so this lifecycle compiles and is testable on every
 *       host (the kernel driver / sensors are platform-bound and reported via
 *       the flag channel).
 * Target platforms: Windows, Linux, macOS.
 * Implements: ac/include/horkos/ac.h
 *
 * PoC scope: with no kernel driver loaded in a host build, ac_start reports
 * HK_AC_DEGRADED (userspace-only) rather than HK_AC_OK — honest about the
 * absence of kernel visibility. A deployment that has probed and attached the
 * driver sets the active mode via hk_ac_set_driver_present before ac_start.
 */

#include <horkos/ac.h>

#include <atomic>

struct ac_config_t {
    uint32_t reserved;
};

namespace {

enum class State : uint32_t { Idle = 0, Running = 1 };

std::atomic<State> g_state{State::Idle};
std::atomic<uint32_t> g_last_flag{0u};
std::atomic<bool> g_driver_present{false};

} // namespace

/* Backend hook (not in the public header): a platform driver-probe sets this
 * before ac_start so the lifecycle reports active vs degraded honestly. */
extern "C" void hk_ac_set_driver_present(int present) {
    g_driver_present.store(present != 0, std::memory_order_relaxed);
}

/* Backend hook (not in the public header): a sensor reports a detection by
 * OR-ing its signal bit into the latched flag. ac_get_last_flag reads it; the
 * bypass tests assert detection-without-ban through this channel. */
extern "C" void hk_ac_report_flag(uint32_t flag_bit) {
    g_last_flag.fetch_or(flag_bit, std::memory_order_relaxed);
}

extern "C" int ac_start(const ac_config_t* /*cfg*/) {
    State expected = State::Idle;
    // Single-start guard: a second start without a stop is rejected.
    if (!g_state.compare_exchange_strong(expected, State::Running,
                                         std::memory_order_acq_rel)) {
        return HK_AC_ALREADY_RUNNING;
    }
    // Fresh run: clear the latched flag.
    g_last_flag.store(0u, std::memory_order_relaxed);
    // Without a kernel driver attached, the client runs userspace-only.
    return g_driver_present.load(std::memory_order_relaxed) ? HK_AC_OK
                                                            : HK_AC_DEGRADED;
}

extern "C" int ac_stop(void) {
    g_state.store(State::Idle, std::memory_order_release);
    return HK_AC_OK;
}

extern "C" uint32_t ac_get_last_flag(void) {
    return g_last_flag.load(std::memory_order_relaxed);
}
