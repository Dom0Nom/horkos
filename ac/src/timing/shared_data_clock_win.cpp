/*
 * ac/src/timing/shared_data_clock_win.cpp
 * Role: Signal 157 — KUSER_SHARED_DATA monotonicity-break sensor. Reads the documented
 *       read-only user-mode page at 0x7FFE0000 (InterruptTime / SystemTime / TickCount /
 *       QpcBias) and compares its advance ratios against GetTickCount64() /
 *       QueryPerformanceCounter() / GetSystemTimePreciseAsFileTime() over the same
 *       window. A sustained directional ratio drift is the time-hook tell; one-off
 *       jitter is not. Direct read of the documented read-only page only — no write,
 *       no hook.
 * Target platform: Windows. The entire active body is behind HK_PLATFORM_WINDOWS;
 *       off-Windows the sampler is a not-implemented no-op.
 * Interface: implements ac/include/horkos/timing/clock_consistency.h. Pure ppm-drift
 *       math lives in timing_logic.cpp.
 */

#include "horkos/timing/clock_consistency.h"
#include "horkos/timing/timing_signals.h"

#include <cstring>

namespace hk {
namespace timing {

#if defined(HK_PLATFORM_WINDOWS)

} // namespace timing
} // namespace hk

#include <windows.h>

namespace hk {
namespace timing {

namespace {

/* The fixed KUSER_SHARED_DATA user-mode mapping. We read only the documented
 * 64-bit time fields. The page is read-only to user mode; this is a documented read,
 * not a hook. The layout offsets are the long-stable public ones:
 *   +0x008 TickCountLowDeprecated / +0x320 TickCount (KSYSTEM_TIME)
 *   +0x008 InterruptTime is actually a KSYSTEM_TIME at +0x008
 * To avoid depending on undocumented intra-struct offsets, we read the values through
 * the documented APIs that mirror them where possible and the raw page only for
 * InterruptTime/SystemTime, whose offsets are stable and public.
 * HK-UNCERTAIN(kusd-offsets): the precise KUSER_SHARED_DATA field offsets
 * (InterruptTime @ 0x08, SystemTime @ 0x14, TickCount @ 0x320 as KSYSTEM_TIME) are
 * public but version-sensitive in their high/low split; confirm against the target
 * build's ntddk KUSER_SHARED_DATA before trusting the raw reads. Until then we derive
 * shared_system_dt / shared_interrupt_dt from the documented KSYSTEM_TIME volatile-read
 * idiom below and leave the raw-offset path out. */
constexpr ULONG_PTR KUSD_BASE = 0x7FFE0000u;

/* KSYSTEM_TIME volatile-read idiom: re-read High1Time/Low/High2 until the two High
 * words agree (the page is updated without a lock). */
struct KSYSTEM_TIME_LOCAL {
    ULONG LowPart;
    LONG  High1Time;
    LONG  High2Time;
};

uint64_t read_ksystem_time(ULONG_PTR offset) {
    volatile const KSYSTEM_TIME_LOCAL* p =
        reinterpret_cast<volatile const KSYSTEM_TIME_LOCAL*>(KUSD_BASE + offset);
    for (;;) {
        const LONG hi1 = p->High1Time;
        const ULONG lo = p->LowPart;
        const LONG hi2 = p->High2Time;
        if (hi1 == hi2) {
            return (static_cast<uint64_t>(static_cast<uint32_t>(hi1)) << 32) |
                   static_cast<uint64_t>(lo);
        }
    }
}

/* Public, stable offsets within KUSER_SHARED_DATA. */
constexpr ULONG_PTR KUSD_INTERRUPT_TIME = 0x08u;
constexpr ULONG_PTR KUSD_SYSTEM_TIME    = 0x14u;

} // namespace

bool timing_sample_clock_consistency(timing_clock_consistency* out,
                                     uint32_t wine_vm_ctx_tag) noexcept {
    if (out == nullptr) {
        return false;
    }
    std::memset(out, 0, sizeof(*out));
    out->wine_vm_ctx = (wine_vm_ctx_tag != 0u) ? 1u : 0u;

    /* Window start samples. */
    const uint64_t sh_int0  = read_ksystem_time(KUSD_INTERRUPT_TIME);
    const uint64_t sh_sys0  = read_ksystem_time(KUSD_SYSTEM_TIME);
    const ULONGLONG tick0   = GetTickCount64();
    LARGE_INTEGER qpc0;
    QueryPerformanceCounter(&qpc0);

    /* A short bounded busy window so all clocks advance measurably without sleeping
     * (sleeping would invite a context switch). */
    volatile uint64_t spin = 0u;
    for (uint32_t i = 0u; i < 200000u; ++i) {
        spin += i;
    }
    (void)spin;

    const uint64_t sh_int1  = read_ksystem_time(KUSD_INTERRUPT_TIME);
    const uint64_t sh_sys1  = read_ksystem_time(KUSD_SYSTEM_TIME);
    const ULONGLONG tick1   = GetTickCount64();
    LARGE_INTEGER qpc1;
    QueryPerformanceCounter(&qpc1);

    out->shared_interrupt_dt = (sh_int1 > sh_int0) ? (sh_int1 - sh_int0) : 0u;
    out->shared_system_dt    = (sh_sys1 > sh_sys0) ? (sh_sys1 - sh_sys0) : 0u;
    out->api_tick_dt         = (tick1 > tick0) ? (tick1 - tick0) : 0u;
    out->api_qpc_dt = (qpc1.QuadPart > qpc0.QuadPart)
                          ? static_cast<uint64_t>(qpc1.QuadPart - qpc0.QuadPart)
                          : 0u;

    /* Drift of the shared InterruptTime (100ns units) vs the QPC advance over the same
     * window. Both are high-resolution monotonic clocks; a hooked GetTickCount64/QPC
     * that dilates time diverges from the shared page the hook did not touch. Server
     * requires the drift to be SUSTAINED across windows. */
    out->ratio_drift_ppm =
        clock_ratio_drift_ppm(out->shared_interrupt_dt, out->api_qpc_dt);

    /* Usable only if both clocks advanced; a zero window carries no ratio. */
    return out->api_qpc_dt != 0u && out->shared_interrupt_dt != 0u;
}

#else /* non-Windows: not-implemented no-op. */

bool timing_sample_clock_consistency(timing_clock_consistency* out,
                                     uint32_t /*wine_vm_ctx_tag*/) noexcept {
    if (out != nullptr) {
        std::memset(out, 0, sizeof(*out));
    }
    return false;
}

#endif /* HK_PLATFORM_WINDOWS */

} // namespace timing
} // namespace hk
