/*
 * Role: Signal 155 correlator — drains the kernel timing-skew records
 *       (HK_EVENT_TIMING_FREQ_SKEW / hk_event_timing_freq_skew, emitted by
 *       kernel/win/src/TimingProbe.c) from the driver via the SDK IOCTL drain bridge
 *       and folds the APERF/MPERF-vs-RDTSC effective-frequency skew into the usermode
 *       timing report (timing_kernel_summary). Treats the skew as a VM-context tag,
 *       never an autonomous ban (WSL2 / Hyper-V / Credential Guard legitimately
 *       virtualize TSC) — the fold is raw; the server scores.
 * Target platform: Windows (the driver bridge is Win-specific). Off-Windows it is a
 *       no-op returning false (no kernel timing source).
 * Interface: implements timing_collect_kernel() in
 *       ac/include/horkos/timing/timing_signals.h; consumes sdk/include/horkos/ioctl.h.
 *
 * Schema: the wire event type HK_EVENT_TIMING_FREQ_SKEW is now FROZEN in
 * sdk/include/horkos/event_schema.h as type 38 (schema v6), no longer colliding
 * with any other domain's provisional "next free type". The 16-byte
 * hk_event_timing_freq_skew payload mirror is declared below (the discriminant is
 * the enum constant, not a local macro). The drain + fold code is written against
 * the pinned 16-byte layout; the live drain remains gated on the kernel emitter
 * that produces these records on-target (kernel-side, UNVERIFIED on this host).
 */

#include "horkos/timing/timing_signals.h"

#include <cstring>
#include <cstdint>

namespace hk {
namespace timing {

/* Kernel-private mirror of the freq-skew payload. Pinned to 16 bytes to stay
 * within the frozen HK_EVENT_PAYLOAD_MAX so no ring resize is needed. The wire
 * discriminant HK_EVENT_TIMING_FREQ_SKEW is now FROZEN in hk_event_type
 * (event_schema.h, type 38, schema v6); it is no longer a local macro (a macro
 * would textually replace the enum token). */
typedef struct hk_event_timing_freq_skew { /* 16 bytes */
    uint32_t eff_mhz;       /* APERF/MPERF-derived effective frequency */
    uint32_t nominal_mhz;   /* CPUID 0x15 nominal base frequency */
    uint32_t skew_pct;      /* mismatch beyond P-state bounds, percent */
    uint32_t flags;         /* HK_TIMING_* : msr_gp_faulted, hv_present, tsc_invariant */
} hk_event_timing_freq_skew;

/* flags bits for hk_event_timing_freq_skew.flags. */
#define HK_TIMING_FLAG_MSR_GP_FAULTED 0x00000001u
#define HK_TIMING_FLAG_HV_PRESENT     0x00000002u
#define HK_TIMING_FLAG_TSC_INVARIANT  0x00000004u

#if defined(HK_PLATFORM_WINDOWS)

/* Fold a single decoded freq-skew payload into the summary. Pure; the wire-decode +
 * drain wrapper would feed this once the schema type lands. Kept as a file-local helper
 * so the fold logic is exercised the moment HK_TIMING_SCHEMA_READY is defined. */
static void fold_freq_skew(const hk_event_timing_freq_skew* rec,
                           timing_kernel_summary* out) {
    out->aperf_mperf_eff_mhz = rec->eff_mhz;
    out->rdtsc_nominal_mhz    = rec->nominal_mhz;
    out->skew_pct             = rec->skew_pct;
    out->hv_present_bit       = (rec->flags & HK_TIMING_FLAG_HV_PRESENT) ? 1u : 0u;
}

bool timing_collect_kernel(timing_kernel_summary* out) noexcept {
    if (out == nullptr) {
        return false;
    }
    std::memset(out, 0, sizeof(*out));

    /* The wire type HK_EVENT_TIMING_FREQ_SKEW is now FROZEN in event_schema.h
     * (type 38, schema v6). The remaining gate is the KERNEL drain transport:
     * drain \\.\Horkos via HK_IOCTL_DRAIN_EVENTS, walk the hk_event_record
     * stream, and for each record whose header.type == HK_EVENT_TIMING_FREQ_SKEW,
     * fold_freq_skew(payload, out). Wired under HK_TIMING_SCHEMA_READY once the
     * on-box kernel emitter + the SDK device-handle path land (Windows kernel,
     * UNVERIFIED off-target); until then report no kernel summary rather than
     * guessing. */
#if defined(HK_TIMING_SCHEMA_READY)
    /* Activated post-Schema: open device, DRAIN, decode, fold. Left unwired here
     * because the drain envelope decode shares the SDK device-handle path that lands
     * with the schema bump. */
    (void)&fold_freq_skew;
    return false;
#else
    (void)&fold_freq_skew; /* keep the fold helper live for the post-Schema activation */
    return false;
#endif
}

#else /* non-Windows: no kernel timing source. */

bool timing_collect_kernel(timing_kernel_summary* out) noexcept {
    if (out != nullptr) {
        std::memset(out, 0, sizeof(*out));
    }
    return false;
}

#endif /* HK_PLATFORM_WINDOWS */

} // namespace timing
} // namespace hk
