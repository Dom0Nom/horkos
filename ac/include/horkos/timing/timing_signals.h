/*
 * Role: The stable usermode timing/execution-trace sensor surface the detection
 *       catalog names for timing-side-channels (catalog signals 154/156/157/159/
 *       161/162, plus 155 folded from the kernel ring). Declares the plain-POD
 *       per-signal result structs, the `timing_report` aggregate, the
 *       `timing_collect_all()` aggregator, and the PURE classifier cores (modality,
 *       cadence, divergence, leaf-fan flatness) the sampler TUs call. Backends change
 *       behind this header; the header itself does not (guardrail #10).
 * Target platforms: Windows + cross (the clock-core sensors 156/162 are
 *       cross-platform via platform/ intrinsics; 154/157/159/161 + the kernel-ring
 *       fold are Windows-only and behind HK_PLATFORM_WINDOWS in their .cpp).
 * Interface: this IS the timing sensor surface; the ac/src/timing TUs implement it;
 *       consumed by ac/src/ac.cpp. No platform API in this header (guardrail #1):
 *       the POD structs hold sampled scalars only; all OS calls live in the .cpp.
 *
 * Server is the only classifier — every sampler ships raw vectors/histograms/owner
 * scalars; NONE of the cores here decides a ban. The pure cores answer narrow
 * "is there reportable evidence / what shape is it" questions the server FP-gates.
 *
 * HK-TODO(schema): signal 155's wire record (HK_EVENT_TIMING_FREQ_SKEW /
 * hk_event_timing_freq_skew) is NOT yet in the frozen sdk/include/horkos/event_schema.h
 * (still v2, no type 5). The kernel sensor + the userspace correlator are written
 * against the plan's pinned 16-byte layout and stubbed around the missing type until
 * the Schema phase lands it; `timing_kernel_summary` below is the in-memory fold of
 * that record (NOT a wire struct) and is safe to define here.
 */

#pragma once

#include <cstdint>

namespace hk {
namespace timing {

/* -------------------------------------------------------------------------
 * Detection-catalog signal ids covered by this domain. Used as report tags;
 * NOT wire event-type values.
 * ------------------------------------------------------------------------- */
enum class Signal : uint32_t {
    VehAttrib      = 154,
    FreqSkew       = 155, /* kernel-assisted (KMDF); folded from the ring */
    Watchdog       = 156,
    ClockConsist   = 157,
    ExcLatency     = 159,
    GuardCadence   = 161,
    CpuidFan       = 162,
};

/* sensors_ok bitmask: one bit per sampler that ran cleanly this pass. "ran cleanly"
 * means the sampler produced a usable result, NOT "found a cheat". A sampler that
 * could not run (API unavailable, non-x86, decoy not armed) leaves its bit clear so
 * the server never reads a zeroed result as "clean". */
enum SensorOk : uint32_t {
    HK_TIMING_OK_NONE     = 0u,
    HK_TIMING_OK_VEH      = 1u << 0,  /* 154 */
    HK_TIMING_OK_WATCHDOG = 1u << 1,  /* 156 */
    HK_TIMING_OK_CLOCK    = 1u << 2,  /* 157 */
    HK_TIMING_OK_EXC      = 1u << 3,  /* 159 */
    HK_TIMING_OK_GUARD    = 1u << 4,  /* 161 */
    HK_TIMING_OK_CPUID    = 1u << 5,  /* 162 */
    HK_TIMING_OK_KERNEL   = 1u << 6,  /* 155 */
};

/* Fixed histogram bucket count shared by 159 (dispatch latency) and 161
 * (guard-fault inter-arrival). The server validates length on deserialize. */
constexpr uint32_t HK_TIMING_HIST_BUCKETS = 32u;
/* Fixed leaf-fan width for 162. The swept leaf ids accompany the latencies. */
constexpr uint32_t HK_TIMING_CPUID_LEAVES = 16u;

/* ---- Per-signal POD result structs (mirror the plan §Interfaces sketch). ---- */

typedef struct timing_veh_attrib {        /* signal 154 */
    uint32_t foreign_resolver;     /* 1 if first resolver's image is outside game/known runtime */
    uint32_t resolver_signed;      /* 1 if resolver image is signed / on attest module list */
    uint32_t dr6_stepbit;          /* CONTEXT.Dr6 single-step/BP bit observed */
    uint32_t dr7_local_enable;     /* CONTEXT.Dr7 L0..L3 mask */
    uint64_t resolver_image_base;  /* RtlPcToFileHeader(ReturnAddress); 0 = unmapped */
} timing_veh_attrib;

typedef struct timing_watchdog {          /* signal 156 */
    uint64_t in_section_tsc_delta;
    uint64_t watchdog_tsc_delta;
    uint32_t aux_core_in;          /* IA32_TSC_AUX read in-section (0 = unknown) */
    uint32_t aux_core_watch;       /* IA32_TSC_AUX read by watchdog (0 = unknown) */
    uint32_t ctx_switch_seen;      /* GetThreadTimes-derived: window had a switch */
    uint32_t divergence_pct;       /* |delta| / in_section * 100, clamped to 1000 */
} timing_watchdog;

typedef struct timing_clock_consistency { /* signal 157 */
    uint64_t shared_interrupt_dt;  /* KUSER_SHARED_DATA.InterruptTime delta */
    uint64_t shared_system_dt;     /* KUSER_SHARED_DATA.SystemTime delta */
    uint64_t api_tick_dt;          /* GetTickCount64 delta over same window */
    uint64_t api_qpc_dt;           /* QueryPerformanceCounter delta */
    uint32_t ratio_drift_ppm;      /* sustained directional drift, parts-per-million */
    uint32_t wine_vm_ctx;          /* 1 if Wine/Proton/VM context already tagged */
} timing_clock_consistency;

typedef struct timing_exc_latency {       /* signal 159 */
    uint32_t hist[HK_TIMING_HIST_BUCKETS]; /* dispatch-latency buckets */
    uint32_t baseline_modes;       /* mode count of the per-machine startup baseline */
    uint32_t live_modes;           /* mode count of the live distribution */
    uint32_t reserved;
} timing_exc_latency;

typedef struct timing_guard_cadence {     /* signal 161 */
    uint32_t inter_arrival[HK_TIMING_HIST_BUCKETS]; /* guard-fault inter-arrival buckets */
    uint32_t fault_count;          /* faults per logical invocation */
    uint32_t uniform_cadence;      /* 1 if tight high-count uniform-cadence burst */
    uint32_t eflags_tf_or_dr6;     /* TF set or DR6 BP bit in same VEH */
} timing_guard_cadence;

typedef struct timing_cpuid_fan {         /* signal 162 */
    uint32_t leaf_latency[HK_TIMING_CPUID_LEAVES]; /* per-leaf RDTSCP-fenced latency (cycles) */
    uint32_t leaf_id[HK_TIMING_CPUID_LEAVES];      /* the swept leaf values */
    uint32_t flat_baseline_cycles; /* near-flat bare-metal reference */
    uint32_t reserved;
} timing_cpuid_fan;

typedef struct timing_kernel_summary {    /* signal 155, folded from kernel ring */
    uint32_t aperf_mperf_eff_mhz;  /* derived effective frequency */
    uint32_t rdtsc_nominal_mhz;    /* nominal base from CPUID 0x15 */
    uint32_t skew_pct;             /* mismatch beyond P-state bounds, percent */
    uint32_t hv_present_bit;       /* cross-checked hypervisor-present tag */
} timing_kernel_summary;

typedef struct timing_report {
    timing_veh_attrib        veh;      /* 154 */
    timing_watchdog          wdog;     /* 156 */
    timing_clock_consistency clock;    /* 157 */
    timing_exc_latency       exc;      /* 159 */
    timing_guard_cadence     guard;    /* 161 */
    timing_cpuid_fan         cpuid;    /* 162 */
    timing_kernel_summary    kern;     /* 155 */
    uint32_t                 sensors_ok; /* SensorOk bitmask: which samplers ran cleanly */
} timing_report;

/* -------------------------------------------------------------------------
 * Aggregator. Zero-initializes a timing_report, runs each available sampler,
 * folds the kernel ring (155), and sets the matching SensorOk bit per sampler
 * that produced a usable result. Pure glue; the OS calls live in the per-signal
 * TUs. Returns the sensors_ok bitmask (== report.sensors_ok) for convenience.
 * Implemented in ac/src/timing/timing_collect.cpp.
 * ------------------------------------------------------------------------- */
uint32_t timing_collect_all(timing_report* out) noexcept;

/* Fold the kernel timing ring (signal 155) into *out. Drains the
 * HK_EVENT_TIMING_FREQ_SKEW records via the SDK IOCTL bridge and writes the
 * summary into out->kern. Returns true if a usable kernel summary was folded
 * (sets HK_TIMING_OK_KERNEL upstream). Implemented in
 * ac/src/timing/timing_kernel_correlate.cpp; Windows-only (the driver bridge is
 * Win-specific), a no-op returning false elsewhere.
 *
 * HK-TODO(schema): the wire type HK_EVENT_TIMING_FREQ_SKEW is not yet in the frozen
 * event_schema.h, so the drain cannot decode it as a DISTINCT record yet — see the
 * correlator TU. Until then this returns false (no kernel summary). */
bool timing_collect_kernel(timing_kernel_summary* out) noexcept;

/* =========================================================================
 * Pure per-signal classifier cores. Inputs are already-sampled scalars/vectors;
 * NO platform API, NO I/O, so they are host-testable. None decides a ban —
 * they shape the raw evidence the server FP-gates.
 * ========================================================================= */

/* 156: clamp the watchdog/in-section divergence to a percent (0..1000). Returns
 * 0 when in_section_tsc_delta is 0 (degenerate window — no evidence), so a
 * zero-length window never manufactures a huge ratio. */
uint32_t watchdog_divergence_pct(uint64_t in_section_tsc_delta,
                                 uint64_t watchdog_tsc_delta) noexcept;

/* 156: decide whether a sampled window is usable for the divergence comparison.
 * A window is DISCARDED (returns false) if a context switch was seen, OR if both
 * aux core ids are known (non-zero) and differ (migration). aux==0 means "core
 * unknown" (non-x86 / no TSC_AUX) and must NOT by itself discard the window. */
bool watchdog_window_usable(uint32_t ctx_switch_seen,
                            uint32_t aux_core_in,
                            uint32_t aux_core_watch) noexcept;

/* 157: parts-per-million directional drift of the shared-page clock vs an API
 * clock over the same window. Returns 0 (no evidence) when api_dt is 0. The sign
 * is folded away (magnitude only); the server requires this to be SUSTAINED
 * across windows before weighting it (one-off jitter is not a signal). */
uint32_t clock_ratio_drift_ppm(uint64_t shared_dt, uint64_t api_dt) noexcept;

/* 159/161: count the local modes (peaks) of a fixed-length histogram. A bucket is
 * a mode if it is a strict local maximum (> both neighbors) and carries at least
 * `min_count` samples (noise floor). Endpoints compare against their single
 * in-range neighbor. Multi-modality after a unimodal per-machine baseline is the
 * 159 dispatch-latency tell; the server compares baseline vs live mode counts. */
uint32_t histogram_mode_count(const uint32_t* hist, uint32_t buckets,
                              uint32_t min_count) noexcept;

/* 161: is the inter-arrival distribution a tight, high-count, uniform-cadence
 * burst (the single-step fingerprint)? True iff total faults >= `min_faults` AND
 * at least `concentration_pct` percent of all samples fall in a SINGLE bucket
 * (a uniform stepping cadence concentrates inter-arrivals in one bin). Pure over
 * the captured histogram + fault count. */
bool cadence_is_uniform_burst(const uint32_t* inter_arrival, uint32_t buckets,
                              uint32_t fault_count, uint32_t min_faults,
                              uint32_t concentration_pct) noexcept;

/* 162: spread of the per-leaf latency fan vs a flat bare-metal baseline. Returns
 * (max_leaf_latency - min_leaf_latency) over the populated leaves; the server
 * compares this spread against flat_baseline_cycles + the 155 hv-present bit.
 * Leaves with id 0 are treated as unpopulated and skipped. Returns 0 when fewer
 * than 2 leaves are populated (no spread to measure). */
uint32_t cpuid_fan_spread(const uint32_t* leaf_latency, const uint32_t* leaf_id,
                          uint32_t leaves) noexcept;

} // namespace timing
} // namespace hk
