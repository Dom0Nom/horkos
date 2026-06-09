/*
 * ac/src/timing/cpuid_leaf_fan_win.cpp
 * Role: Signal 162 — CPUID per-leaf latency-fan sensor. Times __cpuidex across a fixed
 *       leaf sweep with RDTSCP + LFENCE serialization fences, emitting a per-leaf
 *       latency vector. Bare-metal baselines are near-flat; selectively-emulated VMM
 *       leaves (esp. the 0x4000_00xx hypervisor range) spike. Strictly a VM-context
 *       tag combined with signal 155 + the hypervisor-present bit server-side — never
 *       standalone (VBS/HVCI on by default on Win11 produces the same fan).
 * Target platforms: cross (x86 only). Named _win for the primary target but compiled
 *       on every host; the sweep is HK_ARCH_X86_64-gated and the timestamp routes
 *       through hk::platform::rdtscp_aux (guardrail #1). On ARM (Apple Silicon) the
 *       sampler returns false so HK_TIMING_OK_CPUID stays clear (not "flat").
 * Interface: implements ac/include/horkos/timing/cpuid_fan.h. Pure spread math lives
 *       in timing_logic.cpp.
 */

#include "horkos/timing/cpuid_fan.h"
#include "horkos/timing/timing_signals.h"
#include "platform.h"

#include <cstring>

/* Arch gate (per plan §162: the core is cross-arch-declared, the sweep is x86-only).
 * This is an ARCH macro, not an OS platform macro — guardrail #1 governs OS platform
 * conditionals (HK_PLATFORM_*), which this file does not use. */
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#  define HK_ARCH_X86_64 1
#endif

#if defined(HK_ARCH_X86_64)
#  if defined(_MSC_VER)
#    include <intrin.h>   /* __cpuidex, _mm_lfence */
#  else
#    include <cpuid.h>    /* __cpuid_count */
#    include <x86intrin.h>/* _mm_lfence */
#  endif
#endif

namespace hk {
namespace timing {

#if defined(HK_ARCH_X86_64)

namespace {

/* The fixed leaf sweep (plan §162): basic 0x0/0x1/0x7/0xB/0x15 plus the hypervisor
 * CPUID range 0x4000_0000..0x4000_0010. A 0 id marks an unused slot for the pure
 * spread core; leaf 0x0 is the first swept entry, so its slot is non-zero by being a
 * real measurement — to keep leaf 0x0 distinguishable from "empty" we never leave a
 * measured slot's id at 0 (0x0 is stored, but the spread core skips id==0; that
 * deliberately excludes the basic-info leaf 0x0 from the spread, which is fine — the
 * VM tell is the hypervisor-range fan, not leaf 0x0). */
const uint32_t kLeaves[HK_TIMING_CPUID_LEAVES] = {
    0x0u, 0x1u, 0x7u, 0xBu, 0x15u,
    0x40000000u, 0x40000001u, 0x40000002u, 0x40000003u, 0x40000004u,
    0x40000005u, 0x40000006u, 0x40000007u, 0x40000008u, 0x40000009u,
    0x4000000Au,
};

inline void do_cpuid(uint32_t leaf, uint32_t subleaf, uint32_t regs[4]) {
#if defined(_MSC_VER)
    int r[4];
    __cpuidex(r, static_cast<int>(leaf), static_cast<int>(subleaf));
    regs[0] = static_cast<uint32_t>(r[0]);
    regs[1] = static_cast<uint32_t>(r[1]);
    regs[2] = static_cast<uint32_t>(r[2]);
    regs[3] = static_cast<uint32_t>(r[3]);
#else
    unsigned int a = 0, b = 0, c = 0, d = 0;
    __cpuid_count(leaf, subleaf, a, b, c, d);
    regs[0] = a; regs[1] = b; regs[2] = c; regs[3] = d;
#endif
}

} // namespace

bool timing_sample_cpuid_fan(timing_cpuid_fan* out) noexcept {
    if (out == nullptr) {
        return false;
    }
    std::memset(out, 0, sizeof(*out));

    uint32_t min_lat = 0xFFFFFFFFu;
    /* Volatile sink keeps every CPUID result live so the optimizer cannot hoist or
     * elide the instruction we are timing. */
    volatile uint32_t reg_sink = 0u;

    for (uint32_t i = 0u; i < HK_TIMING_CPUID_LEAVES; ++i) {
        uint32_t regs[4] = {0u, 0u, 0u, 0u};

        /* Serialize: LFENCE before the start timestamp, run CPUID (itself
         * serializing), LFENCE + a fenced timestamp after. rdtscp orders prior loads;
         * the lfences bound the CPUID window so the measured cycles are the leaf's
         * dispatch cost, not reordered neighbors. */
        _mm_lfence();
        uint32_t aux0 = 0u;
        const uint64_t t0 = hk::platform::rdtscp_aux(&aux0);
        _mm_lfence();

        do_cpuid(kLeaves[i], 0u, regs);

        _mm_lfence();
        uint32_t aux1 = 0u;
        const uint64_t t1 = hk::platform::rdtscp_aux(&aux1);
        _mm_lfence();

        /* Consume regs through the volatile sink so the compiler cannot elide CPUID. */
        reg_sink = regs[0] ^ regs[1] ^ regs[2] ^ regs[3];

        const uint32_t cycles = (t1 > t0) ? static_cast<uint32_t>(t1 - t0) : 0u;
        out->leaf_latency[i] = cycles;
        out->leaf_id[i]      = kLeaves[i];

        if (cycles != 0u && cycles < min_lat) {
            min_lat = cycles;
        }
    }

    /* The flat bare-metal reference is the minimum observed leaf latency: on bare
     * metal every leaf is near-flat, so min ~= the whole fan; the server compares the
     * SPREAD (cpuid_fan_spread) against this floor + the 155 hv-present bit. */
    out->flat_baseline_cycles = (min_lat == 0xFFFFFFFFu) ? 0u : min_lat;
    (void)reg_sink;
    return true;
}

#else /* non-x86: no CPUID. Return not-collected (never a synthetic "flat" result). */

bool timing_sample_cpuid_fan(timing_cpuid_fan* out) noexcept {
    if (out != nullptr) {
        std::memset(out, 0, sizeof(*out));
    }
    /* HK-UNCERTAIN(arm-cpuid): ARM has no CPUID leaf-fan analogue; signal 162 is x86-
     * only by design. The server reads a clear HK_TIMING_OK_CPUID bit as "not
     * collected on this arch", not as "bare metal". */
    return false;
}

#endif /* HK_ARCH_X86_64 */

} // namespace timing
} // namespace hk
