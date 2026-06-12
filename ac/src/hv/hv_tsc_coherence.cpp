/*
 * Role: Signal 45 sampler — per-logical-processor RDTSCP sampling to surface
 *       cross-vCPU TSC skew vs the invariant-TSC capability. Pins to each LP with
 *       SetThreadAffinityMask, reads RDTSCP (whose IA32_TSC_AUX returns the CPU id
 *       so the pin can be verified), and fills hv_tsc_coherence with the RAW
 *       max-spread (computed by the host-tested pure core hv_tsc_spread) plus the
 *       invariant-TSC bit. The server models skew distributions per CPU SKU; no
 *       client tolerance.
 *       READ-ONLY: affinity + RDTSCP only.
 * Target platforms: Windows. Guardrail #1: Win32/RDTSCP confined here.
 * Interface: implements hv_sample_tsc_coherence from hv_signals.h.
 */

#include "horkos/hv_logic.h"
#include "horkos/hv_signals.h"

#if defined(HK_PLATFORM_WINDOWS)

#include <windows.h>
#include <intrin.h>

extern "C" int hv_sample_tsc_coherence(hv_tsc_coherence* out)
{
    DWORD i, lp;
    unsigned aux;
    int regs[4];
    uint64_t samples[64];
    BOOL monotonic = TRUE;
    HANDLE thread = GetCurrentThread();
    DWORD_PTR processMask = 0, systemMask = 0;

    if (out == nullptr) {
        return HK_AC_NOT_IMPLEMENTED;
    }
    RtlSecureZeroMemory(out, sizeof(*out));

    if (!GetProcessAffinityMask(GetCurrentProcess(), &processMask, &systemMask)) {
        return HK_AC_NOT_IMPLEMENTED;
    }

    lp = 0;
    for (i = 0; i < 64u && lp < 64u; ++i) {
        DWORD_PTR bit = ((DWORD_PTR)1) << i;
        DWORD_PTR prev;
        uint64_t t;
        if ((processMask & bit) == 0) {
            continue;
        }
        prev = SetThreadAffinityMask(thread, bit);
        if (prev == 0) {
            continue;
        }
        YieldProcessor();
        t = __rdtscp(&aux); /* aux carries the CPU id of the executing LP. */
        samples[lp] = t;
        /* aux low bits == the LP index confirms the pin actually took. */
        if ((aux & 0xFFFu) == i) {
            out->aux_pin_verified = 1u;
        }
        if (lp > 0 && samples[lp] < samples[lp - 1]) {
            monotonic = FALSE; /* a later LP read a smaller TSC — skew. */
        }
        ++lp;
        SetThreadAffinityMask(thread, prev);
    }

    out->lp_count = lp;
    out->monotonic = monotonic ? 1u : 0u;
    out->max_abs_skew = hv_tsc_spread(samples, lp);

    /* CPUID 0x80000007 EDX[8] = invariant TSC. */
    __cpuid(regs, (int)0x80000007u);
    out->invariant_tsc = ((uint32_t)regs[3] & 0x100u) ? 1u : 0u;

    return HK_AC_OK;
}

#else

extern "C" int hv_sample_tsc_coherence(hv_tsc_coherence* out)
{
    (void)out;
    return HK_AC_NOT_IMPLEMENTED;
}

#endif
