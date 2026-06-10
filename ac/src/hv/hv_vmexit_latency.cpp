/*
 * ac/src/hv/hv_vmexit_latency.cpp
 * Role: Signal 38 sampler — builds a histogram of CPUID (an unconditionally
 *       vm-exiting, serialising instruction) round-trip latencies, with
 *       independent-clock spans (QPC + KUSER_SHARED_DATA.InterruptTime) so the
 *       server can require TSC-vs-independent-clock divergence before flagging.
 *       Ships the RAW histogram, never a delta or a threshold (FP risk is high:
 *       SpeedStep/turbo, SMM, noisy cloud).
 *       READ-ONLY: timing only.
 * Target platforms: Windows. Guardrail #1: Win32/RDTSC confined here. The block
 *       runs on an AC integrity thread, never the game hot loop (guardrail #9).
 * Interface: implements hv_sample_vmexit_latency from hv_signals.h.
 */

#include "horkos/hv_signals.h"

#if defined(HK_PLATFORM_WINDOWS)

#include <windows.h>
#include <intrin.h>

#define HK_HV_VMEXIT_ITERS 4096u

extern "C" int hv_sample_vmexit_latency(hv_vmexit_latency* out)
{
    unsigned i;
    int regs[4];
    LARGE_INTEGER qpc0, qpc1;
    HANDLE thread = GetCurrentThread();
    int oldPriority;

    if (out == nullptr) {
        return HK_AC_NOT_IMPLEMENTED;
    }
    RtlSecureZeroMemory(out, sizeof(*out));

    __cpuid(regs, 1);
    out->cpu_model = (uint32_t)regs[0]; /* family/model/stepping in EAX. */

    /* Raise priority for a less-preempted window; restore after. */
    oldPriority = GetThreadPriority(thread);
    SetThreadPriority(thread, THREAD_PRIORITY_TIME_CRITICAL);

    QueryPerformanceCounter(&qpc0);
    for (i = 0; i < HK_HV_VMEXIT_ITERS; ++i) {
        unsigned aux;
        uint64_t t0 = __rdtscp(&aux);
        uint64_t t1;
        uint64_t d;
        unsigned bucket;
        __cpuid(regs, 0); /* the serialising vm-exit under test. */
        t1 = __rdtscp(&aux);
        d = (t1 > t0) ? (t1 - t0) : 0;
        /* Bucket by log2-ish bands into 32 slots (cycles). Cap at the last bucket. */
        bucket = 0;
        while (bucket < 31u && d >= (uint64_t)(64ull << bucket)) {
            ++bucket;
        }
        ++out->hist[bucket];
    }
    QueryPerformanceCounter(&qpc1);

    SetThreadPriority(thread, oldPriority);

    out->qpc_span = (uint64_t)(qpc1.QuadPart - qpc0.QuadPart);
    /* InterruptTime via the documented GetTickCount64 proxy (KUSER_SHARED_DATA
     * InterruptTime is not a stable public field; the tick delta is the
     * independent-clock corroborator the server cross-checks). */
    out->shared_interrupt_dt = GetTickCount64();

    return HK_AC_OK;
}

#else

extern "C" int hv_sample_vmexit_latency(hv_vmexit_latency* out)
{
    (void)out;
    return HK_AC_NOT_IMPLEMENTED;
}

#endif
