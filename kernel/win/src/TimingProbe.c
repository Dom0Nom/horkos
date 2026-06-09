/*
 * kernel/win/src/TimingProbe.c
 * Role: Signal 155 — APERF/MPERF-vs-RDTSC invariant-skew sensor (KMDF). Userspace
 *       cannot read IA32_APERF/IA32_MPERF, so this kernel probe reads them around a
 *       fixed busy-loop, derives the effective frequency, and compares it to the
 *       __rdtsc delta / KeQueryPerformanceCounter delta and the CPUID-0x15 nominal
 *       base. Emits HK_EVENT_TIMING_FREQ_SKEW via HkRingEmit. The skew is a VM-context
 *       TAG (WSL2 / Hyper-V / Credential Guard legitimately virtualize TSC) — never an
 *       autonomous ban; the server scores it with the hypervisor-present bit.
 * Target platforms: Windows kernel mode (KMDF). No-op when HK_WIN_TIMING_FREQSKEW is
 *       not defined (build flag OFF by default — the MSR probe is field-gatable).
 * Interface: HkTimingFreqSkewProbe(Ctx), declared locally here (the integrity-scan
 *       orchestrator wiring belongs to the win-kernel-driver-integrity domain — this
 *       TU does not edit HkIntegrityScanAll). Emits via HkRingEmit (RingBuffer.c).
 *
 * Guardrails: #1 (Windows-only TU, no HK_PLATFORM macros — CMake selects it on WIN32),
 * #4 (kernel TU; never shares a TU with userspace), #5 (safe string/zero functions;
 * every NTSTATUS-returning call checked). Read-only: it samples MSRs and emits; it
 * never writes an MSR or modifies state.
 *
 * HK-TODO(schema): the wire type HK_EVENT_TIMING_FREQ_SKEW (= 5) and the 16-byte
 * hk_event_timing_freq_skew payload are NOT yet in the frozen
 * sdk/include/horkos/event_schema.h (still v2, no type 5; the schema bump 2->3 is owned
 * by the Schema phase). Until they land, this TU compiles against the kernel-PRIVATE
 * mirror below (declared only when the frozen symbol is absent so there is no collision
 * once the Schema phase appends it). The payload is pinned at 16 bytes == the current
 * HK_EVENT_PAYLOAD_MAX, so it crosses the existing 40-byte HK_IOCTL_DRAIN_EVENTS
 * envelope WITHOUT a ring resize; but the record carries the provisional discriminant
 * 5u, which collides pre-Schema with other domains' "next free type", so it CANNOT be
 * decoded as a DISTINCT type by userspace/server until the frozen enum assigns the real
 * value — the intended, flagged gap. The emit below is therefore guarded by
 * HK_TIMING_SCHEMA_READY (defined only once the frozen schema carries the type).
 */

#include <ntddk.h>
#include <wdf.h>
#include <intrin.h>   /* __readmsr, __rdtsc, __cpuid */

#include "horkos_kernel.h"

#if defined(HK_WIN_TIMING_FREQSKEW)

/* HK-TODO(schema): kernel-private mirror of the (pre-Schema) freq-skew wire record. */
#ifndef HK_EVENT_TIMING_FREQ_SKEW
#  define HK_EVENT_TIMING_FREQ_SKEW 5u  /* HK-TODO(schema): move to hk_event_type */

typedef struct hk_event_timing_freq_skew {  /* 16 bytes */
    uint32_t eff_mhz;       /* APERF/MPERF-derived effective frequency */
    uint32_t nominal_mhz;   /* CPUID 0x15 nominal base frequency */
    uint32_t skew_pct;      /* mismatch beyond P-state bounds, percent */
    uint32_t flags;         /* HK_TIMING_* below */
} hk_event_timing_freq_skew;
HK_STATIC_ASSERT(sizeof(hk_event_timing_freq_skew) == 16,
    "hk_event_timing_freq_skew size mismatch (HK-TODO schema mirror)");

#  define HK_TIMING_FLAG_MSR_GP_FAULTED 0x00000001u
#  define HK_TIMING_FLAG_HV_PRESENT     0x00000002u
#  define HK_TIMING_FLAG_TSC_INVARIANT  0x00000004u
#endif /* HK_EVENT_TIMING_FREQ_SKEW */

/* Architectural MSR numbers (Intel SDM Vol.4 / AMD APM). IA32_MPERF/IA32_APERF are the
 * fixed-function "maximum-performance" and "actual-performance" counters; their ratio
 * over a window is the effective vs nominal frequency factor. */
#define HK_IA32_MPERF 0xE7u
#define HK_IA32_APERF 0xE8u

/* Local prototype (the scan-orchestrator call site is owned by the integrity domain;
 * this TU does not edit HkIntegrityScanAll). */
_IRQL_requires_max_(PASSIVE_LEVEL)
void HkTimingFreqSkewProbe(_In_ PHK_DEVICE_CONTEXT Ctx);

/* Read the CPUID-0x15 nominal base frequency in MHz, or 0 if leaf 0x15 does not report
 * it (then CPUID-0x16 base-frequency could be consulted; left as 0 = unknown here so a
 * missing value is never read as a real nominal). */
static uint32_t HkReadNominalMhz(void)
{
    int regs[4] = { 0, 0, 0, 0 };
    int max_leaf;

    __cpuid(regs, 0);
    max_leaf = regs[0];
    if (max_leaf < 0x15) {
        return 0u; /* leaf 0x15 unsupported — nominal unknown */
    }

    /* CPUID.15H: EAX = denominator, EBX = numerator, ECX = nominal crystal Hz.
     * Core crystal clock = ECX; TSC frequency = ECX * EBX / EAX. */
    __cpuidex(regs, 0x15, 0);
    {
        uint32_t denom = (uint32_t)regs[0];
        uint32_t numer = (uint32_t)regs[1];
        uint32_t crystal_hz = (uint32_t)regs[2];
        uint64_t tsc_hz;

        if (denom == 0u || numer == 0u || crystal_hz == 0u) {
            return 0u; /* leaf present but does not report the ratio/crystal */
        }
        tsc_hz = ((uint64_t)crystal_hz * (uint64_t)numer) / (uint64_t)denom;
        return (uint32_t)(tsc_hz / 1000000ull);
    }
}

/* Hypervisor-present bit: CPUID.1:ECX[31]. Set under any hypervisor (incl. VBS/HVCI). */
static uint32_t HkHypervisorPresent(void)
{
    int regs[4] = { 0, 0, 0, 0 };
    __cpuid(regs, 1);
    return ((uint32_t)regs[2] & 0x80000000u) ? HK_TIMING_FLAG_HV_PRESENT : 0u;
}

_Use_decl_annotations_
void HkTimingFreqSkewProbe(PHK_DEVICE_CONTEXT Ctx)
{
    hk_event_timing_freq_skew rec;
    uint32_t flags = 0u;
    uint32_t nominal_mhz;

    UNREFERENCED_PARAMETER(Ctx);
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    RtlZeroMemory(&rec, sizeof(rec));

    nominal_mhz = HkReadNominalMhz();
    flags |= HkHypervisorPresent();

    /* -----------------------------------------------------------------------
     * HK-UNCERTAIN(155-irql-cpupin): the APERF/MPERF busy-loop MUST run pinned to a
     * single CPU at a known, bounded IRQL — otherwise the scheduler can migrate the
     * loop mid-window (corrupting the APERF/MPERF ratio) or, if IRQL is raised too
     * high, a watchdog timeout / BSOD results. The exact primitive is NOT settled:
     *   - KeSetSystemAffinityThreadEx pins the thread to one CPU at PASSIVE_LEVEL, but
     *     does not prevent DPC/interrupt interference within the window.
     *   - Raising to DISPATCH_LEVEL via KeRaiseIrql reduces preemption but __readmsr +
     *     a busy-loop at DISPATCH must be SHORT (no >~ a few us) to avoid the DPC
     *     watchdog; the exact safe window length is build/host dependent.
     *   - KeIpiGenericCall runs the read on a target CPU at IPI level (no migration),
     *     but a busy-LOOP at IPI level is unacceptable (it stalls the whole system).
     * Per guardrail #13 this is NOT guessed: the MSR reads + busy-loop are left
     * UNIMPLEMENTED below. The probe currently computes only the nominal/HV-present
     * half (pure CPUID, migration-safe) and emits eff_mhz=0 (unmeasured) so the record
     * shape + emit path are exercised without the unverified raised-IRQL/pinned MSR
     * window. Resolve the IRQL/CPU-pin choice (WDK docs / a kernel dev) and validate
     * on-box BEFORE enabling the __readmsr(IA32_APERF/MPERF) busy-loop window.
     * -----------------------------------------------------------------------
     *
     * The intended (post-verification) body, for reference, is:
     *   KAFFINITY old = KeSetSystemAffinityThreadEx(1ull << cpu);
     *   // optional: KIRQL irql; KeRaiseIrql(DISPATCH_LEVEL, &irql);
     *   UINT64 a0 = __readmsr(HK_IA32_APERF), m0 = __readmsr(HK_IA32_MPERF);
     *   UINT64 t0 = __rdtsc();  LARGE_INTEGER q0 = KeQueryPerformanceCounter(NULL);
     *   <fixed short busy-loop>
     *   UINT64 a1 = __readmsr(HK_IA32_APERF), m1 = __readmsr(HK_IA32_MPERF);
     *   UINT64 t1 = __rdtsc();  LARGE_INTEGER q1 = KeQueryPerformanceCounter(NULL);
     *   // KeLowerIrql(irql); KeRevertToUserAffinityThreadEx(old);
     *   eff = nominal * (a1-a0) / (m1-m0);   // APERF/MPERF effective-frequency factor
     *   skew = |eff - (tsc-delta-derived freq)| beyond P-state bounds.
     * __readmsr can #GP on a virtualized MSR; the intended body wraps it so a fault
     * sets HK_TIMING_FLAG_MSR_GP_FAULTED rather than bugchecking. NONE of that runs
     * until the IRQL/pin uncertainty is resolved. */
    rec.eff_mhz     = 0u;          /* unmeasured — see HK-UNCERTAIN above */
    rec.nominal_mhz = nominal_mhz;
    rec.skew_pct    = 0u;          /* no measured eff => no skew computed */
    rec.flags       = flags;       /* HV-present bit is valid; GP/skew not yet measured */

#if defined(HK_TIMING_SCHEMA_READY)
    /* Emit only once the frozen schema carries HK_EVENT_TIMING_FREQ_SKEW as a DISTINCT
     * type — otherwise the provisional 5u collides with other domains' pre-Schema type
     * and userspace/server cannot decode it. HkRingEmit copies the 16-byte payload into
     * the ring (within HK_EVENT_PAYLOAD_MAX). */
    HkRingEmit(HK_EVENT_TIMING_FREQ_SKEW, &rec, (uint32_t)sizeof(rec));
#else
    /* Pre-Schema: the record is built and the emit path is reachable, but emitting it
     * with the colliding discriminant would mis-route on the server. Hold it. */
    UNREFERENCED_PARAMETER(rec);
#endif
}

#else /* HK_WIN_TIMING_FREQSKEW not defined — compile to a no-op. */

_IRQL_requires_max_(PASSIVE_LEVEL)
void HkTimingFreqSkewProbe(_In_ PHK_DEVICE_CONTEXT Ctx);

_Use_decl_annotations_
void HkTimingFreqSkewProbe(PHK_DEVICE_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
}

#endif /* HK_WIN_TIMING_FREQSKEW */
