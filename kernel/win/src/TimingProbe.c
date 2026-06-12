/*
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

/* Architectural MSR numbers.
 * HK-VERIFIED (Intel SDM Vol.4, Table 2-2, MSRs 0E7H/0E8H; AMD APM Vol.2 MSR
 * MPERF/APERF): IA32_MPERF (0xE7) and IA32_APERF (0xE8) are fixed-function
 * counters defined in both Intel and AMD architectures. RDMSR requires CPL 0
 * (ring 0) -- generates #GP(0) otherwise. At ring 0 the instruction has no
 * IRQL restriction from the CPU side; it executes at any Windows IRQL as long
 * as the calling thread is in kernel mode (MSVC __readmsr intrinsic docs: "only
 * available in kernel mode"). The remaining uncertainty is NOT readability but
 * the enclosing busy-loop: a loop long enough to accumulate a meaningful
 * APERF/MPERF delta must not stall the system, and the scheduler migration
 * window must be controlled -- those constraints are documented in the
 * HK-UNCERTAIN block below. The MSR read itself is safe at any IRQL. */
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
     * HK-UNCERTAIN(155-cpupin-looplen): RDMSR itself is ring-0-only with no IRQL
     * restriction from the CPU side (HK-VERIFIED above). The remaining unsettled
     * question is the enclosing busy-loop design:
     *   - CPU affinity: KeSetSystemAffinityThreadEx pins to one LP at PASSIVE_LEVEL
     *     so the scheduler cannot migrate, but DPCs and interrupts can still fire
     *     within the window, perturbing the APERF/MPERF ratio. Raising IRQL to
     *     DISPATCH_LEVEL blocks DPC preemption; it does NOT prevent hardware
     *     interrupts, but those are rare enough for a short window. A loop at
     *     DISPATCH must complete in a few microseconds to stay under the DPC watchdog.
     *   - KeIpiGenericCall runs on the target LP at IPI level with no migration, but
     *     a busy-loop at IPI level stalls other CPUs -- not acceptable.
     *   - The unsettled question is the LOOP DURATION: how many APERF ticks
     *     constitute a statistically significant sample at DISPATCH_LEVEL on a slow
     *     VM, and whether that duration stays within the DPC watchdog on all builds.
     *     This requires measurement on the Windows box. The MSR read itself is NOT
     *     the blocker.
     * Per guardrail #13 the loop body remains UNIMPLEMENTED until loop duration and
     * IRQL/affinity strategy are validated on-box. The probe captures the
     * nominal/HV-present half (pure CPUID, fully safe) and emits eff_mhz=0 so the
     * record shape and emit path are exercised without the unverified loop window.
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
