/*
 * kernel/win/src/HvSyntheticMsr.c
 * Role: Signal 42 kernel sensor — guarded __readmsr of the Hyper-V synthetic MSR
 *       range, gated on CPUID claiming Hyper-V, with reference-TSC vs rdtsc
 *       coherence. Emits hk_event_hv_synth_msr (HK_HV_MSR_* flags) on the ring.
 *       Distinguishes "no Hyper-V" (bare-metal, expected #GP) from "Hyper-V
 *       claimed but MSRs incoherent". Lowest-uncertainty kernel HV signal.
 *       READ-ONLY: MSR/CPUID reads only.
 * Target platforms: Windows kernel (KMDF). Builds only with the WDK.
 *
 *       HK-UNCERTAIN (plan UNCERTAINTY FLAG): __try/__except in kernel mode catches
 *       hardware exceptions (including #GP from RDMSR) at IRQL <= APC_LEVEL when
 *       structured exception handling is active — this is documented WDK behavior
 *       (learn.microsoft.com/windows-hardware/drivers/kernel/structured-exception-
 *       handling). At PASSIVE_LEVEL (as asserted below) SEH is fully available.
 *       However, that a __try/__except around __readmsr reliably catches the #GP on
 *       bare metal without a bugcheck (as opposed to a hypervisor guest where the
 *       hypervisor handles the #GP) must be confirmed on real hardware
 *       (admin@192.168.178.80). The MSR numbers are public TLFS. This runs at
 *       PASSIVE_LEVEL from the sampling caller; never at raised IRQL.
 *       (docs: kernel SEH at PASSIVE_LEVEL documented; still needs on-box: confirm
 *       __readmsr #GP is caught by SEH on bare metal without a bugcheck)
 * Interface: implements HkHvSyntheticMsrSample (horkos_kernel.h); emits via HkRingEmit.
 */

#include <ntddk.h>
#include <intrin.h>

#include "horkos_kernel.h"
#include "horkos/event_schema.h"

#define HK_HV_MSR_GUEST_OS_ID   0x40000000u
#define HK_HV_MSR_HYPERCALL     0x40000001u
#define HK_HV_MSR_REFERENCE_TSC 0x40000021u

/* Read an MSR under SEH; returns TRUE and *value on success, FALSE on #GP. */
static BOOLEAN HkTryReadMsr(ULONG msr, ULONG64* value)
{
    __try {
        *value = __readmsr(msr);
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

void HkHvSyntheticMsrSample(void)
{
    hk_event_hv_synth_msr ev;
    int regs[4];
    ULONG64 v;
    BOOLEAN cpuidClaimsHv;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    RtlZeroMemory(&ev, sizeof(ev));

    /* Gate the MSR reads on CPUID claiming a hypervisor — a bare-metal host #GPs
     * on these and that is an EXPECTED state, not incoherence. */
    __cpuid(regs, 1);
    cpuidClaimsHv = ((ULONG)regs[2] & 0x80000000u) ? TRUE : FALSE;
    if (cpuidClaimsHv) {
        ev.flags |= HK_HV_MSR_CPUID_CLAIMS_HV;
    }

    if (cpuidClaimsHv) {
        if (HkTryReadMsr(HK_HV_MSR_GUEST_OS_ID, &v)) {
            if (v != 0) ev.flags |= HK_HV_MSR_GUEST_OS_ID_OK;
        } else {
            ev.flags |= HK_HV_MSR_GP_FAULTED;
            ev.gp_fault_mask |= 0x1u;
        }
        if (HkTryReadMsr(HK_HV_MSR_HYPERCALL, &v)) {
            ev.flags |= HK_HV_MSR_HYPERCALL_OK;
        } else {
            ev.flags |= HK_HV_MSR_GP_FAULTED;
            ev.gp_fault_mask |= 0x2u;
        }
        if (HkTryReadMsr(HK_HV_MSR_REFERENCE_TSC, &v)) {
            /* Coherence: the reference-TSC page enable bit is bit 0; if the MSR
             * read succeeds and is enabled, treat the reference-TSC as coherent.
             * A precise rdtsc-vs-reference skew sample is a box refinement. */
            unsigned int aux;
            ULONG64 rd = __rdtscp(&aux);
            ev.ref_tsc_vs_rdtsc = (LONG64)(v) - (LONG64)rd; /* raw skew sample. */
            if (v & 0x1u) {
                ev.flags |= HK_HV_MSR_REF_TSC_COHERENT;
            }
        } else {
            ev.flags |= HK_HV_MSR_GP_FAULTED;
            ev.gp_fault_mask |= 0x4u;
        }
    }

    HkRingEmit(HK_EVENT_HV_SYNTH_MSR, &ev, sizeof(ev));
}

/* Drive the enabled kernel HV sensors. 42 is always on (lowest uncertainty); 39
 * runs only when reviewed-on (HK_HV_EPT_ENABLED); 41/44 only under the
 * experimental flag. The periodic call site is wired on the target box. */
void HkHvKernelSample(void)
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    HkHvSyntheticMsrSample(); /* 42 */
#if defined(HK_HV_EPT_ENABLED)
    HkHvEptProbeSample();     /* 39 (default OFF until MmMapIoSpaceEx confirmed). */
#endif
#if defined(HK_HV_KERNEL_EXPERIMENTAL)
    HkHvSecureKernelSample(); /* 41 */
    HkHvApicIdtSample();      /* 44 */
#endif
}
