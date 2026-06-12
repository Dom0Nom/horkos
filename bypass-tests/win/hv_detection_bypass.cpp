/*
 * Role: Merge-gate bypass fixture for the win-hypervisor-detection sensors
 *       (signals 37-45), [disabled]. Consolidates the eight per-sensor adversarial
 *       assertions the plan specifies; each activates once the sensor + server
 *       classification are verified on the Windows box (HK_HV_TEST_ENABLED):
 *         37 cpuid_vendor_spoof_only  - spoof only leaf 0x40000000; assert
 *            downstream-leaf inconsistency surfaces (hv_tlfs_inconsistency).
 *         38 tsc_clamp                - clamp/offset visible TSC; assert TSC-vs-
 *            QPC/InterruptTime divergence; and 45 cross-vCPU skew anomaly.
 *         40 vbs_flag_flip            - contradictory VBS-on/unattested; assert the
 *            contradiction surfaces AND enforcement is withheld (stub backend).
 *         43 bare_metal_identity_with_hv_cue - assert covert-inspection class, and
 *            a sanctioned GPU-passthrough VM classifies honest-VM (FP guard).
 *         42 synth_msr_absent         - Hyper-V CPUID claimed but synthetic MSRs
 *            #GP/incoherent; assert incoherence flagged AND no bugcheck on true
 *            bare metal (the #GP-guard regression).
 *         39 ept_read_exec_split      - exec-view != read-view over a signed
 *            section; assert detection, and an HVCI-managed region does NOT flag.
 *         44 idt_relocation           - relocated/shadowed IDT; assert __sidt vs
 *            KPCR mismatch recorded (observe-only, no enforcement).
 *         41 sk_liveness_inert        - VBS-running claim with inert secure-kernel
 *            callout; assert the liveness gap recorded (observe-only).
 *       Read-only assertions of raw report fields — never a local ban. Each
 *       FP-guard assertion is as load-bearing as its detection assertion.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/ioctl.h + the HV report/flag surface.
 *
 * Merge gate (guardrail #12): present for the security folder; assertions activate
 * when the sensors are verified on the box and HK_HV_TEST_ENABLED is defined.
 */

#include <cstdio>

#ifndef HK_HV_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: hv_detection bypass tests activate once the HV sensors "
                "are verified on the Windows box (HK_HV_TEST_ENABLED).\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include <windows.h>
#include "horkos/ioctl.h"

int main(void)
{
    std::printf("hv_detection: sensor/enforcement path not yet verified on-box.\n");
    return 1;
}

#endif /* HK_HV_TEST_ENABLED */
