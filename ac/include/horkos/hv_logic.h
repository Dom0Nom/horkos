/*
 * ac/include/horkos/hv_logic.h
 * Role: Pure, platform-free structural-consistency cores for the hypervisor
 *       sensors. They turn the RAW sampled fields (CPUID leaf vectors, synthetic-
 *       MSR flags, __sidt-vs-KPCR bases, per-LP TSC samples, VBS posture) into
 *       raw structural observations — internal inconsistencies a covert
 *       hypervisor leaves behind. NONE of these is a verdict or a threshold: they
 *       report structural facts (e.g. "CPUID claims a hypervisor but exposes no
 *       leaves"), and the server does the FP-aware, population-relative
 *       classification. Pure arithmetic over the hv_signals.h POD structs, no
 *       platform API, so they are host-tested (tests/unit/test_hv_logic.cpp)
 *       without a Windows runner — the plan's "ship raw, server classifies"
 *       contract with the testable structural layer factored out.
 *       READ-ONLY: derives observations; mutates nothing.
 * Target platforms: all (decision math; the sampling that fills the inputs is
 *       Windows-only, in ac/src/hv/*.cpp).
 * Interface: consumed by ac/src/hv/*.cpp + hv_kernel_correlate.cpp.
 */

#pragma once

#include <stdint.h>

#include "horkos/event_schema.h" /* HK_HV_MSR_* / HK_HV_APIC_IDT_* flag bits. */
#include "horkos/hv_signals.h"

#ifdef __cplusplus
extern "C" {
#endif

/* hv_tlfs_inconsistency() flag bits — structural contradictions in the TLFS
 * CPUID leaf vector + OS hypervisor-present posture. */
#define HK_HV_TLFS_PRESENT_NO_LEAVES 0x1u /* HV-present bit set, but no HV leaves. */
#define HK_HV_TLFS_LEAVES_NO_PRESENT 0x2u /* HV leaves advertised, but bit clear. */
#define HK_HV_TLFS_VENDOR_TRUNCATED  0x4u /* max-leaf claims >=0x40000001 yet the
                                             0x40000001 leaf is all-zero (the
                                             vendor-leaf-only spoof shape). */

/*
 * Signal 37 — TLFS leaf consistency. A real hypervisor that sets the CPUID
 * hypervisor-present bit (leaf 1 ECX[31]) also exposes a coherent
 * 0x40000000.. leaf range; a spoof that flips only one of those leaves the
 * other inconsistent. Returns an OR of HK_HV_TLFS_* structural-inconsistency
 * bits (0 = internally consistent). Raw observation; the server still models
 * known-good nested-Hyper-V / WSL2 / Sandbox vectors before it concludes.
 *
 * leaf[0] is CPUID 0x40000000: EAX = highest hypervisor leaf, EBX/ECX/EDX =
 * vendor string. leaf[1] is 0x40000001.
 */
static inline uint32_t hv_tlfs_inconsistency(const hv_tlfs_leaves *t)
{
    uint32_t flags = 0u;
    uint32_t max_leaf;
    int present_bit;
    int advertises_leaves;
    if (t == 0) {
        return 0u;
    }
    max_leaf = t->leaf[0][0];
    present_bit = (t->cpuid1_ecx31_hv != 0u || t->os_hv_present != 0u) ? 1 : 0;
    advertises_leaves = (max_leaf >= 0x40000001u) ? 1 : 0;

    if (present_bit && max_leaf == 0u) {
        flags |= HK_HV_TLFS_PRESENT_NO_LEAVES;
    }
    if (advertises_leaves && !present_bit) {
        flags |= HK_HV_TLFS_LEAVES_NO_PRESENT;
    }
    if (advertises_leaves) {
        /* The 0x40000001 leaf must carry something if the max-leaf field claims
         * it exists; an all-zero 0x40000001 with a high max-leaf is the
         * spoofed-vendor-leaf-only shape the bypass test exercises. */
        if ((t->leaf[1][0] | t->leaf[1][1] | t->leaf[1][2] | t->leaf[1][3]) == 0u) {
            flags |= HK_HV_TLFS_VENDOR_TRUNCATED;
        }
    }
    return flags;
}

/*
 * Signal 42 — synthetic-MSR coherence. If CPUID claims Hyper-V, the synthetic
 * MSRs should be coherent (no #GP, guest-OS-id present, reference-TSC tracks
 * rdtsc). Returns 1 if CPUID claims a hypervisor yet the MSR surface is
 * incoherent — the "Hyper-V claimed but synthetic MSRs absent/incoherent" state,
 * distinct from honest bare-metal (no claim, no MSRs). Raw observation.
 */
static inline int hv_synth_msr_incoherent(uint32_t flags)
{
    if ((flags & HK_HV_MSR_CPUID_CLAIMS_HV) == 0u) {
        /* No hypervisor claimed — bare metal #GP'ing on these MSRs is expected,
         * NOT incoherent. */
        return 0;
    }
    if ((flags & HK_HV_MSR_GP_FAULTED) != 0u) {
        return 1;
    }
    if ((flags & HK_HV_MSR_GUEST_OS_ID_OK) == 0u) {
        return 1;
    }
    if ((flags & HK_HV_MSR_REF_TSC_COHERENT) == 0u) {
        return 1;
    }
    return 0;
}

/*
 * Signal 44 — APIC/IDT residue: the __sidt-reported IDT base disagrees with the
 * KPCR-authoritative base. Pure low-32-bit comparison; observe-only, low weight
 * (genuine Hyper-V/VBS virtualizes the APIC and may relocate descriptors — the
 * server cohorts this).
 */
static inline int hv_apic_idt_mismatch(uint32_t sidt_base_low, uint32_t kpcr_idt_base_low)
{
    return (sidt_base_low != kpcr_idt_base_low) ? 1 : 0;
}

/*
 * Signal 45 — cross-vCPU TSC spread: max minus min over the per-LP first-sample
 * array. A raw feature the server compares against per-SKU skew distributions
 * (never a fixed client tolerance). A NULL/empty array yields 0.
 */
static inline uint64_t hv_tsc_spread(const uint64_t *samples, uint32_t count)
{
    uint64_t lo;
    uint64_t hi;
    uint32_t i;
    if (samples == 0 || count == 0u) {
        return 0;
    }
    lo = samples[0];
    hi = samples[0];
    for (i = 1; i < count; ++i) {
        if (samples[i] < lo) {
            lo = samples[i];
        }
        if (samples[i] > hi) {
            hi = samples[i];
        }
    }
    return hi - lo;
}

/*
 * Signal 40 — VBS-vs-attestation contradiction: the OS claims VBS is running but
 * a TPM attestation quote is available AND contradicts that claim. Report-only
 * until a real Attestation backend lands (the quote-available gate keeps this 0
 * while the backend is a NotImplemented stub). Raw observation, never enforced
 * client-side.
 */
static inline int hv_vbs_contradiction(const hv_vbs_attest *v)
{
    if (v == 0) {
        return 0;
    }
    if (v->attest_quote_avail == 0u) {
        return 0; /* no quote to contradict (stub backend) — withhold. */
    }
    return (v->attest_contradiction != 0u) ? 1 : 0;
}

#ifdef __cplusplus
} /* extern "C" */
#endif
