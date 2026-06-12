/*
 * Role: Host-buildable unit tests for the hypervisor structural-consistency
 *       cores (ac/include/horkos/hv_logic.h, signals 37/40/42/44/45). Exercises
 *       the TLFS leaf-vector consistency flags, the synthetic-MSR incoherence
 *       rule (bare-metal vs Hyper-V-claimed-but-absent), the APIC/IDT base
 *       mismatch, the TSC spread feature, and the VBS-vs-attestation
 *       contradiction (withheld while the attestation backend is a stub) — with
 *       synthetic inputs, no CPUID, no MSR, no Windows runner.
 * Target platforms: host (any).
 * Interface: exercises hv_tlfs_inconsistency / hv_synth_msr_incoherent /
 *            hv_apic_idt_mismatch / hv_tsc_spread / hv_vbs_contradiction.
 */

#include <gtest/gtest.h>

#include <cstring>

#include "horkos/hv_logic.h"

namespace {

hv_tlfs_leaves ZeroTlfs()
{
    hv_tlfs_leaves t;
    std::memset(&t, 0, sizeof(t));
    return t;
}

} // namespace

TEST(HvLogic, TlfsConsistentHyperVHasNoInconsistency)
{
    hv_tlfs_leaves t = ZeroTlfs();
    t.cpuid1_ecx31_hv = 1;
    t.os_hv_present = 1;
    t.leaf[0][0] = 0x40000006; /* max leaf */
    t.leaf[0][1] = 0x7263694D; /* "Micr" — a populated vendor leaf. */
    t.leaf[1][0] = 0x31237648; /* 0x40000001 populated. */
    EXPECT_EQ(hv_tlfs_inconsistency(&t), 0u);
}

TEST(HvLogic, TlfsPresentBitButNoLeaves)
{
    hv_tlfs_leaves t = ZeroTlfs();
    t.cpuid1_ecx31_hv = 1; /* claims a hypervisor... */
    t.leaf[0][0] = 0;      /* ...but exposes no leaves. */
    EXPECT_TRUE(hv_tlfs_inconsistency(&t) & HK_HV_TLFS_PRESENT_NO_LEAVES);
}

TEST(HvLogic, TlfsLeavesButNoPresentBit)
{
    hv_tlfs_leaves t = ZeroTlfs();
    t.cpuid1_ecx31_hv = 0; /* present bit clear... */
    t.os_hv_present = 0;
    t.leaf[0][0] = 0x40000005; /* ...yet advertises leaves. */
    t.leaf[1][0] = 0x1;
    EXPECT_TRUE(hv_tlfs_inconsistency(&t) & HK_HV_TLFS_LEAVES_NO_PRESENT);
}

TEST(HvLogic, TlfsVendorLeafOnlySpoof)
{
    /* The bypass-test shape: spoof only 0x40000000 (high max-leaf), leave the
     * downstream 0x40000001 leaf all-zero. */
    hv_tlfs_leaves t = ZeroTlfs();
    t.cpuid1_ecx31_hv = 1;
    t.leaf[0][0] = 0x40000010; /* claims many leaves */
    t.leaf[1][0] = 0;          /* but 0x40000001 is empty */
    t.leaf[1][1] = 0;
    t.leaf[1][2] = 0;
    t.leaf[1][3] = 0;
    EXPECT_TRUE(hv_tlfs_inconsistency(&t) & HK_HV_TLFS_VENDOR_TRUNCATED);
}

TEST(HvLogic, SynthMsrBareMetalIsNotIncoherent)
{
    /* No hypervisor claimed: #GP on the synthetic MSRs is expected, not a signal. */
    uint32_t flags = HK_HV_MSR_GP_FAULTED; /* no CPUID_CLAIMS_HV bit */
    EXPECT_EQ(hv_synth_msr_incoherent(flags), 0);
}

TEST(HvLogic, SynthMsrClaimedButGpFaulted)
{
    uint32_t flags = HK_HV_MSR_CPUID_CLAIMS_HV | HK_HV_MSR_GP_FAULTED;
    EXPECT_EQ(hv_synth_msr_incoherent(flags), 1);
}

TEST(HvLogic, SynthMsrClaimedAndCoherent)
{
    uint32_t flags = HK_HV_MSR_CPUID_CLAIMS_HV | HK_HV_MSR_GUEST_OS_ID_OK |
                     HK_HV_MSR_HYPERCALL_OK | HK_HV_MSR_REF_TSC_COHERENT;
    EXPECT_EQ(hv_synth_msr_incoherent(flags), 0);
}

TEST(HvLogic, SynthMsrClaimedButRefTscIncoherent)
{
    uint32_t flags = HK_HV_MSR_CPUID_CLAIMS_HV | HK_HV_MSR_GUEST_OS_ID_OK;
    /* REF_TSC_COHERENT bit absent => incoherent. */
    EXPECT_EQ(hv_synth_msr_incoherent(flags), 1);
}

TEST(HvLogic, ApicIdtMismatch)
{
    EXPECT_EQ(hv_apic_idt_mismatch(0x1000, 0x1000), 0);
    EXPECT_EQ(hv_apic_idt_mismatch(0x1000, 0x2000), 1);
}

TEST(HvLogic, TscSpread)
{
    uint64_t samples[] = {100, 140, 90, 220};
    EXPECT_EQ(hv_tsc_spread(samples, 4), 130u); /* 220 - 90 */
    EXPECT_EQ(hv_tsc_spread(nullptr, 0), 0u);
    uint64_t one[] = {500};
    EXPECT_EQ(hv_tsc_spread(one, 1), 0u);
}

TEST(HvLogic, VbsContradictionWithheldWithoutQuote)
{
    hv_vbs_attest v;
    std::memset(&v, 0, sizeof(v));
    v.vbs_status = 1;
    v.attest_contradiction = 1;
    v.attest_quote_avail = 0; /* stub backend: no quote -> withhold. */
    EXPECT_EQ(hv_vbs_contradiction(&v), 0);
}

TEST(HvLogic, VbsContradictionSurfacedWithQuote)
{
    hv_vbs_attest v;
    std::memset(&v, 0, sizeof(v));
    v.attest_quote_avail = 1;
    v.attest_contradiction = 1;
    EXPECT_EQ(hv_vbs_contradiction(&v), 1);
}
