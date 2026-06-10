/*
 * ac/src/hv/hv_tlfs_leaves.cpp
 * Role: Signal 37 sampler — reads the hypervisor CPUID leaf range
 *       (0x40000000..0x4000000A) plus the leaf-1 hypervisor-present bit and the
 *       OS hypervisor/VBS posture, filling hv_tlfs_leaves with the RAW vector.
 *       The server models known-good nested-Hyper-V / WSL2 / Sandbox vectors; the
 *       structural-consistency view is the host-tested pure core
 *       hv_tlfs_inconsistency (hv_logic.h), not computed here.
 *       READ-ONLY: pure CPUID + a documented system-information query.
 * Target platforms: Windows (PC). Guardrail #1: all Win32/CPUID confined here;
 *       non-Windows compiles a HK_AC_NOT_IMPLEMENTED stub.
 * Interface: implements hv_sample_tlfs_leaves from hv_signals.h.
 */

#include "horkos/hv_signals.h"

#if defined(HK_PLATFORM_WINDOWS)

#include <windows.h>
#include <intrin.h>

extern "C" int hv_sample_tlfs_leaves(hv_tlfs_leaves* out)
{
    int regs[4];
    unsigned leaf;

    if (out == nullptr) {
        return HK_AC_NOT_IMPLEMENTED;
    }
    RtlSecureZeroMemory(out, sizeof(*out));

    /* Hypervisor leaf range 0x40000000..0x4000000A (11 leaves). __cpuid is the
     * documented intrinsic; pure user-mode read, no IRQL concern. */
    for (leaf = 0; leaf < 11u; ++leaf) {
        __cpuid(regs, (int)(0x40000000u + leaf));
        out->leaf[leaf][0] = (uint32_t)regs[0];
        out->leaf[leaf][1] = (uint32_t)regs[1];
        out->leaf[leaf][2] = (uint32_t)regs[2];
        out->leaf[leaf][3] = (uint32_t)regs[3];
    }

    /* Leaf 1 ECX bit 31 = hypervisor-present. */
    __cpuid(regs, 1);
    out->cpuid1_ecx31_hv = ((uint32_t)regs[2] & 0x80000000u) ? 1u : 0u;

    /* HK-UNCERTAIN: NtQuerySystemInformation(SystemHypervisorDetailInformation /
     * SystemIsolatedUserModeInformation) info-class layouts vary by build and are
     * only semi-documented. The OS posture fields are confirmed on the box (Win11
     * 25H2); until then they stay 0 (read by the server as "not collected"), and
     * the CPUID half — which is fully documented — carries the signal. */
    out->os_hv_present = out->cpuid1_ecx31_hv; /* best available without the query. */
    out->os_vbs_running = 0;

    return HK_AC_OK;
}

#else /* non-Windows: HV CPUID leaves are a Windows-PC signal. */

extern "C" int hv_sample_tlfs_leaves(hv_tlfs_leaves* out)
{
    (void)out;
    return HK_AC_NOT_IMPLEMENTED;
}

#endif
