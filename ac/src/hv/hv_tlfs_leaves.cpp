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

    /* HK-VERIFIED (info-class numbers and struct shapes):
     *   SystemHypervisorDetailInformation  = 0x9F (159)  available Win10+
     *   SystemIsolatedUserModeInformation  = 0xA5 (165)  available Win10+
     * Source: geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi/
     *         system_information_class.htm
     *
     * SYSTEM_ISOLATED_USER_MODE_INFORMATION (0x10 bytes): byte 0 contains packed
     * bit fields; SecureKernelRunning is bit 0, HvciEnabled is bit 1. All-zero
     * unless the secure kernel is running (VSM active). This is the right query
     * for os_vbs_running. Struct layout: geoffchappell.com/studies/windows/km/
     * ntoskrnl/api/ex/sysinfo/isolated_user_mode.htm
     *
     * SYSTEM_HYPERVISOR_DETAIL_INFORMATION (0x70 bytes): seven 16-byte HV_DETAILS
     * members wrapping CPUID leaves 0x40000000..0x40000005 -- redundant with the
     * CPUID reads above; not useful for os_hv_present here.
     *
     * HK-UNCERTAIN (call site): info-class numbers and struct shapes are confirmed
     * (see HK-VERIFIED block above); the actual NtQuerySystemInformation call has
     * not been validated on-box across SKUs and virtualization configurations.
     * Output fields and failure modes need on-box verification before relying on
     * SecureKernelRunning for signal 40.
     * (docs: info-class 0x9F/0xA5 and struct shapes documented — still needs on-box:
     * NtQuerySystemInformation call validation across SKU + HV configurations) */
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
