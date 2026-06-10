/*
 * ac/src/hv/hv_vm_identity.cpp
 * Role: Signal 43 sampler — reads SMBIOS firmware (GetSystemFirmwareTable 'RSMB')
 *       and the CPUID hypervisor-present bit to classify the host as {bare-metal,
 *       honest-VM, covert-inspection} and fills hv_vm_identity with the RAW tuple
 *       + structural class. Operators whitelist sanctioned fleets by attested
 *       vTPM EK server-side; the client ships the class, never the trust verdict.
 *       READ-ONLY.
 * Target platforms: Windows. Guardrail #1: firmware/CPUID confined here.
 * Interface: implements hv_sample_vm_identity from hv_signals.h.
 */

#include "horkos/hv_signals.h"

#if defined(HK_PLATFORM_WINDOWS)

#include <windows.h>
#include <intrin.h>
#include <string.h>

/* Scan the raw SMBIOS table for vendor/product strings that mark a VM (VMware,
 * VirtualBox, QEMU, KVM, Xen, Hyper-V, Parallels). Returns 1 on a match. Bounded
 * substring scan over the firmware blob. */
static uint32_t HkSmbiosVmMarker(void)
{
    DWORD size;
    BYTE* buf;
    uint32_t found = 0;
    static const char* kMarkers[] = {
        "VMware", "VirtualBox", "innotek", "QEMU", "Xen", "Microsoft Corporation Virtual",
        "Parallels", "KVM", "Bochs",
    };

    size = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
    if (size == 0) {
        return 0;
    }
    buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, size);
    if (buf == nullptr) {
        return 0;
    }
    if (GetSystemFirmwareTable('RSMB', 0, buf, size) == size) {
        size_t n = (size_t)size;
        for (size_t m = 0; m < sizeof(kMarkers) / sizeof(kMarkers[0]) && !found; ++m) {
            size_t klen = strlen(kMarkers[m]);
            if (klen == 0 || klen > n) continue;
            for (size_t i = 0; i + klen <= n; ++i) {
                if (memcmp(buf + i, kMarkers[m], klen) == 0) {
                    found = 1;
                    break;
                }
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, buf);
    return found;
}

extern "C" int hv_sample_vm_identity(hv_vm_identity* out)
{
    int regs[4];

    if (out == nullptr) {
        return HK_AC_NOT_IMPLEMENTED;
    }
    RtlSecureZeroMemory(out, sizeof(*out));

    __cpuid(regs, 1);
    out->cpuid_hv_present = ((uint32_t)regs[2] & 0x80000000u) ? 1u : 0u;
    out->smbios_vm_marker = HkSmbiosVmMarker();
    /* HK-UNCERTAIN: device-tree (SetupAPI) + vTPM EK (Tbsi/NCrypt) reads deferred
     * to the box; left 0. */
    out->devicetree_vm_marker = 0;
    out->vtpm_ek_present = 0;

    /* Raw structural class: hypervisor-present with NO honest VM identity markers
     * is the covert-inspection shape; markers present => honest VM; neither =>
     * bare metal. The server overrides against attested-fleet allowlists. */
    if (out->cpuid_hv_present && !out->smbios_vm_marker) {
        out->classification = HK_HV_VMID_COVERT_INSPECTION;
    } else if (out->smbios_vm_marker) {
        out->classification = HK_HV_VMID_HONEST_VM;
    } else {
        out->classification = HK_HV_VMID_BARE_METAL;
    }

    return HK_AC_OK;
}

#else

extern "C" int hv_sample_vm_identity(hv_vm_identity* out)
{
    (void)out;
    return HK_AC_NOT_IMPLEMENTED;
}

#endif
