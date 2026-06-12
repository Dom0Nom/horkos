/*
 * Role: Windows ACS / IOMMU-group topology forensics (sig 133). Intended to read
 *       the ACS extended capability (cap ID 0x000D) control bits — Source
 *       Validation and P2P Request Redirect — on the path bridges. Windows has no
 *       direct /sys/kernel/iommu_groups equivalent; group membership would be
 *       inferred from the device-relations tree under the same DMA-remapping unit.
 * Target platforms: Windows only. Selected by CMake if(WIN32); linked into
 *       hk_dma_detect.
 * Implements: hk_dma_win_fill_acs (symmetric with the Linux arm; the Windows
 *       ConfigSpaceForensics leaves acs_* zero today and is the integration point).
 *
 * *** HK-VERIFIED(win-config-read): ACS extended capability (cap ID 0x000D per
 * PCIe Base Spec §7.7.8) lives at an offset >= 256 in extended config space; this
 * requires the kernel-only HAL API (HalGetBusDataByOffset, kernel-only per WDK docs;
 * see ConfigSpaceForensics.cpp). No documented userspace Win32 path exists for
 * extended config. Additionally, Windows has no /sys/kernel/iommu_groups equivalent
 * surfaced to userspace (IOMMU group membership is managed by the DMA-remapping
 * driver, not exposed via SetupAPI or cfgmgr32 in public APIs). Per guardrail #13
 * this TU does NOT guess either API path. acs_source_validation / acs_p2p_redirect /
 * iommu_group_membership stay 0 = unknown; server treats as "cannot corroborate".
 * (docs: kernel restriction + ACS cap layout per PCIe spec confirmed — still needs
 * KMDF IOCTL + ext-config path on-box before implementing) ***
 */

#include <windows.h>
#include <cfgmgr32.h>
#include <cstdint>

#include "../../include/horkos/dma_forensics.h"

/* -------------------------------------------------------------------------
 * hk_dma_win_fill_acs
 *
 * HK-VERIFIED(win-config-read): see file header. KMDF IOCTL + ACS ext-cap and
 * iommu-group topology paths required on-box. Fields stay 0 = unknown.
 * ------------------------------------------------------------------------- */
extern "C" void hk_dma_win_fill_acs(DEVINST devinst,
                                    hk_dma_device_forensics *d) {
    (void)devinst;
    d->acs_source_validation = 0u;
    d->acs_p2p_redirect = 0u;
    d->iommu_group_membership = 0u;
}
