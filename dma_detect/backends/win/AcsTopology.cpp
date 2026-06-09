/*
 * dma_detect/backends/win/AcsTopology.cpp
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
 * *** HK-UNCERTAIN(win-config-read): reading the ACS ext-cap requires EXTENDED
 * config access (offset >= 256), the explicit impl-plan Risk #1 unknown on Windows
 * (no confirmed userspace path without the KMDF driver). AND there is no documented
 * userspace surface equivalent to Linux iommu_groups for the membership-size
 * corroboration. Per guardrail #13 this TU does NOT guess either API: it leaves
 * acs_source_validation / acs_p2p_redirect / iommu_group_membership unknown (0).
 * The server treats absence as "cannot corroborate", never as a verdict. CONFIRM
 * the ext-config + DMA-remapping-topology userspace paths on-box first. ***
 */

#include <windows.h>
#include <cfgmgr32.h>
#include <cstdint>

#include "../../include/horkos/dma_forensics.h"

/* -------------------------------------------------------------------------
 * hk_dma_win_fill_acs
 *
 * HK-UNCERTAIN(win-config-read): unimplemented pending confirmed ext-config +
 * topology userspace paths. Fields stay 0 = unknown.
 * ------------------------------------------------------------------------- */
extern "C" void hk_dma_win_fill_acs(DEVINST devinst,
                                    hk_dma_device_forensics *d) {
    (void)devinst;
    d->acs_source_validation = 0u;
    d->acs_p2p_redirect = 0u;
    d->iommu_group_membership = 0u;
}
