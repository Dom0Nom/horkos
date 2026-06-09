/*
 * dma_detect/backends/win/MsixForensics.cpp
 * Role: Windows MSI-X BIR/PBA containment forensics (sig 129). The containment
 *       check itself (offset + entries*16 <= bar_len, 64-bit-correct) is the
 *       shared platform-clean helper in forensics_report.cpp; this TU's job is to
 *       source the MSI-X cap fields (table size, Table/PBA Offset+BIR) from the
 *       device's PCI config space and the referenced BAR lengths from the BAR
 *       profiler, then call that helper. Read-only.
 * Target platforms: Windows only. Selected by CMake if(WIN32); linked into
 *       hk_dma_detect alongside ConfigSpaceForensics.
 * Implements: hk_dma_win_fill_msix (consumed by win/ConfigSpaceForensics.cpp).
 *
 * *** HK-UNCERTAIN(win-config-read): reading PCI config space (legacy cap list AND
 * the MSI-X cap at its offset) from a USERSPACE AC component on Windows is the SAME
 * unconfirmed question as extended config (impl-plan Risk #1): whether
 * BusInterfaceStandard.GetBusData / HalGetBusDataByOffset is reachable without the
 * Horkos KMDF driver is NOT established (HalGetBusDataByOffset is a KERNEL API).
 * Per guardrail #13 this TU does NOT guess that API surface: it leaves the MSI-X
 * fields unknown (0) and records the same "needs kernel routing" sentinel the
 * config backend uses. The 64-bit-correct containment math is fully implemented in
 * forensics_report.cpp and unit-tested; only the Windows config SOURCE is deferred.
 * CONFIRM on-box whether config reads must route through a new KMDF IOCTL. ***
 */

#include <windows.h>
#include <cfgmgr32.h>
#include <cstdint>

#include "../../include/horkos/dma_forensics.h"

/* Shared 64-bit-correct containment check (forensics_report.cpp). Declared here
 * so this TU is ready to call it the moment a Windows config-read path is
 * confirmed; the call site is staged below behind the HK-UNCERTAIN gate. */
extern "C" int hk_dma_msix_containment_violation(
    uint64_t table_bar_len, uint64_t table_offset,
    uint64_t pba_bar_len,   uint64_t pba_offset,
    uint16_t table_size_entries);

/* Sentinel matching win/ConfigSpaceForensics.cpp HK_DMA_WIN_EXTCFG_UNAVAILABLE.
 * Kept local (the value is the contract, not the symbol) so the server can tell
 * "MSI-X not sampled on this Windows build" from a genuine clean record. */
static const uint32_t HK_DMA_WIN_CONFIG_UNAVAILABLE = 0xE0000001u;

/* -------------------------------------------------------------------------
 * hk_dma_win_fill_msix
 *
 * HK-UNCERTAIN(win-config-read): the MSI-X cap walk needs a confirmed userspace
 * config-read path. Until then we leave msix_table_size / containment unknown (0)
 * and mark the record so the server does NOT read the absence as "clean". The
 * containment helper above is the real logic; wiring it here is a one-function
 * change once GetBusData routing is settled on a real box.
 * ------------------------------------------------------------------------- */
extern "C" void hk_dma_win_fill_msix(DEVINST devinst,
                                     hk_dma_device_forensics *d) {
    (void)devinst;
    d->msix_table_size = 0u;
    d->msix_containment_violation = 0u;
    if (d->scan_error == 0u) {
        d->scan_error = HK_DMA_WIN_CONFIG_UNAVAILABLE;
    }
}
