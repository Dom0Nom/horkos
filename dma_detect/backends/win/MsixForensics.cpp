/*
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
 * *** HK-VERIFIED(win-config-read): HalGetBusDataByOffset is a kernel-only HAL
 * export (see dma_detect/backends/win/ConfigSpaceForensics.cpp for the primary
 * citation). Reading PCI config space (legacy cap list AND the MSI-X cap offset)
 * from a userspace AC component on Windows requires routing through a kernel driver
 * (the Horkos KMDF driver via DeviceIoControl IOCTL). BusInterfaceStandard is also
 * a kernel-mode bus-driver interface; not accessible from userspace.
 * (docs: kernel API restriction confirmed — still needs KMDF IOCTL design + on-box
 * test for the legacy+extended config read path)
 * Per guardrail #12 this TU does NOT guess that API surface: MSI-X fields are left
 * unknown (0) with the "needs kernel routing" sentinel. The 64-bit-correct
 * containment math is fully implemented in forensics_report.cpp and unit-tested. ***
 */

#include <windows.h>
#include <cfgmgr32.h>
#include <cstdint>

#include "../../include/horkos/dma_forensics.h"

/* Shared 64-bit-correct containment check (forensics_report.cpp). Declared here
 * so this TU is ready to call it the moment a Windows config-read path is
 * confirmed; the call site is staged below behind the HK-VERIFIED(win-config-read) gate. */
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
 * HK-VERIFIED(win-config-read): see file header. KMDF IOCTL route confirmed
 * required; msix_table_size / containment stay unknown (0) with the sentinel.
 * The containment helper above is the real logic; wiring it here is a one-function
 * change once the KMDF config-read IOCTL lands on-box.
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
