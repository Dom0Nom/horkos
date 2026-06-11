/*
 * dma_detect/backends/win/OptionRomForensics.cpp
 * Role: Windows option-ROM identity forensics (sig 130). Intended to read the
 *       Expansion ROM BAR (config 0x30), parse the 0xAA55 + PCIR header, and
 *       compare the PCIR VID/DID to the device's config VID/DID — a clone board
 *       whose ROM advertises a different identity than its faked config IDs is
 *       the catch.
 * Target platforms: Windows only. Selected by CMake if(WIN32); linked into
 *       hk_dma_detect alongside ConfigSpaceForensics.
 * Implements: hk_dma_win_fill_rom (consumed by win/ConfigSpaceForensics.cpp).
 *
 * *** HK-VERIFIED(win-config-read): same kernel-API restriction as MSI-X/ext-config
 * (see ConfigSpaceForensics.cpp). Reading the Expansion ROM BAR (offset 0x30 in
 * PCI config space) requires a config-read primitive; HalGetBusDataByOffset is
 * kernel-only. There is no documented userspace Win32 API for reading raw PCI
 * config registers. The Linux arm enables ROM decode via sysfs (no Windows
 * equivalent confirmed read-only and non-perturbing). Per guardrail #13 this TU
 * does NOT guess: rom_present and rom_pcir_id_mismatch stay unknown (0) with the
 * needs-kernel sentinel. PCIR header layout: PCIe Base Spec §6.3.10 (0xAA55
 * signature at offset 0, PCIR struct at PCI Data Structure pointer).
 * (docs: kernel restriction confirmed + PCIR layout per spec — still needs KMDF
 * IOCTL + on-box validation of the read-only ROM-access path) ***
 */

#include <windows.h>
#include <cfgmgr32.h>
#include <cstdint>

#include "../../include/horkos/dma_forensics.h"

static const uint32_t HK_DMA_WIN_CONFIG_UNAVAILABLE = 0xE0000001u;

/* -------------------------------------------------------------------------
 * hk_dma_win_fill_rom
 *
 * HK-VERIFIED(win-config-read): see file header. KMDF IOCTL + on-box ROM-path
 * validation required. ROM fields 0 = unknown; server never reads as "clean".
 * ------------------------------------------------------------------------- */
extern "C" void hk_dma_win_fill_rom(DEVINST devinst,
                                    hk_dma_device_forensics *d) {
    (void)devinst;
    d->rom_present = 0u;
    d->rom_pcir_id_mismatch = 0u;
    if (d->scan_error == 0u) {
        d->scan_error = HK_DMA_WIN_CONFIG_UNAVAILABLE;
    }
}
