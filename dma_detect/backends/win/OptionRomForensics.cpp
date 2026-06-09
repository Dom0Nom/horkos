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
 * *** HK-UNCERTAIN(win-config-read): same unresolved question as MSI-X/ext-config
 * (impl-plan Risk #1). Reading the Expansion ROM BAR and mapping/reading the ROM
 * image from a userspace AC component on Windows has NO confirmed documented path
 * without the Horkos KMDF driver. The Linux arm enables ROM decode via sysfs and
 * restores it (impl-plan Risk #4 side-effect, mitigated there); there is no
 * equivalent userspace primitive on Windows that is confirmed read-only and
 * non-perturbing. Per guardrail #13 this TU does NOT guess: rom_present and
 * rom_pcir_id_mismatch stay unknown (0) and the record is marked needs-kernel.
 * The option-ROM probe is the ONE non-pure-read in the domain (Risk #4); shipping
 * a wrong Windows enable/restore sequence could perturb a live device, which is
 * exactly the BSOD-class outcome guardrail #13 forbids guessing at. CONFIRM the
 * read-only ROM-access path on-box before implementing. ***
 */

#include <windows.h>
#include <cfgmgr32.h>
#include <cstdint>

#include "../../include/horkos/dma_forensics.h"

static const uint32_t HK_DMA_WIN_CONFIG_UNAVAILABLE = 0xE0000001u;

/* -------------------------------------------------------------------------
 * hk_dma_win_fill_rom
 *
 * HK-UNCERTAIN(win-config-read): unimplemented pending a confirmed read-only ROM
 * access path on Windows. Leaves the ROM fields unknown (0) and marks the record
 * so the server treats "no ROM data" as unknown, never as "ROM identity clean".
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
