/*
 * Role: macOS option-ROM identity forensics (sig 130). Reads the device's
 *       expansion-ROM image where IOKit publishes it, parses the 0xAA55 + PCIR
 *       structure, and compares the PCIR VID/DID to the device's config VID/DID.
 *       A clone board whose ROM advertises a different identity than its faked
 *       config IDs is the catch.
 * Target platforms: macOS only (IOKit). Selected by CMake elseif(APPLE).
 * Implements: hk_dma_macos_fill_rom (consumed by ConfigSpaceForensics.mm).
 *
 * SIDE-EFFECT CAUTION (impl-plan Risk #4): on Linux enabling ROM decode is the one
 * non-pure-read probe; on macOS there is no userspace "enable ROM decode" knob —
 * IOKit either publishes a "rom-image" / "ROM" property (read-only, already
 * decoded by the firmware/driver) or it does not. We therefore read ONLY the
 * published property and never toggle decode, so this arm stays fully read-only on
 * macOS. If no ROM property is published we report rom_present = 0 (absent), never
 * an error.
 *
 * *** HK-UNCERTAIN(macos-rom-property): the exact IORegistry key carrying a raw
 * option-ROM image for a given IOPCIDevice is not a stable documented contract
 * across macOS releases (Apple-silicon Macs largely lack legacy option ROMs). We
 * probe a small set of plausible published keys read-only and do NOT guess a
 * private user-client selector to force a ROM read. Confirm the real key on a box
 * that actually carries an option ROM before relying on this arm.
 * (docs: no public IOPCIDevice ROM property key documented in IOKit/pci/ headers or
 * IOKit developer documentation through macOS 15.5 SDK. The "rom-image"/"ROM"/
 * "VideoBIOS" key names come from open-source IOPCIFamily and third-party usage;
 * not formally documented as stable — still needs on-box verification on an Intel
 * Mac with a discrete GPU that has an option ROM) ***
 */

#import <IOKit/IOKitLib.h>
#import <CoreFoundation/CoreFoundation.h>

#include <cstdint>
#include <cstring>

#include "../../include/horkos/dma_forensics.h"

namespace {

/* parse_rom_image — apply the same AA55/PCIR parse the Linux backend uses to a
 * read-only buffer IOKit handed us. Sets rom_present / rom_pcir_id_mismatch. */
void parse_rom_image(const uint8_t *buf, uint32_t got, hk_dma_device_forensics *d) {
    if (got < 0x20u) { d->rom_present = 0u; return; }
    if (!(buf[0] == 0x55u && buf[1] == 0xAAu)) { d->rom_present = 0u; return; }
    d->rom_present = 1u;

    uint32_t pcir_off = static_cast<uint32_t>(buf[0x18] | (buf[0x19] << 8));
    if (pcir_off + 0x08u > got) { d->rom_pcir_id_mismatch = 0u; return; }
    if (!(buf[pcir_off] == 'P' && buf[pcir_off + 1] == 'C' &&
          buf[pcir_off + 2] == 'I' && buf[pcir_off + 3] == 'R')) {
        d->rom_pcir_id_mismatch = 0u;
        return;
    }

    uint16_t pcir_vid = static_cast<uint16_t>(buf[pcir_off + 4] | (buf[pcir_off + 5] << 8));
    uint16_t pcir_did = static_cast<uint16_t>(buf[pcir_off + 6] | (buf[pcir_off + 7] << 8));

    if (d->vendor_id != 0u && d->device_id != 0u) {
        d->rom_pcir_id_mismatch =
            (pcir_vid != d->vendor_id || pcir_did != d->device_id) ? 1u : 0u;
    } else {
        d->rom_pcir_id_mismatch = 0u;
    }
}

} /* anonymous namespace */

/* -------------------------------------------------------------------------
 * hk_dma_macos_fill_rom
 * ------------------------------------------------------------------------- */
extern "C" void hk_dma_macos_fill_rom(io_service_t dev, hk_dma_device_forensics *d) {
    /* Read-only: only consult a property IOKit already published. Try the keys
     * IOPCIFamily/firmware have used for a raw ROM image; stop at the first hit. */
    static const CFStringRef kRomKeys[] = {
        CFSTR("rom-image"),
        CFSTR("ROM"),
        CFSTR("VideoBIOS"),
    };

    for (unsigned k = 0; k < sizeof(kRomKeys) / sizeof(kRomKeys[0]); ++k) {
        CFTypeRef v = IORegistryEntryCreateCFProperty(dev, kRomKeys[k],
                                                      kCFAllocatorDefault, 0);
        if (v == nullptr) continue;
        if (CFGetTypeID(v) == CFDataGetTypeID()) {
            CFDataRef data = static_cast<CFDataRef>(v);
            CFIndex len = CFDataGetLength(data);
            if (len > 0) {
                uint32_t got = static_cast<uint32_t>(len > 4096 ? 4096 : len);
                parse_rom_image(CFDataGetBytePtr(data), got, d);
            }
            CFRelease(v);
            return;
        }
        CFRelease(v);
    }
    /* No published ROM image — absent, not an error (HK-UNCERTAIN above). */
    d->rom_present = 0u;
    d->rom_pcir_id_mismatch = 0u;
}
