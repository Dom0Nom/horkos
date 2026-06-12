/*
 * Role: macOS BAR geometry profiler (sig 131). Reconstructs each BAR's
 *       {size, 64-bit, prefetchable, io} from the kernel-recorded
 *       "assigned-addresses" IORegistry property (and IOPCIDevice memory-range
 *       lengths) — never by issuing the write-all-ones BAR-sizing sequence
 *       ourselves (that mutates device state; every Horkos probe is read-only).
 *       Ships raw geometry; the server holds the per-VID/DID reference table.
 * Target platforms: macOS only (IOKit). Selected by CMake elseif(APPLE).
 * Implements: hk_dma_macos_fill_bar (consumed by ConfigSpaceForensics.mm).
 *
 * "assigned-addresses" is an array of 5-uint32 PCI address cells (the device-tree
 * "reg"/"assigned-addresses" encoding IOPCIFamily publishes):
 *   cell[0] = phys.hi (bbbbbsss bbbbbbbb dddddfff rrrrrrrr) — the high word
 *             carries the space-type bits (n, p) and the BAR config-offset (rr).
 *   cell[1] = phys.mid  (high 32 bits of the 64-bit address)
 *   cell[2] = phys.lo   (low 32 bits)
 *   cell[3] = size.hi   (high 32 bits of the region length)
 *   cell[4] = size.lo   (low 32 bits)
 * phys.hi bit 31 (n) = non-relocatable; bit 30 (p) = prefetchable; bits 25:24
 * (ss) = space code (00=config, 01=I/O, 10=32-bit mem, 11=64-bit mem); bits 7:0
 * (rrrrrrrr) = the config-space BAR offset (0x10..0x24), which maps to BAR index.
 */

#import <IOKit/IOKitLib.h>
#import <CoreFoundation/CoreFoundation.h>

#include <cstdint>
#include <cstring>

#include "../../include/horkos/dma_forensics.h"

/* bar_flags bit layout (mirrors dma_forensics.h). */
static const uint8_t BAR_FLAG_64BIT    = 0x01u;
static const uint8_t BAR_FLAG_PREFETCH  = 0x02u;
static const uint8_t BAR_FLAG_IO       = 0x04u;

/* PCI "assigned-addresses" phys.hi field bits (Open Firmware / device-tree). */
static const uint32_t OFW_PREFETCH_BIT = 0x40000000u; /* p (bit 30) */
static const uint32_t OFW_SPACE_MASK   = 0x03000000u; /* ss (bits 25:24) */
static const uint32_t OFW_SPACE_IO     = 0x01000000u;
static const uint32_t OFW_SPACE_MEM64  = 0x03000000u;
static const uint32_t OFW_BAR_OFF_MASK = 0x000000FFu; /* rrrrrrrr config offset */

/* -------------------------------------------------------------------------
 * hk_dma_macos_fill_bar
 *
 * Maps each assigned-addresses cell to a BAR index by the config-space offset it
 * carries (0x10 = BAR0, step 4), records the decoded 64-bit length and the
 * space/prefetch flags. Read-only; the lengths are the kernel's already-correct
 * decode, so the 64-bit high-dword combination (sig 129/131 shared FP source) is
 * never re-derived by us.
 * ------------------------------------------------------------------------- */
extern "C" void hk_dma_macos_fill_bar(io_service_t dev, hk_dma_device_forensics *d) {
    CFTypeRef prop = IORegistryEntryCreateCFProperty(
        dev, CFSTR("assigned-addresses"), kCFAllocatorDefault, 0);
    if (prop == nullptr) return; /* leave bar_profile_count = 0 (unknown). */
    if (CFGetTypeID(prop) != CFDataGetTypeID()) {
        CFRelease(prop);
        return;
    }

    CFDataRef data = static_cast<CFDataRef>(prop);
    CFIndex bytes = CFDataGetLength(data);
    const uint8_t *raw = CFDataGetBytePtr(data);
    /* Each cell is 5 * uint32 = 20 bytes; the property is host-endian uint32s. */
    const CFIndex cell_bytes = 20;
    CFIndex n_cells = bytes / cell_bytes;

    uint8_t count = 0;
    for (CFIndex c = 0; c < n_cells; ++c) {
        const uint8_t *cell = raw + c * cell_bytes;
        uint32_t words[5];
        std::memcpy(words, cell, sizeof(words)); /* host-endian uint32 cells. */

        uint32_t phys_hi = words[0];
        uint32_t space   = phys_hi & OFW_SPACE_MASK;
        if (space == 0u) continue; /* config-space cell — not a BAR window. */

        uint32_t bar_cfg_off = phys_hi & OFW_BAR_OFF_MASK;
        if (bar_cfg_off < 0x10u || bar_cfg_off > 0x24u) continue; /* not a BAR. */
        unsigned bar_index = (bar_cfg_off - 0x10u) / 4u;
        if (bar_index >= 6u) continue;

        uint64_t size = (static_cast<uint64_t>(words[3]) << 32) |
                        static_cast<uint64_t>(words[4]);
        d->bar_size[bar_index] = size;

        uint8_t bf = 0;
        if (space == OFW_SPACE_MEM64)  bf |= BAR_FLAG_64BIT;
        if (space == OFW_SPACE_IO)     bf |= BAR_FLAG_IO;
        if (phys_hi & OFW_PREFETCH_BIT) bf |= BAR_FLAG_PREFETCH;
        d->bar_flags[bar_index] = bf;
        if (size != 0u || bf != 0u) ++count;
    }

    CFRelease(prop);
    d->bar_profile_count = count;
}
