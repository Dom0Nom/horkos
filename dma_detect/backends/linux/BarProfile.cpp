/*
 * dma_detect/backends/linux/BarProfile.cpp
 * Role: Linux BAR geometry profiler (sig 131). Reconstructs each BAR's
 *       {size, 64-bit, prefetchable, io} from the kernel-recorded
 *       /sys/bus/pci/devices/<BDF>/resource file — never by issuing the
 *       write-all-ones BAR-sizing sequence ourselves (that mutates device state;
 *       every Horkos probe is read-only). Ships raw geometry; the server holds
 *       the per-VID/DID reference table and scores mismatch.
 * Target platforms: Linux only (sysfs). Selected by CMake elseif(UNIX).
 * Implements: hk_dma_linux_fill_bar (consumed by ConfigSpaceForensics.cpp).
 */

#include <cstdio>
#include <cstdint>
#include <cstring>

#include "../../include/horkos/dma_forensics.h"

/* bar_flags bit layout (mirrors dma_forensics.h). */
static const uint8_t BAR_FLAG_64BIT  = 0x01u;
static const uint8_t BAR_FLAG_PREFETCH = 0x02u;
static const uint8_t BAR_FLAG_IO     = 0x04u;

/* -------------------------------------------------------------------------
 * hk_dma_linux_fill_bar
 *
 * /sys/bus/pci/devices/<BDF>/resource has one line per resource:
 *   0x<start> 0x<end> 0x<flags>
 * The first 6 lines are BAR0..BAR5 (line 7+ are expansion ROM / bridge windows,
 * which we ignore for the BAR profile). size = end - start + 1 when start <= end
 * and the resource is populated (start != 0 || flags != 0); 0 for an unused BAR.
 *
 * The IORESOURCE flag bits we read (include/linux/ioport.h, stable ABI):
 *   bit 0  (0x0100 IORESOURCE_IO)        — I/O-space BAR
 *   0x00001000 IORESOURCE_PREFETCH       — prefetchable
 *   0x00100000 IORESOURCE_MEM_64         — 64-bit BAR
 * We read the documented values rather than re-deriving from the raw BAR
 * registers, so the 64-bit high-dword combination (the sig 129/131 shared FP
 * source) is the kernel's already-correct decode, not ours.
 * ------------------------------------------------------------------------- */
extern "C" void hk_dma_linux_fill_bar(const char *dev_dir,
                                      hk_dma_device_forensics *d) {
    char path[640];
    std::snprintf(path, sizeof(path), "%s/resource", dev_dir);
    FILE *f = std::fopen(path, "r");
    if (!f) return; /* leave bar_profile_count = 0 (unknown). */

    /* IORESOURCE_* bits (include/linux/ioport.h). */
    const uint64_t IORESOURCE_IO       = 0x00000100ull;
    const uint64_t IORESOURCE_PREFETCH = 0x00001000ull;
    const uint64_t IORESOURCE_MEM_64   = 0x00100000ull;

    uint8_t count = 0;
    char line[256];
    for (int bar = 0; bar < 6 && std::fgets(line, sizeof(line), f); ++bar) {
        unsigned long long start = 0, end = 0, flags = 0;
        if (std::sscanf(line, "%llx %llx %llx", &start, &end, &flags) != 3) {
            continue;
        }
        if (start == 0ull && end == 0ull && flags == 0ull) {
            d->bar_size[bar]  = 0ull;
            d->bar_flags[bar] = 0u;
            continue; /* unused BAR slot. */
        }
        uint64_t size = (end >= start) ? (end - start + 1ull) : 0ull;
        d->bar_size[bar] = size;

        uint8_t bf = 0;
        if (flags & IORESOURCE_MEM_64)   bf |= BAR_FLAG_64BIT;
        if (flags & IORESOURCE_PREFETCH) bf |= BAR_FLAG_PREFETCH;
        if (flags & IORESOURCE_IO)       bf |= BAR_FLAG_IO;
        d->bar_flags[bar] = bf;
        ++count;
    }
    std::fclose(f);
    d->bar_profile_count = count;
}
