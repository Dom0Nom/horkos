/*
 * dma_detect/backends/linux/OptionRomForensics.cpp
 * Role: Linux option-ROM identity forensics (sig 130). Reads the expansion ROM
 *       via /sys/bus/pci/devices/<BDF>/rom, parses the 0xAA55 signature and the
 *       PCIR structure, and compares the PCIR's VID/DID to the device's config
 *       VID/DID. A clone board whose ROM advertises a different identity than
 *       its faked config IDs is the catch.
 * Target platforms: Linux only. Selected by CMake elseif(UNIX).
 * Implements: hk_dma_linux_fill_rom (consumed by ConfigSpaceForensics.cpp).
 *
 * SIDE-EFFECT CAUTION (impl-plan Risk #4): enabling ROM decode to read it is the
 * ONE non-pure-read probe in this domain. Mitigation enforced here: we only
 * enable+read+restore when NO driver owns the device (driver_bound == 0). If a
 * driver is bound, the ROM region may be in active use — we SKIP rather than
 * perturb it. The sysfs `rom` node also returns -EINVAL when the kernel has the
 * ROM shadowed/owned, which we treat as "skip", not "error".
 */

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

#include "../../include/horkos/dma_forensics.h"

/* -------------------------------------------------------------------------
 * read_rom_header
 *
 * The sysfs rom node requires writing "1" to enable decode before reading, and
 * "0" to restore. We bound the read to the header window we need: the legacy
 * ROM header is at 0x00 (0xAA55 signature) with a pointer at 0x18 to the PCIR
 * data structure; PCIR has "PCIR" at +0x00, VID at +0x04, DID at +0x06.
 * 4 KB is more than enough to reach a first-image PCIR.
 * ------------------------------------------------------------------------- */
extern "C" void hk_dma_linux_fill_rom(const char *dev_dir,
                                      hk_dma_device_forensics *d) {
    /* Skip entirely if a driver owns the device — do not perturb a live ROM. */
    if (d->driver_bound != 0u) {
        d->rom_present = 0u;
        d->rom_pcir_id_mismatch = 0u;
        return;
    }

    char path[640];
    std::snprintf(path, sizeof(path), "%s/rom", dev_dir);

    /* Enable ROM decode: write "1". If the node is absent or write fails, there
     * is no readable ROM — leave rom_present = 0 (not an error). */
    int wfd = ::open(path, O_WRONLY);
    if (wfd < 0) return;
    bool enabled = (::write(wfd, "1", 1) == 1);
    ::close(wfd);
    if (!enabled) return;

    uint8_t buf[4096];
    std::memset(buf, 0, sizeof(buf));
    uint32_t got = 0;
    int rfd = ::open(path, O_RDONLY);
    if (rfd >= 0) {
        ssize_t n = ::read(rfd, buf, sizeof(buf));
        if (n > 0) got = static_cast<uint32_t>(n);
        ::close(rfd);
    }

    /* Restore: write "0" to disable decode again (best-effort; the device had
     * no driver, so leaving it enabled would still be a state change we must
     * undo). */
    int dfd = ::open(path, O_WRONLY);
    if (dfd >= 0) {
        ssize_t wn = ::write(dfd, "0", 1);
        (void)wn;
        ::close(dfd);
    }

    if (got < 0x20u) {
        d->rom_present = 0u;
        return;
    }

    /* Legacy ROM signature 0xAA55 (little-endian: buf[0]=0x55, buf[1]=0xAA). */
    if (!(buf[0] == 0x55u && buf[1] == 0xAAu)) {
        d->rom_present = 0u;
        return;
    }
    d->rom_present = 1u;

    /* Pointer to PCIR at offset 0x18 (little-endian u16). */
    uint32_t pcir_off = static_cast<uint32_t>(buf[0x18] | (buf[0x19] << 8));
    if (pcir_off + 0x08u > got) {
        /* Header present but PCIR out of the window we read — cannot compare. */
        d->rom_pcir_id_mismatch = 0u;
        return;
    }

    /* PCIR signature "PCIR" at pcir_off. */
    if (!(buf[pcir_off] == 'P' && buf[pcir_off + 1] == 'C' &&
          buf[pcir_off + 2] == 'I' && buf[pcir_off + 3] == 'R')) {
        d->rom_pcir_id_mismatch = 0u;
        return;
    }

    uint16_t pcir_vid = static_cast<uint16_t>(buf[pcir_off + 4] | (buf[pcir_off + 5] << 8));
    uint16_t pcir_did = static_cast<uint16_t>(buf[pcir_off + 6] | (buf[pcir_off + 7] << 8));

    /* Mismatch if the ROM advertises an identity that differs from config.
     * Only assert when both config IDs are known (non-zero); a 0 config VID
     * means we could not read it and must not assert a mismatch. */
    if (d->vendor_id != 0u && d->device_id != 0u) {
        d->rom_pcir_id_mismatch =
            (pcir_vid != d->vendor_id || pcir_did != d->device_id) ? 1u : 0u;
    } else {
        d->rom_pcir_id_mismatch = 0u;
    }
}
