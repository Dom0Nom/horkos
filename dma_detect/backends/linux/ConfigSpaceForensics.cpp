/*
 * dma_detect/backends/linux/ConfigSpaceForensics.cpp
 * Role: Linux config-space forensics backend and the Linux hk_dma_forensics_scan
 *       entry point. Walks /sys/bus/pci/devices/<BDF>/, pread()s the 4 KB
 *       extended config space, and fills hk_dma_device_forensics for sig 127
 *       (DSN forgery), 128 (ext-config stability), 131 (BAR geometry), and the
 *       structural gates (bus master / driver bound). The MSI-X (129), option-ROM
 *       (130), and ACS (133) per-device arms live in sibling Linux TUs and are
 *       invoked here. Read-only (no config writes); degrades gracefully on EACCES.
 * Target platforms: Linux only (sysfs). Selected by CMake elseif(UNIX AND NOT APPLE).
 * Implements: dma_detect/include/horkos/dma_forensics.h (hk_dma_forensics_scan).
 *
 * Read-only discipline: the 4 KB config is read via pread on the sysfs `config`
 * node; no offset is ever written. BAR sizes are taken from the kernel-recorded
 * `resource` file, never by issuing the write-all-ones BAR-sizing sequence
 * ourselves (that would mutate device state — guardrail: every probe is a read).
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "../../include/horkos/dma_forensics.h"

/* Sibling Linux arms (defined in the same backend folder). Declared here so the
 * scan orchestrator can call them per device without a shared private header
 * (this is the only Linux TU that includes them; keeps the surface small). */
extern "C" void hk_dma_linux_fill_msix(const char *dev_dir,
                                       const uint8_t *cfg, uint32_t cfg_len,
                                       const uint64_t *bar_len, uint8_t bar_count,
                                       hk_dma_device_forensics *d);
extern "C" void hk_dma_linux_fill_rom(const char *dev_dir,
                                      hk_dma_device_forensics *d);
extern "C" void hk_dma_linux_fill_acs(const char *dev_dir,
                                      hk_dma_device_forensics *d);
extern "C" void hk_dma_linux_fill_bar(const char *dev_dir,
                                      hk_dma_device_forensics *d);

/* Shared platform-clean helpers from forensics_report.cpp. */
extern "C" uint32_t hk_dma_dsn_oui(uint64_t eui64);
extern "C" int hk_dma_extcfg_aliases_low(const uint8_t *buf, uint32_t len);

static const char SYSFS_PCI_DEVICES[] = "/sys/bus/pci/devices";

/* PCIe extended capability IDs (PCIe spec 7.6). */
static const uint16_t PCIE_EXT_CAP_DSN = 0x0003u;

/* Number of ext-config re-reads for the sig-128 stability check. A genuine
 * device returns byte-identical config; an FPGA shadow occasionally drifts. */
static const int EXTCFG_STABILITY_SAMPLES = 4;

/* -------------------------------------------------------------------------
 * read_le16 / read_le32 — bounded little-endian reads out of a config buffer.
 * Config space is little-endian on PCIe. Return 0 if the field is out of range
 * (caller treats 0 as "not present", which never asserts a positive fact).
 * ------------------------------------------------------------------------- */
static uint16_t read_le16(const uint8_t *buf, uint32_t len, uint32_t off) {
    if (off + 2u > len) return 0u;
    return static_cast<uint16_t>(buf[off] | (buf[off + 1] << 8));
}

static uint32_t read_le32(const uint8_t *buf, uint32_t len, uint32_t off) {
    if (off + 4u > len) return 0u;
    return static_cast<uint32_t>(buf[off]) |
           (static_cast<uint32_t>(buf[off + 1]) << 8) |
           (static_cast<uint32_t>(buf[off + 2]) << 16) |
           (static_cast<uint32_t>(buf[off + 3]) << 24);
}

/* -------------------------------------------------------------------------
 * pread_config — read up to want bytes from <dev_dir>/config via pread.
 *
 * Returns the number of bytes read (0 on open/read failure). On a host without
 * CAP_SYS_ADMIN the kernel exposes only the first 256 bytes of config; ext
 * space reads short. We treat a short read as "ext space unavailable" (degrade,
 * do not error) per the impl-plan's graceful-degradation requirement.
 * ------------------------------------------------------------------------- */
static uint32_t pread_config(const char *dev_dir, uint8_t *buf, uint32_t want,
                             int *out_errno) {
    char path[640];
    std::snprintf(path, sizeof(path), "%s/config", dev_dir);
    int fd = ::open(path, O_RDONLY);
    if (fd < 0) {
        if (out_errno) *out_errno = errno;
        return 0u;
    }
    uint32_t total = 0;
    while (total < want) {
        ssize_t n = ::pread(fd, buf + total, want - total, total);
        if (n <= 0) break;
        total += static_cast<uint32_t>(n);
    }
    ::close(fd);
    return total;
}

/* -------------------------------------------------------------------------
 * parse_bdf — turn "0000:03:00.1" into hk_pci_bdf.
 * Returns true on a well-formed BDF string.
 * ------------------------------------------------------------------------- */
static bool parse_bdf(const char *name, hk_pci_bdf *out) {
    unsigned dom = 0, bus = 0, dev = 0, fn = 0;
    if (std::sscanf(name, "%x:%x:%x.%x", &dom, &bus, &dev, &fn) != 4) return false;
    out->domain = static_cast<uint16_t>(dom);
    out->bus    = static_cast<uint8_t>(bus);
    out->devfn  = static_cast<uint8_t>(((dev & 0x1Fu) << 3) | (fn & 0x07u));
    return true;
}

/* -------------------------------------------------------------------------
 * read_sysfs_hex16 — read a sysfs file that holds "0x1234\n" into a u16.
 * Returns 0 on any failure (the field stays "unknown").
 * ------------------------------------------------------------------------- */
static uint16_t read_sysfs_hex16(const char *dev_dir, const char *leaf) {
    char path[640];
    std::snprintf(path, sizeof(path), "%s/%s", dev_dir, leaf);
    FILE *f = std::fopen(path, "r");
    if (!f) return 0u;
    char buf[16] = {0};
    size_t n = std::fread(buf, 1, sizeof(buf) - 1, f);
    std::fclose(f);
    if (n == 0) return 0u;
    return static_cast<uint16_t>(std::strtoul(buf, nullptr, 0) & 0xFFFFu);
}

static bool path_exists(const char *path) {
    struct stat st;
    return ::stat(path, &st) == 0;
}

/* -------------------------------------------------------------------------
 * walk_ext_caps_for_dsn (sig 127)
 *
 * Walks the PCIe extended-capability linked list starting at 0x100. Each cap
 * header is a u32: bits 0-15 = cap ID, bits 16-19 = version, bits 20-31 = next
 * cap offset (PCIe spec 7.6.3). If a DSN cap (0x0003) is found, reads the EUI-64
 * (lower dword at cap+0x04, upper dword at cap+0x08) and reports presence + the
 * extracted OUI via the dsn_oui output (the server compares OUI vs VID table).
 *
 * Bounded: the next-offset is monotonic-checked and capped at 4 KB so a
 * malformed/looping list cannot spin.
 * ------------------------------------------------------------------------- */
static void walk_ext_caps_for_dsn(const uint8_t *cfg, uint32_t cfg_len,
                                  hk_dma_device_forensics *d) {
    if (cfg_len <= 0x100u) return; /* no ext space available; leave dsn_* = 0. */

    uint32_t off = 0x100u;
    int guard = 0;
    while (off >= 0x100u && off + 4u <= cfg_len && guard++ < 1024) {
        uint32_t hdr = read_le32(cfg, cfg_len, off);
        if (hdr == 0u || hdr == 0xFFFFFFFFu) break; /* end / unimplemented. */
        uint16_t cap_id = static_cast<uint16_t>(hdr & 0xFFFFu);
        uint32_t next   = (hdr >> 20) & 0xFFFu;

        if (cap_id == PCIE_EXT_CAP_DSN) {
            d->dsn_present = 1u;
            uint32_t lo = read_le32(cfg, cfg_len, off + 0x04u);
            uint32_t hi = read_le32(cfg, cfg_len, off + 0x08u);
            uint64_t eui64 = (static_cast<uint64_t>(hi) << 32) | lo;
            uint32_t oui = hk_dma_dsn_oui(eui64);
            /* The OUI-vs-VID match is a server-side table lookup. The client
             * cannot hold the full IEEE registry, but it can detect the
             * locally-administered bit (bit 1 of the first octet), which is
             * never set on a real IEEE-assigned OUI. dsn_oui_locally_administered
             * is 1 when that bit is set (suspicious), 0 when clear (unknown;
             * the server compares OUI against the VID registry). */
            uint8_t first_octet = static_cast<uint8_t>((oui >> 16) & 0xFFu);
            bool locally_administered = (first_octet & 0x02u) != 0u;
            d->dsn_oui_locally_administered = locally_administered ? 1u : 0u;
        }

        if (next == 0u || next <= off) break; /* terminator / no back-edges. */
        off = next;
    }
}

/* -------------------------------------------------------------------------
 * check_rsvdp_invariants (sig 128)
 *
 * A minimal RsvdP (reserved, preserve) sanity check: the PCIe spec requires
 * certain reserved fields read as zero on real silicon. We check a small,
 * stable, vendor-neutral invariant — the reserved byte at config 0x03 (the
 * upper byte of the BIST/Header-Type/Latency/Cacheline dword has reserved bits)
 * is intentionally NOT used (too vendor-variable). Instead we assert the
 * extended-capability list terminator discipline already validated above, and
 * here flag the single robust invariant: bytes 0x2E-0x2F (Subsystem ID region
 * is defined, skip) — to avoid false positives we restrict the RsvdP check to
 * the PCIe-cap reserved fields, which the per-cap walk cannot easily reach.
 *
 * Conservative: this returns 0 (no violation) unless we have a high-confidence
 * reserved-zero field that is non-zero. The dominant, low-FP one is the
 * extended-config "all FFs" sentinel appearing mid-list (handled in the walk).
 * Kept as a stub returning 0 so we never assert an RsvdP violation we are not
 * certain about (the catalog marks 128 high-FP — client ships facts only).
 * ------------------------------------------------------------------------- */
static uint8_t check_rsvdp_invariants(const uint8_t *cfg, uint32_t cfg_len) {
    (void)cfg;
    (void)cfg_len;
    /* HK-UNCERTAIN(rsvdp): which config-space reserved fields are reliably zero
     * across all genuine vendors without tripping quirky-but-legitimate devices
     * is not settled on-box. Asserting a wrong RsvdP invariant is an FP that
     * bans a clean player. Leaving this 0 (no violation) until the reserved-zero
     * field set is validated against a hardware corpus; the alias + stability
     * checks below carry sig 128 in the meantime. */
    return 0u;
}

/* -------------------------------------------------------------------------
 * extcfg_read_unstable (sig 128)
 *
 * Re-reads ext config N times and reports 1 if any two reads differ. A genuine
 * device is byte-stable; some FPGA shadows that compute config on the fly drift.
 * We skip the legacy 256 bytes (BME/status bits legitimately change) and compare
 * only 0x100-0xFFF, which must be invariant for a quiescent device.
 * ------------------------------------------------------------------------- */
static uint8_t sample_extcfg_unstable(const char *dev_dir, uint32_t cfg_len) {
    if (cfg_len <= 0x100u) return 0u; /* no ext space to compare. */
    uint8_t ref[4096];
    uint8_t cur[4096];
    int ig = 0;
    uint32_t first = pread_config(dev_dir, ref, cfg_len, &ig);
    if (first <= 0x100u) return 0u;
    for (int s = 1; s < EXTCFG_STABILITY_SAMPLES; ++s) {
        uint32_t got = pread_config(dev_dir, cur, first, &ig);
        if (got != first) return 0u; /* short read: degrade, do not assert. */
        if (std::memcmp(ref + 0x100, cur + 0x100, first - 0x100) != 0) {
            return 1u;
        }
    }
    return 0u;
}

/* -------------------------------------------------------------------------
 * fill_structural_gates — bus master + driver-bound (used by every signal gate).
 * ------------------------------------------------------------------------- */
static void fill_structural_gates(const char *dev_dir, const uint8_t *cfg,
                                  uint32_t cfg_len, hk_dma_device_forensics *d) {
    /* PCI_COMMAND at config 0x04, bit 2 = Bus Master Enable. */
    uint16_t command = read_le16(cfg, cfg_len, 0x04u);
    d->bus_master_enabled = (command & 0x0004u) ? 1u : 0u;

    char path[640];
    std::snprintf(path, sizeof(path), "%s/driver", dev_dir);
    d->driver_bound = path_exists(path) ? 1u : 0u;
}

/* -------------------------------------------------------------------------
 * scan_one_device
 * ------------------------------------------------------------------------- */
static void scan_one_device(const char *bdf_name, hk_dma_device_forensics *d) {
    std::memset(d, 0, sizeof(*d));

    char dev_dir[576];
    std::snprintf(dev_dir, sizeof(dev_dir), "%s/%s", SYSFS_PCI_DEVICES, bdf_name);

    if (!parse_bdf(bdf_name, &d->bdf)) {
        d->scan_error = static_cast<uint32_t>(EINVAL);
        return;
    }

    d->vendor_id        = read_sysfs_hex16(dev_dir, "vendor");
    d->device_id        = read_sysfs_hex16(dev_dir, "device");
    d->subsys_vendor_id = read_sysfs_hex16(dev_dir, "subsystem_vendor");

    uint8_t cfg[4096];
    int cfg_errno = 0;
    uint32_t cfg_len = pread_config(dev_dir, cfg, sizeof(cfg), &cfg_errno);
    if (cfg_len == 0u) {
        /* Could not read even legacy config — record the errno and bail. The
         * server treats scan_error != 0 as "do not trust this record". */
        d->scan_error = static_cast<uint32_t>(cfg_errno != 0 ? cfg_errno : EIO);
        return;
    }

    fill_structural_gates(dev_dir, cfg, cfg_len, d);

    /* sig 127 — DSN cap walk (needs ext config). */
    walk_ext_caps_for_dsn(cfg, cfg_len, d);

    /* sig 128 — ext-config aliasing + RsvdP + stability. */
    d->extcfg_aliases_low  = static_cast<uint8_t>(hk_dma_extcfg_aliases_low(cfg, cfg_len));
    d->rsvdp_nonzero       = check_rsvdp_invariants(cfg, cfg_len);
    d->extcfg_read_unstable = sample_extcfg_unstable(dev_dir, cfg_len);

    /* sig 131 — BAR geometry from the kernel-recorded `resource` file. */
    hk_dma_linux_fill_bar(dev_dir, d);

    /* sig 129 — MSI-X containment (needs cfg + decoded BAR lengths). */
    hk_dma_linux_fill_msix(dev_dir, cfg, cfg_len, d->bar_size,
                           d->bar_profile_count, d);

    /* sig 130 — option-ROM identity. */
    hk_dma_linux_fill_rom(dev_dir, d);

    /* sig 133 — ACS control bits + IOMMU-group membership. */
    hk_dma_linux_fill_acs(dev_dir, d);

    /* sig 132 (TLP latency) and sig 135 (IOMMU faults) are filled by separate
     * subsystems (TlpLatencyProbe / the eBPF loader merge), not in this pass. */
}

/* -------------------------------------------------------------------------
 * hk_dma_forensics_scan — Linux implementation.
 * ------------------------------------------------------------------------- */
extern "C" int hk_dma_forensics_scan(hk_dma_device_forensics *out,
                                     uint32_t *inout_count) {
    if (out == nullptr || inout_count == nullptr) return -1;
    const uint32_t cap = *inout_count;
    *inout_count = 0u;

    DIR *bus = ::opendir(SYSFS_PCI_DEVICES);
    if (!bus) return -1;

    uint32_t written = 0;
    struct dirent *ent;
    while ((ent = ::readdir(bus)) != nullptr && written < cap) {
        if (ent->d_name[0] == '.') continue;
        scan_one_device(ent->d_name, &out[written]);
        ++written;
    }
    ::closedir(bus);

    *inout_count = written;
    return 0;
}
