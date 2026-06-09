/*
 * dma_detect/backends/linux/AcsTopology.cpp
 * Role: Linux ACS / IOMMU-group topology forensics (sig 133). Reads the device's
 *       ACS extended capability (cap ID 0x000D) control bits — Source Validation
 *       and P2P Request Redirect — and corroborates with the device's IOMMU-group
 *       membership size from /sys/kernel/iommu_groups/<n>/devices/. A bus-master
 *       suspect sharing an oversized group with a sensitive endpoint, with ACS
 *       redirect controls weak, is the catalog shape — the SERVER scores it
 *       against a consumer-chipset allowlist; the client only ships the facts.
 * Target platforms: Linux only. Selected by CMake elseif(UNIX).
 * Implements: hk_dma_linux_fill_acs (consumed by ConfigSpaceForensics.cpp).
 */

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <limits.h>

#include "../../include/horkos/dma_forensics.h"

static const uint16_t PCIE_EXT_CAP_ACS = 0x000Du;

/* ACS Control Register bits (PCIe spec 7.7.8.3), at cap + 0x06 (16-bit). */
static const uint16_t ACS_CTRL_SOURCE_VALIDATION = 0x0001u; /* bit 0 */
static const uint16_t ACS_CTRL_P2P_REQ_REDIRECT  = 0x0004u; /* bit 2 */

static uint32_t pread_cfg(const char *dev_dir, uint8_t *buf, uint32_t want) {
    char path[640];
    std::snprintf(path, sizeof(path), "%s/config", dev_dir);
    int fd = ::open(path, O_RDONLY);
    if (fd < 0) return 0u;
    uint32_t total = 0;
    while (total < want) {
        ssize_t n = ::pread(fd, buf + total, want - total, total);
        if (n <= 0) break;
        total += static_cast<uint32_t>(n);
    }
    ::close(fd);
    return total;
}

static uint32_t le32(const uint8_t *b, uint32_t len, uint32_t off) {
    if (off + 4u > len) return 0u;
    return static_cast<uint32_t>(b[off]) | (static_cast<uint32_t>(b[off + 1]) << 8) |
           (static_cast<uint32_t>(b[off + 2]) << 16) | (static_cast<uint32_t>(b[off + 3]) << 24);
}
static uint16_t le16(const uint8_t *b, uint32_t len, uint32_t off) {
    if (off + 2u > len) return 0u;
    return static_cast<uint16_t>(b[off] | (b[off + 1] << 8));
}

/* -------------------------------------------------------------------------
 * find_acs_cap — walk the ext-cap list for ACS (0x000D). Returns offset or 0.
 * ------------------------------------------------------------------------- */
static uint32_t find_acs_cap(const uint8_t *cfg, uint32_t len) {
    if (len <= 0x100u) return 0u;
    uint32_t off = 0x100u;
    int guard = 0;
    while (off >= 0x100u && off + 4u <= len && guard++ < 1024) {
        uint32_t hdr = le32(cfg, len, off);
        if (hdr == 0u || hdr == 0xFFFFFFFFu) break;
        uint16_t cap_id = static_cast<uint16_t>(hdr & 0xFFFFu);
        uint32_t next   = (hdr >> 20) & 0xFFFu;
        if (cap_id == PCIE_EXT_CAP_ACS) return off;
        if (next == 0u || next <= off) break;
        off = next;
    }
    return 0u;
}

/* -------------------------------------------------------------------------
 * count_iommu_group_members
 *
 * /sys/bus/pci/devices/<BDF>/iommu_group is a symlink to
 * /sys/kernel/iommu_groups/<n>; its devices/ subdir lists every device sharing
 * the group. A large group (many devices behind one ACS-incapable bridge) means
 * a peer device could DMA to a group member without IOMMU mediation — the
 * server gates a suspect that shares such a group with a sensitive endpoint.
 * Returns the member count, or 0 if the group cannot be resolved.
 * ------------------------------------------------------------------------- */
static uint32_t count_iommu_group_members(const char *dev_dir) {
    char link[640];
    std::snprintf(link, sizeof(link), "%s/iommu_group", dev_dir);
    char target[PATH_MAX];
    ssize_t n = ::readlink(link, target, sizeof(target) - 1);
    if (n <= 0) return 0u;
    target[n] = '\0';

    /* The symlink target ends in the group number; build the devices/ path off
     * the canonical iommu_groups location to avoid relative-path resolution. */
    const char *slash = std::strrchr(target, '/');
    if (!slash) return 0u;
    char devices_dir[768];
    std::snprintf(devices_dir, sizeof(devices_dir),
                  "/sys/kernel/iommu_groups/%s/devices", slash + 1);

    DIR *d = ::opendir(devices_dir);
    if (!d) return 0u;
    uint32_t count = 0;
    struct dirent *e;
    while ((e = ::readdir(d)) != nullptr) {
        if (e->d_name[0] == '.') continue;
        ++count;
    }
    ::closedir(d);
    return count;
}

/* -------------------------------------------------------------------------
 * hk_dma_linux_fill_acs
 * ------------------------------------------------------------------------- */
extern "C" void hk_dma_linux_fill_acs(const char *dev_dir,
                                      hk_dma_device_forensics *d) {
    d->iommu_group_membership = count_iommu_group_members(dev_dir);

    uint8_t cfg[4096];
    uint32_t len = pread_cfg(dev_dir, cfg, sizeof(cfg));
    if (len <= 0x100u) {
        /* No ext config readable (no CAP_SYS_ADMIN) — ACS bits stay 0 = unknown.
         * The server treats absence as "cannot corroborate", never as a verdict. */
        return;
    }

    uint32_t acs = find_acs_cap(cfg, len);
    if (acs == 0u) {
        /* Device has no ACS cap. For an endpoint this is normal; the server
         * gates on the GROUP size + suspect conjunction, not on bare ACS-less. */
        return;
    }

    uint16_t ctrl = le16(cfg, len, acs + 0x06u);
    d->acs_source_validation = (ctrl & ACS_CTRL_SOURCE_VALIDATION) ? 1u : 0u;
    d->acs_p2p_redirect      = (ctrl & ACS_CTRL_P2P_REQ_REDIRECT) ? 1u : 0u;
}
