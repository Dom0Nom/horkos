/*
 * Role: Linux backend for DMA-attack detection.
 *       Walks /sys/bus/pci/devices/ to enumerate PCIe devices and inspect
 *       class codes, driver binding, and Bus Master Enable state.
 *       Queries /sys/class/iommu/ and /sys/kernel/iommu_groups/ to
 *       independently corroborate firmware IOMMU claims.
 * Target platforms: Linux only.  Selected by CMake elseif(UNIX).
 * Implements: dma_detect/include/horkos/dma_detect.h (hk_dma_scan)
 */

/*
 * Linux-specific headers are confined to this file (guardrail #1).
 * We do not include platform/platform.h because this file is selected by
 * CMake and does not need the HK_PLATFORM_* detection macros at file scope.
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <dirent.h>     /* opendir, readdir, closedir                           */
#include <sys/stat.h>   /* stat, S_ISDIR                                        */
#include <unistd.h>     /* access                                               */
#include <fcntl.h>      /* open, O_RDONLY                                       */

#include "../../include/horkos/dma_detect.h"

/* -------------------------------------------------------------------------
 * Sysfs path constants.
 *
 * /sys/bus/pci/devices/
 *   Each entry is a symlink → ../../devices/pci<domain>:<bus>/<domain>:<B>:<D>.<F>/
 *   Inside each device directory:
 *     class       : ASCII hex "0x<BaseClass><SubClass><ProgIf>\n"
 *     driver/     : symlink present when a driver is bound
 *     enable      : "1\n" when the device is enabled (PCI_COMMAND.BME may be set)
 *
 * /sys/class/iommu/
 *   Each entry is a symlink to an IOMMU instance registered with the kernel.
 *   Presence of ANY entry here means the kernel's IOMMU framework has at least
 *   one unit initialised.
 *   Ref: Documentation/ABI/stable/sysfs-class-iommu
 *
 * /sys/kernel/iommu_groups/
 *   Each directory is a numbered IOMMU group.  Number of directories equals
 *   the number of distinct isolation groups the IOMMU has created.
 *   Ref: Documentation/ABI/testing/sysfs-kernel-iommu_groups
 *
 * /proc/iomem
 *   "DMAR" entries indicate the firmware DMAR/SMMU ACPI table was parsed by
 *   the kernel.  We use this as the firmware-claim proxy (less fragile than
 *   parsing /dev/mem or relying on a kernel module).
 * ------------------------------------------------------------------------- */
static const char SYSFS_PCI_DEVICES[]   = "/sys/bus/pci/devices";
static const char SYSFS_IOMMU_CLASS[]   = "/sys/class/iommu";
static const char SYSFS_IOMMU_GROUPS[]  = "/sys/kernel/iommu_groups";
static const char PROC_IOMEM[]          = "/proc/iomem";

/* -------------------------------------------------------------------------
 * PCI base class codes (upper byte of ClassCode register, PCI Spec §6.2.1).
 * Consistent with the Windows backend's classification logic.
 * ------------------------------------------------------------------------- */
static const uint8_t PCI_BASECLASS_STORAGE         = 0x01;
static const uint8_t PCI_BASECLASS_NETWORK          = 0x02;
static const uint8_t PCI_BASECLASS_MULTIMEDIA       = 0x04;
static const uint8_t PCI_BASECLASS_COMM             = 0x07;
static const uint8_t PCI_BASECLASS_COPY_PROCESSOR   = 0x12;

static bool is_dma_capable_class(uint8_t base_class) {
    switch (base_class) {
    case PCI_BASECLASS_STORAGE:
    case PCI_BASECLASS_NETWORK:
    case PCI_BASECLASS_MULTIMEDIA:
    case PCI_BASECLASS_COMM:
    case PCI_BASECLASS_COPY_PROCESSOR:
        return true;
    default:
        return false;
    }
}

/* -------------------------------------------------------------------------
 * read_sysfs_string
 *
 * Reads up to (buf_len - 1) bytes from a sysfs file into buf, null-
 * terminates, and returns true.  Returns false on any read error.
 * Sysfs files are at most a page; we always pass a small fixed-size buffer.
 * ------------------------------------------------------------------------- */
static bool read_sysfs_string(const char *path, char *buf, size_t buf_len) {
    FILE *f = fopen(path, "r");
    if (!f) return false;
    size_t n = fread(buf, 1, buf_len - 1, f);
    buf[n]   = '\0';
    fclose(f);
    return n > 0;
}

/* -------------------------------------------------------------------------
 * count_dir_entries
 *
 * Counts the number of entries in dir_path (excluding "." and "..").
 * Returns 0 on any error (permissions, not-a-directory, absent path).
 * ------------------------------------------------------------------------- */
static uint32_t count_dir_entries(const char *dir_path) {
    DIR *d = opendir(dir_path);
    if (!d) return 0u;

    uint32_t count = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != nullptr) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        ++count;
    }
    closedir(d);
    return count;
}

/* -------------------------------------------------------------------------
 * path_exists
 *
 * Returns true if path exists (stat succeeds).
 * ------------------------------------------------------------------------- */
static bool path_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

/* -------------------------------------------------------------------------
 * firmware_claims_iommu
 *
 * Checks /proc/iomem for a "DMAR" entry (Intel VT-d) or "SMMU" entry
 * (ARM SMMU).  The presence of such a line means the kernel's ACPI/IORT
 * parser found and registered a remapping table from firmware.
 *
 * This is the "firmware claim" side of the cross-check.  It does NOT
 * guarantee the IOMMU is actually protecting anything.
 *
 * Ref: kernel source arch/x86/kernel/acpi/boot.c (dmar_table_init),
 *      drivers/iommu/arm/arm-smmu-v3/arm-smmu-v3.c
 *
 * NOTE: /proc/iomem format is kernel-version dependent.  The DMAR/SMMU
 * strings have been stable since kernel 3.x; kernels < 4.15 are EOL.
 * ------------------------------------------------------------------------- */
static bool firmware_claims_iommu() {
    FILE *f = fopen(PROC_IOMEM, "r");
    if (!f) return false;

    char line[256];
    bool found = false;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "DMAR") || strstr(line, "SMMU")) {
            found = true;
            break;
        }
    }
    fclose(f);
    return found;
}

/* -------------------------------------------------------------------------
 * scan_pci_device
 *
 * Inspects a single entry under /sys/bus/pci/devices/<bdf>/.
 * Increments *suspicious if the device is DMA-capable and either has no
 * driver bound or has an unrecognised (all-zeros) class code.
 *
 * driver/  sub-directory is present when a driver is bound.
 * Ref: Documentation/ABI/testing/sysfs-bus-pci ("driver" symlink)
 *
 * enable   contains "1" when the PCI_COMMAND register's I/O-space or memory-
 * space decode bits are set (which typically implies Bus Master Enable is also
 * set for functional devices).
 * Ref: Documentation/ABI/testing/sysfs-bus-pci ("enable" attribute)
 * ------------------------------------------------------------------------- */
static void scan_pci_device(const char *dev_dir, uint32_t *suspicious,
                            bool *iommu_cross_mismatch, bool iommu_os_active) {
    char path[512];

    /* Read class code. */
    snprintf(path, sizeof(path), "%s/class", dev_dir);
    char class_str[32] = {0};
    if (!read_sysfs_string(path, class_str, sizeof(class_str))) {
        /* If we can't read the class, conservatively treat the device as
         * a suspect if it also has no driver. */
    }

    /* /sys/bus/pci/devices/<bdf>/class is "0xCCSSPP\n"
     * where CC = base class, SS = sub-class, PP = prog-if.
     * strtoul with base 0 handles the "0x" prefix. */
    unsigned long class_code = strtoul(class_str, nullptr, 0);
    uint8_t base_class       = static_cast<uint8_t>((class_code >> 16) & 0xFF);

    /* Check driver binding: "driver" is a symlink when a driver is attached. */
    snprintf(path, sizeof(path), "%s/driver", dev_dir);
    bool driver_bound = path_exists(path);

    /* Read PCI_COMMAND (config space offset 0x04, 16-bit little-endian); bit 2
     * is Bus Master Enable. A BME-enabled device can initiate DMA — this is the
     * real signal the header advertises, read here rather than assumed. */
    bool bus_master = false;
    {
        snprintf(path, sizeof(path), "%s/config", dev_dir);
        FILE *cf = fopen(path, "rb");
        if (cf != nullptr) {
            unsigned char cfg[6] = {0};
            size_t got = fread(cfg, 1, sizeof(cfg), cf);
            fclose(cf);
            if (got >= 5) {
                bus_master = (cfg[4] & 0x04u) != 0;
            }
        }
    }

    bool dma_capable = is_dma_capable_class(base_class);
    bool class_unknown = (class_code == 0); /* Zero class → firmware/BIOS default, unset. */

    bool suspect = false;
    if (dma_capable && !driver_bound) {
        /* A storage/network/etc device with no kernel driver has no IOMMU
         * input-output page-table managed by the OS. A device that ALSO has Bus
         * Master Enable set can actively initiate DMA — the strongest signal. */
        suspect = true;
        /* A BME-enabled, driverless DMA device while firmware claims IOMMU is
         * on is the firmware-lies signal — flag the cross-check directly. */
        if (bus_master && iommu_os_active) {
            *iommu_cross_mismatch = true;
        }
    }
    if (class_unknown && !driver_bound) {
        /* Unrecognised device, no driver — matches the blank-class-code
         * presentation of many FPGA-based DMA boards (e.g., PCILeech). */
        suspect = true;
    }

    if (suspect) {
        ++(*suspicious);
        /* Cross-check: if IOMMU is supposedly OS-active but we have an
         * unprotected device, the protection is incomplete. */
        if (iommu_os_active) {
            *iommu_cross_mismatch = true;
        }
    }
}

/* -------------------------------------------------------------------------
 * hk_dma_scan — Linux implementation
 * ------------------------------------------------------------------------- */
extern "C" int hk_dma_scan(hk_dma_report *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));

    /* Step 1: Firmware IOMMU claim via /proc/iomem. */
    bool fw_iommu = firmware_claims_iommu();
    out->iommu_enabled = fw_iommu ? 1u : 0u;

    /* Step 2: Kernel IOMMU corroboration.
     *
     * /sys/class/iommu/ — presence of any entry means the kernel IOMMU
     *   subsystem has at least one unit registered.
     *
     * /sys/kernel/iommu_groups/ — number of entries is the group count,
     *   which we surface as iommu_groups_present.  This is the stronger
     *   corroboration because groups are only created after the IOMMU
     *   successfully starts and scans the bus topology.
     *
     * NOTE: On kernels without CONFIG_IOMMU_DEBUGFS or where iommu_groups is
     * a CONFIG_IOMMU_API option, these paths may be absent even on correctly-
     * functioning IOMMU hardware.  If both paths are absent, fall back to
     * /sys/class/iommu/ count only.
     */
    uint32_t iommu_groups   = count_dir_entries(SYSFS_IOMMU_GROUPS);
    uint32_t iommu_class_entries = count_dir_entries(SYSFS_IOMMU_CLASS);

    /* Use group count as the primary kernel-visible metric; if iommu_groups
     * sysfs is absent but class entries are present, treat it as at least 1. */
    out->iommu_groups_present = iommu_groups;
    if (out->iommu_groups_present == 0 && iommu_class_entries > 0) {
        out->iommu_groups_present = iommu_class_entries;
    }

    bool iommu_os_active = (out->iommu_groups_present > 0);

    /* Step 3: Enumerate PCIe devices via /sys/bus/pci/devices/. */
    DIR *bus_dir = opendir(SYSFS_PCI_DEVICES);
    if (!bus_dir) {
        out->scan_error = static_cast<uint32_t>(errno);
        return -1;
    }

    uint32_t suspicious          = 0;
    bool     iommu_cross_mismatch = false;
    struct dirent *ent;
    char dev_dir[512];

    while ((ent = readdir(bus_dir)) != nullptr) {
        if (ent->d_name[0] == '.') continue;

        /* Each entry under /sys/bus/pci/devices is the canonical BDF string,
         * e.g. "0000:00:1f.3".  Build the full path to the device directory. */
        snprintf(dev_dir, sizeof(dev_dir), "%s/%s", SYSFS_PCI_DEVICES, ent->d_name);
        scan_pci_device(dev_dir, &suspicious, &iommu_cross_mismatch, iommu_os_active);
    }
    closedir(bus_dir);

    out->suspicious_device_count = suspicious;

    /* Step 4: Compute high_confidence_flag.
     *
     * Three conditions each independently set it:
     *   (a) Firmware claims IOMMU on but the kernel sees 0 IOMMU groups —
     *       classic firmware lie or IOMMU initialisation failure.
     *   (b) Suspicious devices present and IOMMU is not OS-corroborated —
     *       full DMA attack surface with no kernel-level protection.
     *   (c) IOMMU OS-active but a DMA-capable device has no driver bound —
     *       IOMMU group exists but VT-d/SMMU may not map the device correctly
     *       without a driver to own the IOVA space.
     *
     * The server — not this library — decides whether to take action.
     */
    if ((fw_iommu && out->iommu_groups_present == 0) ||
        (suspicious > 0 && !iommu_os_active)          ||
        iommu_cross_mismatch) {
        out->high_confidence_flag = 1u;
    }

    return 0;
}
