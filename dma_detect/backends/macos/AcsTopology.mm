/*
 * dma_detect/backends/macos/AcsTopology.mm
 * Role: macOS ACS / IOMMU-group topology forensics (sig 133). On macOS the IOMMU
 *       is the DART (Device Address Resolution Table) on Apple silicon / VT-d on
 *       Intel; there is no /sys/kernel/iommu_groups equivalent, so the "group
 *       membership" fact is approximated by counting the IOPCIDevice peers behind
 *       the same parent bridge in the IOService plane. The ACS control bits live
 *       in the bridge's PCIe extended config, whose read shares the same
 *       config-read uncertainty as the other macOS arms. Read-only.
 * Target platforms: macOS only (IOKit). Selected by CMake elseif(APPLE).
 * Implements: hk_dma_macos_fill_acs (consumed by ConfigSpaceForensics.mm).
 *
 * *** HK-UNCERTAIN(macos-config-read): the ACS extended-capability control bits
 * (cap 0x000D) require a live ext-config read of the upstream bridge via the
 * IOPCIFamily user client — the same unconfirmed userspace path as the DSN/MSI-X
 * arms. We do NOT guess that selector surface; acs_source_validation /
 * acs_p2p_redirect are left unknown (0). The group-membership count (a topology
 * fact readable from the IOService plane without a config read) IS filled, since
 * the server's primary gate is the oversized-group + suspect conjunction.
 * (docs: IOKit/pci/IOPCIDevice.h documents configRead32/extendedConfigRead32 as
 * virtual methods on the kernel-side IOPCIDevice class (kext), NOT a userspace API.
 * No public userspace selector for IOPCIFamily user client config reads is
 * documented in MacOSX.sdk through 15.5 — still needs on-box verification of
 * whether the user client is reachable unentitled or requires a System Extension) ***
 */

#import <IOKit/IOKitLib.h>

#include <cstdint>

#include "../../include/horkos/dma_forensics.h"

namespace {

/* count_bridge_peers — count the IOPCIDevice siblings under this device's parent
 * bridge in the IOService plane. A large peer set behind one bridge is the macOS
 * stand-in for an oversized IOMMU group: peers that a DMA-capable board could
 * reach if the bridge does not isolate them. Returns the peer count (including
 * the device itself), or 0 if the parent cannot be resolved. */
uint32_t count_bridge_peers(io_service_t dev) {
    io_registry_entry_t parent = IO_OBJECT_NULL;
    if (IORegistryEntryGetParentEntry(dev, kIOServicePlane, &parent) != KERN_SUCCESS) {
        return 0u;
    }
    io_iterator_t children = IO_OBJECT_NULL;
    if (IORegistryEntryGetChildIterator(parent, kIOServicePlane, &children) != KERN_SUCCESS) {
        IOObjectRelease(parent);
        return 0u;
    }
    uint32_t count = 0;
    io_object_t c;
    while ((c = IOIteratorNext(children)) != IO_OBJECT_NULL) {
        if (IOObjectConformsTo(c, "IOPCIDevice")) ++count;
        IOObjectRelease(c);
    }
    IOObjectRelease(children);
    IOObjectRelease(parent);
    return count;
}

} /* anonymous namespace */

/* -------------------------------------------------------------------------
 * hk_dma_macos_fill_acs
 * ------------------------------------------------------------------------- */
extern "C" void hk_dma_macos_fill_acs(io_service_t dev, hk_dma_device_forensics *d) {
    d->iommu_group_membership = count_bridge_peers(dev);

    /* HK-UNCERTAIN(macos-config-read): ACS control bits need an ext-config read of
     * the upstream bridge; left unknown (0) until the config-read user client is
     * confirmed reachable unentitled (see file header — docs note appended there).
     * The server treats absence as "cannot corroborate", never as a verdict. */
    d->acs_source_validation = 0u;
    d->acs_p2p_redirect = 0u;
}
