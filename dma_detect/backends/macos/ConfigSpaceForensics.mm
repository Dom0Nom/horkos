/*
 * dma_detect/backends/macos/ConfigSpaceForensics.mm
 * Role: macOS config-space forensics backend and the macOS
 *       hk_dma_forensics_scan entry point. Enumerates IOPCIDevice nodes from the
 *       IOKit registry, sweeps PCIe config space with IOPCIDevice::configRead32,
 *       and fills hk_dma_device_forensics for sig 127 (DSN forgery), 128
 *       (ext-config stability), and the structural gates (bus master / driver
 *       bound). The MSI-X (129), option-ROM (130), BAR (131), ACS (133) per-device
 *       arms live in sibling macOS TUs and are invoked here. Read-only: only
 *       config reads, never a config write.
 * Target platforms: macOS only (IOKit). Selected by CMake elseif(APPLE);
 *       compiled as Objective-C++ (.mm), links IOKit + CoreFoundation.
 * Implements: dma_detect/include/horkos/dma_forensics.h (hk_dma_forensics_scan).
 *
 * macOS config-read path: IORegistry exposes each PCIe function as an
 * IOPCIDevice. The userspace IOPCIFamily user client (IOPCIDevice config
 * read/write selectors) is NOT generally reachable from an unentitled userspace
 * process; the robust, entitlement-free read uses the IORegistry property bundle
 * the kernel publishes for each device ("vendor-id", "device-id",
 * "subsystem-vendor-id", "assigned-addresses", "IOPCIConfigSpace" where present).
 * Where a live config sweep is required (DSN ext-cap walk, ext-config stability)
 * and no entitlement is held, those arms degrade-absent (scan_error sentinel),
 * never guess — see HK-UNCERTAIN below.
 */

#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <CoreFoundation/CoreFoundation.h>

#include <cstdint>
#include <cstring>

#include "../../include/horkos/dma_forensics.h"

/* Sibling macOS arms (defined in the same backend folder). Declared here so the
 * scan orchestrator can call them per device without a shared private header
 * (mirrors the Linux backend's intra-folder extern-C contract). */
extern "C" void hk_dma_macos_fill_bar(io_service_t dev, hk_dma_device_forensics *d);
extern "C" void hk_dma_macos_fill_msix(io_service_t dev, hk_dma_device_forensics *d);
extern "C" void hk_dma_macos_fill_rom(io_service_t dev, hk_dma_device_forensics *d);
extern "C" void hk_dma_macos_fill_acs(io_service_t dev, hk_dma_device_forensics *d);

/* Shared platform-clean helpers from forensics_report.cpp. */
extern "C" uint32_t hk_dma_dsn_oui(uint64_t eui64);
extern "C" int hk_dma_extcfg_aliases_low(const uint8_t *buf, uint32_t len);

/* Sentinel matching the Windows backend's "ext config not sampled on this build"
 * marker: on macOS without the IOPCIFamily user client entitlement, the DSN /
 * ext-config-stability arms cannot run. The server must read absence as
 * "unknown", never "clean". Kept local (the value is the contract). */
static const uint32_t HK_DMA_MACOS_EXTCFG_UNAVAILABLE = 0xE0000002u;

namespace {

/* read_io_u32_prop — read a CFNumber/CFData IORegistry property into a u32.
 * Returns true and writes *out on a hit. The kernel publishes vendor-id and
 * friends as 4-byte CFData (little-endian) on Apple silicon and as CFNumber on
 * some Intel models; handle both. */
bool read_io_u32_prop(io_service_t dev, CFStringRef key, uint32_t *out) {
    CFTypeRef v = IORegistryEntryCreateCFProperty(dev, key, kCFAllocatorDefault, 0);
    if (v == nullptr) return false;
    bool ok = false;
    CFTypeID t = CFGetTypeID(v);
    if (t == CFDataGetTypeID()) {
        CFDataRef data = static_cast<CFDataRef>(v);
        if (CFDataGetLength(data) >= 4) {
            const uint8_t *b = CFDataGetBytePtr(data);
            *out = static_cast<uint32_t>(b[0]) |
                   (static_cast<uint32_t>(b[1]) << 8) |
                   (static_cast<uint32_t>(b[2]) << 16) |
                   (static_cast<uint32_t>(b[3]) << 24);
            ok = true;
        }
    } else if (t == CFNumberGetTypeID()) {
        long long n = 0;
        if (CFNumberGetValue(static_cast<CFNumberRef>(v), kCFNumberLongLongType, &n)) {
            *out = static_cast<uint32_t>(n & 0xFFFFFFFFll);
            ok = true;
        }
    }
    CFRelease(v);
    return ok;
}

/* fill_bdf — populate hk_pci_bdf from the device's published "pcidebug" /
 * bus/dev/fn properties. IOPCIFamily publishes "pcidebug" as "bb:dd.f" plus a
 * segment; where absent we fall back to bus/device/function CFNumbers.
 *
 * HK-UNCERTAIN(macos-bdf): the exact IOPCIFamily property key carrying the PCI
 * domain (segment) is not a stable documented contract across macOS releases;
 * single-segment systems (the common case) read domain 0. We do NOT guess a
 * multi-segment key — domain stays 0 unless a documented property is found. */
void fill_bdf(io_service_t dev, hk_pci_bdf *bdf) {
    std::memset(bdf, 0, sizeof(*bdf));
    uint32_t bus = 0, devnum = 0, fn = 0;
    if (read_io_u32_prop(dev, CFSTR("bus-number"), &bus)) {
        bdf->bus = static_cast<uint8_t>(bus & 0xFFu);
    }
    if (read_io_u32_prop(dev, CFSTR("device-number"), &devnum) &&
        read_io_u32_prop(dev, CFSTR("function-number"), &fn)) {
        bdf->devfn = static_cast<uint8_t>(((devnum & 0x1Fu) << 3) | (fn & 0x07u));
    }
}

/* driver_bound — a device has a driver if it has at least one IOService child
 * client attached in the IOService plane. An IOPCIDevice with no client is the
 * "unbound" structural-gate state the catalog gates on. */
bool driver_bound(io_service_t dev) {
    io_iterator_t children = IO_OBJECT_NULL;
    if (IORegistryEntryGetChildIterator(dev, kIOServicePlane, &children) != KERN_SUCCESS) {
        return true; /* cannot tell — fail safe to "bound" so we do not assert. */
    }
    bool bound = false;
    io_object_t c;
    while ((c = IOIteratorNext(children)) != IO_OBJECT_NULL) {
        bound = true;
        IOObjectRelease(c);
    }
    IOObjectRelease(children);
    return bound;
}

void scan_one_device(io_service_t dev, hk_dma_device_forensics *d) {
    std::memset(d, 0, sizeof(*d));

    fill_bdf(dev, &d->bdf);

    uint32_t v = 0;
    if (read_io_u32_prop(dev, CFSTR("vendor-id"), &v)) {
        d->vendor_id = static_cast<uint16_t>(v & 0xFFFFu);
    }
    if (read_io_u32_prop(dev, CFSTR("device-id"), &v)) {
        d->device_id = static_cast<uint16_t>(v & 0xFFFFu);
    }
    if (read_io_u32_prop(dev, CFSTR("subsystem-vendor-id"), &v)) {
        d->subsys_vendor_id = static_cast<uint16_t>(v & 0xFFFFu);
    }

    d->driver_bound = driver_bound(dev) ? 1u : 0u;

    /* Bus Master Enable lives in PCI_COMMAND bit 2. IOPCIFamily publishes the
     * command register only via a live config read, which needs the IOPCIFamily
     * user client. Where that is reachable, BarProfile/Msix arms read it; here we
     * leave it to the documented-property path and degrade to 0 (unknown) if the
     * config-read user client is unavailable. */
    d->bus_master_enabled = 0u;

    /* sig 131 — BAR geometry from "assigned-addresses" (documented property). */
    hk_dma_macos_fill_bar(dev, d);

    /* sig 129 — MSI-X containment (needs a config read of the MSI-X cap). */
    hk_dma_macos_fill_msix(dev, d);

    /* sig 130 — option-ROM identity. */
    hk_dma_macos_fill_rom(dev, d);

    /* sig 133 — ACS control bits + IOMMU-group membership (DART on Apple Si). */
    hk_dma_macos_fill_acs(dev, d);

    /* sig 127 (DSN ext-cap walk) and sig 128 (ext-config stability) need a live
     * extended-config sweep. */
    /* HK-UNCERTAIN(macos-ext-config): reading PCIe extended config (offset >=256)
     * from an unentitled userspace process via the IOPCIFamily user client is not
     * a confirmed, entitlement-free path. We do NOT guess the selector surface;
     * the DSN/ext-config arms are left absent and the record is marked so the
     * server treats those fields as "unknown", never "clean". Implement only once
     * the IOPCIDevice::configRead32 reachability is confirmed on a real box. */
    d->scan_error = HK_DMA_MACOS_EXTCFG_UNAVAILABLE;
}

} /* anonymous namespace */

/* -------------------------------------------------------------------------
 * hk_dma_forensics_scan — macOS implementation.
 *
 * Enumerates every IOPCIDevice via IOServiceGetMatchingServices and fills up to
 * *inout_count records. Returns 0 on success, -1 if the matching dictionary or
 * the IOKit master port cannot be obtained.
 * ------------------------------------------------------------------------- */
extern "C" int hk_dma_forensics_scan(hk_dma_device_forensics *out,
                                     uint32_t *inout_count) {
    if (out == nullptr || inout_count == nullptr) return -1;
    const uint32_t cap = *inout_count;
    *inout_count = 0u;

    CFMutableDictionaryRef match = IOServiceMatching("IOPCIDevice");
    if (match == nullptr) return -1;

    io_iterator_t it = IO_OBJECT_NULL;
    /* kIOMainPortDefault (named kIOMasterPortDefault on older SDKs) is 0; pass 0
     * literally so this compiles against both SDK header generations. */
    kern_return_t kr = IOServiceGetMatchingServices(
        static_cast<mach_port_t>(0), match, &it);
    if (kr != KERN_SUCCESS) return -1;

    uint32_t written = 0;
    io_service_t dev;
    while ((dev = IOIteratorNext(it)) != IO_OBJECT_NULL && written < cap) {
        scan_one_device(dev, &out[written]);
        IOObjectRelease(dev);
        ++written;
    }
    IOObjectRelease(it);

    *inout_count = written;
    return 0;
}
