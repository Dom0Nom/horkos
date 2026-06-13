/*
 * Role: macOS MSI-X BIR/PBA containment forensics (sig 129). Sources the MSI-X
 *       capability fields (table size, Table/PBA Offset+BIR) from the device's
 *       config space and the referenced BAR lengths from the BAR profiler, then
 *       calls the shared 64-bit-correct containment helper. Read-only.
 * Target platforms: macOS only (IOKit). Selected by CMake elseif(APPLE).
 * Implements: hk_dma_macos_fill_msix (consumed by ConfigSpaceForensics.mm).
 *
 * *** HK-UNCERTAIN(macos-config-read): reading the MSI-X capability out of PCI
 * config space requires a live config read via the IOPCIFamily user client
 * (IOPCIDevice config read selectors), which is NOT a confirmed entitlement-free
 * userspace path on macOS (same open question as the ext-config sweep in
 * ConfigSpaceForensics.mm). Per guardrail #12 this TU does NOT guess that selector
 * surface: it leaves the MSI-X fields unknown (0). The 64-bit-correct containment
 * math is fully implemented + unit-tested in forensics_report.cpp; only the macOS
 * config SOURCE is deferred. CONFIRM on a real box whether the config-read user
 * client is reachable unentitled, or whether a System Extension is required.
 * (docs: same as ConfigSpaceForensics.mm HK-UNCERTAIN(macos-ext-config) —
 * IOPCIDevice config read methods are kext-side only; no public userspace user-client
 * selector documented in MacOSX.sdk through 15.5) ***
 */

#import <IOKit/IOKitLib.h>

#include <cstdint>

#include "../../include/horkos/dma_forensics.h"

/* Shared 64-bit-correct containment check (forensics_report.cpp). Declared here
 * so this TU is ready to call it the moment a macOS config-read path is
 * confirmed; the call site is staged behind the HK-UNCERTAIN gate. */
extern "C" int hk_dma_msix_containment_violation(
    uint64_t table_bar_len, uint64_t table_offset,
    uint64_t pba_bar_len,   uint64_t pba_offset,
    uint16_t table_size_entries);

/* -------------------------------------------------------------------------
 * hk_dma_macos_fill_msix
 *
 * HK-UNCERTAIN(macos-config-read): the MSI-X cap walk needs a confirmed config
 * read (see file header — docs note appended there). Until then we leave
 * msix_table_size / containment unknown (0); the parent ConfigSpaceForensics.mm
 * already marks the record's scan_error so the server does NOT read the absence
 * as "clean". Wiring the containment helper here is a one-function change once
 * the config-read selector is settled on a real box.
 * ------------------------------------------------------------------------- */
extern "C" void hk_dma_macos_fill_msix(io_service_t dev, hk_dma_device_forensics *d) {
    (void)dev;
    d->msix_table_size = 0u;
    d->msix_containment_violation = 0u;
}
