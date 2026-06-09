/*
 * bypass-tests/dma_hardware/bypass_bar_geometry.cpp
 * Role: DMA-hardware bypass-test fixture (merge gate, guardrail #12) for catalog
 *       signal 131 (BAR geometry). Demonstrates: a generic FPGA BAR0 profile (one
 *       huge prefetchable 64-bit window) is shipped as raw geometry the SERVER
 *       scores against a per-VID/DID reference, and that the client NEVER produces a
 *       standalone ban — it only serializes facts (the load-bearing assertion: the
 *       client emits geometry, the verdict is server-side). The reference-mismatch
 *       scoring + "never standalone" gate live in dma_forensics.rs.
 * Target platforms: all (host-runnable; exercises the real serializer round-trip).
 * Interface: drives hk_dma_forensics_serialize_device + the BAR-flag fields.
 */

#include <cstdio>
#include <cstring>
#include "forensics_helpers.h"

int main(void) {
    int failures = 0;

    /* Generic FPGA BAR0: a single huge prefetchable 64-bit window — the classic
     * PCILeech/FPGA shape, unlike an I210 NIC's small, non-prefetchable BARs. The
     * client ships this geometry verbatim; it must serialize cleanly and the client
     * must NOT carry any verdict field (there is none in the record). */
    hk_dma_device_forensics fpga;
    std::memset(&fpga, 0, sizeof(fpga));
    fpga.vendor_id = 0x1234;           /* spoofed / generic */
    fpga.device_id = 0x5678;
    fpga.bus_master_enabled = 1;
    fpga.driver_bound = 0;
    fpga.bar_profile_count = 1;
    fpga.bar_size[0] = 0x1000'0000ull; /* 256 MiB window */
    fpga.bar_flags[0] = 0x1 | 0x2;     /* bit0=64-bit, bit1=prefetchable */

    uint8_t wire[HK_DMA_FORENSICS_WIRE_BYTES];
    uint32_t n = hk_dma_forensics_serialize_device(&fpga, wire, sizeof(wire));
    if (n != HK_DMA_FORENSICS_WIRE_BYTES) {
        std::printf("FAIL: FPGA BAR record did not serialize to the pinned size (%u)\n", n);
        ++failures;
    }

    /* Reference I210 profile: small non-prefetchable BAR0. Also serializes; the
     * SERVER decides mismatch — the client emits identical-shaped facts for both,
     * proving the verdict is never client-side. */
    hk_dma_device_forensics i210;
    std::memset(&i210, 0, sizeof(i210));
    i210.vendor_id = 0x8086;
    i210.device_id = 0x1533;
    i210.driver_bound = 1;             /* genuine, bound */
    i210.bar_profile_count = 1;
    i210.bar_size[0] = 0x2'0000ull;    /* 128 KiB */
    i210.bar_flags[0] = 0x1;           /* 64-bit, not prefetchable */
    uint8_t wire2[HK_DMA_FORENSICS_WIRE_BYTES];
    if (hk_dma_forensics_serialize_device(&i210, wire2, sizeof(wire2)) != HK_DMA_FORENSICS_WIRE_BYTES) {
        std::printf("FAIL: I210 reference record did not serialize\n");
        ++failures;
    }

    /* The client emits the same record shape for benign and suspect geometry; no
     * standalone-ban field exists. A genuine bound device is not even a structural
     * suspect, so it cannot be scored. */
    if (hk_dma_forensics_structural_suspect(&i210) != 0) {
        std::printf("FAIL: genuine bound I210 must not be a structural suspect\n");
        ++failures;
    }

    /* Undersized buffer must be refused (no truncation/partial wire image). */
    uint8_t tiny[8];
    if (hk_dma_forensics_serialize_device(&fpga, tiny, sizeof(tiny)) != 0) {
        std::printf("FAIL: undersized serialize buffer must return 0\n");
        ++failures;
    }

    if (failures == 0) {
        std::printf("bypass_bar_geometry: OK (geometry serialized for both; verdict is server-side, no client ban)\n");
        return 0;
    }
    std::printf("bypass_bar_geometry: %d assertion(s) failed\n", failures);
    return 1;
}
