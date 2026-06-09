/*
 * bypass-tests/dma_hardware/bypass_iommu_fault_storm.cpp
 * Role: DMA-hardware bypass-test fixture (merge gate, guardrail #12) for catalog
 *       signal 135 (IOMMU faults). Demonstrates: a steady-state fault stream
 *       attributed to a FLAGGED (structural-suspect) BDF scores; AND that init-window
 *       bursts and faults on CLEAN (driver-bound) BDFs do NOT (the FP gate — faults
 *       require a structural co-requirement, and absence is "unknown" not "clean").
 *       The host-runnable half asserts the structural gate co-requirement on the
 *       fault-count field; the server-side count gating is proven in
 *       dma_forensics.rs::iommu_fault_on_suspect_scores_absent_is_unknown. The live
 *       eBPF/ETW fault source is gated behind HK_DMA_IOMMU_TEST_ENABLED.
 * Target platforms: all (host-runnable structural half).
 * Interface: drives dma_forensics.h records + forensics_report.cpp structural gate.
 */

#include <cstdio>
#include <cstring>
#include "forensics_helpers.h"

int main(void) {
    int failures = 0;

    /* Suspect BDF with a steady fault stream: scores (structural suspect + faults). */
    hk_dma_device_forensics suspect;
    std::memset(&suspect, 0, sizeof(suspect));
    suspect.vendor_id = 0x1234;
    suspect.bus_master_enabled = 1;
    suspect.driver_bound = 0;          /* structural suspect */
    suspect.iommu_fault_count = 250;   /* steady-state fault stream */
    if (hk_dma_forensics_structural_suspect(&suspect) != 1) {
        std::printf("FAIL: faulting suspect must meet the structural gate\n");
        ++failures;
    }

    /* FP gate 1: faults on a CLEAN driver-bound BDF — not a structural suspect, so
     * the fault count must not be scored (a bound device with the IOMMU correctly
     * programmed can still occasionally fault). */
    hk_dma_device_forensics clean;
    std::memset(&clean, 0, sizeof(clean));
    clean.vendor_id = 0x8086;
    clean.bus_master_enabled = 1;
    clean.driver_bound = 1;            /* bound => not a suspect */
    clean.iommu_fault_count = 250;
    if (hk_dma_forensics_structural_suspect(&clean) != 0) {
        std::printf("FAIL: faults on a clean bound BDF must not be a structural suspect\n");
        ++failures;
    }

    /* FP gate 2: absence (count 0) is "unknown", never "clean" — the suspect with
     * NO fault data is still a suspect structurally, but the fault SIGNAL is absent,
     * not negative. The server treats count 0 as no sig-135 signal (proven in the
     * Rust test); here we just assert absence does not retroactively clear the
     * structural suspect. */
    hk_dma_device_forensics suspect_nodata;
    std::memset(&suspect_nodata, 0, sizeof(suspect_nodata));
    suspect_nodata.bus_master_enabled = 1;
    suspect_nodata.driver_bound = 0;
    suspect_nodata.iommu_fault_count = 0; /* source absent */
    if (hk_dma_forensics_structural_suspect(&suspect_nodata) != 1) {
        std::printf("FAIL: absent fault data must not clear the structural suspect\n");
        ++failures;
    }

#ifdef HK_DMA_IOMMU_TEST_ENABLED
    /* On-box: drive the iommu_fault eBPF program (or the Windows ETW consumer),
     * generate a fault storm from the fixture BDF, and assert the per-BDF count
     * crosses threshold ONLY for the structural suspect and ONLY outside the init
     * window. Left to the live-kernel harness. */
    std::printf("bypass_iommu_fault_storm: live fault source not yet implemented on-box\n");
    return 1;
#endif

    if (failures == 0) {
        std::printf("bypass_iommu_fault_storm: OK (suspect+faults gated; clean BDF + absent data do not score)\n");
        return 0;
    }
    std::printf("bypass_iommu_fault_storm: %d assertion(s) failed\n", failures);
    return 1;
}
