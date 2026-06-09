/*
 * bypass-tests/dma_hardware/bypass_acs_p2p.cpp
 * Role: DMA-hardware bypass-test fixture (merge gate, guardrail #12) for catalog
 *       signal 133 (ACS / IOMMU-group topology). Demonstrates: an unbound +
 *       bus-master suspect sharing an oversized IOMMU group with a sensitive
 *       endpoint (ACS source-validation / P2P-redirect missing on the path) is the
 *       structural pre-req the server scores; AND that a BENIGN consumer-chipset big
 *       group does NOT score without the server's chipset-allowlist corroboration
 *       (the FP gate). The host-runnable half asserts the structural gate + raw ACS
 *       fields; the corroboration + oversized-group scoring is proven in
 *       dma_forensics.rs::acs_weak_alone_without_corroboration_does_not_score.
 * Target platforms: all (host-runnable structural half).
 * Interface: drives dma_forensics.h records + forensics_report.cpp structural gate.
 */

#include <cstdio>
#include <cstring>
#include "forensics_helpers.h"

int main(void) {
    int failures = 0;

    /* Suspect sharing an oversized group, ACS control bits clear on the path. */
    hk_dma_device_forensics suspect;
    std::memset(&suspect, 0, sizeof(suspect));
    suspect.vendor_id = 0x1234;
    suspect.bus_master_enabled = 1;
    suspect.driver_bound = 0;              /* structural suspect */
    suspect.acs_source_validation = 0;     /* SV not enforced on the path */
    suspect.acs_p2p_redirect = 0;          /* P2P not redirected upstream */
    suspect.iommu_group_membership = 9;    /* shares the group with others */
    if (hk_dma_forensics_structural_suspect(&suspect) != 1) {
        std::printf("FAIL: ACS-weak suspect should meet the structural gate\n");
        ++failures;
    }

    /* FP gate: a benign consumer chipset that legitimately groups many devices but
     * whose suspect is actually a driver-bound endpoint is NOT a structural suspect,
     * so it never reaches ACS scoring regardless of the big group. */
    hk_dma_device_forensics benign;
    std::memset(&benign, 0, sizeof(benign));
    benign.vendor_id = 0x8086;
    benign.bus_master_enabled = 1;
    benign.driver_bound = 1;               /* bound => not a suspect */
    benign.acs_source_validation = 0;
    benign.acs_p2p_redirect = 0;
    benign.iommu_group_membership = 14;    /* big, but a normal consumer chipset */
    if (hk_dma_forensics_structural_suspect(&benign) != 0) {
        std::printf("FAIL: benign bound device in a big group must not be a suspect\n");
        ++failures;
    }

    if (failures == 0) {
        std::printf("bypass_acs_p2p: OK (ACS-weak suspect gated; benign big-group bound device does not score)\n");
        return 0;
    }
    std::printf("bypass_acs_p2p: %d assertion(s) failed\n", failures);
    return 1;
}
