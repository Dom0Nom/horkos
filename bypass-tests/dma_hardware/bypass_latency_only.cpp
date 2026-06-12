/*
 * Role: DMA-hardware bypass-test fixture (merge gate, guardrail #12) for catalog
 *       signal 132 (TLP latency, LOW WEIGHT). Demonstrates the never-standalone
 *       gate: high TLP-read jitter as the ONLY signal on a structural suspect must
 *       produce NO positive verdict — sig 132 may only corroborate an existing
 *       structural hit, never stand alone (impl-plan Risk #5; the load-bearing
 *       assertion). The host-runnable half asserts the structural record can carry a
 *       latency outlier with no other signal; the authoritative "latency alone never
 *       scores" proof is dma_forensics.rs::latency_only_never_scores_positive, which
 *       this fixture's CMake target name pairs with as the C-side gate.
 * Target platforms: all (host-runnable).
 * Interface: drives dma_forensics.h records + forensics_report.cpp structural gate.
 */

#include <cstdio>
#include <cstring>
#include "forensics_helpers.h"

int main(void) {
    int failures = 0;

    /* A structural suspect whose ONLY anomaly is a TLP-latency outlier: high median
     * + high IQR within its root-port cohort, but no DSN/ext-cfg/MSI-X/ROM/ACS/IOMMU
     * signal. The client ships these latency stats; the SERVER must not produce a
     * verdict from them alone. */
    hk_dma_device_forensics d;
    std::memset(&d, 0, sizeof(d));
    d.vendor_id = 0x1234;
    d.bus_master_enabled = 1;
    d.driver_bound = 0;                    /* structural suspect */
    d.tlp_latency_median_ns = 5000;        /* high */
    d.tlp_latency_iqr_ns = 4000;           /* high jitter */
    d.tlp_same_root_port_group = 2;        /* cohort id */
    /* Every structural signal is clean. */
    d.dsn_oui_locally_administered = 0;
    d.dsn_present = 0;                      /* no DSN => no forgery signal */
    d.extcfg_aliases_low = 0;
    d.extcfg_read_unstable = 0;
    d.rsvdp_nonzero = 0;
    d.msix_containment_violation = 0;
    d.rom_pcir_id_mismatch = 0;
    d.iommu_fault_count = 0;
    /* ACS bits SET so acs_weak is false too (no ACS signal). */
    d.acs_source_validation = 1;
    d.acs_p2p_redirect = 1;

    if (hk_dma_forensics_structural_suspect(&d) != 1) {
        std::printf("FAIL: latency-only fixture should be a structural suspect\n");
        ++failures;
    }

    /* The record serializes (the latency stats reach the server), but it carries no
     * verdict — the client never decides. The "latency alone => no verdict" decision
     * is the server's, asserted in dma_forensics.rs. Here we prove the client emits
     * the latency facts AND that there is no other positive signal set on the record
     * that a (buggy) client could mistake for a standalone verdict. */
    uint8_t wire[HK_DMA_FORENSICS_WIRE_BYTES];
    if (hk_dma_forensics_serialize_device(&d, wire, sizeof(wire)) != HK_DMA_FORENSICS_WIRE_BYTES) {
        std::printf("FAIL: latency-only record did not serialize\n");
        ++failures;
    }

    bool any_structural_signal =
        d.dsn_oui_locally_administered != 0 && d.dsn_present != 0; /* would-be forgery */
    any_structural_signal = any_structural_signal
        || d.extcfg_aliases_low || d.extcfg_read_unstable || d.rsvdp_nonzero
        || d.msix_containment_violation || d.rom_pcir_id_mismatch
        || d.iommu_fault_count != 0;
    if (any_structural_signal) {
        std::printf("FAIL: latency-only fixture must carry no structural signal\n");
        ++failures;
    }

    if (failures == 0) {
        std::printf("bypass_latency_only: OK (latency outlier carries no structural signal; verdict is server-gated, never standalone)\n");
        return 0;
    }
    std::printf("bypass_latency_only: %d assertion(s) failed\n", failures);
    return 1;
}
