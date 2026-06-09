/*
 * bypass-tests/dma_hardware/bypass_msix_overflow.cpp
 * Role: DMA-hardware bypass-test fixture (merge gate, guardrail #12) for catalog
 *       signal 129 (MSI-X containment). Demonstrates: an MSI-X Table offset+size that
 *       exceeds the referenced BAR's decoded length fires the hard-containment
 *       violation; AND that a VALID 64-bit-BAR layout (whose containment is only OK
 *       once the high dword is combined) does NOT fire — the catalog's named FP
 *       source (the load-bearing assertion).
 * Target platforms: all (host-runnable; exercises the real
 *       hk_dma_msix_containment_violation helper from forensics_report.cpp).
 * Interface: drives the shared BAR-sizing containment helper.
 */

#include <cstdio>
#include "forensics_helpers.h"

int main(void) {
    int failures = 0;

    /* Each MSI-X entry is 16 bytes; PBA is 1 bit/entry. */

    /* Violation: 64 entries (1024 bytes of table) at offset 0x1000 into a BAR that
     * is only 0x800 long. table_offset alone already exceeds bar_len. */
    if (hk_dma_msix_containment_violation(/*table_bar_len=*/0x800, /*table_offset=*/0x1000,
                                          /*pba_bar_len=*/0x800, /*pba_offset=*/0x0,
                                          /*entries=*/64) != 1) {
        std::printf("FAIL: offset-beyond-BAR not flagged\n");
        ++failures;
    }

    /* Violation: offset fits but table span overflows. 64 entries = 1024 bytes; at
     * offset 0x400 into a 0x800 BAR, 0x400 + 0x400 = 0x800 fits exactly (NOT a
     * violation), but 65 entries (1040 bytes) overflows. */
    if (hk_dma_msix_containment_violation(0x800, 0x400, 0x800, 0x0, 64) != 0) {
        std::printf("FAIL: exact-fit table wrongly flagged\n");
        ++failures;
    }
    if (hk_dma_msix_containment_violation(0x800, 0x400, 0x800, 0x0, 65) != 1) {
        std::printf("FAIL: span overflow not flagged\n");
        ++failures;
    }

    /* FP gate (the catalog's named false positive): a 64-bit BAR whose true length
     * is 0x1_0000_0000 (4 GiB, high dword combined). A table at offset 0x2_0000 with
     * 2048 entries (0x8000 bytes) is well inside. If a caller mistakenly used only
     * the low 32-bit BAR view (length 0), they'd "overflow"; the helper is given the
     * reconstructed 64-bit length and must NOT flag. */
    if (hk_dma_msix_containment_violation(0x1'0000'0000ull, 0x2'0000ull,
                                          0x1'0000'0000ull, 0x3'0000ull,
                                          2048) != 0) {
        std::printf("FAIL: valid 64-bit-BAR layout wrongly flagged (FP gate broken)\n");
        ++failures;
    }

    /* Undecodable BAR (len 0) must never assert (unknown != violation). */
    if (hk_dma_msix_containment_violation(0, 0x10000, 0, 0x10000, 256) != 0) {
        std::printf("FAIL: undecodable BAR must not assert containment violation\n");
        ++failures;
    }

    if (failures == 0) {
        std::printf("bypass_msix_overflow: OK (overflow flagged; valid 64-bit BAR + undecodable BAR do not)\n");
        return 0;
    }
    std::printf("bypass_msix_overflow: %d assertion(s) failed\n", failures);
    return 1;
}
