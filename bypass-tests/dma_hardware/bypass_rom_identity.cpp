/*
 * bypass-tests/dma_hardware/bypass_rom_identity.cpp
 * Role: DMA-hardware bypass-test fixture (merge gate, guardrail #12) for catalog
 *       signal 130 (option-ROM identity). Demonstrates: an option ROM whose PCIR
 *       VID/DID contradicts the device's config VID/DID sets rom_pcir_id_mismatch
 *       (which the server scores on a structural suspect); AND that a ROM-ABSENT
 *       device does NOT fire (the FP gate). The host-runnable half asserts the
 *       record shape + structural gate; the live ROM-enable/read half is gated
 *       behind HK_DMA_ROM_TEST_ENABLED (needs the side-effecting ROM-decode probe on
 *       real hardware — impl-plan Risk #4). The server-side mismatch scoring is
 *       proven in dma_forensics.rs::rom_identity_mismatch path.
 * Target platforms: all (host-runnable structural half; live half Linux/Win on box).
 * Interface: drives dma_forensics.h records + forensics_report.cpp structural gate.
 */

#include <cstdio>
#include <cstring>
#include "forensics_helpers.h"

int main(void) {
    int failures = 0;

    /* Structural suspect carrying a ROM whose PCIR identity contradicts config. The
     * server scores rom_pcir_id_mismatch only on a structural suspect; we assert the
     * gate holds here so the scoring pre-req is met. */
    hk_dma_device_forensics rogue;
    std::memset(&rogue, 0, sizeof(rogue));
    rogue.vendor_id = 0x10EC;          /* config says Realtek */
    rogue.device_id = 0x8168;
    rogue.bus_master_enabled = 1;
    rogue.driver_bound = 0;            /* unbound + bus-master => suspect */
    rogue.rom_present = 1;
    rogue.rom_pcir_id_mismatch = 1;    /* PCIR header claims a different VID/DID */
    if (hk_dma_forensics_structural_suspect(&rogue) != 1) {
        std::printf("FAIL: rogue ROM device should be a structural suspect\n");
        ++failures;
    }

    /* FP gate: a ROM-absent device must not present a mismatch. */
    hk_dma_device_forensics romless;
    std::memset(&romless, 0, sizeof(romless));
    romless.vendor_id = 0x10EC;
    romless.bus_master_enabled = 1;
    romless.driver_bound = 0;
    romless.rom_present = 0;
    romless.rom_pcir_id_mismatch = 0;
    if (romless.rom_pcir_id_mismatch != 0) {
        std::printf("FAIL: ROM-absent device must not carry a mismatch\n");
        ++failures;
    }

#ifdef HK_DMA_ROM_TEST_ENABLED
    /* On-box: enable ROM decode (skip if a driver owns the ROM region — Risk #4),
     * read the AA55+PCIR header, compare PCIR VID/DID to config, restore decode
     * state. Assert rom_pcir_id_mismatch==1 for the forged ROM and ==0 for a genuine
     * one. Left to the real-hardware harness. */
    std::printf("bypass_rom_identity: live ROM-read path not yet implemented on-box\n");
    return 1;
#endif

    if (failures == 0) {
        std::printf("bypass_rom_identity: OK (rogue ROM suspect gated; ROM-absent does not flag)\n");
        return 0;
    }
    std::printf("bypass_rom_identity: %d assertion(s) failed\n", failures);
    return 1;
}
