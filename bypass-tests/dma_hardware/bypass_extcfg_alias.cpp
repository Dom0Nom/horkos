/*
 * bypass-tests/dma_hardware/bypass_extcfg_alias.cpp
 * Role: DMA-hardware bypass-test fixture (merge gate, guardrail #12) for catalog
 *       signal 128 (ext-config stability / aliasing). Demonstrates: an FPGA-style
 *       "shadow config" that backs extended config (0x100+) with the same memory as
 *       legacy config (so 0x100..0x1FF mirrors 0x000..0x0FF) is detected; AND that a
 *       device whose extended space is independent (a real quirk-listed bridge) does
 *       NOT trip the aliasing detector (the FP gate — load-bearing assertion).
 * Target platforms: all (host-runnable; exercises the real
 *       hk_dma_extcfg_aliases_low helper from forensics_report.cpp).
 * Interface: drives forensics_report.cpp helper over a synthetic 4KB config image.
 */

#include <cstdio>
#include <cstring>
#include "forensics_helpers.h"

int main(void) {
    int failures = 0;

    /* 4KB config image. Fill legacy 0x000..0x0FF with a recognizable pattern. */
    uint8_t cfg[0x1000];
    std::memset(cfg, 0, sizeof(cfg));
    for (int i = 0; i < 0x100; ++i) {
        cfg[i] = static_cast<uint8_t>((i * 7 + 3) & 0xFF);
    }

    /* FPGA shadow: ext space first 256 bytes mirror legacy. DETECTION must fire. */
    std::memcpy(cfg + 0x100, cfg, 0x100);
    if (hk_dma_extcfg_aliases_low(cfg, sizeof(cfg)) != 1) {
        std::printf("FAIL: aliasing not detected on mirrored shadow config\n");
        ++failures;
    }

    /* Real device: independent ext-cap structures at 0x100+. FP gate: NO alias. */
    for (int i = 0; i < 0x100; ++i) {
        cfg[0x100 + i] = static_cast<uint8_t>((i * 13 + 1) & 0xFF);
    }
    /* Make sure at least one byte differs (it does by construction). */
    if (hk_dma_extcfg_aliases_low(cfg, sizeof(cfg)) != 0) {
        std::printf("FAIL: independent ext config wrongly flagged as aliasing\n");
        ++failures;
    }

    /* Too-short buffer must never assert (cannot-read != detected). */
    if (hk_dma_extcfg_aliases_low(cfg, 0x80) != 0) {
        std::printf("FAIL: short buffer must not assert aliasing\n");
        ++failures;
    }

    if (failures == 0) {
        std::printf("bypass_extcfg_alias: OK (shadow-alias detected; independent ext config + short buf do not trip)\n");
        return 0;
    }
    std::printf("bypass_extcfg_alias: %d assertion(s) failed\n", failures);
    return 1;
}
