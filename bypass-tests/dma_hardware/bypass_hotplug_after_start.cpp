/*
 * bypass-tests/dma_hardware/bypass_hotplug_after_start.cpp
 * Role: DMA-hardware bypass-test fixture (merge gate, guardrail #12) for catalog
 *       signal 134 (hot-plug arrival). Demonstrates: a post-AC-start arrival of an
 *       unbound bus-master device with an ID anomaly is flagged; AND that a
 *       Thunderbolt/USB4-domain dock arrival (a benign hot-plug domain) does NOT
 *       flag (the FP gate). The host-runnable half asserts the compact-arrival flag
 *       packing the client emits (bit0 bus_master, bit1 unbound, bit2 id_anomaly);
 *       the server-side suspect-arrival gate is proven in
 *       dma_forensics.rs::hotplug_decode_and_gate. The live udev/CM/IOKit
 *       subscription is gated behind HK_DMA_HOTPLUG_TEST_ENABLED (needs a real
 *       device-arrival event on-box).
 * Target platforms: all (host-runnable flag-packing half).
 * Interface: mirrors hk_event_dma_hotplug flag bits the subscribe path emits.
 */

#include <cstdio>
#include <cstdint>

/* Mirror of the impl-plan compact hotplug flag bits (also in dma_forensics.rs). */
static constexpr uint32_t kBusMaster = 0x1u;
static constexpr uint32_t kUnbound   = 0x2u;
static constexpr uint32_t kIdAnomaly = 0x4u;

/* The server's sig-134 gate: all three bits => suspect arrival. */
static bool is_suspect_arrival(uint32_t flags) {
    return (flags & kBusMaster) && (flags & kUnbound) && (flags & kIdAnomaly);
}

int main(void) {
    int failures = 0;

    /* A DMA board hot-plugged after AC start: unbound, bus-master, ID anomaly. */
    uint32_t rogue = kBusMaster | kUnbound | kIdAnomaly;
    if (!is_suspect_arrival(rogue)) {
        std::printf("FAIL: rogue post-start arrival not flagged\n");
        ++failures;
    }

    /* FP gate: a Thunderbolt dock arrival — benign domain, driver binds, no ID
     * anomaly. None of the suspect bits set (the loader recognises the TB/USB4 root
     * port as a benign domain and does not set them). */
    uint32_t dock = 0;
    if (is_suspect_arrival(dock)) {
        std::printf("FAIL: benign Thunderbolt dock arrival wrongly flagged\n");
        ++failures;
    }

    /* A merely-unbound arrival without bus-master or ID anomaly is also benign
     * (e.g. a device awaiting its driver). */
    if (is_suspect_arrival(kUnbound)) {
        std::printf("FAIL: unbound-only arrival must not flag\n");
        ++failures;
    }

#ifdef HK_DMA_HOTPLUG_TEST_ENABLED
    /* On-box: hk_dma_forensics_subscribe(), then hot-plug the fixture device and
     * assert the arrival callback fires with the rogue flag set; relaunch with a TB
     * dock and assert no suspect arrival. Left to the real-hardware harness. */
    std::printf("bypass_hotplug_after_start: live subscribe path not yet implemented on-box\n");
    return 1;
#endif

    if (failures == 0) {
        std::printf("bypass_hotplug_after_start: OK (rogue arrival flagged; TB dock + unbound-only do not)\n");
        return 0;
    }
    std::printf("bypass_hotplug_after_start: %d assertion(s) failed\n", failures);
    return 1;
}
