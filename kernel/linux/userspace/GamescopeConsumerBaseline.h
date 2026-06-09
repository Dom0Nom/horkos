/*
 * kernel/linux/userspace/GamescopeConsumerBaseline.h
 * Role: Signal 106 baseliner — classify a frame-consumer record (a Wayland
 *       connect to the gamescope socket, or a DRM lease/PRIME import) against the
 *       allowlist of legitimate consumers: gamescope itself, the pipewire/
 *       xdg-desktop-portal capture chain, Steam streaming PIDs, the screenshot-key
 *       path. HIGH FP — produces only the OFF_ALLOWLIST flag for a LOW-WEIGHT
 *       server corroborator; never a standalone decision.
 * Target platform: Linux userspace.
 * Interface: ClassifyConsumer() returns the HK_PW_FRAME_* bitmask (kernel flags
 *            enriched with OFF_ALLOWLIST). Allowlisted tgids are injected.
 */

#pragma once

#include <cstdint>
#include <unordered_set>

namespace horkos::framecons {

/* HK_PW_FRAME_* bits (mirror hk_bpf_shared.h / event_schema.h). */
inline constexpr uint32_t kFrameWayland     = 0x1u;
inline constexpr uint32_t kFrameDrmLease    = 0x2u;
inline constexpr uint32_t kFramePrime       = 0x4u;
inline constexpr uint32_t kFrameOffAllowlist = 0x8u;

class GamescopeConsumerBaseline {
public:
    /* @allowed_tgids: gamescope/pipewire/portal/Steam-stream/screenshot tgids
     *   resolved at session start. */
    explicit GamescopeConsumerBaseline(std::unordered_set<uint32_t> allowed_tgids)
        : allowed_tgids_(std::move(allowed_tgids)) {}

    /* Classify a consumer record. `kernel_flags` carries WAYLAND/DRM_LEASE/PRIME.
     * Returns the enriched bitmask: an off-allowlist consumer_tgid adds
     * OFF_ALLOWLIST; an allowlisted one does not (suppressed). The record is ALWAYS
     * emitted (the server weights it low) — this only sets the report flag. */
    uint32_t ClassifyConsumer(uint32_t consumer_tgid, uint32_t kernel_flags) const;

private:
    std::unordered_set<uint32_t> allowed_tgids_;
};

}  // namespace horkos::framecons
