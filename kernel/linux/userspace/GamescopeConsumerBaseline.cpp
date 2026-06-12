/*
 * Role: Implementation of the signal-106 compositor-consumer baseliner declared
 *       in GamescopeConsumerBaseline.h. The allowlist (gamescope/pipewire/portal/
 *       Steam-stream) is the FP gate; OBS-via-portal and Steam Remote Play must
 *       NOT be flagged off-allowlist. Emits only a low-weight corroborator flag.
 * Target platform: Linux userspace.
 * Interface: implements horkos::framecons.
 *
 * Guardrail compliance: #1, #3, #4 (no BPF headers).
 */

#include "GamescopeConsumerBaseline.h"

namespace horkos::framecons {

uint32_t GamescopeConsumerBaseline::ClassifyConsumer(uint32_t consumer_tgid,
                                                     uint32_t kernel_flags) const {
    uint32_t flags = kernel_flags;
    if (allowed_tgids_.count(consumer_tgid) == 0)
        flags |= kFrameOffAllowlist;
    return flags;
}

}  // namespace horkos::framecons
