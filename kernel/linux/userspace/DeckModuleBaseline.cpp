/*
 * Role: Implementation of the signal-104 Deck module baseliner declared in
 *       DeckModuleBaseline.h. Distinguishes a post-boot BYOVD cheat module from a
 *       legitimate hotplug (xpad/hid-*) or an OS update-window load — the
 *       load-bearing FP gate the bypass test asserts.
 * Target platform: Linux userspace.
 * Interface: implements horkos::deckmod.
 *
 * Guardrail compliance: #1, #3, #4 (no BPF headers).
 */

#include "DeckModuleBaseline.h"

namespace horkos::deckmod {

uint32_t DeckModuleBaseline::ClassifyModuleLoad(uint64_t module_name_hash,
                                                uint64_t event_time_ns) const {
    /* Present at boot — not a post-boot load. */
    if (boot_modules_.count(module_name_hash) != 0)
        return 0;

    uint32_t flags = kModPostBoot;

    bool hotplug = signed_hotplug_.count(module_name_hash) != 0;
    bool update  = in_update_window_ && in_update_window_(event_time_ns);

    if (hotplug)
        flags |= kModHotplug;
    if (update)
        flags |= kModUpdateWindow;

    /* The cheat shape: a post-boot load that is neither an allowed hotplug nor an
     * OS update. Both legitimate cases are flagged distinctly (not as cheats);
     * OFF_BASELINE is reserved for the genuinely unexplained module. */
    if (!hotplug && !update)
        flags |= kModOffBaseline;

    return flags;
}

}  // namespace horkos::deckmod
