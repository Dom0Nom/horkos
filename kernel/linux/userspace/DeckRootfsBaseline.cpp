/*
 * Role: Implementation of the signal-105 Deck rootfs baseliner declared in
 *       DeckRootfsBaseline.h. The immutable-distro gate is the load-bearing FP
 *       control: a desktop distro's RW root must NOT flag; a SteamOS RO->RW
 *       outside an update window is the breach.
 * Target platform: Linux userspace.
 * Interface: implements horkos::deckrootfs.
 *
 * Guardrail compliance: #1, #3, #4 (no BPF headers).
 */

#include "DeckRootfsBaseline.h"

namespace horkos::deckrootfs {

uint32_t DeckRootfsBaseline::ClassifyRootfsRw(uint32_t kernel_flags,
                                              uint64_t event_time_ns) const {
    /* Desktop distros have a normally-RW root: the whole signal is suppressed. */
    if (!immutable_distro_)
        return 0;

    uint32_t flags = kernel_flags | kRootfsImmutableDistro;

    /* A frzr/rauc update legitimately makes the root RW: tag it so the server
     * treats it as an OS update, not a cheat. The REMOUNT_RW/PROTECTED_WRITE
     * evidence from the kernel still rides along for correlation. */
    if (in_update_window_ && in_update_window_(event_time_ns))
        flags |= kRootfsUpdateWindow;

    return flags;
}

}  // namespace horkos::deckrootfs
