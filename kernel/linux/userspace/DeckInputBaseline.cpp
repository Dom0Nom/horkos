/*
 * kernel/linux/userspace/DeckInputBaseline.cpp
 * Role: Implementation of the signal-108 Deck synthetic-input baseliner declared
 *       in DeckInputBaseline.h. The allowlist + mid-session gate is the
 *       load-bearing FP control: Steam Input's own pre-focus uinput device
 *       (allowlisted) must NOT flag; only a mid-session uinput create/inject by a
 *       non-allowlisted tgid is reportable, as a low-weight server-correlated
 *       signal (the kernel record is always emitted; this only enriches flags).
 * Target platform: Linux userspace.
 * Interface: implements horkos::deckinput.
 *
 * Guardrail compliance: #1, #3, #4 (no BPF headers).
 */

#include "DeckInputBaseline.h"

namespace horkos::deckinput {

uint32_t DeckInputBaseline::ClassifyInput(uint32_t injector_tgid,
                                          uint32_t kernel_flags,
                                          uint64_t event_time_ns) const {
    /* Steam Input / hid-steam / gamescope-libinput: their uinput device is
     * created pre-focus and is on the allowlist. Suppress (kernel evidence is
     * not promoted to an off-allowlist verdict). The record still rides along to
     * the server with only the kernel UINPUT_CREATE/INJECT bits. */
    if (allowed_tgids_.count(injector_tgid) != 0)
        return kernel_flags;

    uint32_t flags = kernel_flags | kSynthOffAllowlist;

    /* A create/inject after the in-game session started is mid-session — the
     * macro/cheat shape (Steam Input's device predates focus). A pre-session
     * off-allowlist device (e.g. a remapper started at boot) is off-allowlist but
     * not mid-session, a weaker signal the server weighs accordingly. */
    if (event_time_ns >= session_start_ns_)
        flags |= kSynthMidSession;

    return flags;
}

}  // namespace horkos::deckinput
