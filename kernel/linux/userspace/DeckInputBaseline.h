/*
 * kernel/linux/userspace/DeckInputBaseline.h
 * Role: Signal 108 baseliner — classify a synthetic-input record (uinput create
 *       or evdev inject) against the Steam-Input/hid-steam/gamescope-libinput tgid
 *       baseline and the pre-focus uinput allowlist. HIGH FP — only a uinput
 *       device created MID-SESSION by a non-allowlisted tgid driving game-relevant
 *       EV codes is reportable, as a weighted server-correlated signal.
 * Target platform: Linux userspace.
 * Interface: ClassifyInput() returns the HK_PW_SYNTH_* bitmask. The allowlisted
 *            tgids and the session-start time are injected.
 */

#pragma once

#include <cstdint>
#include <unordered_set>

namespace horkos::deckinput {

/* HK_PW_SYNTH_* bits (mirror hk_bpf_shared.h / event_schema.h). */
inline constexpr uint32_t kSynthUinputCreate = 0x1u;
inline constexpr uint32_t kSynthInject       = 0x2u;
inline constexpr uint32_t kSynthMidSession   = 0x4u;
inline constexpr uint32_t kSynthOffAllowlist = 0x8u;

class DeckInputBaseline {
public:
    /* @allowed_tgids: Steam Input / hid-steam / gamescope-libinput tgids resolved
     *   at session start (pre-focus uinput allowlist).
     * @session_start_ns: the in-game session start; a uinput create after this is
     *   mid-session. */
    DeckInputBaseline(std::unordered_set<uint32_t> allowed_tgids,
                      uint64_t session_start_ns)
        : allowed_tgids_(std::move(allowed_tgids)),
          session_start_ns_(session_start_ns) {}

    /* Classify a synthetic-input record. `kernel_flags` carries UINPUT_CREATE
     * and/or INJECT from the BPF side. Returns the enriched HK_PW_SYNTH_* bitmask:
     *   - allowlisted injector_tgid -> kernel_flags unchanged (suppressed)
     *   - off-allowlist -> OFF_ALLOWLIST, plus MID_SESSION if the create/inject
     *     happened after session start. Steam Input's own pre-focus uinput device
     *     (allowlisted) does not flag. The record is always emitted (low weight). */
    uint32_t ClassifyInput(uint32_t injector_tgid, uint32_t kernel_flags,
                           uint64_t event_time_ns) const;

private:
    std::unordered_set<uint32_t> allowed_tgids_;
    uint64_t session_start_ns_;
};

}  // namespace horkos::deckinput
