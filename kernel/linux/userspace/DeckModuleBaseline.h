/*
 * kernel/linux/userspace/DeckModuleBaseline.h
 * Role: Signal 104 baseliner — classify a module-load record against the boot
 *       /proc/modules snapshot, the SteamOS signed-module hash set, the hotplug
 *       allowlist (usb-storage/xpad/hid-*), and the SteamOS update window. Gates
 *       the post-boot / off-baseline / hotplug / update-window flags so the
 *       server distinguishes a BYOVD cheat module from a legitimate hotplug or an
 *       OS update.
 * Target platform: Linux userspace.
 * Interface: ClassifyModuleLoad() returns the HK_PW_MOD_* bitmask. Boot snapshot,
 *            signed set, hotplug set and update-window predicate are injected.
 */

#pragma once

#include <cstdint>
#include <functional>
#include <unordered_set>

namespace horkos::deckmod {

/* HK_PW_MOD_* bits (mirror hk_bpf_shared.h / event_schema.h). */
inline constexpr uint32_t kModPostBoot     = 0x1u;
inline constexpr uint32_t kModOffBaseline  = 0x2u;
inline constexpr uint32_t kModHotplug      = 0x4u;
inline constexpr uint32_t kModUpdateWindow = 0x8u;

/* Predicate: was the OS in a frzr/rauc update window at time_ns? Injected. */
using UpdateWindowFn = std::function<bool(uint64_t /*event_time_ns*/)>;

class DeckModuleBaseline {
public:
    /* @boot_modules: FNV64 name-hashes present at client start (/proc/modules).
     * @signed_hotplug: FNV64 name-hashes of the allowed hotplug set (xpad/hid-*).
     * @in_update_window: update-window predicate. */
    DeckModuleBaseline(std::unordered_set<uint64_t> boot_modules,
                       std::unordered_set<uint64_t> signed_hotplug,
                       UpdateWindowFn in_update_window)
        : boot_modules_(std::move(boot_modules)),
          signed_hotplug_(std::move(signed_hotplug)),
          in_update_window_(std::move(in_update_window)) {}

    /* Classify a module load by its FNV64 name-hash + load time. Returns the
     * HK_PW_MOD_* bitmask:
     *   - name-hash in the boot snapshot -> 0 (was already loaded at boot)
     *   - else POST_BOOT, plus:
     *       HOTPLUG       if the name-hash is in the signed hotplug set
     *       UPDATE_WINDOW if loaded during a frzr/rauc update window
     *       OFF_BASELINE  if neither hotplug nor update-window (the cheat shape) */
    uint32_t ClassifyModuleLoad(uint64_t module_name_hash,
                                uint64_t event_time_ns) const;

private:
    std::unordered_set<uint64_t> boot_modules_;
    std::unordered_set<uint64_t> signed_hotplug_;
    UpdateWindowFn in_update_window_;
};

}  // namespace horkos::deckmod
