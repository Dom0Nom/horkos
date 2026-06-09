/*
 * kernel/linux/userspace/DeckRootfsBaseline.h
 * Role: Signal 105 baseliner — classify a rootfs-RW record against the immutable-
 *       distro gate (os-release), the /proc/mounts RO baseline, and the SteamOS
 *       update window (frzr/rauc). On a desktop distro with a normally-RW root the
 *       signal is suppressed entirely; on SteamOS a remount-rw / protected-write
 *       outside an update window is the breach.
 * Target platform: Linux userspace.
 * Interface: ClassifyRootfsRw() returns the HK_PW_ROOTFS_* bitmask. The immutable-
 *            distro boolean and update-window predicate are injected.
 */

#pragma once

#include <cstdint>
#include <functional>

namespace horkos::deckrootfs {

/* HK_PW_ROOTFS_* bits (mirror hk_bpf_shared.h / event_schema.h). */
inline constexpr uint32_t kRootfsRemountRw       = 0x1u;
inline constexpr uint32_t kRootfsProtectedWrite  = 0x2u;
inline constexpr uint32_t kRootfsUpdateWindow    = 0x4u;
inline constexpr uint32_t kRootfsImmutableDistro = 0x8u;

using UpdateWindowFn = std::function<bool(uint64_t /*event_time_ns*/)>;

class DeckRootfsBaseline {
public:
    /* @immutable_distro: true iff os-release identifies an immutable rootfs
     *   (SteamOS/Bazzite/Silverblue). When false the signal is suppressed.
     * @in_update_window: frzr/rauc update-window predicate. */
    DeckRootfsBaseline(bool immutable_distro, UpdateWindowFn in_update_window)
        : immutable_distro_(immutable_distro),
          in_update_window_(std::move(in_update_window)) {}

    /* Classify a rootfs-RW record. `kernel_flags` carries REMOUNT_RW (and/or
     * PROTECTED_WRITE once the file_open arm lands) from the BPF side. Returns the
     * enriched HK_PW_ROOTFS_* bitmask:
     *   - not an immutable distro -> 0 (desktop RW root is normal; suppressed)
     *   - immutable distro: set IMMUTABLE_DISTRO; if in an update window set
     *     UPDATE_WINDOW (legitimate); otherwise the kernel_flags (REMOUNT_RW /
     *     PROTECTED_WRITE) stand as the breach evidence. */
    uint32_t ClassifyRootfsRw(uint32_t kernel_flags, uint64_t event_time_ns) const;

private:
    bool immutable_distro_;
    UpdateWindowFn in_update_window_;
};

}  // namespace horkos::deckrootfs
