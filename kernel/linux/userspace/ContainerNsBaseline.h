/*
 * Role: Signal 103 baseliner — resolve the pressure-vessel (pv-bwrap/bwrap)
 *       launcher PID lineage and the game-container ns inodes, then classify a
 *       setns record (caller_tgid joining a target ns inode) as anomalous. A
 *       setns into the game's namespaces whose caller is NOT a descendant of the
 *       recorded launcher chain is OFF_LINEAGE; a manual dev `nsenter` is a
 *       reported (not banned) exception.
 * Target platform: Linux userspace.
 * Interface: ClassifyNsEntry() returns the HK_PW_NS_FLAG_* bitmask. The process-
 *            tree (pid->ppid) and the launcher-lineage set are injected so the
 *            classifier is host-testable without /proc.
 */

#pragma once

#include <cstdint>
#include <functional>
#include <unordered_set>

namespace horkos::containerns {

/* HK_PW_NS_FLAG_* bits (mirror hk_bpf_shared.h / event_schema.h). */
inline constexpr uint32_t kNsFlagOffLineage = 0x1u;
inline constexpr uint32_t kNsFlagDevNsenter = 0x2u;

/* ppid lookup seam: maps a pid to its parent pid, 0 if pid 1 / unknown. In
 * production this walks /proc/<pid>/stat; tests inject a map. */
using PpidFn = std::function<uint32_t(uint32_t)>;

class ContainerNsBaseline {
public:
    /* @launcher_pids: the recorded pv-bwrap/bwrap launcher PID set (the roots of
     *   the legitimate container lineage).
     * @game_ns_inodes: the baselined game-container ns inodes (mnt/pid/user).
     * @ppid: parent-pid lookup. */
    ContainerNsBaseline(std::unordered_set<uint32_t> launcher_pids,
                        std::unordered_set<uint64_t> game_ns_inodes,
                        PpidFn ppid)
        : launcher_pids_(std::move(launcher_pids)),
          game_ns_inodes_(std::move(game_ns_inodes)),
          ppid_(std::move(ppid)) {}

    /* Walk caller_tgid's parent chain; true if any ancestor (or itself) is a
     * recorded launcher PID. Bounded to kMaxAncestorWalk hops to avoid a cycle. */
    bool IsDescendantOfLauncher(uint32_t caller_tgid) const;

    /* Classify a setns record. Returns the HK_PW_NS_FLAG_* bitmask:
     *   - target ns inode not a game ns -> 0 (out of scope, not the game)
     *   - caller in the launcher lineage -> 0 (pressure-vessel's own setns)
     *   - caller off-lineage -> OFF_LINEAGE (+ DEV_NSENTER if `is_dev_nsenter`)
     * `is_dev_nsenter` is a userspace heuristic (the caller comm is `nsenter` or
     * an interactive shell) flagged separately so the server can treat a manual
     * dev exception differently from a cheat injector. */
    uint32_t ClassifyNsEntry(uint32_t caller_tgid, uint64_t target_ns_inode,
                             bool is_dev_nsenter) const;

private:
    static constexpr int kMaxAncestorWalk = 64;

    std::unordered_set<uint32_t> launcher_pids_;
    std::unordered_set<uint64_t> game_ns_inodes_;
    PpidFn ppid_;
};

}  // namespace horkos::containerns
