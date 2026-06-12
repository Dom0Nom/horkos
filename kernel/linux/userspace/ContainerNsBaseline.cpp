/*
 * Role: Implementation of the signal-103 pressure-vessel namespace baseliner
 *       declared in ContainerNsBaseline.h. The launcher-lineage descent check is
 *       the load-bearing FP gate: pressure-vessel's own setns is a descendant of
 *       the recorded bwrap chain and must NOT flag; an off-lineage setns into the
 *       game namespaces is the breach.
 * Target platform: Linux userspace.
 * Interface: implements horkos::containerns.
 *
 * Guardrail compliance: #1, #3, #4 (no BPF headers).
 */

#include "ContainerNsBaseline.h"

namespace horkos::containerns {

bool ContainerNsBaseline::IsDescendantOfLauncher(uint32_t caller_tgid) const {
    uint32_t cur = caller_tgid;
    for (int hop = 0; hop < kMaxAncestorWalk; ++hop) {
        if (cur == 0)
            return false;  // reached init / unknown without hitting a launcher
        if (launcher_pids_.count(cur) != 0)
            return true;
        uint32_t parent = ppid_ ? ppid_(cur) : 0;
        if (parent == cur)
            return false;  // self-parent guard (defensive against a bad /proc read)
        cur = parent;
    }
    return false;  // walk bound exceeded — treat as not-a-descendant (server scores)
}

uint32_t ContainerNsBaseline::ClassifyNsEntry(uint32_t caller_tgid,
                                              uint64_t target_ns_inode,
                                              bool is_dev_nsenter) const {
    /* Only a setns INTO one of the game's container namespaces is in scope. A
     * setns into some unrelated namespace is not a breach of the game container. */
    if (game_ns_inodes_.count(target_ns_inode) == 0)
        return 0;

    /* Pressure-vessel's own setns: the caller is a descendant of the recorded
     * pv-bwrap/bwrap launcher chain. Suppress. */
    if (IsDescendantOfLauncher(caller_tgid))
        return 0;

    /* Off-lineage entry into the game namespaces — the breach. */
    uint32_t flags = kNsFlagOffLineage;
    if (is_dev_nsenter)
        flags |= kNsFlagDevNsenter;  // reported as a manual exception, still emitted
    return flags;
}

}  // namespace horkos::containerns
