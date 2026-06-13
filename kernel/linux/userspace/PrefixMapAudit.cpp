/*
 * Role: Implementation of the signal-101 foreign-SO map classifier declared in
 *       PrefixMapAudit.h. The off-tree / overlay-allowlist decision lives here
 *       (userspace) by design — the kernel stays allowlist-free.
 * Target platform: Linux userspace.
 * Interface: implements horkos::prefixmap.
 *
 * Guardrail compliance: #1, #3, #4 (no BPF headers).
 */

#include "PrefixMapAudit.h"

namespace horkos::prefixmap {

namespace {

std::string Basename(const std::string& path) {
    auto slash = path.find_last_of('/');
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

/* True if `path` starts with `root` at a path-component boundary (so "/usr" does
 * not match "/usrlib"). */
bool HasPathPrefix(const std::string& path, const std::string& root) {
    if (root.empty() || path.size() < root.size())
        return false;
    if (path.compare(0, root.size(), root) != 0)
        return false;
    // Boundary: exact match, or the next char is '/'.
    return path.size() == root.size() || path[root.size()] == '/';
}

}  // namespace

bool PrefixMapClassifier::UnderOnTreeRoot(const std::string& path) const {
    for (const auto& root : on_tree_roots_) {
        if (HasPathPrefix(path, root))
            return true;
    }
    return false;
}

bool PrefixMapClassifier::IsOverlayAllowlisted(const std::string& path) const {
    const std::string base = Basename(path);
    for (const auto& allowed : overlay_allowlist_) {
        if (base == allowed)
            return true;
    }
    return false;
}

uint32_t PrefixMapClassifier::ClassifyMap(const std::string& resolved_path,
                                          uint32_t kernel_flags) const {
    uint32_t flags = kernel_flags;

    /* Anonymous / memfd exec mapping: no backing path. This is a reflective load
     * (memfd_create + mmap PROT_EXEC), always off-tree. The BPF side already set
     * ANON_THEN_BACKED for a file==NULL map; the memfd correlation (Loader's
     * memfd join) flips MEMFD. Either way, no path means off-tree. */
    if (resolved_path.empty()) {
        flags |= kMapOffTree;
        return flags;
    }

    /* An overlay SO on the signed allowlist is benign wherever it is mapped from
     * (the runtime LD_PRELOADs it from outside the dist tree). Suppress off-tree. */
    if (IsOverlayAllowlisted(resolved_path))
        return flags;  // not off-tree

    /* A file-backed exec map under a known on-tree root is benign. */
    if (UnderOnTreeRoot(resolved_path))
        return flags;  // not off-tree

    /* Otherwise: off-tree foreign SO. */
    flags |= kMapOffTree;
    return flags;
}

}  // namespace horkos::prefixmap
