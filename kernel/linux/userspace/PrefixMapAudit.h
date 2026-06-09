/*
 * kernel/linux/userspace/PrefixMapAudit.h
 * Role: Signal 101 verifier — classify a PROT_EXEC mapping (emitted with dev:ino
 *       + map_flags by mmap_exec_audit.bpf.c) as off-tree / off-allowlist. Holds
 *       the dist-tree / sniper-sysroot / prefix drive_c path set and the overlay-
 *       SO SHA256 allowlist (MangoHud/vkBasalt/obs-vkcapture/gameoverlayrenderer/
 *       GameMode). Produces the HK_PW_MAP_* report flags.
 * Target platform: Linux userspace.
 * Interface: ClassifyMap() takes the resolved backing path (looked up from
 *            /proc/<pid>/maps by dev:ino at report time) + the kernel map_flags
 *            and returns the enriched flag bitmask. Manifest/allowlist injected
 *            for host testing.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace horkos::prefixmap {

/* HK_PW_MAP_* flag bits (mirror hk_bpf_shared.h / event_schema.h). */
inline constexpr uint32_t kMapAnonThenBacked = 0x1u;
inline constexpr uint32_t kMapMemfd          = 0x2u;
inline constexpr uint32_t kMapOffTree        = 0x4u;
inline constexpr uint32_t kMapDeletedInode   = 0x8u;

/* The classifier holds the legitimate exec-mapping provenance: prefix path roots
 * that are on-tree (the Proton dist dir, the sniper/soldier sysroot, the WINE
 * prefix drive_c) and the overlay-SO basenames that are allowlisted regardless of
 * path (they are LD_PRELOADed from the runtime). Both are server-supplied; tests
 * inject fixtures. */
class PrefixMapClassifier {
public:
    PrefixMapClassifier(std::vector<std::string> on_tree_roots,
                        std::vector<std::string> overlay_so_allowlist)
        : on_tree_roots_(std::move(on_tree_roots)),
          overlay_allowlist_(std::move(overlay_so_allowlist)) {}

    /* Classify one exec mapping. `resolved_path` is the backing file path (empty
     * for anon/memfd). `kernel_flags` is the map_flags the BPF side set
     * (ANON_THEN_BACKED / DELETED_INODE / MEMFD). Returns the full HK_PW_MAP_*
     * bitmask the loader reports:
     *   - a path under an on-tree root and on no deny -> kernel_flags unchanged
     *   - an anon/memfd exec map -> MEMFD | OFF_TREE (reflective load)
     *   - a file-backed exec map NOT under any on-tree root and whose basename is
     *     NOT overlay-allowlisted -> OFF_TREE
     *   - an overlay-allowlisted basename -> NOT off-tree (suppressed) */
    uint32_t ClassifyMap(const std::string& resolved_path,
                         uint32_t kernel_flags) const;

private:
    bool UnderOnTreeRoot(const std::string& path) const;
    bool IsOverlayAllowlisted(const std::string& path) const;

    std::vector<std::string> on_tree_roots_;
    std::vector<std::string> overlay_allowlist_;  // basenames
};

}  // namespace horkos::prefixmap
