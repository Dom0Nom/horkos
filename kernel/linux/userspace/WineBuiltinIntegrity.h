/*
 * kernel/linux/userspace/WineBuiltinIntegrity.h
 * Role: Signal 107 verifier — Wine builtin PE-section integrity. Two arms:
 *       (a) the inode/SHA arm: walk /proc/<pid>/maps, find VMAs whose pathname is
 *           a Wine builtin SO (ntdll/kernelbase/win32u), stat the backing inode,
 *           compare dev:ino + SHA256 of the ON-DISK dist file against the per-
 *           Proton-version manifest;
 *       (b) the W^X arm: correlate a mprotect_wx_audit.bpf.c record (a PROT_EXEC
 *           re-arm) to a builtin VMA range.
 *       ESYNC/FSYNC + PE-loader relocation are accounted for by hashing the
 *       on-disk dist file (not the relocated in-memory image).
 * Target platform: Linux userspace.
 * Interface: ClassifyBuiltin*() return the HK_PW_WX_* bitmask. The dist manifest
 *            (builtin-SO basename -> {dev,ino,sha256}) is injected; the maps walk
 *            is behind a query seam so the classifier is host-testable.
 */

#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <unordered_map>

namespace horkos::winebuiltin {

/* HK_PW_WX_* bits (mirror hk_bpf_shared.h / event_schema.h). */
inline constexpr uint32_t kWxWasRx            = 0x1u;
inline constexpr uint32_t kWxInBuiltin        = 0x2u;
inline constexpr uint32_t kWxInodeOffManifest = 0x4u;

using Sha256 = std::array<uint8_t, 32>;

/* One per-Proton-version manifest entry for a builtin SO. */
struct BuiltinManifestEntry {
    uint32_t dev;
    uint64_t inode;
    Sha256   sha256;   /* SHA256 of the ON-DISK dist file */
};

/* A VMA observed in /proc/<pid>/maps (the inputs the maps-walk seam yields). */
struct ObservedVma {
    std::string basename;   /* builtin SO basename, e.g. "ntdll.so" */
    uint32_t    dev;
    uint64_t    inode;
    Sha256      on_disk_sha256;  /* SHA256 of the backing file the inode resolves to */
    uint64_t    vm_start;
    uint64_t    vm_end;
};

class WineBuiltinIntegrity {
public:
    /* @manifest: builtin-SO basename -> expected {dev,ino,sha256} for this Proton
     *   build. A basename absent from the manifest is treated as off-manifest. */
    explicit WineBuiltinIntegrity(
        std::unordered_map<std::string, BuiltinManifestEntry> manifest)
        : manifest_(std::move(manifest)) {}

    /* Inode/SHA arm: classify one observed builtin VMA. Returns the HK_PW_WX_*
     * bitmask:
     *   - basename not in the manifest -> IN_BUILTIN | INODE_OFF_MANIFEST
     *   - dev:ino mismatch OR on-disk SHA256 mismatch -> IN_BUILTIN |
     *     INODE_OFF_MANIFEST (the builtin SO was swapped for an off-dist file)
     *   - exact match -> 0 (legitimate; relocations do not change the on-disk hash) */
    uint32_t ClassifyBuiltinInode(const ObservedVma& vma) const;

    /* W^X arm: given a mprotect_wx_audit record (was-RX flag from the kernel) that
     * resolves to `vma`, combine the kernel WAS_RX flag with the in-builtin range
     * and the inode arm. Returns the HK_PW_WX_* bitmask reported. */
    uint32_t ClassifyWxArm(uint32_t kernel_flags, const ObservedVma& vma) const;

private:
    std::unordered_map<std::string, BuiltinManifestEntry> manifest_;
};

}  // namespace horkos::winebuiltin
