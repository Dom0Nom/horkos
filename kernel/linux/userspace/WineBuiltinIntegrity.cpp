/*
 * Role: Implementation of the signal-107 Wine builtin integrity verifier declared
 *       in WineBuiltinIntegrity.h. Hashes the ON-DISK dist file (so ESYNC/FSYNC +
 *       PE-loader relocations do not false-positive); a swapped builtin SO or a
 *       W^X re-arm of a builtin .text page is the breach.
 * Target platform: Linux userspace.
 * Interface: implements horkos::winebuiltin.
 *
 * Guardrail compliance: #1, #3, #4 (no BPF headers).
 *
 * HK-UNCERTAIN(builtin-maps-walk): the live /proc/<pid>/maps walk + on-disk
 * SHA256 of each builtin SO is the production input to ClassifyBuiltinInode. The
 * walk itself (path matching ntdll.so/kernelbase.so/win32u.so, stat for dev:ino,
 * SHA256 of the backing file) is a straightforward proc parse but is NOT
 * implemented in this scaffolding pass — it depends on the per-Proton-version
 * dist manifest being produced (a data dependency not yet resolved).
 * The classifier here is the testable decision core; the maps-walk seam feeds it
 * ObservedVma rows. Wire the live walk when the manifest tooling lands.
 * (docs: /proc/pid/maps format and PTRACE_MODE_READ access confirmed in
 * proc_pid_maps(5) — still needs Proton dist manifest tooling and on-target wiring)
 */

#include "WineBuiltinIntegrity.h"

namespace horkos::winebuiltin {

uint32_t WineBuiltinIntegrity::ClassifyBuiltinInode(const ObservedVma& vma) const {
    /* Every observed builtin VMA is in-builtin by construction (the maps walk only
     * yields VMAs whose basename matched a builtin SO name). */
    uint32_t flags = kWxInBuiltin;

    auto it = manifest_.find(vma.basename);
    if (it == manifest_.end()) {
        /* The builtin SO is not in this Proton build's manifest at all — an
         * off-dist SO masquerading under a builtin name. */
        return flags | kWxInodeOffManifest;
    }

    const BuiltinManifestEntry& exp = it->second;
    if (vma.dev != exp.dev || vma.inode != exp.inode ||
        vma.on_disk_sha256 != exp.sha256) {
        /* dev:ino or on-disk SHA mismatch: the builtin was swapped. Hashing the
         * on-disk file (not the relocated image) means a legitimate relocated
         * load matches exactly here. */
        return flags | kWxInodeOffManifest;
    }

    return 0;  // exact match — legitimate builtin (no IN_BUILTIN noise on a match)
}

uint32_t WineBuiltinIntegrity::ClassifyWxArm(uint32_t kernel_flags,
                                             const ObservedVma& vma) const {
    /* Start from the kernel's WAS_RX evidence, add the inode-arm verdict (which
     * also asserts IN_BUILTIN). A W^X re-arm of a builtin whose inode also drifted
     * off-manifest is the strongest 107 evidence. */
    uint32_t flags = (kernel_flags & kWxWasRx);
    flags |= ClassifyBuiltinInode(vma);
    /* A re-arm inside a builtin range that still matches the manifest (relocation/
     * legitimate JIT in a builtin? rare) keeps only WAS_RX | IN_BUILTIN so the
     * server sees the transition without an inode-mismatch verdict. */
    if (flags & (kWxInBuiltin | kWxInodeOffManifest))
        flags |= kWxInBuiltin;
    return flags;
}

}  // namespace horkos::winebuiltin
