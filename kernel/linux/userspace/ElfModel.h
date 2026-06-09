/*
 * kernel/linux/userspace/ElfModel.h
 * Role: Shared read-only ELF + /proc parsing utilities for the Linux injection
 *       correlators (signals 82-90). Provides the DT_NEEDED closure,
 *       section-header / load-bias math, NT_GNU_BUILD_ID extraction, a VMA-map
 *       snapshot model, and a maps-line classifier (anon / (deleted) / memfd: /
 *       r-xp file-backed / RELRO r--p). All reads go through a ProcReader seam so
 *       unit tests can inject fixture /proc snapshots without a live PID.
 * Target platform: Linux userspace (guardrail #4 — never shares a TU with any
 *                   BPF kernel object; no BPF headers here).
 * Interface: pure helper library consumed by every correlator
 *            (DsoProvenance / GotPltMap / InterpCheck / PreloadWatch /
 *            DlopenBacking / LinkMapOrder / RDebugCheck / TextPageBacking).
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace horkos::elfmodel {

/* ---- ProcReader seam ------------------------------------------------------
 * All /proc access funnels through this interface so tests inject fixtures.
 * The production implementation reads the real /proc/<pid> files; tests use
 * an in-memory map. */
class ProcReader {
public:
    virtual ~ProcReader() = default;
    /* Returns the full text of /proc/<pid>/<name> (e.g. "maps", "smaps",
     * "pagemap" is binary — see ReadBytes). std::nullopt if unreadable. */
    virtual std::optional<std::string> ReadText(uint32_t pid,
                                                const std::string& name) const = 0;
    /* Reads `len` bytes from /proc/<pid>/<name> at byte `offset` (for mem/pagemap).
     * Returns the bytes actually read (may be shorter); empty on failure. */
    virtual std::vector<uint8_t> ReadBytes(uint32_t pid, const std::string& name,
                                           uint64_t offset, size_t len) const = 0;
};

/* Production ProcReader backed by the real filesystem. */
class FsProcReader final : public ProcReader {
public:
    std::optional<std::string> ReadText(uint32_t pid,
                                        const std::string& name) const override;
    std::vector<uint8_t> ReadBytes(uint32_t pid, const std::string& name,
                                   uint64_t offset, size_t len) const override;
};

/* ---- Backing-store classification (signal 86 / 90) ----------------------- */
enum class MapBacking {
    kUnknown,
    kFileBacked,   /* a real path, present on disk */
    kDeleted,      /* path ends with " (deleted)" */
    kMemfd,        /* "/memfd:..." backing */
    kAnonymous,    /* no path (anonymous mapping) */
};

/* One parsed /proc/<pid>/maps line. */
struct VmaEntry {
    uint64_t    start = 0;
    uint64_t    end = 0;
    bool        readable = false;
    bool        writable = false;
    bool        executable = false;
    bool        priv = false;       /* 'p' private vs 's' shared */
    uint64_t    file_offset = 0;
    uint64_t    inode = 0;
    std::string path;               /* raw path field (without the " (deleted)") */
    MapBacking  backing = MapBacking::kUnknown;
};

/* Parse a full /proc/<pid>/maps text blob into VMA entries. Robust to short or
 * malformed lines (skips them). */
std::vector<VmaEntry> ParseMaps(const std::string& maps_text);

/* True if `va` falls within an executable mapping in `vmas`; returns the entry. */
std::optional<VmaEntry> FindExecVmaForAddr(const std::vector<VmaEntry>& vmas,
                                           uint64_t va);

/* ---- DT_NEEDED closure (signal 82 / 87) ----------------------------------
 * Parse the direct DT_NEEDED sonames of an ELF blob (the bytes of
 * /proc/<pid>/exe or a DSO). Returns the soname strings in DT order.
 * The TRANSITIVE closure is built by the caller by recursively resolving each
 * needed soname's own DT_NEEDED (BuildNeededClosure below). */
std::vector<std::string> ParseDtNeeded(const std::vector<uint8_t>& elf);

/* ---- NT_GNU_BUILD_ID (signal 82 / 84 / 89) -------------------------------
 * Extract the 20-byte (typically) build-id from an ELF blob's .note.gnu.build-id.
 * Returns the raw bytes; empty if absent. */
std::vector<uint8_t> ParseBuildId(const std::vector<uint8_t>& elf);

/* First 8 bytes of a build-id packed little-endian into a u64 (the kernel-record
 * "build-id prefix"); 0 if the build-id is shorter than 8 bytes. */
uint64_t BuildIdPrefix(const std::vector<uint8_t>& build_id);

/* ---- Section-header / load-bias math (signal 83) -------------------------
 * Resolve the load-biased VA of the .got.plt section given the ELF blob and the
 * load bias (l_addr) from the link map. std::nullopt if the section is absent. */
struct GotPltSpan {
    uint64_t va = 0;     /* load-biased start VA of .got.plt */
    uint64_t size = 0;   /* section size in bytes */
    uint64_t entsize = 0;/* slot size (8 on LP64) */
};
std::optional<GotPltSpan> ResolveGotPlt(const std::vector<uint8_t>& elf,
                                        uint64_t load_bias);

}  // namespace horkos::elfmodel
