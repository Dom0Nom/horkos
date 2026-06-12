/*
 * Role: Implementation of the shared ELF + /proc parsing helpers declared in
 *       ElfModel.h. Maps-line parsing and backing classification are fully
 *       self-contained (no libelf) so they unit-test on any host. ELF64 note /
 *       dynamic-section parsing is a minimal, dependency-free reader (sufficient
 *       for DT_NEEDED + NT_GNU_BUILD_ID + section-header lookup); a libelf-backed
 *       path can replace it later without changing the interface.
 * Target platform: Linux userspace.
 * Interface: implements horkos::elfmodel from ElfModel.h.
 *
 * Guardrail compliance: #1 (no raw platform macros; whole subtree Linux-gated by
 * CMake), #3 (this module comment), #4 (no BPF headers).
 */

#include "ElfModel.h"

#include <cstring>
#include <fstream>
#include <sstream>

namespace horkos::elfmodel {

namespace {

/* ---- Minimal, bounds-checked ELF64 little-endian reader ------------------
 * Only what the correlators need. Every access bounds-checks against the blob
 * size; a malformed/truncated ELF yields empty results, never a read past end. */

template <typename T>
bool ReadAt(const std::vector<uint8_t>& b, size_t off, T* out) {
    if (off + sizeof(T) > b.size()) return false;
    std::memcpy(out, b.data() + off, sizeof(T));
    return true;
}

constexpr unsigned char kElfMag0 = 0x7f;
constexpr uint16_t      kEtNone = 0;
constexpr uint32_t      kShtDynamic = 6;
constexpr uint32_t      kShtNote = 7;
constexpr int64_t       kDtNull = 0;
constexpr int64_t       kDtNeeded = 1;
constexpr int64_t       kDtStrtab = 5;
constexpr uint32_t      kNtGnuBuildId = 3;

struct Elf64Header {
    uint64_t e_shoff = 0;
    uint16_t e_shentsize = 0;
    uint16_t e_shnum = 0;
    uint16_t e_shstrndx = 0;
    bool ok = false;
};

Elf64Header ParseHeader(const std::vector<uint8_t>& b) {
    Elf64Header h;
    if (b.size() < 64) return h;
    if (b[0] != kElfMag0 || b[1] != 'E' || b[2] != 'L' || b[3] != 'F') return h;
    if (b[4] != 2 /* ELFCLASS64 */ || b[5] != 1 /* ELFDATA2LSB */) return h;
    (void)kEtNone;
    if (!ReadAt(b, 40, &h.e_shoff)) return h;
    if (!ReadAt(b, 58, &h.e_shentsize)) return h;
    if (!ReadAt(b, 60, &h.e_shnum)) return h;
    if (!ReadAt(b, 62, &h.e_shstrndx)) return h;
    h.ok = true;
    return h;
}

struct Elf64Shdr {
    uint32_t sh_name = 0;
    uint32_t sh_type = 0;
    uint64_t sh_addr = 0;
    uint64_t sh_offset = 0;
    uint64_t sh_size = 0;
    uint64_t sh_link = 0;
    uint64_t sh_entsize = 0;
};

bool ReadShdr(const std::vector<uint8_t>& b, uint64_t shoff, uint16_t entsize,
              uint16_t idx, Elf64Shdr* out) {
    size_t off = static_cast<size_t>(shoff) + static_cast<size_t>(idx) * entsize;
    uint32_t name32 = 0, type32 = 0;
    uint64_t addr = 0, offset = 0, size = 0, entsz = 0;
    uint32_t link32 = 0;
    if (!ReadAt(b, off + 0, &name32)) return false;
    if (!ReadAt(b, off + 4, &type32)) return false;
    if (!ReadAt(b, off + 16, &addr)) return false;
    if (!ReadAt(b, off + 24, &offset)) return false;
    if (!ReadAt(b, off + 32, &size)) return false;
    if (!ReadAt(b, off + 40, &link32)) return false;
    if (!ReadAt(b, off + 56, &entsz)) return false;
    out->sh_name = name32;
    out->sh_type = type32;
    out->sh_addr = addr;
    out->sh_offset = offset;
    out->sh_size = size;
    out->sh_link = link32;
    out->sh_entsize = entsz;
    return true;
}

std::string ReadCStr(const std::vector<uint8_t>& b, size_t off) {
    std::string s;
    while (off < b.size() && b[off] != 0) {
        s.push_back(static_cast<char>(b[off]));
        ++off;
    }
    return s;
}

}  // namespace

// ---------------------------------------------------------------------------
// FsProcReader
// ---------------------------------------------------------------------------

std::optional<std::string> FsProcReader::ReadText(uint32_t pid,
                                                  const std::string& name) const {
    std::ostringstream path;
    path << "/proc/" << pid << "/" << name;
    std::ifstream f(path.str(), std::ios::in | std::ios::binary);
    if (!f) return std::nullopt;
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

std::vector<uint8_t> FsProcReader::ReadBytes(uint32_t pid, const std::string& name,
                                             uint64_t offset, size_t len) const {
    std::ostringstream path;
    path << "/proc/" << pid << "/" << name;
    std::ifstream f(path.str(), std::ios::in | std::ios::binary);
    std::vector<uint8_t> out;
    if (!f) return out;
    f.seekg(static_cast<std::streamoff>(offset));
    if (!f) return out;
    out.resize(len);
    f.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(len));
    out.resize(static_cast<size_t>(f.gcount()));
    return out;
}

// ---------------------------------------------------------------------------
// maps parsing + backing classification
// ---------------------------------------------------------------------------

std::vector<VmaEntry> ParseMaps(const std::string& maps_text) {
    std::vector<VmaEntry> out;
    std::istringstream lines(maps_text);
    std::string line;
    while (std::getline(lines, line)) {
        if (line.empty()) continue;
        VmaEntry e;
        // Format: start-end perms offset dev inode path
        char perms[8] = {0};
        unsigned long long start = 0, end = 0, off = 0, inode = 0;
        char devbuf[16] = {0};
        int consumed = 0;
        int n = std::sscanf(line.c_str(), "%llx-%llx %4s %llx %15s %llu%n",
                            &start, &end, perms, &off, devbuf, &inode, &consumed);
        if (n < 6) continue;
        e.start = start;
        e.end = end;
        e.readable   = perms[0] == 'r';
        e.writable   = perms[1] == 'w';
        e.executable = perms[2] == 'x';
        e.priv       = perms[3] == 'p';
        e.file_offset = off;
        e.inode = inode;

        // The remainder (after the consumed numeric fields) is the path, leading
        // whitespace trimmed.
        std::string rest = (consumed > 0 && static_cast<size_t>(consumed) <= line.size())
                               ? line.substr(static_cast<size_t>(consumed))
                               : std::string();
        size_t p = rest.find_first_not_of(" \t");
        std::string path = (p == std::string::npos) ? std::string() : rest.substr(p);

        // Classify backing. A memfd mapping commonly renders as
        // "/memfd:name (deleted)"; the memfd nature is the salient classification,
        // so detect it BEFORE the generic (deleted) case. The trailing
        // " (deleted)" suffix is stripped from the recorded path either way.
        const std::string kDeletedSuffix = " (deleted)";
        bool had_deleted = false;
        if (path.size() >= kDeletedSuffix.size() &&
            path.compare(path.size() - kDeletedSuffix.size(),
                         kDeletedSuffix.size(), kDeletedSuffix) == 0) {
            had_deleted = true;
            path.erase(path.size() - kDeletedSuffix.size());
        }
        if (path.empty()) {
            e.backing = MapBacking::kAnonymous;
        } else if (path.rfind("/memfd:", 0) == 0 || path.rfind("memfd:", 0) == 0) {
            e.backing = MapBacking::kMemfd;
        } else if (path[0] == '[') {
            // [stack], [heap], [vdso] etc. — treat as anonymous special.
            e.backing = MapBacking::kAnonymous;
        } else if (had_deleted) {
            e.backing = MapBacking::kDeleted;
        } else {
            e.backing = MapBacking::kFileBacked;
        }
        e.path = path;
        out.push_back(std::move(e));
    }
    return out;
}

std::optional<VmaEntry> FindExecVmaForAddr(const std::vector<VmaEntry>& vmas,
                                           uint64_t va) {
    for (const auto& e : vmas) {
        if (e.executable && va >= e.start && va < e.end) return e;
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// DT_NEEDED
// ---------------------------------------------------------------------------

std::vector<std::string> ParseDtNeeded(const std::vector<uint8_t>& elf) {
    std::vector<std::string> out;
    Elf64Header h = ParseHeader(elf);
    if (!h.ok || h.e_shentsize == 0) return out;

    // Find the .dynamic section and its associated string table.
    Elf64Shdr dyn{};
    bool have_dyn = false;
    for (uint16_t i = 0; i < h.e_shnum; ++i) {
        Elf64Shdr sh{};
        if (!ReadShdr(elf, h.e_shoff, h.e_shentsize, i, &sh)) continue;
        if (sh.sh_type == kShtDynamic) { dyn = sh; have_dyn = true; break; }
    }
    if (!have_dyn) return out;

    // The dynamic string table: prefer DT_STRTAB resolved through a section whose
    // sh_addr matches; fall back to the section pointed to by dyn.sh_link.
    Elf64Shdr strsh{};
    bool have_str = false;
    if (dyn.sh_link < h.e_shnum &&
        ReadShdr(elf, h.e_shoff, h.e_shentsize,
                 static_cast<uint16_t>(dyn.sh_link), &strsh)) {
        have_str = true;
    }

    // Walk the dynamic entries (Elf64_Dyn = { int64 d_tag; uint64 d_val }).
    const size_t kDynEnt = 16;
    uint64_t strtab_addr = 0;
    std::vector<uint64_t> needed_offsets;
    for (uint64_t off = dyn.sh_offset; off + kDynEnt <= dyn.sh_offset + dyn.sh_size;
         off += kDynEnt) {
        int64_t tag = 0;
        uint64_t val = 0;
        if (!ReadAt(elf, off, &tag)) break;
        if (!ReadAt(elf, off + 8, &val)) break;
        if (tag == kDtNull) break;
        if (tag == kDtStrtab) strtab_addr = val;
        if (tag == kDtNeeded) needed_offsets.push_back(val);
    }

    // Resolve the string-table file offset. If DT_STRTAB's VA matches a section's
    // sh_addr, use that section's file offset; otherwise use the sh_link section.
    uint64_t str_file_off = 0;
    if (strtab_addr != 0) {
        for (uint16_t i = 0; i < h.e_shnum; ++i) {
            Elf64Shdr sh{};
            if (!ReadShdr(elf, h.e_shoff, h.e_shentsize, i, &sh)) continue;
            if (sh.sh_addr == strtab_addr) { str_file_off = sh.sh_offset; break; }
        }
    }
    if (str_file_off == 0 && have_str) str_file_off = strsh.sh_offset;

    for (uint64_t name_off : needed_offsets) {
        std::string s = ReadCStr(elf, static_cast<size_t>(str_file_off + name_off));
        if (!s.empty()) out.push_back(std::move(s));
    }
    return out;
}

// ---------------------------------------------------------------------------
// NT_GNU_BUILD_ID
// ---------------------------------------------------------------------------

std::vector<uint8_t> ParseBuildId(const std::vector<uint8_t>& elf) {
    std::vector<uint8_t> out;
    Elf64Header h = ParseHeader(elf);
    if (!h.ok || h.e_shentsize == 0) return out;

    for (uint16_t i = 0; i < h.e_shnum; ++i) {
        Elf64Shdr sh{};
        if (!ReadShdr(elf, h.e_shoff, h.e_shentsize, i, &sh)) continue;
        if (sh.sh_type != kShtNote) continue;
        // Walk notes: { u32 namesz; u32 descsz; u32 type; name[]; desc[] } with
        // 4-byte alignment on name and desc.
        uint64_t off = sh.sh_offset;
        uint64_t end = sh.sh_offset + sh.sh_size;
        while (off + 12 <= end) {
            uint32_t namesz = 0, descsz = 0, type = 0;
            if (!ReadAt(elf, off, &namesz)) break;
            if (!ReadAt(elf, off + 4, &descsz)) break;
            if (!ReadAt(elf, off + 8, &type)) break;
            uint64_t name_off = off + 12;
            uint64_t name_aligned = (namesz + 3u) & ~3u;
            uint64_t desc_off = name_off + name_aligned;
            uint64_t desc_aligned = (descsz + 3u) & ~3u;
            if (type == kNtGnuBuildId && descsz > 0 &&
                desc_off + descsz <= elf.size() && desc_off + descsz <= end) {
                out.assign(elf.begin() + static_cast<long>(desc_off),
                           elf.begin() + static_cast<long>(desc_off + descsz));
                return out;
            }
            off = desc_off + desc_aligned;
            if (name_aligned == 0 && desc_aligned == 0) break;  // avoid stall
        }
    }
    return out;
}

uint64_t BuildIdPrefix(const std::vector<uint8_t>& build_id) {
    if (build_id.size() < 8) return 0;
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= static_cast<uint64_t>(build_id[static_cast<size_t>(i)]) << (8 * i);
    }
    return v;
}

// ---------------------------------------------------------------------------
// .got.plt section lookup
// ---------------------------------------------------------------------------

std::optional<GotPltSpan> ResolveGotPlt(const std::vector<uint8_t>& elf,
                                        uint64_t load_bias) {
    Elf64Header h = ParseHeader(elf);
    if (!h.ok || h.e_shentsize == 0 || h.e_shstrndx >= h.e_shnum) return std::nullopt;

    Elf64Shdr shstr{};
    if (!ReadShdr(elf, h.e_shoff, h.e_shentsize, h.e_shstrndx, &shstr))
        return std::nullopt;

    for (uint16_t i = 0; i < h.e_shnum; ++i) {
        Elf64Shdr sh{};
        if (!ReadShdr(elf, h.e_shoff, h.e_shentsize, i, &sh)) continue;
        std::string name = ReadCStr(elf, static_cast<size_t>(shstr.sh_offset + sh.sh_name));
        if (name == ".got.plt") {
            GotPltSpan span;
            span.va = sh.sh_addr + load_bias;
            span.size = sh.sh_size;
            span.entsize = (sh.sh_entsize != 0) ? sh.sh_entsize : 8;
            return span;
        }
    }
    return std::nullopt;
}

}  // namespace horkos::elfmodel
