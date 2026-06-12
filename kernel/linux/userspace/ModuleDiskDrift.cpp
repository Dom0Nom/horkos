/*
 * Role: Implementation of signal 95 userspace half (build-id memory-vs-disk
 *       drift) declared in ModuleDiskDrift.h.
 * Target platform: Linux userspace.
 * Interface: implements horkos::modint::ParseBuildIdNote / CompareBuildId /
 *            AnalyzeModuleDisk / hk_sensor_module_disk.
 *
 * Guardrail compliance: #1, #3, #4. Read-only / audit-only.
 */

#include "ModuleDiskDrift.h"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace horkos::modint {

namespace {

uint32_t ReadLe32(const std::string& s, size_t off) {
    uint32_t v = 0;
    std::memcpy(&v, s.data() + off, sizeof(v));
    return v;   /* Horkos targets LE hosts; note words are native-endian on disk */
}

std::string ReadFileBest(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

/* Scan an ELF .ko's section headers for a SHT_NOTE carrying the build-id. To
 * avoid a full ELF parser here we reuse the note-format scan: search the file
 * for the "GNU\0" build-id note signature with type==3. This is a heuristic but
 * robust for the single build-id note kernel modules carry.
 *
 * HK-UNCERTAIN(ko-buildid-scan): scanning the whole .ko for the GNU note
 * signature can in principle match an unrelated embedded "GNU\0" string. The
 * correct extraction walks the ELF section headers to the .note.gnu.build-id
 * SHT_NOTE and reads the descriptor there. The NT_GNU_BUILD_ID note type (3) and
 * the 4-byte "GNU\0" name are documented in the GNU build-id spec and the ELF
 * note format (ELF spec §5, Nhdr layout: namesz/descsz/type + name + desc), so
 * the note structure itself is public. Whether a real DKMS .ko's only GNU note
 * is the build-id (no other "GNU\0" embedded strings) is an on-box question.
 * (docs: NT_GNU_BUILD_ID format confirmed from ELF spec — still needs on-target
 * .ko sampling to confirm absence of false-match strings) */
std::vector<uint8_t> ScanKoBuildId(const std::string& ko_bytes) {
    static const char kName[] = {'G', 'U', '\0'};   /* "GNU" minus leading G to
                                                        widen the search window */
    (void)kName;
    /* Walk for note headers of the form: namesz(4)=4, descsz(4)=N, type(4)=3,
     * "GNU\0". */
    for (size_t i = 0; i + 16 <= ko_bytes.size(); ++i) {
        uint32_t namesz = ReadLe32(ko_bytes, i);
        uint32_t descsz = ReadLe32(ko_bytes, i + 4);
        uint32_t type = ReadLe32(ko_bytes, i + 8);
        if (namesz != 4 || type != 3 /* NT_GNU_BUILD_ID */) continue;
        if (i + 12 + 4 > ko_bytes.size()) continue;
        if (std::memcmp(ko_bytes.data() + i + 12, "GNU\0", 4) != 0) continue;
        size_t desc_off = i + 12 + 4;   /* name is 4 bytes, already aligned */
        if (descsz == 0 || desc_off + descsz > ko_bytes.size()) continue;
        return std::vector<uint8_t>(ko_bytes.begin() + desc_off,
                                    ko_bytes.begin() + desc_off + descsz);
    }
    return {};
}

}  // namespace

std::vector<uint8_t> ParseBuildIdNote(const std::string& raw_note) {
    if (raw_note.size() < 16) return {};
    uint32_t namesz = ReadLe32(raw_note, 0);
    uint32_t descsz = ReadLe32(raw_note, 4);
    uint32_t type = ReadLe32(raw_note, 8);
    if (type != 3 /* NT_GNU_BUILD_ID */ || namesz != 4) return {};
    if (raw_note.size() < 12 + 4) return {};
    if (std::memcmp(raw_note.data() + 12, "GNU\0", 4) != 0) return {};
    size_t desc_off = 12 + 4;   /* 4-byte name, aligned to 4 */
    if (descsz == 0 || desc_off + descsz > raw_note.size()) return {};
    return std::vector<uint8_t>(raw_note.begin() + desc_off,
                                raw_note.begin() + desc_off + descsz);
}

bool CompareBuildId(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    if (a.empty() || b.empty()) return false;
    return a == b;
}

int AnalyzeModuleDisk(const std::string& module_name,
                      const std::vector<uint8_t>& mem_build_id,
                      const std::vector<uint8_t>& disk_build_id,
                      bool disk_found, HkEventSink sink) {
    if (mem_build_id.empty()) {
        /* In-memory build-id unreadable — coverage gap, not drift. Skip silently;
         * the live caller decides whether to emit a single SENSOR_UNAVAILABLE. */
        return 0;
    }

    if (!disk_found) {
        HkEvtModuleDiskDrift ev{};
        ev.name_hash = HkNameHash(module_name);
        ev.reason = HK_MD_NO_DISK_KO;
        ev.reserved = 0;
        HkEmit(sink, kEvtModuleDiskDrift, &ev, sizeof(ev));
        return 1;
    }

    if (!CompareBuildId(mem_build_id, disk_build_id)) {
        HkEvtModuleDiskDrift ev{};
        ev.name_hash = HkNameHash(module_name);
        ev.reason = HK_MD_BUILDID_MISMATCH;
        ev.reserved = 0;
        HkEmit(sink, kEvtModuleDiskDrift, &ev, sizeof(ev));
        return 1;
    }
    return 0;   /* match — DKMS-safe (both sides moved together) */
}

int hk_sensor_module_disk(const HkSymbolMap* map, HkEventSink sink) {
    (void)map;

    /* Resolve the running kernel release for the on-disk module path. */
    std::string release = ReadFileBest("/proc/sys/kernel/osrelease");
    while (!release.empty() &&
           (release.back() == '\n' || release.back() == '\r')) {
        release.pop_back();
    }
    if (release.empty()) {
        HkEmitUnavailable(sink, kSignalModuleDisk, 0);
        return 0;
    }
    std::string mod_root = "/lib/modules/" + release;

    std::error_code ec;
    std::filesystem::directory_iterator it("/sys/module", ec), end;
    if (ec) {
        HkEmitUnavailable(sink, kSignalModuleDisk, ec.value());
        return 0;
    }

    for (; it != end; it.increment(ec)) {
        if (ec) break;
        if (!it->is_directory(ec)) continue;
        std::string mname = it->path().filename().string();

        std::string note = ReadFileBest(
            it->path().string() + "/notes/.note.gnu.build-id");
        std::vector<uint8_t> mem_id = ParseBuildIdNote(note);
        if (mem_id.empty()) continue;   /* built-in / no note — not a loadable .ko */

        /* Find the backing .ko. Module file names use '-' or '_' interchangeably;
         * search recursively for <name>.ko[.gz/.xz/.zst]. We only handle the
         * uncompressed .ko build-id scan here (compressed needs decompression —
         * HK-UNCERTAIN below). */
        bool disk_found = false;
        std::vector<uint8_t> disk_id;
        std::error_code rec;
        for (std::filesystem::recursive_directory_iterator
                 rit(mod_root, rec), rend;
             rit != rend; rit.increment(rec)) {
            if (rec) break;
            if (!rit->is_regular_file(rec)) continue;
            std::string fn = rit->path().filename().string();
            std::string stem = fn;
            size_t dot = stem.find(".ko");
            if (dot == std::string::npos) continue;
            std::string base = stem.substr(0, dot);
            /* normalise '-'/'_' */
            for (char& c : base) if (c == '-') c = '_';
            std::string want = mname;
            for (char& c : want) if (c == '-') c = '_';
            if (base != want) continue;

            if (fn.size() > dot + 3) {
                /* compressed .ko.gz/.xz/.zst — decompression not done here. */
                /* HK-UNCERTAIN(compressed-ko): distros increasingly ship
                 * .ko.zst/.ko.xz (Fedora, Ubuntu 22.04+, Steam Deck). Build-id
                 * extraction then needs the matching decompressor (zstd, liblzma).
                 * No public kernel doc specifies which compression format a given
                 * distro uses; it is a per-distro packaging decision. Treat a
                 * compressed-only backing as "found" so we do NOT false-positive
                 * NO_DISK_KO, but skip the build-id compare (no mismatch can be
                 * asserted). (docs: .ko.zst common on Fedora/Ubuntu 22.04+ — still
                 * needs on-target decompressor path confirmed per distro) */
                disk_found = true;
                disk_id.clear();
                continue;
            }

            std::string ko = ReadFileBest(rit->path().string());
            disk_id = ScanKoBuildId(ko);
            disk_found = true;
            break;
        }

        /* If the only backing was compressed (disk_id empty but disk_found), do
         * not assert a mismatch — pass disk_id==mem_id semantics by short-circuit:
         * only emit NO_DISK_KO when not found at all. */
        if (disk_found && disk_id.empty()) {
            continue;   /* compressed-only; compare skipped (see HK-UNCERTAIN) */
        }
        AnalyzeModuleDisk(mname, mem_id, disk_id, disk_found, sink);
    }
    return 0;
}

}  // namespace horkos::modint
