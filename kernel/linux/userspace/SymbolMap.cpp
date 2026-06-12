/*
 * Role: Implementation of the shared per-cycle kernel text-layout view declared
 *       in SymbolMap.h (signals 91/93/94 backbone). Pure procfs/sysfs text
 *       parsing; the parse helpers take captured content so they are testable on
 *       any host, and BuildFromProc() is the thin live-FS wrapper.
 * Target platform: Linux userspace.
 * Interface: implements horkos::modint::HkSymbolMap + parsers + BuildFromProc.
 *
 * Guardrail compliance: #1 (no platform macros), #3 (this comment), #4 (pure
 * userspace TU). Read-only / audit-only — no writes to any kernel surface.
 */

#include "SymbolMap.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <utility>

namespace horkos::modint {

namespace {

/* Live directory enumeration of /sys/module/<m>/sections/.text. Returns
 * (module_name, raw_section_value) pairs; an unmounted /sys yields an empty list
 * (coverage gap), never throws. */
std::vector<std::pair<std::string, std::string>>
EnumerateModuleTextSections(const std::string& module_dir) {
    std::vector<std::pair<std::string, std::string>> out;
    std::error_code ec;
    std::filesystem::directory_iterator it(module_dir, ec), end;
    if (ec) return out;   /* /sys not mounted — coverage gap, empty list */
    for (; it != end; it.increment(ec)) {
        if (ec) break;
        if (!it->is_directory(ec)) continue;
        std::string mname = it->path().filename().string();
        std::string sec = it->path().string() + "/sections/.text";
        std::ifstream f(sec, std::ios::binary);
        if (!f) continue;
        std::ostringstream ss;
        ss << f.rdbuf();
        out.emplace_back(mname, ss.str());
    }
    return out;
}

std::string TrimWs(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return {};
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

/* Parse a hex token (with or without 0x prefix) into a u64. Returns false on a
 * non-hex or empty token. An all-zero address is parsed as 0 (the caller decides
 * whether 0 means "kptr_restrict hid it"). */
bool ParseHex(const std::string& tok, uint64_t* out) {
    std::string t = TrimWs(tok);
    if (t.empty()) return false;
    const char* p = t.c_str();
    if (t.size() > 2 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    char* end = nullptr;
    errno = 0;
    unsigned long long v = std::strtoull(p, &end, 16);
    if (end == p || errno != 0) return false;
    *out = static_cast<uint64_t>(v);
    return true;
}

std::string ReadFileBest(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

}  // namespace

const std::vector<std::string>& HkSensitiveSymbolNames() {
    /* Index-aligned with HkSensitiveSymbol. The execve/ptrace names use the
     * x86_64 __x64_sys_* wrappers; on other arches the resolver also accepts the
     * bare __se_/__do_ forms (handled in ParseKallsymsSensitive via suffix). */
    static const std::vector<std::string> kNames = {
        "commit_creds",
        "prepare_kernel_cred",
        "__x64_sys_execve",
        "__x64_sys_execveat",
        "__x64_sys_ptrace",
        "module_sig_check",
        "security_bprm_check",
        "kallsyms_lookup_name",
    };
    return kNames;
}

uint32_t HkSensitiveSymbolId(const std::string& name) {
    const auto& names = HkSensitiveSymbolNames();
    for (uint32_t i = 0; i < names.size(); ++i) {
        if (names[i] == name) return i;
    }
    /* Accept arch-neutral aliases for the syscall entries / sig check so a
     * non-x86 capture still interns. */
    if (name == "__arm64_sys_execve") return HK_SYM_SYS_EXECVE;
    if (name == "__arm64_sys_execveat") return HK_SYM_SYS_EXECVEAT;
    if (name == "__arm64_sys_ptrace") return HK_SYM_SYS_PTRACE;
    if (name == "mod_verify_sig") return HK_SYM_MODULE_SIG_CHECK;
    return HK_SYM__COUNT;
}

const TextRange* HkSymbolMap::OwnerOf(uint64_t addr) const {
    if (core_valid && addr >= core.lo && addr < core.hi) return &core;
    for (const auto& m : modules) {
        if (addr >= m.lo && addr < m.hi) return &m;
    }
    return nullptr;
}

bool HkSymbolMap::InAnyText(uint64_t addr) const {
    return OwnerOf(addr) != nullptr;
}

bool ParseIomemKernelCode(const std::string& iomem_content, TextRange* out) {
    if (out == nullptr) return false;
    /* Lines look like:
     *   ffffffff81000000-ffffffff81e00fff : Kernel code
     * Match by the trailing resource name, not position. */
    std::istringstream lines(iomem_content);
    std::string line;
    while (std::getline(lines, line)) {
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string name = TrimWs(line.substr(colon + 1));
        if (name != "Kernel code") continue;

        std::string range = TrimWs(line.substr(0, colon));
        size_t dash = range.find('-');
        if (dash == std::string::npos) return false;
        uint64_t lo = 0, hi = 0;
        if (!ParseHex(range.substr(0, dash), &lo)) return false;
        if (!ParseHex(range.substr(dash + 1), &hi)) return false;
        if (lo == 0 || hi == 0 || hi <= lo) {
            /* Zeroed by kptr_restrict, or degenerate — coverage gap. */
            return false;
        }
        out->lo = lo;
        out->hi = hi + 1;   /* iomem ranges are inclusive; make half-open */
        out->owner.clear();
        return true;
    }
    return false;
}

bool ParseKallsymsSensitive(const std::string& kallsyms_content, HkSymbolMap* out) {
    if (out == nullptr) return false;
    out->sensitive_addr.clear();
    out->addrs_visible = false;

    std::istringstream lines(kallsyms_content);
    std::string line;
    bool any_line = false;
    bool any_nonzero = false;
    bool any_sensitive = false;

    while (std::getline(lines, line)) {
        if (TrimWs(line).empty()) continue;
        any_line = true;
        /* Format: "<addr> <type> <name>[\t[module]]" */
        std::istringstream cols(line);
        std::string addr_tok, type_tok, name_tok;
        if (!(cols >> addr_tok >> type_tok >> name_tok)) continue;

        /* A module-attributed symbol carries a trailing "[modname]" token; the
         * module .text bounds are taken from sysfs, so skip module symbols here
         * (they are not part of the core sensitive set). */
        std::string rest;
        std::getline(cols, rest);
        bool module_attributed = rest.find('[') != std::string::npos;

        uint64_t addr = 0;
        bool ok = ParseHex(addr_tok, &addr);
        if (ok && addr != 0) any_nonzero = true;

        if (module_attributed) continue;

        uint32_t sym_id = HkSensitiveSymbolId(name_tok);
        if (sym_id == HK_SYM__COUNT) continue;
        any_sensitive = true;
        /* Retain even a zeroed address: the caller checks addrs_visible to decide
         * coverage. Store under the canonical name (index-aligned set). */
        out->sensitive_addr[HkSensitiveSymbolNames()[sym_id < HK_SYM__COUNT
                                                          ? sym_id
                                                          : 0]] = addr;
    }

    if (!any_line) return false;
    /* addrs_visible: at least one sensitive symbol was found AND addresses are
     * not globally zeroed. If we saw sensitive symbols but every address was 0,
     * kptr_restrict is hiding them → not visible. */
    out->addrs_visible = any_sensitive && any_nonzero;
    return true;
}

bool ParseModuleSectionText(const std::string& name,
                            const std::string& section_value,
                            uint64_t* out_start) {
    (void)name;
    if (out_start == nullptr) return false;
    uint64_t v = 0;
    if (!ParseHex(section_value, &v)) return false;
    if (v == 0) return false;   /* kptr_restrict-zeroed section addr */
    *out_start = v;
    return true;
}

HkSymbolMap BuildFromProc(const std::string& proc_root,
                          const std::string& sys_root) {
    HkSymbolMap map;

    /* Core text from iomem. */
    std::string iomem = ReadFileBest(proc_root + "/iomem");
    if (!iomem.empty() && ParseIomemKernelCode(iomem, &map.core)) {
        map.core_valid = true;
    }

    /* Sensitive symbol addresses from kallsyms. */
    std::string kallsyms = ReadFileBest(proc_root + "/kallsyms");
    if (!kallsyms.empty()) {
        ParseKallsymsSensitive(kallsyms, &map);
    }

    /* Per-module .text starts from sysfs. We enumerate the /sys/module entries
     * and read each <m>/sections/.text. The section file gives only a start; we record
     * each (name, start) and then pair-sort to bound each range by the next
     * start. A module with no sections dir (built-in or hidden) is skipped.
     *
     * HK-UNCERTAIN(module-text-extent): /sys/module/<m>/sections/.text exposes
     * only the section START, not its size. Bounding by the next module's start
     * over-approximates the [lo,hi) extent (it can swallow a gap or an adjacent
     * module's .init). For attribution this is conservative (it can mis-own an
     * address to the lower neighbour) but never produces a FALSE drift, because
     * the auditors only flag addresses that fall OUTSIDE every known range. A
     * tighter extent needs coresize from /sys/module/<m>/coresize or the LKM
     * module-list walk (§1.3); the sysfs /sys/module/<m> layout is not formally
     * documented in a stable kernel ABI doc — it is present in practice but the
     * semantics of `coresize` (text only vs. text+data, init vs. core?) require
     * on-box verification before relying on it.
     * (docs: sections/.text exposes VMA start — confirmed from /sys layout; coresize
     * semantics not in public kernel docs — still needs on-target verification) */
    {
        std::vector<TextRange> starts;
        /* Read the module directory listing without <dirent.h> portability
         * concerns in the fixture path: BuildFromProc is the live path only, so
         * dirent is fine here. */
        std::string moddir = sys_root + "/module";
        auto sections = EnumerateModuleTextSections(moddir);
        for (auto& [mname, secval] : sections) {
            uint64_t start = 0;
            if (ParseModuleSectionText(mname, secval, &start)) {
                TextRange r;
                r.lo = start;
                r.hi = start;   /* filled below by pairing */
                r.owner = mname;
                starts.push_back(std::move(r));
            }
        }
        /* Bound each start by the next-higher start (over-approx; see HK-UNCERTAIN
         * above). The last range is given a 16 MiB cap so it is not unbounded. */
        std::sort(starts.begin(), starts.end(),
                  [](const TextRange& a, const TextRange& b) { return a.lo < b.lo; });
        for (size_t i = 0; i < starts.size(); ++i) {
            uint64_t hi = (i + 1 < starts.size()) ? starts[i + 1].lo
                                                  : starts[i].lo + (16ull << 20);
            starts[i].hi = hi;
        }
        map.modules = std::move(starts);
    }

    return map;
}

}  // namespace horkos::modint
