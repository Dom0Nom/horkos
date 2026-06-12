/*
 * Role: Implementation of signal 94 (sensitive-symbol kprobe audit) declared in
 *       KprobeAudit.h.
 * Target platform: Linux userspace.
 * Interface: implements horkos::modint::ParseKprobeList / AnalyzeKprobes /
 *            hk_sensor_kprobe.
 *
 * Guardrail compliance: #1, #3, #4. Read-only / audit-only.
 */

#include "KprobeAudit.h"

#include <cstdlib>
#include <fstream>
#include <sstream>

namespace horkos::modint {

namespace {

std::string TrimWs(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return {};
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

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

/* Strip a trailing "+0xNN" offset from a "symbol+offset" token. */
std::string SymbolBase(const std::string& sym_off) {
    size_t plus = sym_off.find('+');
    return (plus == std::string::npos) ? sym_off : sym_off.substr(0, plus);
}

}  // namespace

std::vector<KprobeRow> ParseKprobeList(const std::string& content) {
    std::vector<KprobeRow> rows;
    std::istringstream lines(content);
    std::string line;
    while (std::getline(lines, line)) {
        std::string t = TrimWs(line);
        if (t.empty()) continue;

        std::istringstream cols(t);
        std::vector<std::string> toks;
        std::string tok;
        while (cols >> tok) toks.push_back(tok);
        if (toks.size() < 3) continue;   /* need addr, type, symbol at least */

        KprobeRow row;
        if (!ParseHex(toks[0], &row.probe_addr)) continue;
        /* toks[1] is the type (k/r); toks[2] is symbol+offset. */
        row.symbol = SymbolBase(toks[2]);

        /* Remaining tokens are flag brackets and an optional trailing [module].
         * A bracketed token whose content is a known flag is a flag; any OTHER
         * bracketed token is treated as the owner module. */
        for (size_t i = 3; i < toks.size(); ++i) {
            const std::string& f = toks[i];
            if (f.size() >= 2 && f.front() == '[' && f.back() == ']') {
                std::string inner = f.substr(1, f.size() - 2);
                if (inner == "OPTIMIZED") {
                    row.optimized = true;
                } else if (inner == "DISABLED") {
                    row.disabled = true;
                } else if (inner == "FTRACE" || inner == "GONE") {
                    /* known non-owner flags; ignore */
                } else {
                    row.owner_module = inner;
                }
            }
        }
        rows.push_back(std::move(row));
    }
    return rows;
}

bool IsKnownSignedKprobeOwner(const std::string& owner_module) {
    /* Client-side floor only — a named owner is "known" relative to a module-less
     * probe. The real signed-EDR allowlist lives server-side (§6). */
    return !owner_module.empty();
}

int AnalyzeKprobes(const std::string& kprobe_list_content,
                   const HkSymbolMap& map, HkEventSink sink, bool source_readable) {
    if (!source_readable) {
        HkEmitUnavailable(sink, kSignalKprobe, 0);
        return 0;
    }
    (void)map;   /* probe rows already carry the symbol name; the map is used by
                    the live entry only to corroborate the address if needed */

    auto rows = ParseKprobeList(kprobe_list_content);
    int emitted = 0;

    for (const auto& row : rows) {
        uint32_t sym_id = HkSensitiveSymbolId(row.symbol);
        if (sym_id == HK_SYM__COUNT) continue;

        HkEvtKprobeSensitive ev{};
        ev.probe_addr = row.probe_addr;
        ev.symbol_id = sym_id;
        ev.flags = 0;
        if (row.optimized) ev.flags |= HK_KP_OPTIMIZED;
        if (row.disabled) ev.flags |= HK_KP_DISABLED;
        if (row.owner_module.empty()) ev.flags |= HK_KP_MODULELESS;
        ev.owner_signed = IsKnownSignedKprobeOwner(row.owner_module) ? 1u : 0u;
        ev.reserved = 0;
        HkEmit(sink, kEvtKprobeSensitive, &ev, sizeof(ev));
        ++emitted;
    }
    return emitted;
}

int hk_sensor_kprobe(const HkSymbolMap* map, HkEventSink sink) {
    if (map == nullptr) return -1;

    static const char* kPaths[] = {
        "/sys/kernel/debug/kprobes/list",
        "/sys/kernel/tracing/kprobe_events",   /* user-defined probes */
    };
    std::string content;
    bool readable = false;
    for (const char* p : kPaths) {
        std::string c = ReadFileBest(p);
        std::ifstream probe(p);
        if (!c.empty() || probe.good()) {
            content += c;
            readable = true;
        }
    }

    AnalyzeKprobes(content, *map, sink, readable);
    return 0;
}

}  // namespace horkos::modint
