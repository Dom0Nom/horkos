/*
 * kernel/linux/userspace/FtraceAudit.cpp
 * Role: Implementation of signal 93 (ftrace ownership audit) declared in
 *       FtraceAudit.h. Pure parsing + attribution over the shared HkSymbolMap.
 * Target platform: Linux userspace.
 * Interface: implements horkos::modint::ParseEnabledFunctions / AnalyzeFtrace /
 *            hk_sensor_ftrace.
 *
 * Guardrail compliance: #1, #3, #4. Read-only / audit-only.
 */

#include "FtraceAudit.h"

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

}  // namespace

std::vector<FtraceRow> ParseEnabledFunctions(const std::string& content) {
    std::vector<FtraceRow> rows;
    std::istringstream lines(content);
    std::string line;
    FtraceRow* cur = nullptr;

    while (std::getline(lines, line)) {
        if (line.empty()) continue;
        bool indented = (line[0] == ' ' || line[0] == '\t');
        std::string trimmed = TrimWs(line);
        if (trimmed.empty()) continue;

        if (!indented) {
            /* New function row: "<symbol> (<count>) ..." */
            FtraceRow row;
            std::istringstream cols(trimmed);
            std::string sym;
            cols >> sym;
            row.func_name = sym;
            /* Optional "(N)" count token. */
            std::string ntok;
            if (cols >> ntok && ntok.size() >= 2 && ntok.front() == '(') {
                std::string num = ntok.substr(1, ntok.find(')') == std::string::npos
                                                     ? ntok.size() - 1
                                                     : ntok.find(')') - 1);
                row.callback_count = static_cast<uint32_t>(std::strtoul(num.c_str(), nullptr, 10));
            }
            rows.push_back(std::move(row));
            cur = &rows.back();
        } else if (cur != nullptr) {
            /* Continuation: "tramp: <hex>" or "ops: <hex> ...". Capture the first
             * owner address we see; tramp takes precedence (it is the call
             * target) but ops is a fine owner attribution too. */
            uint64_t addr = 0;
            size_t colon = trimmed.find(':');
            if (colon != std::string::npos) {
                std::string key = TrimWs(trimmed.substr(0, colon));
                std::string val = TrimWs(trimmed.substr(colon + 1));
                /* val may carry trailing tokens; take the first. */
                std::istringstream vs(val);
                std::string first;
                vs >> first;
                if ((key == "tramp" || key == "ops" || key == "direct") &&
                    ParseHex(first, &addr) && cur->ops_owner_addr == 0) {
                    cur->ops_owner_addr = addr;
                }
            }
        }
    }
    return rows;
}

int AnalyzeFtrace(const std::string& enabled_functions_content,
                  const HkSymbolMap& map, HkEventSink sink, bool source_readable) {
    if (!source_readable) {
        HkEmitUnavailable(sink, kSignalFtrace, 0);
        return 0;
    }

    auto rows = ParseEnabledFunctions(enabled_functions_content);
    int emitted = 0;

    for (const auto& row : rows) {
        uint32_t func_id = HkSensitiveSymbolId(row.func_name);
        if (func_id == HK_SYM__COUNT) continue;   /* not a sensitive function */

        /* Resolve the function address from the map if the row did not carry it
         * inline; the hook's presence on a sensitive function is the signal. */
        uint64_t func_addr = row.func_addr;
        if (func_addr == 0) {
            auto it = map.sensitive_addr.find(row.func_name);
            if (it != map.sensitive_addr.end()) func_addr = it->second;
        }

        /* Attribute the ops owner. owner_attributed=1 when the owner address
         * lands in the kernel core text or a known module text. An owner that
         * resolves nowhere (or no owner exposed) is unattributable → flag.
         *
         * NOTE: the catalog FP gate (signed-tracer allowlist — Falco/Tetragon/
         * Datadog/bpftrace) is applied SERVER-SIDE on the module identity behind
         * ops_owner_addr; the client reports the raw attribution only (§6). */
        uint32_t attributed = 0;
        if (row.ops_owner_addr != 0 && map.InAnyText(row.ops_owner_addr)) {
            const TextRange* owner = map.OwnerOf(row.ops_owner_addr);
            /* In-core ftrace_ops is the built-in tracer infrastructure — that is
             * attributed. A module-owned ops is attributed (server decides if the
             * module is allowlisted). Both set attributed=1; only a non-resolving
             * owner is the strong client-side anomaly. */
            attributed = (owner != nullptr) ? 1u : 0u;
        }

        if (attributed == 0) {
            HkEvtFtraceHook ev{};
            ev.func_addr = func_addr;
            ev.ops_owner_addr = row.ops_owner_addr;
            ev.owner_attributed = 0;
            ev.func_id = func_id;
            HkEmit(sink, kEvtFtraceHook, &ev, sizeof(ev));
            ++emitted;
        }
    }
    return emitted;
}

int hk_sensor_ftrace(const HkSymbolMap* map, HkEventSink sink) {
    if (map == nullptr) return -1;

    /* tracefs may be unmounted; probe both the modern and legacy mount points.
     * touched_functions (>=5.18) is read but enabled_functions is the primary. */
    static const char* kPaths[] = {
        "/sys/kernel/tracing/enabled_functions",
        "/sys/kernel/debug/tracing/enabled_functions",
    };
    std::string content;
    bool readable = false;
    for (const char* p : kPaths) {
        content = ReadFileBest(p);
        if (!content.empty()) { readable = true; break; }
        std::ifstream probe(p);
        if (probe.good()) { readable = true; break; }   /* present but empty */
    }

    AnalyzeFtrace(content, *map, sink, readable);
    return 0;
}

}  // namespace horkos::modint
