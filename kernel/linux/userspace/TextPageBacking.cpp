/*
 * kernel/linux/userspace/TextPageBacking.cpp
 * Role: Implementation of the signal-90 text COW-broken correlator declared in
 *       TextPageBacking.h.
 * Target platform: Linux userspace.
 * Interface: implements horkos::inject::TextPageBacking.
 *
 * Guardrail compliance: #1, #3, #4. Read-only/audit-only.
 *
 * HK-UNCERTAIN(pagemap-caps): the per-page file-backed bit comes from
 * /proc/<pid>/pagemap, whose layout changed across kernels and whose cross-process
 * read requires CAP_SYS_ADMIN (tightened in recent kernels). It is NOT verified
 * that the loader's CAP_BPF/CAP_PERFMON set suffices. This correlator therefore
 * scores on smaps Private_Dirty (which IS readable without CAP_SYS_ADMIN) as the
 * primary evidence; the pagemap file-backed cross-check is an OPTIONAL refinement
 * the loader supplies only if its capability set is confirmed sufficient on-box.
 * Default-OFF (CMake) until verified.
 */

#include "TextPageBacking.h"

#include <sstream>

namespace horkos::inject {

std::vector<SmapsExecVma> TextPageBacking::ParseExecSmaps(
    const std::string& smaps_text) {
    std::vector<SmapsExecVma> out;
    std::istringstream lines(smaps_text);
    std::string line;
    SmapsExecVma cur;
    bool in_exec = false;

    auto flush = [&]() {
        if (in_exec) out.push_back(cur);
        in_exec = false;
        cur = SmapsExecVma{};
    };

    while (std::getline(lines, line)) {
        // A header line looks like: "addr-addr perms offset dev inode path"
        // Detect it by the '-' between two hex addresses at the start.
        unsigned long long start = 0, end = 0, off = 0, inode = 0;
        char perms[8] = {0};
        char devbuf[16] = {0};
        int consumed = 0;
        int n = std::sscanf(line.c_str(), "%llx-%llx %4s %llx %15s %llu%n",
                            &start, &end, perms, &off, devbuf, &inode, &consumed);
        if (n >= 6 && perms[0] != '\0') {
            // New mapping header — flush the previous exec mapping.
            flush();
            if (perms[2] == 'x') {
                in_exec = true;
                cur.start = start;
                cur.end = end;
                std::string rest =
                    (consumed > 0 && static_cast<size_t>(consumed) <= line.size())
                        ? line.substr(static_cast<size_t>(consumed))
                        : std::string();
                size_t p = rest.find_first_not_of(" \t");
                std::string path =
                    (p == std::string::npos) ? std::string() : rest.substr(p);
                cur.file_backed = !path.empty() && path[0] == '/';
            }
            continue;
        }
        // A "Private_Dirty:    N kB" field line within the current mapping.
        if (in_exec) {
            unsigned long long kb = 0;
            if (std::sscanf(line.c_str(), "Private_Dirty: %llu kB", &kb) == 1) {
                cur.private_dirty_kb = kb;
            }
        }
    }
    flush();
    return out;
}

bool TextPageBacking::OnTick(
    const TextTickEvent& ev, const std::vector<SmapsExecVma>& exec_vmas,
    const std::vector<std::pair<uint64_t, uint64_t>>& allowed_spans,
    InjectionFinding* out) {
    if (ev.tracer_attached) return false;  // debugger legitimately dirties code

    for (const auto& v : exec_vmas) {
        if (!v.file_backed) continue;          // only file-backed code matters here
        if (v.private_dirty_kb == 0) continue; // COW intact — not patched

        // Suppress if the whole mapping is covered by an allowed IFUNC/reloc span.
        bool covered = false;
        for (const auto& span : allowed_spans) {
            if (v.start >= span.first && v.end <= span.second) {
                covered = true;
                break;
            }
        }
        if (covered) continue;

        if (out) {
            out->event_type = kEvtTextPatch;
            out->pid = ev.pid;
            out->flags = HK_LI_TEXT_COW_BROKEN;
            out->detail = v.start;
        }
        return true;
    }
    return false;
}

}  // namespace horkos::inject
