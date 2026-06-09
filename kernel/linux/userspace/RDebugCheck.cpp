/*
 * kernel/linux/userspace/RDebugCheck.cpp
 * Role: Implementation of the signal-88 _r_debug r_brk / RELRO correlator
 *       declared in RDebugCheck.h.
 * Target platform: Linux userspace.
 * Interface: implements horkos::inject::RDebugCheck.
 *
 * Guardrail compliance: #1, #3, #4. Read-only/audit-only.
 *
 * HK-UNCERTAIN(proc-mem-self-suppress): reading another process's /proc/<pid>/mem
 * at the load-biased _r_debug address has the same ptrace-access-mode gating as a
 * debugger; whether the loader can do this WITHOUT itself becoming a ptrace
 * tracer (which would self-suppress this very signal via tracer_attached) is
 * unconfirmed on the target. The r_brk VALUE is therefore supplied to this
 * correlator (RdebugTickEvent.r_brk) by whatever read path the loader ultimately
 * uses; this module only performs the VMA range-check + tracer suppression. The
 * actual /proc/<pid>/mem read mechanism is flagged for on-box verification before
 * signal 88 is enabled (default-OFF in CMake).
 */

#include "RDebugCheck.h"

namespace horkos::inject {

namespace {

bool IsLdSoPath(const std::string& path) {
    // ld-linux-x86-64.so.2, ld-linux-aarch64.so.1, ld-2.31.so, ld-musl-*.so ...
    size_t slash = path.find_last_of('/');
    std::string base = (slash == std::string::npos) ? path : path.substr(slash + 1);
    return base.rfind("ld-", 0) == 0 || base.rfind("ld.so", 0) == 0 ||
           base.find("ld-linux") != std::string::npos;
}

}  // namespace

RDebugCheck::RDebugCheck(const elfmodel::ProcReader& proc) : proc_(proc) {}

bool RDebugCheck::OnTick(const RdebugTickEvent& ev, InjectionFinding* out) {
    // Suppress when a tracer is attached — a debugger legitimately moves r_brk.
    if (ev.tracer_attached) return false;
    if (ev.r_brk == 0) return false;

    auto maps = proc_.ReadText(ev.pid, "maps");
    if (!maps) return false;
    auto vmas = elfmodel::ParseMaps(*maps);

    // r_brk must fall inside the ld.so executable VMA. Find that VMA range.
    bool inside_ldso = false;
    bool found_ldso = false;
    for (const auto& v : vmas) {
        if (!IsLdSoPath(v.path)) continue;
        found_ldso = true;
        if (ev.r_brk >= v.start && ev.r_brk < v.end) {
            inside_ldso = true;
            break;
        }
    }
    if (!found_ldso) return false;   // can't locate ld.so — FP-safe: no finding
    if (inside_ldso) return false;   // r_brk inside ld.so — normal

    if (out) {
        out->event_type = kEvtRdebugAnomaly;
        out->pid = ev.pid;
        out->flags = HK_LI_RDEBUG_FOREIGN;
        out->detail = ev.r_brk;
    }
    return true;
}

}  // namespace horkos::inject
