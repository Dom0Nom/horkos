/*
 * Role: Implementation of the signal-85 transient-preload correlator declared in
 *       PreloadWatch.h. Pure correlation/scoring; the inotify FD lifetime is the
 *       loader's responsibility.
 * Target platform: Linux userspace.
 * Interface: implements horkos::inject::PreloadWatch.
 *
 * Guardrail compliance: #1, #3, #4. Read-only/audit-only.
 */

#include "PreloadWatch.h"

#include <sstream>

namespace horkos::inject {

namespace {

std::string Basename(const std::string& path) {
    size_t slash = path.find_last_of('/');
    return (slash == std::string::npos) ? path : path.substr(slash + 1);
}

std::string TrimWs(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return {};
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

}  // namespace

PreloadWatch::PreloadWatch(const allowlist::OverlayAllowlist& allow,
                           std::string scope)
    : allow_(allow), scope_(std::move(scope)) {}

void PreloadWatch::SetSteadyStatePreload(const std::string& file_content) {
    steady_preload_.clear();
    std::istringstream lines(file_content);
    std::string line;
    while (std::getline(lines, line)) {
        std::string t = TrimWs(line);
        if (t.empty() || t[0] == '#') continue;
        steady_preload_.push_back(t);
    }
}

bool PreloadWatch::OnExecEnv(const BprmEnvEvent& ev, InjectionFinding* out) {
    bool has_preload = (ev.env_flags & HK_ENV_LD_PRELOAD) != 0;
    bool has_audit = (ev.env_flags & HK_ENV_LD_AUDIT) != 0;
    if (!has_preload && !has_audit) return false;

    // The injected module is the env value (LD_PRELOAD takes precedence for the
    // signal-85 transient-preload case; LD_AUDIT is corroborated by dl_audit).
    const std::string& injected =
        has_preload ? ev.ld_preload_value : ev.ld_audit_value;
    if (injected.empty()) {
        // Presence without a captured value still indicates a transient env (the
        // env value lives only for this launch, not in the steady-state file).
    } else {
        // If the injected module IS listed in the steady-state preload file, it is
        // a system-wide, persistent preload — not a transient per-launch one.
        std::string inj_base = Basename(injected);
        for (const auto& s : steady_preload_) {
            if (s == injected || Basename(s) == inj_base) {
                return false;  // matches steady state — persistent, not transient
            }
        }
        // Allowlisted overlay/allocator → suppress.
        if (allow_.IsAllowed(inj_base, {}, scope_) ||
            allow_.IsAllowed(injected, {}, scope_)) {
            return false;
        }
    }

    if (out) {
        out->event_type = kEvtPreloadAnomaly;
        out->pid = ev.pid;
        out->flags = HK_LI_PRELOAD_TRANSIENT;
        if (has_audit) out->flags |= HK_LI_LD_AUDIT_ACTIVE;
        out->detail = ev.ancestor_pid;  // env-setting ancestor attribution
        out->soname_or_path = injected;
    }
    return true;
}

}  // namespace horkos::inject
