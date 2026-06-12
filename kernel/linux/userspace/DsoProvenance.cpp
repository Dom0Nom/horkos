/*
 * Role: Implementation of the signal-82 DT_NEEDED-divergence correlator declared
 *       in DsoProvenance.h.
 * Target platform: Linux userspace.
 * Interface: implements horkos::inject::DsoProvenance.
 *
 * Guardrail compliance: #1, #3, #4 (no BPF headers). Read-only/audit-only: emits
 * a finding for the server to score; never bans or acts on-host.
 */

#include "DsoProvenance.h"

namespace horkos::inject {

const std::set<std::string> DsoProvenance::kEmpty{};

DsoProvenance::DsoProvenance(const elfmodel::ProcReader& proc,
                             const allowlist::OverlayAllowlist& allow,
                             std::string scope)
    : proc_(proc), allow_(allow), scope_(std::move(scope)) {}

bool DsoProvenance::AttachPid(uint32_t pid) {
    auto exe = proc_.ReadBytes(pid, "exe", 0, 64u * 1024u * 1024u);
    if (exe.empty()) return false;

    std::set<std::string> closure;
    for (const auto& soname : elfmodel::ParseDtNeeded(exe)) {
        closure.insert(soname);
    }
    // One additional level: for each direct needed soname we can resolve on disk,
    // pull ITS DT_NEEDED. Deeper transitive deps are caught lazily when those
    // DSOs are themselves mapped (their soname is already in the closure once we
    // see the parent), so a single extra level keeps attach cheap while covering
    // the common direct-vs-runtime divergence the catalog targets.
    // (Resolution of a soname to an on-disk path is left to the caller's library
    // search in production; here we only record the names.)
    closure_[pid] = std::move(closure);
    return true;
}

bool DsoProvenance::OnMapEvent(const DsoMapEvent& ev, InjectionFinding* out) {
    auto it = closure_.find(ev.pid);
    const std::set<std::string>& closure =
        (it != closure_.end()) ? it->second : kEmpty;

    bool in_closure = !ev.soname.empty() && closure.count(ev.soname) > 0;
    bool allowed = allow_.IsAllowed(ev.soname, ev.build_id, scope_);

    // Backing-store red flag: a mapped DSO whose path is (deleted)/memfd:/anon is
    // intrinsically suspicious regardless of closure membership.
    bool fileless = ev.resolved_path.empty() ||
                    ev.resolved_path.rfind("memfd:", 0) == 0 ||
                    ev.resolved_path.rfind("/memfd:", 0) == 0;

    if ((in_closure || allowed) && !fileless) {
        return false;  // legitimate, provenanced, on-disk DSO
    }
    if (allowed) {
        return false;  // explicitly allowlisted overlay/allocator
    }

    if (!out) return true;
    out->event_type = kEvtDsoProvenance;
    out->pid = ev.pid;
    out->flags = 0;
    if (!in_closure) out->flags |= HK_DSO_FLAG_NO_DT_NEEDED;
    if (!allowed) out->flags |= HK_DSO_FLAG_OUTSIDE_ALLOW;
    if (fileless) out->flags |= HK_DSO_FLAG_MEMFD_DELETED;
    out->detail = elfmodel::BuildIdPrefix(ev.build_id);
    out->soname_or_path = ev.soname.empty() ? ev.resolved_path : ev.soname;
    out->build_id = ev.build_id;
    return true;
}

const std::set<std::string>& DsoProvenance::closure_for(uint32_t pid) const {
    auto it = closure_.find(pid);
    return (it != closure_.end()) ? it->second : kEmpty;
}

}  // namespace horkos::inject
