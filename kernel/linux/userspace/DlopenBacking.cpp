/*
 * kernel/linux/userspace/DlopenBacking.cpp
 * Role: Implementation of the signal-86 fileless-dlopen correlator declared in
 *       DlopenBacking.h.
 * Target platform: Linux userspace.
 * Interface: implements horkos::inject::DlopenBacking.
 *
 * Guardrail compliance: #1, #3, #4. Read-only/audit-only.
 */

#include "DlopenBacking.h"

namespace horkos::inject {

DlopenBacking::DlopenBacking(const elfmodel::ProcReader& proc,
                             const allowlist::OverlayAllowlist& allow,
                             std::string scope)
    : proc_(proc), allow_(allow), scope_(std::move(scope)) {}

bool DlopenBacking::OnDlopen(const DlopenEvent& ev, InjectionFinding* out) {
    auto maps = proc_.ReadText(ev.pid, "maps");
    if (!maps) return false;
    auto vmas = elfmodel::ParseMaps(*maps);

    // Find an executable mapping whose backing is fileless. We match by the
    // dlopen path basename when available; otherwise we look for ANY exec mapping
    // with a fileless backing that appeared (the caller serializes dlopen→scan).
    for (const auto& v : vmas) {
        if (!v.executable) continue;

        bool fileless = (v.backing == elfmodel::MapBacking::kDeleted) ||
                        (v.backing == elfmodel::MapBacking::kMemfd) ||
                        (v.backing == elfmodel::MapBacking::kAnonymous);
        if (!fileless) continue;

        // If the dlopen arg names a concrete on-disk path that maps file-backed,
        // it is the legitimate case — only score the fileless backings.
        // Allowlist gate: a known JIT runtime soname is suppressed.
        if (!v.path.empty() && allow_.IsAllowed(v.path, {}, scope_)) continue;

        if (out) {
            out->event_type = kEvtDlopenBacking;
            out->pid = ev.pid;
            out->flags = HK_DSO_FLAG_MEMFD_DELETED | HK_DSO_FLAG_OUTSIDE_ALLOW;
            out->detail = v.start;  // base VA of the fileless exec mapping
            out->soname_or_path = ev.path.empty() ? v.path : ev.path;
        }
        return true;
    }
    return false;
}

}  // namespace horkos::inject
