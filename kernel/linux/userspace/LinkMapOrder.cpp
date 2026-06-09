/*
 * kernel/linux/userspace/LinkMapOrder.cpp
 * Role: Implementation of the signal-87 (corroborating-only) load-order
 *       interposition correlator declared in LinkMapOrder.h.
 * Target platform: Linux userspace.
 * Interface: implements horkos::inject::LinkMapOrder.
 *
 * Guardrail compliance: #1, #3, #4. Corroborating-only: the finding carries no
 * standalone ban weight; the server applies a low weight (never bans on 87 alone).
 */

#include "LinkMapOrder.h"

namespace horkos::inject {

const std::vector<std::string>& LinkMapOrder::WatchedSymbols() {
    static const std::vector<std::string> kSyms = {
        "malloc", "recv", "glXSwapBuffers", "vkQueuePresentKHR", "time", "rand",
    };
    return kSyms;
}

LinkMapOrder::LinkMapOrder(const allowlist::OverlayAllowlist& allow,
                           std::string scope)
    : allow_(allow), scope_(std::move(scope)) {}

bool LinkMapOrder::OnMapEvent(const DsoMapEvent& ev, bool has_dt_needed,
                              const std::vector<std::string>& exported_syms,
                              bool is_canonical_libc, InjectionFinding* out) {
    bool allowed = allow_.IsAllowed(ev.soname, ev.build_id, scope_);

    bool emitted = false;
    for (const auto& sym : exported_syms) {
        // Only watched symbols matter.
        bool watched = false;
        for (const auto& w : WatchedSymbols()) {
            if (w == sym) { watched = true; break; }
        }
        if (!watched) continue;

        auto key = std::make_pair(ev.pid, sym);

        if (is_canonical_libc) {
            // Record the canonical provider's index (first/min wins).
            auto it = canonical_index_.find(key);
            if (it == canonical_index_.end() || ev.link_map_index < it->second) {
                canonical_index_[key] = ev.link_map_index;
            }
            continue;
        }

        // Triple gate: outside allowlist AND no DT_NEEDED provenance AND it
        // precedes the canonical provider for a watched symbol.
        if (allowed || has_dt_needed) continue;

        auto it = canonical_index_.find(key);
        bool precedes_canonical =
            (it == canonical_index_.end()) ||  // libc not yet seen: it precedes
            (ev.link_map_index < it->second);
        if (!precedes_canonical) continue;

        if (out && !emitted) {
            out->event_type = kEvtLoadorderInvert;
            out->pid = ev.pid;
            out->flags = HK_DSO_FLAG_ORDER_INVERT | HK_DSO_FLAG_OUTSIDE_ALLOW |
                         HK_DSO_FLAG_NO_DT_NEEDED;
            out->detail = ev.link_map_index;
            out->soname_or_path = ev.soname.empty() ? ev.resolved_path : ev.soname;
            out->build_id = ev.build_id;
        }
        emitted = true;
    }
    return emitted;
}

}  // namespace horkos::inject
