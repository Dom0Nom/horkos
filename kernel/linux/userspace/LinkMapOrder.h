/*
 * Role: Signal 87 correlator (CORROBORATING-ONLY) — load-order symbol
 *       interposition. Builds the per-PID link_map insertion order from the
 *       dl_map_object event stream; for a fixed set of security-relevant exported
 *       symbols (malloc, recv, glXSwapBuffers, vkQueuePresentKHR, time, rand) it
 *       flags a non-allowlisted DSO with no DT_NEEDED provenance preceding the
 *       canonical provider. Catalog rates this HIGHEST-FP: the gate is the triple
 *       (outside allowlist AND no DT_NEEDED provenance AND interposes a watched
 *       symbol) and the finding is emitted CORROBORATING-ONLY — the server must
 *       never ban on signal 87 standalone (low standalone weight, enforced
 *       server-side, never on-host).
 * Target platform: Linux userspace.
 * Interface: shares the DsoMapEvent stream with DsoProvenance; emits an
 *            InjectionFinding (kEvtLoadorderInvert) per inversion.
 */

#pragma once

#include <map>
#include <string>
#include <vector>

#include "DsoProvenance.h"
#include "InjectionEvents.h"
#include "OverlayAllowlist.h"

namespace horkos::inject {

class LinkMapOrder {
public:
    LinkMapOrder(const allowlist::OverlayAllowlist& allow, std::string scope);

    /* Record a mapped DSO and, if it exports a watched interposable symbol with
     * no provenance and is not allowlisted AND precedes the canonical libc
     * provider already recorded for that symbol, emit a corroborating finding.
     *
     * @has_dt_needed  whether DsoProvenance found this soname in the DT_NEEDED
     *                 closure (caller passes the result so the two correlators
     *                 share one closure parse).
     * @exported_syms  the watched symbols this DSO exports (caller-resolved).
     * @is_canonical_libc  true for the title's real libc (the canonical provider).
     */
    bool OnMapEvent(const DsoMapEvent& ev, bool has_dt_needed,
                    const std::vector<std::string>& exported_syms,
                    bool is_canonical_libc, InjectionFinding* out);

    /* The watched, commonly-interposed symbols. */
    static const std::vector<std::string>& WatchedSymbols();

private:
    const allowlist::OverlayAllowlist& allow_;
    std::string scope_;
    /* Per (pid, symbol): the smallest link_map index of the canonical provider
     * seen so far. A non-canonical, non-provenanced DSO at a SMALLER index that
     * exports the same symbol is an inversion. */
    std::map<std::pair<uint32_t, std::string>, uint32_t> canonical_index_;
};

}  // namespace horkos::inject
