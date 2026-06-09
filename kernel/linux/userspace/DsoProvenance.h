/*
 * kernel/linux/userspace/DsoProvenance.h
 * Role: Signal 82 correlator — DT_NEEDED-closure vs runtime-DSO divergence. At
 *       attach it parses the static DT_NEEDED transitive closure of
 *       /proc/<pid>/exe; for each _dl_map_object event it flags DSOs that are
 *       absent from that closure AND outside the signed runtime/lib allowlist.
 * Target platform: Linux userspace.
 * Interface: consumes the dl_map_object ringbuf events (via DsoMapEvent) and a
 *            ProcReader; emits an InjectionFinding (kEvtDsoProvenance) per anomaly.
 */

#pragma once

#include <map>
#include <set>
#include <string>

#include "ElfModel.h"
#include "InjectionEvents.h"
#include "OverlayAllowlist.h"

namespace horkos::inject {

/* Userspace mirror of one dl_map_object.bpf.c record (the kernel emits the
 * cadence; userspace re-resolves the soname/build-id from its own link_map +
 * /proc parsing, since the kernel does not deref the glibc-internal link_map). */
struct DsoMapEvent {
    uint32_t pid = 0;
    uint32_t link_map_index = 0;
    std::string soname;                 /* resolved by userspace */
    std::vector<uint8_t> build_id;      /* resolved by userspace */
    std::string resolved_path;          /* full path from /proc maps */
    uint64_t load_bias = 0;
};

class DsoProvenance {
public:
    DsoProvenance(const elfmodel::ProcReader& proc,
                  const allowlist::OverlayAllowlist& allow,
                  std::string scope);

    /* Parse the DT_NEEDED closure of /proc/<pid>/exe once at attach. The closure
     * here is the DIRECT DT_NEEDED set of the main exe plus, when readable, each
     * needed DSO's own DT_NEEDED (one level; deeper levels resolved lazily as
     * those DSOs are themselves mapped). Returns false if the exe is unreadable. */
    bool AttachPid(uint32_t pid);

    /* Process one dl_map event. If the mapped soname is outside the DT_NEEDED
     * closure AND not allowlisted, fills `out` and returns true (an anomaly).
     * Returns false (no finding) for in-closure or allowlisted DSOs. */
    bool OnMapEvent(const DsoMapEvent& ev, InjectionFinding* out);

    /* Test/inspection: the recorded closure for a pid. */
    const std::set<std::string>& closure_for(uint32_t pid) const;

private:
    const elfmodel::ProcReader& proc_;
    const allowlist::OverlayAllowlist& allow_;
    std::string scope_;
    std::map<uint32_t, std::set<std::string>> closure_;
    static const std::set<std::string> kEmpty;
};

}  // namespace horkos::inject
