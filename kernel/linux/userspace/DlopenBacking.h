/*
 * Role: Signal 86 correlator — fileless/memfd dlopen backing resolution. On each
 *       dlopen event it inspects the matching /proc/<pid>/maps line(s) for the
 *       resolved path and flags (deleted) / memfd: / anon-exec backing. Gate:
 *       require an EXECUTABLE backing (and, in production, later-called exported
 *       symbols) before scoring; whitelist known JIT runtimes by allowlist.
 * Target platform: Linux userspace.
 * Interface: consumes DlopenEvent + a ProcReader; emits InjectionFinding
 *            (kEvtDlopenBacking).
 */

#pragma once

#include <string>

#include "ElfModel.h"
#include "InjectionEvents.h"
#include "OverlayAllowlist.h"

namespace horkos::inject {

struct DlopenEvent {
    uint32_t pid = 0;
    std::string path;   /* dlopen() file arg as read by the uprobe; "" for NULL */
};

class DlopenBacking {
public:
    DlopenBacking(const elfmodel::ProcReader& proc,
                  const allowlist::OverlayAllowlist& allow,
                  std::string scope);

    /* Resolve the dlopen target against the live VMA map. Flags an anomaly when a
     * matching mapping is executable AND backed by (deleted)/memfd:/anon. A
     * file-backed exec mapping (normal gconv/plugin dlopen) yields no finding.
     * Returns true and fills `out` on an anomaly. */
    bool OnDlopen(const DlopenEvent& ev, InjectionFinding* out);

private:
    const elfmodel::ProcReader& proc_;
    const allowlist::OverlayAllowlist& allow_;
    std::string scope_;
};

}  // namespace horkos::inject
