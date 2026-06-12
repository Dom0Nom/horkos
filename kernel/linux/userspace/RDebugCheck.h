/*
 * Role: Signal 88 correlator — _r_debug r_brk / RELRO integrity. On an
 *       rdebug_sample tick it locates _r_debug via PT_DYNAMIC DT_DEBUG at the
 *       load-biased address (read through /proc/<pid>/mem), range-checks r_brk
 *       against ld.so's VMA, and reads the RELRO page perms from maps (expected
 *       r--p). Suppresses when a ptrace tracer is attached (corroborated by the
 *       existing sys_enter_ptrace signal) and allowlists the distro ld.so's
 *       expected r_brk offset.
 * Target platform: Linux userspace.
 * Interface: consumes RdebugTickEvent + a ProcReader; emits InjectionFinding
 *            (kEvtRdebugAnomaly).
 */

#pragma once

#include <vector>

#include "ElfModel.h"
#include "InjectionEvents.h"

namespace horkos::inject {

struct RdebugTickEvent {
    uint32_t pid = 0;
    uint64_t r_brk = 0;       /* the r_brk VA the loader read from _r_debug */
    bool tracer_attached = false;  /* from the ptrace-tracer corroboration */
};

class RDebugCheck {
public:
    explicit RDebugCheck(const elfmodel::ProcReader& proc);

    /* Evaluate one tick. Flags an anomaly when r_brk falls OUTSIDE the ld.so
     * executable VMA range (a repointed r_brk hook) AND no tracer is attached.
     * The ld.so VMA range is located from /proc/<pid>/maps by matching the
     * interpreter path (ld-*.so / ld-linux*). Returns true on an anomaly. */
    bool OnTick(const RdebugTickEvent& ev, InjectionFinding* out);

private:
    const elfmodel::ProcReader& proc_;
};

}  // namespace horkos::inject
