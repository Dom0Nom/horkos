/*
 * Role: Signal 84 correlator — PT_INTERP vs mapped-loader build-id check. Reads
 *       PT_INTERP + NT_GNU_BUILD_ID from /proc/<pid>/exe, identifies the mapped
 *       interpreter from /proc/<pid>/maps, and resolves the EXPECTED interpreter
 *       through the container manifest (Flatpak metadata / Steam pressure-vessel
 *       soldier/sniper build-id list) before scoring — patchelf/Nix/Steam
 *       legitimately rewrite PT_INTERP, so the manifest resolution is the FP gate.
 * Target platform: Linux userspace.
 * Interface: consumes the sched_process_exec + interp_entry streams (via
 *            InterpEvent) and a ProcReader; emits InjectionFinding
 *            (kEvtInterpMismatch).
 */

#pragma once

#include <string>
#include <vector>

#include "ElfModel.h"
#include "InjectionEvents.h"

namespace horkos::inject {

struct InterpEvent {
    uint32_t pid = 0;
    uint64_t entry_ip = 0;   /* from interp_entry.bpf.c, anchors the live ld.so VMA */
};

/* Container-manifest resolver seam. Given a pid, returns the set of ACCEPTED
 * interpreter build-ids for that container/runtime (e.g. the pressure-vessel
 * soldier/sniper ld.so build-ids, or the Flatpak runtime's). Empty = no manifest
 * (bare host); the host's own /lib64/ld-linux build-id is then the expected one.
 *
 * HK-UNCERTAIN(container-manifest): the exact Flatpak metadata / Steam
 * pressure-vessel manifest format + where to read the accepted build-id list is a
 * runtime-integration detail not finalized here. The interface is fixed; the
 * concrete resolver is wired in ops. A test stub provides the accepted set.
 * (docs: no public doc specifies the pressure-vessel or Flatpak manifest schema
 * for ld.so build-ids — still needs runtime-integration on-target verification) */
using ManifestResolver =
    std::vector<std::vector<uint8_t>> (*)(uint32_t pid, void* user);

class InterpCheck {
public:
    InterpCheck(const elfmodel::ProcReader& proc, ManifestResolver resolver,
                void* resolver_user);

    /* Score one exec/interp correlation. Reads the mapped interpreter's build-id
     * from /proc/<pid>/exe's PT_INTERP target (the interpreter path is taken from
     * the maps line containing entry_ip). If that build-id is neither the host's
     * expected loader nor in the container manifest's accepted set, flag a
     * mismatch. Returns true and fills `out` on an anomaly. */
    bool OnInterp(const InterpEvent& ev, const std::vector<uint8_t>& expected_host,
                  InjectionFinding* out);

private:
    const elfmodel::ProcReader& proc_;
    ManifestResolver resolver_;
    void* resolver_user_;
};

}  // namespace horkos::inject
