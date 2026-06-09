/*
 * kernel/linux/userspace/InterpCheck.cpp
 * Role: Implementation of the signal-84 PT_INTERP-mismatch correlator declared in
 *       InterpCheck.h.
 * Target platform: Linux userspace.
 * Interface: implements horkos::inject::InterpCheck.
 *
 * Guardrail compliance: #1, #3, #4. Read-only/audit-only.
 */

#include "InterpCheck.h"

namespace horkos::inject {

InterpCheck::InterpCheck(const elfmodel::ProcReader& proc,
                         ManifestResolver resolver, void* resolver_user)
    : proc_(proc), resolver_(resolver), resolver_user_(resolver_user) {}

bool InterpCheck::OnInterp(const InterpEvent& ev,
                           const std::vector<uint8_t>& expected_host,
                           InjectionFinding* out) {
    // Locate the mapped interpreter's file from the maps line containing entry_ip.
    auto maps = proc_.ReadText(ev.pid, "maps");
    if (!maps) return false;
    auto vmas = elfmodel::ParseMaps(*maps);
    auto exec_vma = elfmodel::FindExecVmaForAddr(vmas, ev.entry_ip);
    if (!exec_vma || exec_vma->path.empty()) return false;

    // Read the mapped interpreter ELF and extract its build-id. The interpreter
    // file path is exec_vma->path; we read it through the ProcReader's exe-style
    // path is not applicable, so the loader reads the on-disk file. For the seam,
    // we read via a synthetic "interp" channel keyed by the same pid (the FsProc
    // reader maps it to the file; tests inject the bytes).
    auto interp_bytes = proc_.ReadBytes(ev.pid, "map_files/interp", 0,
                                        64u * 1024u * 1024u);
    std::vector<uint8_t> live_build_id = elfmodel::ParseBuildId(interp_bytes);
    if (live_build_id.empty()) {
        // Cannot read the build-id — do not fabricate a mismatch (FP-safe).
        return false;
    }

    // Accept if it matches the host's expected loader build-id.
    if (!expected_host.empty() && live_build_id == expected_host) return false;

    // Accept if it is in the container manifest's accepted set (Flatpak / Steam
    // pressure-vessel legitimately ship their own ld.so).
    if (resolver_) {
        auto accepted = resolver_(ev.pid, resolver_user_);
        for (const auto& a : accepted) {
            if (a == live_build_id) return false;  // legitimate runtime loader
        }
    }

    if (out) {
        out->event_type = kEvtInterpMismatch;
        out->pid = ev.pid;
        out->flags = HK_LI_INTERP_MISMATCH;
        out->detail = exec_vma->start;
        out->soname_or_path = exec_vma->path;
        out->build_id = live_build_id;
    }
    return true;
}

}  // namespace horkos::inject
