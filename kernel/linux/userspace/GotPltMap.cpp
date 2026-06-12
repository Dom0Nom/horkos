/*
 * Role: Implementation of the signal-83 GOT/PLT redirection correlator declared
 *       in GotPltMap.h.
 * Target platform: Linux userspace.
 * Interface: implements horkos::inject::GotPltMap.
 *
 * Guardrail compliance: #1, #3, #4. Read-only/audit-only.
 *
 * HK-VERIFIED(lazy-binding): with lazy binding a GOT slot legitimately holds a
 * pointer back into the corresponding PLT entry (the PLT stub) until first call,
 * per the x86-64 psABI (System V ABI for AMD64, §11 "Program Linkage Table"):
 * "The first time a PLT entry is called, it pushes the relocation index and jumps
 * to PLT[0]; the dynamic linker then resolves and overwrites the GOT entry."
 * The ABI-documented PLT→GOT round-trip is the authoritative source; treating a
 * GOT slot pointing into [own_plt_start, own_plt_end) as benign is correct for
 * unresolved lazy slots. IFUNC (R_*_IRELATIVE) slots are a separate case: they
 * resolve to arbitrary in-DSO addresses per the ABI — also ABI-documented.
 */

#include "GotPltMap.h"

namespace horkos::inject {

GotPltMap::GotPltMap(const allowlist::OverlayAllowlist& allow, std::string scope)
    : allow_(allow), scope_(std::move(scope)) {}

bool GotPltMap::OnSample(const GotSampleEvent& ev,
                         const std::vector<elfmodel::VmaEntry>& vmas,
                         InjectionFinding* out) {
    size_t n = ev.slot_target.size();
    for (size_t i = 0; i < n; ++i) {
        // Skip IFUNC slots — they resolve to arbitrary in-DSO addrs legitimately.
        if (i < ev.is_ifunc.size() && ev.is_ifunc[i]) continue;

        uint64_t target = ev.slot_target[i];
        if (target == 0) continue;  // unbound slot

        // Lazy-binding benign case: points into the process's own PLT stub.
        if (ev.own_plt_end > ev.own_plt_start &&
            target >= ev.own_plt_start && target < ev.own_plt_end) {
            continue;
        }

        auto exec_vma = elfmodel::FindExecVmaForAddr(vmas, target);

        uint32_t flags = 0;
        if (!exec_vma) {
            // Target is not in any executable mapping at all — or it is in a
            // writable/anon mapping. Find the containing VMA to classify.
            for (const auto& v : vmas) {
                if (target >= v.start && target < v.end) {
                    if (v.writable && v.executable) flags |= HK_GOT_FLAG_RWX_TARGET;
                    if (v.backing == elfmodel::MapBacking::kAnonymous)
                        flags |= HK_GOT_FLAG_ANON_TARGET;
                    break;
                }
            }
            if (flags == 0) flags |= HK_GOT_FLAG_ANON_TARGET;  // no/unknown mapping
        } else {
            // In an exec mapping. RWX or allowlisted-foreign classification.
            if (exec_vma->writable) flags |= HK_GOT_FLAG_RWX_TARGET;
            bool allowed = !exec_vma->path.empty() &&
                           allow_.IsAllowed(exec_vma->path, {}, scope_);
            bool file_backed = exec_vma->backing == elfmodel::MapBacking::kFileBacked;
            if (!allowed && !file_backed) flags |= HK_GOT_FLAG_FOREIGN_DSO;
            if (allowed) continue;  // legitimate overlay target
            if (file_backed && !exec_vma->writable) continue;  // normal r-x DSO
        }

        if (flags == 0) continue;

        if (out) {
            out->event_type = kEvtGotAnomaly;
            out->pid = ev.pid;
            out->flags = flags;
            out->detail = target;
            out->soname_or_path = exec_vma ? exec_vma->path : std::string();
        }
        return true;
    }
    return false;
}

}  // namespace horkos::inject
