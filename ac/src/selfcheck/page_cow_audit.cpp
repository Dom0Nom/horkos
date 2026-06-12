/*
 * Role: Signal 146 — per-page Dirty/CoW audit on our read-only code pages (no byte
 *       hashing). Queries the share / private-dirty / CoW state of our .text pages
 *       and emits the private/dirty page counts as raw evidence. Catches a frame the
 *       OS already split that no restore-on-read hook can un-private.
 * Target platforms: all (per-OS page-state read via platform::page_share_state —
 *       guardrail #1). Compiled into hk_ac behind HK_SELFCHECK.
 * Interface: emits HK_EVENT_SELF_PAGE_COW (hk_event_self_page_cow). Uses the pure
 *       page_cow_has_evidence core in self_logic.cpp.
 */

#include "horkos/selfcheck.h"
#include "self_wire.h"
#include "platform.h"

namespace hk {
namespace selfcheck {

#if defined(HK_SELFCHECK)

uint32_t page_cow_audit_run(uint64_t image_base, uint64_t text_base, uint64_t text_size) {
    (void)image_base;

    uint32_t private_pages = 0;
    uint32_t dirty_pages = 0;
    /* The trustworthy share/CoW read is kernel-side (Win PFN share-count / MMPTE,
     * Linux soft-dirty over the AC task, macOS mach_vm_region_recurse SM_COW). It
     * routes through the platform seam; on every host today it reports unavailable
     * (the kernel/daemon self-read gate is unsettled — see platform_*.cpp), so we
     * emit nothing rather than trusting the spoofable usermode page-share view. */
    if (!hk::platform::page_share_state(text_base, text_size, &private_pages, &dirty_pages)) {
        return HK_SELF_FLAG_NONE; /* unavailable — never reported as "clean" */
    }

    if (!page_cow_has_evidence(private_pages, dirty_pages)) {
        return HK_SELF_FLAG_NONE;
    }
    /* HK-TODO(emit): build hk_event_self_page_cow{ pid, page_count, image_base,
     * region_base=text_base, private_pages, dirty_pages } and ship it over the
     * large-record drain plane (pre-Schema; see self_wire.h). The FP gate
     * (apphelp shim / signed hotpatch) is server-side, correlated with 145. */
    return HK_SELF_FLAG_PAGE_COW;
}

#endif /* HK_SELFCHECK */

} // namespace selfcheck
} // namespace hk
