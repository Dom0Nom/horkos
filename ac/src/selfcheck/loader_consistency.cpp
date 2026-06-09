/*
 * ac/src/selfcheck/loader_consistency.cpp
 * Role: Signal 151 — loader-structure consistency. Cross-checks our loader entry
 *       (PEB Ldr / link_map / dyld_all_image_infos) base/size/entrypoint/path against
 *       the in-memory headers we re-parse, the kernel section-object query, and disk.
 *       Flags list-vs-list inconsistency (unlinking) or entrypoint mismatch — not path
 *       cosmetics (App-V/MSIX virtualization layers are accepted).
 * Target platforms: all (orchestration; the kernel image-file-name routes through
 *       platform::module_image_file_name — guardrail #1). Compiled into hk_ac behind
 *       HK_SELFCHECK.
 * Interface: emits HK_EVENT_SELF_LOADER (hk_event_self_compat, signal_id 151).
 */

#include "horkos/selfcheck.h"
#include "self_wire.h"
#include "platform.h"

namespace hk {
namespace selfcheck {

#if defined(HK_SELFCHECK)

uint32_t loader_consistency_run(uint64_t image_base, uint32_t size_of_image,
                                uint32_t entry_point_rva) {
    (void)image_base;
    (void)size_of_image;
    (void)entry_point_rva;

    /* HK-UNCERTAIN(loader-walk): the live loader-structure walk is not wired. Win:
     * PEB->Ldr InLoad/InMemory/InInit lists (+ hash buckets) for our module vs the
     * re-parsed IMAGE_NT_HEADERS vs the kernel section-object query
     * (platform::module_image_file_name -> HK_SELF_READ_IMAGE_FILE) vs ReadFile of
     * disk headers. Linux: link_map(r_debug) vs /proc/self/maps vs DSO file. macOS:
     * dyld_all_image_infos vs mach_vm_region vs file. The decision rule is:
     * treat list-vs-list inconsistency (unlinking) or entrypoint mismatch as the real
     * signal; canonicalize the path (GetFinalPathNameByHandle) and accept known
     * virtualization layers — path cosmetics are NOT the signal. The kernel
     * section-object half routes through the self-read seam, which is unavailable
     * today (platform_*.cpp), so this emits nothing rather than reporting a
     * one-sided, spoofable PEB view. Left unimplemented per guardrail #13 until the
     * per-OS loader walk + the kernel cross-check land. */
    return HK_SELF_FLAG_NONE;
}

#endif /* HK_SELFCHECK */

} // namespace selfcheck
} // namespace hk
