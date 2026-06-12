/*
 * Role: Signal 145 — cross-view .text hash divergence. Hashes our own .text three
 *       ways (in-process VA, kernel foreign read, relocated on-disk bytes) and emits
 *       the three SHA-256s + the agreement matrix + first-diff RVA as raw evidence.
 *       The kernel foreign read (View B) and the disk read (View C) cannot be
 *       restored-on-read by a usermode hook, so they catch a self-read-restoring
 *       hook that View A alone would miss. No verdict — the signed-overlay allow-list
 *       lives server-side.
 * Target platforms: all (orchestration; the kernel/daemon read routes through
 *       platform::selfcheck_kernel_read — guardrail #1). Compiled into hk_ac behind
 *       HK_SELFCHECK.
 * Interface: emits HK_EVENT_SELF_CROSSVIEW (hk_event_self_crossview). Uses the pure
 *       crossview cores in self_logic.cpp.
 */

#include "horkos/selfcheck.h"
#include "self_wire.h"
#include "platform.h"

namespace hk {
namespace selfcheck {

#if defined(HK_SELFCHECK)

/* Run signal 145 once. Returns HK_SELF_FLAG_CROSSVIEW if raw evidence was emitted,
 * else HK_SELF_FLAG_NONE. The three hashes are inputs computed by the three views;
 * this function is the orchestration that wires the (uncertain) live reads to the
 * pure match-matrix core.
 *
 * View A (in-process): SHA-256 our .text via the parsed header range.
 * View B (kernel): platform::selfcheck_kernel_read(HK_SELF_READ_BYTES, ...) returns
 *   BYTES (not a hash) so the AC hashes them — a hooked self-NtReadVirtualMemory
 *   cannot forge View B.
 * View C (disk): the relocated on-disk SHA-256 cached by image_baseline.
 */
uint32_t text_crossview_run(uint64_t image_base, uint32_t text_rva, uint32_t text_size,
                            const uint8_t* hash_disk_or_null) {
    (void)image_base;
    (void)text_rva;
    (void)text_size;

    /* HK-UNCERTAIN(crossview-reads): View A (in-process hash of our .text) and
     * View B (kernel foreign-read bytes) are not sampled yet. View A needs the live
     * .text VA hashed with a SHA-256 primitive; View B needs
     * platform::selfcheck_kernel_read(HK_SELF_READ_BYTES, ...), which returns 0
     * (unavailable) until the HK_IOCTL_SELF_READ_VA caller-identity gate lands
     * (platform_*.cpp). Until both views are real, this sensor cannot produce a
     * trustworthy match matrix, so it emits nothing (fail-closed) rather than
     * reporting an in-process-only view the catalog explicitly forbids trusting.
     *
     * The pure decision core IS wired and tested: once the three hashes exist,
     *   uint32_t mm = crossview_match_matrix(hA, hB, hC);
     *   CrossViewClass cls = crossview_classify(mm);
     *   if (cls != CrossViewClass::AllAgree) { emit hk_event_self_crossview; }
     * with first_diff_rva = first differing byte of the diverging pair. The emit
     * rides the large-record drain plane (pre-Schema; see self_wire.h), so the
     * emit itself activates with that plane. */
    (void)hash_disk_or_null;
    return HK_SELF_FLAG_NONE;
}

#endif /* HK_SELFCHECK */

} // namespace selfcheck
} // namespace hk
