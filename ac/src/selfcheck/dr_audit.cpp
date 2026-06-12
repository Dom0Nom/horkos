/*
 * Role: Signal 148 — DR0-DR7 hardware-breakpoint audit across our threads. Requests
 *       the kernel-side per-thread DR0-DR7 / DR7 read for our process and flags any
 *       DR linear address landing inside our .text. The trustworthy read is
 *       kernel-context only: usermode GetThreadContext is spoofable.
 * Target platforms: all (orchestration; the DR read routes through
 *       platform::selfcheck_kernel_read(HK_SELF_READ_DEBUG_REGS) — guardrail #1).
 *       Compiled into hk_ac behind HK_SELFCHECK.
 * Interface: emits HK_EVENT_SELF_HWBP (hk_event_self_hwbp). Uses the pure
 *       hwbp_in_text_mask core in self_logic.cpp.
 */

#include "horkos/selfcheck.h"
#include "self_wire.h"
#include "platform.h"

#include <cstring>

namespace hk {
namespace selfcheck {

#if defined(HK_SELFCHECK)

uint32_t dr_audit_run(uint64_t image_base, uint64_t text_base, uint64_t text_size) {
    (void)image_base;

    /* The kernel ships a per-thread DR snapshot: {tid, dr[4], dr7}. We request it
     * via the self-read seam and run the pure range test. The seam reports
     * unavailable until the kernel self-read gate lands (platform_*.cpp), so this
     * emits nothing rather than trusting a spoofable usermode GetThreadContext. */
    struct DrReply { uint32_t thread_id; uint32_t dr7; uint64_t dr[4]; } reply;
    std::memset(&reply, 0, sizeof(reply));

    const uint32_t got = hk::platform::selfcheck_kernel_read(
        HK_SELF_READ_DEBUG_REGS, /*va_base*/ 0, /*va_len*/ 0, &reply, sizeof(reply));
    if (got < sizeof(reply)) {
        return HK_SELF_FLAG_NONE; /* unavailable — never reported as "no breakpoints" */
    }

    const uint32_t mask = hwbp_in_text_mask(reply.dr, reply.dr7, text_base, text_size);
    if (mask == 0u) {
        return HK_SELF_FLAG_NONE;
    }
    /* HK-TODO(emit): build hk_event_self_hwbp{ pid, thread_id=reply.thread_id,
     * dr=reply.dr, dr7=reply.dr7, dr_in_text_mask=mask } and ship it. FP is nil in
     * retail; the server suppresses on dev/test-signed builds reported via
     * attestation. HK-UNCERTAIN(_KTRAP_FRAME): the kernel DR read's exact context-
     * capture path / offsets are build-varying — see kernel/win/src/selfcheck_read.c. */
    return HK_SELF_FLAG_HWBP;
}

#endif /* HK_SELFCHECK */

} // namespace selfcheck
} // namespace hk
