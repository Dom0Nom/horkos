/*
 * Role: Signal 150 (Linux/macOS) — validate our SIGTRAP/SIGSEGV sigaction handlers
 *       resolve into our own text and are not chained ahead of by an injected
 *       handler. The POSIX analog of the Windows VEH/unwind audit.
 * Target platforms: POSIX userspace; the live body is HK_PLATFORM_LINUX/MACOS-
 *       guarded (the Windows analog is veh_unwind_audit.cpp). Compiled into hk_ac
 *       behind HK_SELFCHECK (guardrail #1).
 * Interface: emits HK_EVENT_SELF_VEH_UNWIND (hk_event_self_compat, signal_id 150;
 *       posix detail bits). Uses the pure veh_handler_ordered_ahead core.
 */

#include "horkos/selfcheck.h"
#include "self_wire.h"
#include "platform.h"

namespace hk {
namespace selfcheck {

#if defined(HK_SELFCHECK)

uint32_t sig_handler_audit_run(uint64_t image_base, uint64_t text_base, uint64_t text_size) {
    (void)image_base;
    (void)text_base;
    (void)text_size;

#if defined(HK_PLATFORM_LINUX) || defined(HK_PLATFORM_MACOS)
    /* HK-UNCERTAIN(sigaction-chain): the live sigaction(SA_SIGINFO) read for the
     * SIGTRAP/SIGSEGV handlers we rely on + the in-text resolution check + the
     * "foreign handler chained ahead" determination are not wired. The pure ordering
     * core (veh_handler_ordered_ahead) is shared with the Windows path and tested.
     * FP gate (sanitizer/CLR/Crashpad signal handlers): assert only that no foreign
     * handler is ordered ahead of ours on the signals we depend on — not the presence
     * of other handlers. Left unimplemented until the per-OS sigaction inspection +
     * handler-PC attribution are confirmed. */
    return HK_SELF_FLAG_NONE;
#else
    return HK_SELF_FLAG_NONE;
#endif
}

#endif /* HK_SELFCHECK */

} // namespace selfcheck
} // namespace hk
