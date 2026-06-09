/*
 * ac/src/selfcheck/veh_unwind_audit.cpp
 * Role: Signal 150 (Windows) — exception/VEH & unwind-table hijack audit. Validates
 *       VEH-list ordering (hook-free: register our own VEH FIRST and validate
 *       ordering, rather than traversing the undocumented LdrpVectorHandlerList) and
 *       re-parses our .pdata RUNTIME_FUNCTION table for critical functions vs the
 *       on-disk unwind tables.
 * Target platforms: Windows userspace; the live body is HK_PLATFORM_WINDOWS-guarded
 *       (the POSIX analog is sig_handler_audit.cpp). Compiled into hk_ac behind
 *       HK_SELFCHECK (guardrail #1).
 * Interface: emits HK_EVENT_SELF_VEH_UNWIND (hk_event_self_compat, signal_id 150).
 *       Uses the pure veh_handler_ordered_ahead core in self_logic.cpp.
 */

#include "horkos/selfcheck.h"
#include "self_wire.h"
#include "platform.h"

namespace hk {
namespace selfcheck {

#if defined(HK_SELFCHECK)

uint32_t veh_unwind_audit_run(uint64_t image_base, uint32_t exception_dir_rva) {
    (void)image_base;
    (void)exception_dir_rva;

#if defined(HK_PLATFORM_WINDOWS)
    /* HK-UNCERTAIN(veh-list): the live VEH ordering check + .pdata re-parse are not
     * wired. The PRIMARY (hook-free) approach is to register our own VEH first via
     * AddVectoredExceptionHandler(First=TRUE) and then validate that we are still
     * ordered first (our_handler_index==0, no foreign handler ahead) — the pure core
     * veh_handler_ordered_ahead() encodes that decision and is tested. Independently
     * re-parse IMAGE_DIRECTORY_ENTRY_EXCEPTION via RtlLookupFunctionEntry per critical
     * function and compare against the on-disk RUNTIME_FUNCTION array. The raw-list
     * traversal (LdrpVectorHandlerList / RtlpCalloutEntryList) is UNDOCUMENTED and is
     * NOT used (guardrail #13). FP gate (CLR/CEF/Crashpad/ASAN): assert only that OUR
     * critical-fn unwind entries are unmodified and no foreign handler is ordered
     * ahead — not the mere presence of other handlers. Left unimplemented until the
     * documented ordering-validation path is confirmed on-box. */
    return HK_SELF_FLAG_NONE;
#else
    return HK_SELF_FLAG_NONE;
#endif
}

#endif /* HK_SELFCHECK */

} // namespace selfcheck
} // namespace hk
