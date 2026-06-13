/*
 * Role: Signal 147 — return-address provenance / shadow-stack mismatch at our
 *       annotated critical-function prologues (HK_GUARD_ENTRY). Captures the call
 *       stack, attributes each frame to a signed module, and cross-checks the CET
 *       shadow stack. FP risk is high (overlays/profilers/JIT), so the sensor surface
 *       is narrow: only OUR critical prologues, only the immediate-caller rule fires,
 *       and the server alerts only when correlated with a concurrent 145/149/150
 *       signature failure. hk_obfuscate applies here (guardrail #9).
 * Target platforms: all (orchestration; unwind + module attribution route through
 *       platform backends — guardrail #1). Compiled into hk_ac behind HK_SELFCHECK.
 * Interface: provides the body the HK_GUARD_ENTRY macro forwards to; emits
 *       HK_EVENT_SELF_RETADDR (hk_event_self_retaddr). Uses the pure
 *       retaddr_first_unsigned_frame core in self_logic.cpp.
 */

#include "horkos/selfcheck.h"
#include "self_wire.h"

namespace hk {
namespace selfcheck {

#if defined(HK_SELFCHECK)

/* Capture + classify one guarded entry. Annotated for the opt-in LLVM-19 pass
 * (guardrail #9) — this is an integrity symbol, not the game hot loop. Inputs are
 * the already-captured frame signedness array (from the platform unwind +
 * module-attribution backend); the pure core applies the immediate-caller rule. */
uint32_t retaddr_provenance_classify(uint32_t guarded_fn_id,
                                     const uint8_t* frame_is_signed,
                                     uint16_t frame_count,
                                     uint32_t shadow_stack_mismatch)
    HK_SELF_ANNOTATE_OBFUSCATE;

uint32_t retaddr_provenance_classify(uint32_t guarded_fn_id,
                                     const uint8_t* frame_is_signed,
                                     uint16_t frame_count,
                                     uint32_t shadow_stack_mismatch) {
    (void)guarded_fn_id;

    const uint16_t first_unsigned = retaddr_first_unsigned_frame(frame_is_signed, frame_count);
    /* Raw evidence is emitted when there is an unsigned/private frame OR the CET
     * shadow-stack cross-check disagrees. The server applies the immediate-caller +
     * concurrent-signature-failure gate; the client only ships the evidence. */
    if (first_unsigned == HK_SELF_FRAME_NONE && shadow_stack_mismatch == 0u) {
        return HK_SELF_FLAG_NONE;
    }
    /* HK-TODO(emit): hk_event_self_retaddr{ pid, guarded_fn_id, frames[], frame_count,
     * unsigned_frame_idx=first_unsigned, shadow_stack_mismatch } over the large-record
     * plane.
     *
     * HK-UNCERTAIN(stack-capture): the live capture is not wired. Win:
     * RtlCaptureStackBackTrace / RtlVirtualUnwind over .pdata + RtlPcToFileHeader
     * attribution; CET SSP read via the documented usermode path only when CET is
     * active (absence of CET MUST degrade to "shadow-stack check skipped", never a
     * fault — confirm the documented RDSSP availability path). Linux:
     * _Unwind_Backtrace + dl_iterate_phdr. macOS: backtrace()/__builtin_return_address
     * + dladdr. Left unimplemented per guardrail #12 until the per-OS unwind +
     * CET-availability contract is confirmed. */
    return HK_SELF_FLAG_RETADDR;
}

#endif /* HK_SELFCHECK */

} // namespace selfcheck
} // namespace hk
