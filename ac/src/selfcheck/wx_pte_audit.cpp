/*
 * Role: Signal 152 — self-image W^X / PTE protection-drift audit. Correlates the
 *       usermode protection view (VirtualQuery / /proc/self/maps / mach_vm_region)
 *       with the kernel PTE write/NX read of the same VAs and flags ONLY on
 *       disagreement for our image — legitimate software does not produce a
 *       kernel-says-writable / usermode-says-RX split on our own code.
 * Target platforms: all (orchestration; the kernel PTE read routes through
 *       platform::selfcheck_kernel_read(HK_SELF_READ_PTE_PROT) — guardrail #1).
 *       Compiled into hk_ac behind HK_SELFCHECK.
 * Interface: emits HK_EVENT_SELF_WX_DRIFT (hk_event_self_compat, signal_id 152).
 */

#include "horkos/selfcheck.h"
#include "self_wire.h"
#include "platform.h"

#include <cstring>

namespace hk {
namespace selfcheck {

#if defined(HK_SELFCHECK)

uint32_t wx_pte_audit_run(uint64_t image_base, uint64_t text_base, uint64_t text_size) {
    (void)image_base;
    (void)text_size;

    /* The trustworthy half is the kernel leaf-PTE write/NX read. It routes through
     * the self-read seam and is unavailable today (the gate is unsettled AND the
     * leaf-PTE derivation itself is API-uncertain — see selfcheck_read.c §152). We
     * therefore emit nothing rather than reporting the spoofable usermode prot view. */
    struct PteReply { uint32_t kernel_prot; uint32_t usermode_prot; } reply;
    std::memset(&reply, 0, sizeof(reply));

    const uint32_t got = hk::platform::selfcheck_kernel_read(
        HK_SELF_READ_PTE_PROT, text_base, text_size, &reply, sizeof(reply));
    if (got < sizeof(reply)) {
        return HK_SELF_FLAG_NONE;
    }

    /* Flag only on disagreement: kernel reports writable/NX-cleared on a page the
     * usermode view still calls read-execute. */
    uint32_t flags = 0u;
    if (reply.kernel_prot & HK_SELF_WX_KERNEL_WRITABLE) flags |= HK_SELF_WX_KERNEL_WRITABLE;
    if (reply.kernel_prot & HK_SELF_WX_KERNEL_NX_CLEARED) flags |= HK_SELF_WX_KERNEL_NX_CLEARED;
    if (reply.usermode_prot & HK_SELF_WX_USERMODE_RX) flags |= HK_SELF_WX_USERMODE_RX;

    const bool disagreement =
        (flags & (HK_SELF_WX_KERNEL_WRITABLE | HK_SELF_WX_KERNEL_NX_CLEARED)) &&
        (flags & HK_SELF_WX_USERMODE_RX);
    if (!disagreement) {
        return HK_SELF_FLAG_NONE;
    }
    /* HK-TODO(emit): hk_event_self_compat{ signal_id=152, actual_va=kernel_prot,
     * expected_va=usermode_prot, flags } over the large-record plane. */
    return HK_SELF_FLAG_WX_DRIFT;
}

#endif /* HK_SELFCHECK */

} // namespace selfcheck
} // namespace hk
