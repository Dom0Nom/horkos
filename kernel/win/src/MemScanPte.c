/*
 * Role: W^X divergence scanner (signal 11). For committed pages of a VAD it
 *       resolves the leaf-PTE execute state and compares it against the VAD's
 *       declared protection; a divergence (VAD says non-exec, live PTE says exec,
 *       or vice-versa) is the W^X-flip shape. Sampled, never hot-polled (racing a
 *       legitimate VirtualProtect would false-positive). Emits hk_event_mem_wx.
 *       NO verdict.
 *       READ-ONLY.
 *
 *       HK-UNCERTAIN (plan UNCERTAINTY FLAG): deriving the leaf PTE / NX bit
 *       relies on the non-exported, build-varying PTE_BASE. The documented
 *       MmGetPhysicalAddress per sampled page is used to confirm a page is
 *       committed, but the NX-bit read itself is not reachable through a
 *       documented path and must be confirmed on the Windows box. Until then the
 *       PTE-exec input is left equal to the VAD-exec input (no divergence) and
 *       nothing is emitted — never a guessed positive that could BSOD.
 * Target platforms: Windows kernel (KMDF). Builds only with the WDK.
 * Interface: implements HkMemScanPte from mem_scan.h.
 */

#include "mem_scan.h"

void HkMemScanPte(PHK_MEM_SCAN_CTX Ctx)
{
    ULONG i;

    if (Ctx == NULL || Ctx->Layout == NULL || Ctx->NodeCount == 0) {
        return; /* fail closed. */
    }

    for (i = 0; i < Ctx->NodeCount; ++i) {
        const HK_VAD_NODE* n = &Ctx->Nodes[i];
        uint32_t vad_says_exec = (n->protection & HK_MEM_PROT_EXECUTE) ? 1u : 0u;
        uint32_t pte_says_exec;
        PHYSICAL_ADDRESS phys;

        if (n->region_size == 0) continue;

        /* Confirm the first page is committed via the documented call (we are
         * attached, so the VA is the target's). MmGetPhysicalAddress returns 0
         * for a non-resident/invalid page. */
        __try {
            phys = MmGetPhysicalAddress((PVOID)(ULONG_PTR)n->region_base);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            continue;
        }
        if (phys.QuadPart == 0) {
            continue; /* not resident — nothing to compare this tick. */
        }

        /* HK-UNCERTAIN: leaf-PTE NX read not on a documented path -> set the PTE
         * exec state equal to the VAD's so no divergence is fabricated. The box
         * session wires the confirmed NX read here. */
        pte_says_exec = vad_says_exec;

        if (vad_says_exec != pte_says_exec) {
            hk_event_mem_wx ev;
            RtlZeroMemory(&ev, sizeof(ev));
            ev.region.pid = (uint32_t)(ULONG_PTR)Ctx->Pid;
            ev.region.vad_type = n->vad_type;
            ev.region.region_base = n->region_base;
            ev.region.region_size = n->region_size;
            ev.region.protection = n->protection;
            ev.vad_says_exec = vad_says_exec;
            ev.pte_says_exec = pte_says_exec;
            HkMemRingEmit(HK_EVENT_MEM_WX_DIVERGENCE, &ev, sizeof(ev)); /* signal 11 */
        }
    }
}
