/*
 * kernel/win/src/MemScanVad.c
 * Role: VAD-classification scanner for signals 10 (unbacked executable region),
 *       14 (oversized private executable commit) and 15 (exotic VadType / large-
 *       page executable). Consumes the normalized HK_VAD_NODE array produced by
 *       VadWalk.c (while attached) and runs the host-tested pure classifiers
 *       (mem_logic_vad.h), emitting raw hk_mem_region evidence on the mem ring.
 *       NO verdict — the server fuses and decides.
 *       READ-ONLY: classifies already-sampled nodes; mutates nothing.
 * Target platforms: Windows kernel (KMDF). Builds only with the WDK.
 * Interface: implements HkMemScanVad from mem_scan.h, over mem_logic_vad.h.
 */

#include "mem_scan.h"
#include "mem_logic_vad.h"

static void HkEmitRegion(uint32_t type, HANDLE pid, const HK_VAD_NODE* n)
{
    hk_mem_region r;
    RtlZeroMemory(&r, sizeof(r));
    r.pid = (uint32_t)(ULONG_PTR)pid;
    r.vad_type = n->vad_type;
    r.region_base = n->region_base;
    r.region_size = n->region_size;
    r.protection = n->protection;
    r.flags = hk_mem_region_flags(n);
    HkMemRingEmit(type, &r, sizeof(r));
}

void HkMemScanVad(PHK_MEM_SCAN_CTX Ctx)
{
    ULONG i;
    uint64_t private_exec_total;

    if (Ctx == NULL || Ctx->Layout == NULL || Ctx->NodeCount == 0) {
        return; /* fail closed on unconfirmed build / empty walk. */
    }

    for (i = 0; i < Ctx->NodeCount; ++i) {
        const HK_VAD_NODE* n = &Ctx->Nodes[i];
        if (hk_mem_is_unbacked_exec(n)) {
            HkEmitRegion(HK_EVENT_MEM_UNBACKED_EXEC, Ctx->Pid, n);   /* signal 10 */
        }
        if (hk_mem_is_exotic_exec(n)) {
            HkEmitRegion(HK_EVENT_MEM_EXOTIC_VAD, Ctx->Pid, n);      /* signal 15 */
        }
    }

    /* Signal 14: per-region private-exec sizes are already carried by the
     * unbacked/region emits above; emit one aggregate region whose region_size is
     * the process-wide private-exec commit (region_base 0 marks the aggregate).
     * The server baselines the aggregate per title — no kernel threshold. */
    private_exec_total = hk_mem_sum_private_exec_bytes(Ctx->Nodes, Ctx->NodeCount);
    if (private_exec_total > 0) {
        hk_mem_region agg;
        RtlZeroMemory(&agg, sizeof(agg));
        agg.pid = (uint32_t)(ULONG_PTR)Ctx->Pid;
        agg.vad_type = HK_MEM_VAD_NONE;
        agg.region_base = 0; /* aggregate marker. */
        agg.region_size = private_exec_total;
        agg.protection = HK_MEM_PROT_EXECUTE;
        HkMemRingEmit(HK_EVENT_MEM_PRIV_EXEC_COMMIT, &agg, sizeof(agg)); /* signal 14 */
    }
}
