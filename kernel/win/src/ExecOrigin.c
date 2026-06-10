/*
 * kernel/win/src/ExecOrigin.c
 * Role: Execution-origin scanner (signal 17). Resolves each thread's Win32 start
 *       address (preferring the documented ZwQueryInformationThread /
 *       ThreadQuerySetWin32StartAddress over the build-varying ETHREAD field) and
 *       each loaded module's TLS callbacks, maps each target through the VAD
 *       array, and flags origins that resolve into an unbacked region. Uses the
 *       host-tested pure core hk_mem_origin_is_anon (mem_logic_image.h). NO
 *       verdict.
 *       READ-ONLY.
 *
 *       HK-UNCERTAIN: per-thread enumeration of a foreign process + the start-
 *       address query path must be confirmed on the Windows box (the ETHREAD
 *       offset in vad_layout.h is the fail-closed fallback only). Until then no
 *       thread origins are produced and nothing is emitted.
 * Target platforms: Windows kernel (KMDF). Builds only with the WDK.
 * Interface: implements HkExecOrigin from mem_scan.h.
 */

#include "mem_scan.h"
#include "mem_logic_image.h"

/* Resolve which VAD a target address falls into and return its normalized
 * vad_type (HK_MEM_VAD_OTHER if none/unbacked-anon resolves to NONE). */
static uint32_t HkResolveOriginVadType(PHK_MEM_SCAN_CTX Ctx, ULONG64 addr, int* has_jit)
{
    ULONG i;
    *has_jit = 0;
    for (i = 0; i < Ctx->NodeCount; ++i) {
        const HK_VAD_NODE* n = &Ctx->Nodes[i];
        if (addr >= n->region_base && addr < n->region_base + n->region_size) {
            *has_jit = n->has_jit_owner ? 1 : 0;
            return n->vad_type;
        }
    }
    return HK_MEM_VAD_NONE; /* resolves into no known VAD => treat as anon. */
}

static void HkEmitOrigin(PHK_MEM_SCAN_CTX Ctx, uint32_t tid, ULONG64 start, uint32_t flags)
{
    int has_jit = 0;
    uint32_t vt = HkResolveOriginVadType(Ctx, start, &has_jit);
    if (hk_mem_origin_is_anon(vt, has_jit)) {
        hk_event_mem_exec_origin ev;
        RtlZeroMemory(&ev, sizeof(ev));
        ev.pid = (uint32_t)(ULONG_PTR)Ctx->Pid;
        ev.thread_id = tid;
        ev.start_address = start;
        ev.resolved_vad_type = vt;
        ev.flags = flags | HK_MEM_ORIGIN_FLAG_ANON | (has_jit ? HK_MEM_ORIGIN_FLAG_HAS_JIT_OWNER : 0u);
        HkMemRingEmit(HK_EVENT_MEM_EXEC_ORIGIN_ANON, &ev, sizeof(ev)); /* signal 17 */
    }
}

void HkExecOrigin(PHK_MEM_SCAN_CTX Ctx)
{
    if (Ctx == NULL || Ctx->Layout == NULL || Ctx->NodeCount == 0) {
        return; /* fail closed. */
    }
    /* HK-UNCERTAIN (confirm on the box): enumerate the target's threads and read
     * each Win32 start address via ZwQueryInformationThread(
     * ThreadQuerySetWin32StartAddress); enumerate each module's
     * IMAGE_TLS_DIRECTORY AddressOfCallBacks. Until that enumeration is wired,
     * no origins are produced. The classifier path (HkEmitOrigin) is complete and
     * host-tested via mem_logic_image.h so it is ready the moment thread/TLS
     * enumeration lands. */
    (void)HkEmitOrigin;
}
