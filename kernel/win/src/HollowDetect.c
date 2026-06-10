/*
 * kernel/win/src/HollowDetect.c
 * Role: Hollow/doppelgang backing scanner (signal 16). For each image-backed
 *       executable VAD that contains the entry point, compares the backing
 *       FILE_OBJECT name against the Ldr-recorded path and probes delete-pending
 *       / transacted state; the combined gate (exec + entry-region + a backing
 *       anomaly) is the hollowing shape. Uses the host-tested pure cores
 *       hk_mem_is_hollow / hk_mem_hollow_flags (mem_logic_image.h). NO verdict.
 *       READ-ONLY.
 *
 *       HK-UNCERTAIN: reading ControlArea->FilePointer->FileName and the
 *       FILE_OBJECT DeletePending / transacted state from the attached context is
 *       offset- and lifetime-sensitive (vad_layout.h fail-closed; ZwQueryInfo-
 *       rmationFile must run detached at PASSIVE_LEVEL). Until the backing-state
 *       reads are confirmed on the Windows box, the anomaly inputs stay 0 and the
 *       combined gate emits nothing — by design.
 * Target platforms: Windows kernel (KMDF). Builds only with the WDK.
 * Interface: implements HkHollowDetect from mem_scan.h.
 */

#include "mem_scan.h"
#include "mem_logic_image.h"

void HkHollowDetect(PHK_MEM_SCAN_CTX Ctx)
{
    ULONG i;

    if (Ctx == NULL || Ctx->Layout == NULL || Ctx->NodeCount == 0) {
        return; /* fail closed. */
    }

    for (i = 0; i < Ctx->NodeCount; ++i) {
        const HK_VAD_NODE* n = &Ctx->Nodes[i];
        int exec, entry_region, delete_pending, transacted, name_mismatch;

        if (n->vad_type != HK_MEM_VAD_IMAGE) continue;
        exec = (n->protection & HK_MEM_PROT_EXECUTE) != 0 ? 1 : 0;
        if (!exec) continue;

        /* HK-UNCERTAIN backing-state reads (confirm on the box): until the
         * FILE_OBJECT name compare + DeletePending/transaction probe is wired,
         * these stay 0 and the gate cannot fire — never a guessed positive. */
        entry_region = 0;   /* TODO(box): region contains AddressOfEntryPoint. */
        delete_pending = 0; /* TODO(box): ZwQueryInformationFile DeletePending. */
        transacted = 0;     /* TODO(box): FILE_OBJECT transaction state. */
        name_mismatch = 0;  /* TODO(box): ControlArea FileName vs Ldr path. */

        if (hk_mem_is_hollow(exec, entry_region, delete_pending, transacted, name_mismatch)) {
            hk_event_mem_image_anomaly ev;
            RtlZeroMemory(&ev, sizeof(ev));
            ev.pid = (uint32_t)(ULONG_PTR)Ctx->Pid;
            ev.flags = hk_mem_hollow_flags(exec, entry_region, delete_pending,
                                           transacted, name_mismatch, n->has_jit_owner);
            ev.image_base = n->region_base;
            HkMemRingEmit(HK_EVENT_MEM_HOLLOW_BACKING, &ev, sizeof(ev)); /* signal 16 */
        }
    }
}
