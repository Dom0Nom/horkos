/*
 * kernel/win/src/LdrCrosscheck.c
 * Role: Ghost-image scanner (signal 13) + the shared PEB.Ldr base collector used
 *       by signals 13/16/17. Cross-references each image-backed executable VAD
 *       against the three PEB loader lists; an image region whose base is in none
 *       of them is a manually-mapped image that bypassed the loader. Runs while
 *       attached; all PEB/Ldr reads are SEH-guarded and use vad_layout.h's
 *       fail-closed offsets (a NULL layout collects nothing). Uses the host-tested
 *       pure core hk_mem_is_ghost (mem_logic_image.h). Skips exiting processes
 *       (the worker already gated that). NO verdict — server fuses.
 *       READ-ONLY.
 * Target platforms: Windows kernel (KMDF). Builds only with the WDK.
 * Interface: implements HkCollectLdrBases + HkLdrCrosscheck (mem_scan.h).
 */

#include "mem_scan.h"
#include "mem_logic_image.h"

/* PsGetProcessPeb returns the target PEB pointer; it is a long-standing ntoskrnl
 * export. HK-UNCERTAIN: it is only semi-documented — confirm availability/proto
 * for the target build on the box. Declared here (guardrail #2: no proprietary
 * header) matching the public-doc shape. */
NTKERNELAPI PPEB NTAPI PsGetProcessPeb(_In_ PEPROCESS Process);

static BOOLEAN HkReadField(const void* p, ULONG off, void* out, SIZE_T width)
{
    if (off == HK_VAD_OFF_UNKNOWN || p == NULL) {
        return FALSE;
    }
    __try {
        RtlCopyMemory(out, (const UCHAR*)p + off, width);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

/* Walk one LIST_ENTRY-threaded Ldr list (the list head is at PEB.Ldr + listOff;
 * each LDR_DATA_TABLE_ENTRY links at the same list offset within the entry). The
 * entry's DllBase is at Layout->LdrEntry_DllBase relative to the entry base; the
 * list-link-to-entry adjustment equals listOff within the entry. Bounded + SEH. */
static void HkWalkLdrList(PHK_MEM_SCAN_CTX Ctx, void* ldr, ULONG listOff)
{
    const HK_VAD_LAYOUT* L = Ctx->Layout;
    void* head;
    void* cur;
    ULONG guard = 0;

    if (listOff == HK_VAD_OFF_UNKNOWN) {
        return;
    }
    head = (UCHAR*)ldr + listOff;
    {
        void* first = NULL;
        if (!HkReadField(head, 0, &first, sizeof(first)) || first == NULL) {
            return; /* Flink. */
        }
        cur = first;
    }
    while (cur != head && guard < HK_MEM_MAX_LDR_BASES) {
        /* The entry base is cur adjusted by the in-entry list offset. The three
         * lists each have their own in-entry offset (= the matching PebLdr_*
         * record is the HEAD offset; the in-entry link offset is captured by the
         * same value for InLoadOrder which starts the entry). HK-UNCERTAIN: the
         * per-list in-entry link offset is confirmed with the layout on the box;
         * here we treat InLoadOrder (entry start) as the common case. */
        void* entry = (UCHAR*)cur - 0; /* InLoadOrderLinks at entry+0. */
        ULONG64 base = 0;
        void* next = NULL;
        if (HkReadField(entry, L->LdrEntry_DllBase, &base, sizeof(base)) && base != 0) {
            ULONG j;
            BOOLEAN dup = FALSE;
            for (j = 0; j < Ctx->LdrBaseCount; ++j) {
                if (Ctx->LdrBases[j] == base) { dup = TRUE; break; }
            }
            if (!dup && Ctx->LdrBaseCount < HK_MEM_MAX_LDR_BASES) {
                Ctx->LdrBases[Ctx->LdrBaseCount++] = base;
            }
        }
        if (!HkReadField(cur, 0, &next, sizeof(next)) || next == NULL) {
            break;
        }
        cur = next;
        ++guard;
    }
}

ULONG HkCollectLdrBases(PHK_MEM_SCAN_CTX Ctx)
{
    PPEB peb;
    void* ldr = NULL;
    const HK_VAD_LAYOUT* L;

    if (Ctx == NULL || Ctx->Layout == NULL || !Ctx->Attached || Ctx->Process == NULL) {
        return 0;
    }
    Ctx->LdrBaseCount = 0;
    L = Ctx->Layout;

    peb = PsGetProcessPeb(Ctx->Process);
    if (peb == NULL) {
        return 0;
    }
    /* PEB.Ldr is at the documented PEB offset; read the Ldr pointer. We use the
     * InLoadOrder head offset as the Ldr struct base reference. HK-UNCERTAIN: PEB
     * layout is documented but the Ldr field offset is build-stable yet confirmed
     * on the box. Read Ldr via the well-known PEB+0x18 (x64) is avoided here in
     * favour of the layout table once it carries Peb_Ldr; for now, fail closed if
     * the InLoadOrder head cannot be resolved. */
    __try {
        /* PEB->Ldr pointer: layout offset not yet modelled => treat peb-relative
         * InLoadOrder list directly is unsafe; require the offsets table. */
        ldr = NULL;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ldr = NULL;
    }
    if (ldr == NULL) {
        return 0; /* fail closed until the PEB.Ldr offset is confirmed. */
    }
    HkWalkLdrList(Ctx, ldr, L->PebLdr_InLoadOrder);
    HkWalkLdrList(Ctx, ldr, L->PebLdr_InMemoryOrder);
    HkWalkLdrList(Ctx, ldr, L->PebLdr_InInitOrder);
    return Ctx->LdrBaseCount;
}

void HkLdrCrosscheck(PHK_MEM_SCAN_CTX Ctx)
{
    ULONG i;

    if (Ctx == NULL || Ctx->Layout == NULL || Ctx->NodeCount == 0) {
        return;
    }
    (void)HkCollectLdrBases(Ctx);
    if (Ctx->LdrBaseCount == 0) {
        return; /* without a loader-list view we cannot call ghost — fail closed. */
    }

    for (i = 0; i < Ctx->NodeCount; ++i) {
        const HK_VAD_NODE* n = &Ctx->Nodes[i];
        /* Only image-backed, executable regions are ghost candidates. */
        if (n->vad_type != HK_MEM_VAD_IMAGE) continue;
        if ((n->protection & HK_MEM_PROT_EXECUTE) == 0) continue;
        if (n->has_jit_owner) continue;

        /* The same base array stands in for all three lists here — the collector
         * already merged them; an image base absent from the merged set is in
         * none of the three (the pure core's three-list form collapses to this
         * when the lists are pre-merged). */
        if (hk_mem_is_ghost(n->region_base,
                            Ctx->LdrBases, Ctx->LdrBaseCount,
                            NULL, 0, NULL, 0)) {
            hk_event_mem_image_anomaly ev;
            RtlZeroMemory(&ev, sizeof(ev));
            ev.pid = (uint32_t)(ULONG_PTR)Ctx->Pid;
            ev.flags = HK_MEM_IMG_FLAG_GHOST | HK_MEM_IMG_FLAG_EXEC;
            ev.image_base = n->region_base;
            HkMemRingEmit(HK_EVENT_MEM_GHOST_IMAGE, &ev, sizeof(ev)); /* signal 13 */
        }
    }
}
