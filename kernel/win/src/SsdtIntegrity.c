/*
 * kernel/win/src/SsdtIntegrity.c
 * Role: Signal 35 — SSDT range integrity check. Decodes each KiServiceTable
 *       entry (x64 packed-offset form, via the pure HkSsdtDecodeTarget) and
 *       verifies the resolved target lands inside ntoskrnl per the ModuleMap. An
 *       out-of-image entry on an HVCI/PatchGuard system is high-confidence (the
 *       OS would otherwise have bugchecked). READ-ONLY — no table writes (the
 *       sensor only decodes and range-checks; it never modifies KiServiceTable).
 *       The shadow SSDT (win32k) half is DEFERRED (plan Risk 3): its table base
 *       is unexported and locating it safely is undocumented.
 * Target platforms: Windows kernel mode (KMDF).
 * Interface: implements HkSsdtIntegrityScan declared in
 *       kernel/win/include/horkos_kernel.h. Depends on the shared ModuleMap.
 *       No-op when HK_WIN_INTEGRITY_SSDT is not defined. Emits
 *       hk_event_integrity_finding.
 */

#include <ntddk.h>
#include <wdf.h>

#include "horkos_kernel.h"

#if defined(HK_WIN_INTEGRITY_SSDT)

/* KSERVICE_TABLE_DESCRIPTOR — the documented descriptor shape. KeServiceDescriptor
 * Table is exported on x64; it points at KiServiceTable (the LONG-encoded entry
 * array), the (unused on free builds) counter table, the entry count, and the
 * argument-byte table. */
typedef struct _HK_KSERVICE_TABLE_DESCRIPTOR {
    PULONG  Base;          /* KiServiceTable: array of LONG packed entries (x64). */
    PULONG  Count;         /* per-service call counters (checked builds). */
    ULONG   Limit;         /* number of services. */
    PUCHAR  Number;        /* argument-byte table. */
} HK_KSERVICE_TABLE_DESCRIPTOR;

/* Exported on x64 (ntoskrnl). The shadow table (KeServiceDescriptorTableShadow)
 * is NOT exported — see the deferral note below; we only use the non-shadow one. */
extern HK_KSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable[];

/* Upper bound on services we will decode in one pass, defensively capping a
 * corrupt Limit so a bad descriptor cannot drive an unbounded loop. The real
 * NT syscall count is a few hundred; 4096 is a generous, safe ceiling. */
#define HK_SSDT_MAX_SERVICES 4096u

_Use_decl_annotations_
void HkSsdtIntegrityScan(PHK_DEVICE_CONTEXT Ctx, const HK_MODULE_MAP* Map)
{
    HK_KSERVICE_TABLE_DESCRIPTOR* desc;
    PULONG    table;
    ULONG     limit;
    ULONG     i;
    uint64_t  tableBase;

    UNREFERENCED_PARAMETER(Ctx);
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    if (Map == NULL || Map->Count == 0) {
        return; /* no map -> cannot range-check; emit nothing. */
    }

    desc = &KeServiceDescriptorTable[0];
    table = desc->Base;
    limit = desc->Limit;
    if (table == NULL || limit == 0) {
        return;
    }
    if (limit > HK_SSDT_MAX_SERVICES) {
        limit = HK_SSDT_MAX_SERVICES; /* defensive cap against a corrupt Limit. */
    }
    tableBase = (uint64_t)(ULONG_PTR)table;

    /* Wrap the decode/range-check in __try: KiServiceTable is OS-owned and stable,
     * but a tampered descriptor could point Base at unmapped memory, and reading
     * it must not bugcheck the box (guardrail #13 — a fault here is recoverable
     * only if guarded). */
    __try {
        for (i = 0; i < limit; ++i) {
            uint32_t raw = (uint32_t)table[i];
            uint64_t target = HkSsdtDecodeTarget(raw, tableBase);

            /* Resolve the target against ntoskrnl/win32k images. An entry whose
             * target lands in NO loaded image is the hooked case. */
            size_t idx = HkModuleMapResolve(Map, target);
            if (idx == HK_MODRANGE_NONE) {
                /* detail = the service INDEX (i), not the target VA — index is a
                 * stable small integer with no KASLR content. */
                HkIntegrityEmit(35u, HK_INTEGRITY_SSDT_OUT_OF_IMAGE, (uint64_t)i);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* A read faulted — abort the scan cleanly rather than emit garbage. */
        InterlockedExchange(&Ctx->IntegrityScanFaulted, 1);
        return;
    }

    /* HK-UNCERTAIN(ssdt-shadow): the win32k shadow SSDT
     * (KeServiceDescriptorTableShadow) is NOT exported. Locating it requires
     * pattern-scanning ntoskrnl or hardcoded version offsets — exactly the
     * "guess on a kernel API" the guardrail forbids. The shadow half is DEFERRED
     * (plan Risk 3): only the non-shadow KiServiceTable above is checked. Do NOT
     * add an offset-based shadow resolver without per-build validation. */
}

#else /* HK_WIN_INTEGRITY_SSDT not defined — compile to a no-op. */

_Use_decl_annotations_
void HkSsdtIntegrityScan(PHK_DEVICE_CONTEXT Ctx, const HK_MODULE_MAP* Map)
{
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(Map);
}

#endif /* HK_WIN_INTEGRITY_SSDT */
