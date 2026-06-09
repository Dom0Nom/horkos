/*
 * kernel/win/src/NonImageCodeScan.c
 * Role: Signal 32 — non-image executable allocation (manually-mapped driver)
 *       scan. Enumerates big-pool allocations
 *       (ZwQuerySystemInformation(SystemBigPoolInformation)) and flags an
 *       executable system-space range that intersects no ModuleMap image and no
 *       known pool-tag owner as HK_INTEGRITY_NONIMAGE_EXEC — a server-scored
 *       anomaly, never a standalone ban. Rate-limited and SAMPLED (the catalog
 *       forbids enumerating every PTE). Read-only.
 * Target platforms: Windows kernel mode (KMDF).
 * Interface: implements HkNonImageScan declared in
 *       kernel/win/include/horkos_kernel.h. Depends on the shared ModuleMap.
 *       No-op when HK_WIN_INTEGRITY_NONIMAGE is not defined (DEFAULT OFF — plan
 *       Risk 6: HIGH false-positive, lowest weight). Emits
 *       hk_event_integrity_finding.
 */

#include <ntddk.h>
#include <wdf.h>

#include "horkos_kernel.h"

#if defined(HK_WIN_INTEGRITY_NONIMAGE)

_Use_decl_annotations_
void HkNonImageScan(PHK_DEVICE_CONTEXT Ctx, const HK_MODULE_MAP* Map)
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    UNREFERENCED_PARAMETER(Ctx);

    if (Map == NULL || Map->Count == 0) {
        return;
    }

    /* HK-UNCERTAIN(bigpool-executable): the plan flags (Risk 6) that there is NO
     * clean documented query for "is this big-pool range executable". Classifying
     * a range as executable from a KMDF driver relies on MmIsAddressValid plus
     * heuristics (or undocumented PTE inspection), which risks both false
     * positives and misses; the catalog rates this signal HIGH FP. Per guardrail
     * #13 the executability classification + the emit are left UNIMPLEMENTED;
     * this sensor ships DEFAULT OFF and, when ON, must be server-scored at the
     * lowest weight.
     *
     * The intended SAMPLED body (rate-limited; never enumerate every PTE):
     *
     *   probe size via ZwQuerySystemInformation(SystemBigPoolInformation);
     *   alloc paged buffer; read SYSTEM_BIGPOOL_INFORMATION;
     *   for a SAMPLE of entries (not all):
     *       if (entry is NonPaged && classified-executable && private/non-image):
     *           addr = entry.VirtualAddress;
     *           if (!HkModuleRangeContains(Map->Ranges, Map->Count, addr) &&
     *               !known_pool_tag_owner(entry.Tag)):
     *               HkIntegrityEmit(32, HK_INTEGRITY_NONIMAGE_EXEC,
     *                               masked_or_size_only_detail);
     *
     * Do NOT ship the executability heuristic until it is validated — a HIGH-FP
     * standalone signal that could contribute to a ban is exactly what the catalog
     * warns against. This sensor ships DEFAULT OFF, lowest weight, server-scored. */
    (void)0;
}

#else /* HK_WIN_INTEGRITY_NONIMAGE not defined — compile to a no-op. */

_Use_decl_annotations_
void HkNonImageScan(PHK_DEVICE_CONTEXT Ctx, const HK_MODULE_MAP* Map)
{
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(Map);
}

#endif /* HK_WIN_INTEGRITY_NONIMAGE */
