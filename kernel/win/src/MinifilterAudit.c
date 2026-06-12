/*
 * Role: Signal 28 — FltMgr callback-node owner/altitude audit. Walks the
 *       registered minifilters and their instances and cross-checks each
 *       FLT_OPERATION_REGISTRATION pre/post-op callback pointer against the owning
 *       FLT_FILTER image's [base,base+size); a callback pointer outside every
 *       loaded module is flagged HK_INTEGRITY_FLT_OUT_OF_IMAGE. Read-only.
 * Target platforms: Windows kernel mode (KMDF).
 * Interface: implements HkMinifilterAudit declared in
 *       kernel/win/include/horkos_kernel.h. No-op when HK_WIN_INTEGRITY_FLT is not
 *       defined (DEFAULT OFF — plan Risk 2: Flt object lifetime unverified). Emits
 *       hk_event_integrity_finding.
 */

#include <ntddk.h>
#include <wdf.h>

#include "horkos_kernel.h"

#if defined(HK_WIN_INTEGRITY_FLT)

/* NOTE: enabling this sensor links fltmgr.lib; that is wired in CMake/vcxproj only
 * when HK_WIN_INTEGRITY_FLT is ON. Includes the FltKernel header lazily so the
 * default-OFF build needs no FltMgr toolchain dependency. */
#include <fltKernel.h>

_Use_decl_annotations_
void HkMinifilterAudit(PHK_DEVICE_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    /* HK-UNCERTAIN(flt-object-lifetime): FltEnumerateFilters and FltObjectDereference
     * are documented in the WDK FltKernel reference (learn.microsoft.com/windows-
     * hardware/drivers/ddi/fltkernel/nf-fltkernel-fltenumeratefilters and
     * nf-fltkernel-fltobjectdereference). The docs confirm each returned PFLT_FILTER
     * must be released via FltObjectDereference exactly once. However, whether
     * FltEnumerateFilters requires our OWN FltRegisterFilter handle (i.e. the driver
     * must itself be a registered minifilter to call it) is not clearly stated and
     * must be confirmed on-box. A missed FltObjectDereference leaks; a double-deref
     * is a UAF/bugcheck. Per guardrail #13 the live enumeration is left UNIMPLEMENTED.
     * The intended body, ready once the lifetime + registration requirement are
     * confirmed against the WDK docs on-box:
     * (docs: FltEnumerateFilters + FltObjectDereference documented; still needs on-box:
     * whether our own FltRegisterFilter is required to call FltEnumerateFilters)
     *
     * The intended body once the lifetime + registration requirement are confirmed:
     *
     *   ULONG n = 0;
     *   FltEnumerateFilters(NULL, 0, &n);                 // size probe
     *   PFLT_FILTER* filters = pool(n * sizeof(PFLT_FILTER));
     *   if (NT_SUCCESS(FltEnumerateFilters(filters, n, &n))) {
     *       for each filters[i]:
     *           FLT_FILTER_AGGREGATE_BASIC_INFORMATION info; // altitude
     *           FltGetFilterInformation(filters[i], FilterAggregateBasicInformation, ...);
     *           // resolve filters[i] image base/size, then for each registered
     *           // FLT_OPERATION_REGISTRATION pre/post pointer, range-check it:
     *           //   if not in [filterBase, filterBase+size) and not in any module:
     *           //       HkIntegrityEmit(28, HK_INTEGRITY_FLT_OUT_OF_IMAGE, masked_offset);
     *           FltObjectDereference(filters[i]);          // EXACTLY once -- verify!
     *   }
     *
     * Do NOT enable the enumeration until the deref contract is verified -- getting
     * it wrong leaks pool or bugchecks. This sensor ships DEFAULT OFF. */
    (void)0;
}

#else /* HK_WIN_INTEGRITY_FLT not defined — compile to a no-op (no FltMgr dep). */

_Use_decl_annotations_
void HkMinifilterAudit(PHK_DEVICE_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
}

#endif /* HK_WIN_INTEGRITY_FLT */
