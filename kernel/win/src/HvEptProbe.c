/*
 * kernel/win/src/HvEptProbe.c
 * Role: Signal 39 kernel sensor — checksums a signed section of the game two ways
 *       (an exec-view read and an independent data-view read) and emits
 *       hk_event_hv_ept_split when they diverge; an EPT that maps different bytes
 *       for execute vs read is the covert-inspection shape. HVCI-managed regions
 *       are whitelisted (the server-side FP gate; the kernel annotates the bit).
 *       READ-ONLY: checksums only; arms no #VE that mutates state.
 * Target platforms: Windows kernel (KMDF). Builds only with the WDK.
 *
 *       HK-UNCERTAIN (plan UNCERTAINTY FLAG, load-bearing): the data-view read via
 *       MmMapIoSpaceEx (mapping the physical page behind the exec VA) — its IRQL,
 *       cache-type argument, and the GUARANTEED MmUnmapIoSpace on every path — is
 *       security-critical and NOT confirmed. The #VE / EXCEPTION_VIRTUALIZATION_
 *       FAULT (0xC0000420) arming in a non-root partition is equally uncertain.
 *       Until both are confirmed on the box, this emits nothing (no map, no
 *       checksum) rather than risk a leaked mapping or a wrong-cache-type read.
 *       Default OFF until reviewed (the plan: "default ON after review").
 * Interface: implements HkHvEptProbeSample (horkos_kernel.h); emits via HkRingEmit.
 */

#include <ntddk.h>

#include "horkos_kernel.h"
#include "horkos/event_schema.h"

void HkHvEptProbeSample(void)
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    /* HK-UNCERTAIN: MmMapIoSpaceEx is documented (learn.microsoft.com/windows-hardware/
     * drivers/ddi/wdm/nf-wdm-mmmapiospaceex) as mapping a physical address range at
     * IRQL <= DISPATCH_LEVEL with a specified cache type. MmUnmapIoSpace (documented:
     * learn.microsoft.com/windows-hardware/drivers/ddi/wdm/nf-wdm-mmunmapiospace)
     * must be called to release the mapping. However, the correct cache type for
     * reading the physical backing of a kernel executable page (MmCached vs MmNonCached)
     * and whether MmMapIoSpaceEx is safe for this use case (physical page of a kernel
     * image, not a device register) must be confirmed on-box. The #VE /
     * EXCEPTION_VIRTUALIZATION_FAULT (0xC0000420) arming path in a non-root partition
     * is equally uncertain. Until both are confirmed on the box, the exec-view-vs-data-
     * view checksum is not performed and nothing is emitted.
     * (docs: MmMapIoSpaceEx + MmUnmapIoSpace documented; still needs on-box:
     * correct cache type for kernel-page PA read + #VE arming safety) */
}
