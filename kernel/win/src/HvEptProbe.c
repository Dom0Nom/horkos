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

    /* HK-UNCERTAIN: until the MmMapIoSpaceEx lifetime/IRQL/cache-type contract and
     * the #VE arming are confirmed on the box, the exec-view-vs-data-view checksum
     * is not performed and nothing is emitted. The wire shape
     * (hk_event_hv_ept_split: exec_view_crc / read_view_crc / flags / section_id)
     * is in place so the confirmed implementation drops in without a schema change.
     * Emitting a guessed split (or leaking a physical mapping) is worse than a
     * deferred signal (guardrail #13). */
}
