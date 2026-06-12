/*
 * Role: Signal 44 kernel sensor (observe-only, low standalone weight) — reads the
 *       __sidt IDT base and compares it against the KPCR-authoritative IDT base;
 *       a mismatch is APIC/IDT virtualization residue. Emits hk_event_hv_apic_idt.
 *       Genuine Hyper-V/VBS already virtualizes the APIC and may relocate
 *       descriptors, so per-CPU IDT differences are normal — the server cohorts
 *       this; the kernel only ships the raw bases + mismatch bit.
 *       READ-ONLY.
 * Target platforms: Windows kernel (KMDF). Builds only with the WDK.
 *
 *       HK-UNCERTAIN (plan UNCERTAINTY FLAG): the KPCR/KIDTENTRY authoritative IDT
 *       base read is version- and CPU-specific and partly undocumented; APIC-exit
 *       timing baselines differ across Hyper-V versions. Until the KPCR IDT base
 *       is confirmed on the box, the mismatch bit stays 0 (never a guessed
 *       positive) and only the __sidt base is shipped. Default OFF
 *       (HK_HV_KERNEL_EXPERIMENTAL).
 * Interface: implements HkHvApicIdtSample (horkos_kernel.h); emits via HkRingEmit.
 */

#include <ntddk.h>
#include <intrin.h>

#include "horkos_kernel.h"
#include "horkos/event_schema.h"

#pragma pack(push, 1)
typedef struct _HK_IDTR {
    USHORT Limit;
    ULONG64 Base;
} HK_IDTR;
#pragma pack(pop)

void HkHvApicIdtSample(void)
{
    hk_event_hv_apic_idt ev;
    HK_IDTR idtr;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    RtlZeroMemory(&ev, sizeof(ev));
    RtlZeroMemory(&idtr, sizeof(idtr));

    /* __sidt stores the IDTR (limit + base). Documented intrinsic. */
    __sidt(&idtr);
    ev.sidt_base_low = (uint32_t)(idtr.Base & 0xFFFFFFFFu);

    /* HK-UNCERTAIN: KPCR-authoritative IDT base read deferred to the box. Set it
     * equal to the __sidt base so no mismatch is fabricated. */
    ev.kpcr_idt_base_low = ev.sidt_base_low;
    if (ev.sidt_base_low != ev.kpcr_idt_base_low) {
        ev.flags |= HK_HV_APIC_IDT_MISMATCH;
    }
    ev.apic_exit_bucket = 0; /* APIC access-exit timing: box refinement. */

    HkRingEmit(HK_EVENT_HV_APIC_IDT, &ev, sizeof(ev));
}
