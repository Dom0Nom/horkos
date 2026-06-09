/*
 * kernel/win/src/SyscallIntegrity.c
 * Role: x64 syscall/IDT dispatch-surface integrity scan (read-only bounds +
 *       prologue + MSR checks). Signals 208 (native SSDT entry bounds), 209
 *       (shadow SSDT, default-OFF), 210 (IA32_LSTAR per-CPU), 213 (syscall-entry
 *       prologue tamper), 214 (IDT gate bounds), 216 (SSDT descriptor base swap).
 *       Every sensor only reads and bounds-checks kernel globals/pointers against
 *       the ntoskrnl image range and a boot baseline, then emits
 *       HK_EVENT_INTEGRITY_FINDING. NO table writes, NO MSR writes, NO hooks
 *       installed (those would themselves trip PatchGuard and are out of scope).
 *       The per-CPU reads (210/214) run inside KeIpiGenericCall at IPI level and
 *       do nothing but a register/MSR read + store. All other work is at the
 *       single PASSIVE_LEVEL integrity work item.
 * Target platforms: Windows kernel mode (KMDF).
 * Interface: implements HkSyscallEtwArm (SSDT/prologue half) and
 *       HkSsdtValidate / HkShadowSsdtValidate / HkLstarValidate /
 *       HkSyscallPrologueScan / HkIdtValidate / HkSsdtBaselineCheck declared in
 *       kernel/win/include/horkos_kernel.h. Each sensor is a no-op stub unless its
 *       HK_WIN_SYSCALL_* build flag is defined. Emits hk_event_integrity_finding.
 */

#include <ntddk.h>
#include <wdf.h>

#include "horkos_kernel.h"

/* KSERVICE_TABLE_DESCRIPTOR — documented descriptor shape. KeServiceDescriptorTable
 * is exported on x64. Mirrors the local typedef in SsdtIntegrity.c (the sibling
 * signal-35 file); both decode the same exported global, this file owns the
 * canonical per-entry validate (208) per the plan's coordination note. */
typedef struct _HK_KSERVICE_TABLE_DESCRIPTOR {
    PULONG Base;   /* KiServiceTable: array of LONG packed entries (x64). */
    PULONG Count;  /* per-service call counters (checked builds). */
    ULONG  Limit;  /* number of services. */
    PUCHAR Number; /* argument-byte table. */
} HK_KSERVICE_TABLE_DESCRIPTOR;

extern HK_KSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable[];

/* Defensive cap on services decoded in one pass (a corrupt Limit must not drive
 * an unbounded loop). Real NT syscall count is a few hundred. */
#define HK_SSDT_MAX_SERVICES 4096u
/* Expected NT service-count band for the build-fragility gate (208/216): a Limit
 * far outside this band means the descriptor read is unreliable on this build, so
 * the sensor emits UNVERIFIABLE rather than risk a false positive. */
#define HK_SSDT_LIMIT_MIN 200u
#define HK_SSDT_LIMIT_MAX 1000u

/* IA32_LSTAR MSR index (SYSCALL entry RIP). */
#define HK_MSR_IA32_LSTAR 0xC0000082u

/* -------------------------------------------------------------------------
 * Arm-time baseline capture (208/213/216). Always compiled — the orchestrator
 * calls this once at scan init. Snapshots the exported descriptor base/limit and
 * (where resolvable) the KiSystemCall64 prologue window. The unexported-global
 * halves (ExpectedLstar, shadow descriptor) are left zero/Valid-gated so the
 * sensors fall back to UNVERIFIABLE instead of guessing.
 * ------------------------------------------------------------------------- */
_Use_decl_annotations_
void HkSyscallEtwArm(PHK_DEVICE_CONTEXT Ctx)
{
    HK_KSERVICE_TABLE_DESCRIPTOR* desc;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (Ctx == NULL) {
        return;
    }

    RtlZeroMemory(&Ctx->SsdtBaseline, sizeof(Ctx->SsdtBaseline));

    desc = &KeServiceDescriptorTable[0];
    __try {
        Ctx->SsdtBaseline.ServiceTableBase = desc->Base;
        Ctx->SsdtBaseline.ServiceLimit = desc->Limit;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Ctx->SsdtBaseline.Valid = FALSE;
        return;
    }

    /* 213 stable-window prologue capture. HK-UNCERTAIN(syscall-prologue-window):
     * KiSystemCall64 is NOT exported; capturing its bytes requires resolving its
     * address (LSTAR points at it at runtime, but reading LSTAR here at arm time
     * and trusting it as "clean" assumes arm happens before any tamper). The
     * stable-window selection (which bytes survive retpoline/KVA-shadow/hotpatch
     * boot self-patching) must be validated against a clean-machine corpus before
     * 213 leaves report-only (plan Risk 5). Until then PrologueLen stays 0 =>
     * HkSyscallPrologueScan emits UNVERIFIABLE. Do NOT populate PrologueBytes from
     * a guessed address. */
    Ctx->SsdtBaseline.PrologueLen = 0;

    /* ExpectedLstar (210) and the shadow descriptor (209) are unexported-global
     * resolves left for the offset-table strategy (plan Risk 1); zero => the
     * sensors use only their version-independent halves (per-CPU divergence,
     * UNVERIFIABLE). */
    Ctx->SsdtBaseline.ExpectedLstar = NULL;
    Ctx->SsdtBaseline.ShadowServiceTableBase = NULL;
    Ctx->SsdtBaseline.ShadowServiceLimit = 0;

    /* The descriptor base/limit snapshot is the verifiable half: mark Valid iff we
     * read a plausible base+limit (216 base-swap and 208 decode can run). */
    Ctx->SsdtBaseline.Valid =
        (Ctx->SsdtBaseline.ServiceTableBase != NULL &&
         Ctx->SsdtBaseline.ServiceLimit != 0) ? TRUE : FALSE;

    /* ETW provider census baseline (215) + ETW-TI handle presence (212 raw half).
     * Both require the unconfirmed kernel logger-table query / unexported-global
     * resolve (plan Risk 1/6); until those are agreed on-box the baseline is left
     * INVALID so HkEtwSessionCensus / HkEtwTiLiveness fall back to UNVERIFIABLE.
     * The keepalive half (212, version-independent) is independent of this and is
     * gated by EtwKeepaliveArmed instead. */
    RtlZeroMemory(&Ctx->EtwBaseline, sizeof(Ctx->EtwBaseline));
    Ctx->EtwBaseline.Valid = FALSE;

    /* Keepalive counter starts at zero; no consumer bumps it yet (see the
     * HK-UNCERTAIN(etw-ti-consumer) note). EtwKeepaliveArmed stays 0 until a real
     * ETW-TI consumer exists, keeping the keepalive check UNVERIFIABLE-gated. */
    Ctx->EtwTiKeepalive = 0;
    Ctx->EtwTiKeepalivePrev = 0;
    InterlockedExchange(&Ctx->EtwKeepaliveArmed, 0);
}

/* =========================================================================
 * Signal 208 — KiServiceTable (SSDT) entry bounds.
 * ========================================================================= */
#if defined(HK_WIN_SYSCALL_SSDT)

_Use_decl_annotations_
void HkSsdtValidate(PHK_DEVICE_CONTEXT Ctx, const HK_KERNEL_IMAGE* Img)
{
    HK_KSERVICE_TABLE_DESCRIPTOR* desc;
    PULONG   table;
    ULONG    limit;
    ULONG    i;
    uint64_t tableBase;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (Ctx == NULL || Img == NULL || !Img->Valid) {
        return;
    }

    desc = &KeServiceDescriptorTable[0];
    __try {
        table = desc->Base;
        limit = desc->Limit;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedExchange(&Ctx->IntegrityScanFaulted, 1);
        return;
    }
    if (table == NULL || limit == 0) {
        return;
    }

    /* Build-fragility gate: an out-of-band Limit means the descriptor read is not
     * trustworthy on this build — emit UNVERIFIABLE, never a per-entry FP. */
    if (limit < HK_SSDT_LIMIT_MIN || limit > HK_SSDT_LIMIT_MAX) {
        HkIntegrityEmit(208u, HK_INTEGRITY_UNVERIFIABLE, (uint64_t)limit);
        return;
    }
    if (limit > HK_SSDT_MAX_SERVICES) {
        limit = HK_SSDT_MAX_SERVICES;
    }
    tableBase = (uint64_t)(ULONG_PTR)table;

    __try {
        for (i = 0; i < limit; ++i) {
            uint32_t raw = (uint32_t)table[i];
            uint64_t target = HkSsdtDecodeTarget(raw, tableBase);
            if (!HkKernelImageContains(Img, target)) {
                /* detail = service INDEX (stable small integer, no KASLR content). */
                HkIntegrityEmit(208u, HK_INTEGRITY_SSDT_ENTRY_OOI, (uint64_t)i);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedExchange(&Ctx->IntegrityScanFaulted, 1);
    }
}

#else
_Use_decl_annotations_
void HkSsdtValidate(PHK_DEVICE_CONTEXT Ctx, const HK_KERNEL_IMAGE* Img)
{
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(Img);
}
#endif /* HK_WIN_SYSCALL_SSDT */

/* =========================================================================
 * Signal 216 — SSDT descriptor base/limit swap vs arm-time baseline.
 * ========================================================================= */
#if defined(HK_WIN_SYSCALL_SSDT)

_Use_decl_annotations_
void HkSsdtBaselineCheck(PHK_DEVICE_CONTEXT Ctx, const HK_KERNEL_IMAGE* Img)
{
    HK_KSERVICE_TABLE_DESCRIPTOR* desc;
    PVOID nowBase;
    ULONG nowLimit;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (Ctx == NULL || Img == NULL || !Img->Valid) {
        return;
    }
    if (!Ctx->SsdtBaseline.Valid) {
        HkIntegrityEmit(216u, HK_INTEGRITY_UNVERIFIABLE, 0ull);
        return;
    }

    desc = &KeServiceDescriptorTable[0];
    __try {
        nowBase = desc->Base;
        nowLimit = desc->Limit;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedExchange(&Ctx->IntegrityScanFaulted, 1);
        return;
    }

    /* The descriptor base is stable across the OS lifetime; a relocated base or a
     * changed limit is the clone-table-swap case 208 alone misses (a cloned table
     * with pristine entries passes per-entry checks but moves the base). */
    if (nowBase != Ctx->SsdtBaseline.ServiceTableBase ||
        nowLimit != Ctx->SsdtBaseline.ServiceLimit) {
        /* detail = base delta, masked to a base-subtracted value (no raw pointer).
         * Subtract the baseline base so the value carries no KASLR content. */
        uint64_t delta = (uint64_t)(ULONG_PTR)nowBase -
                         (uint64_t)(ULONG_PTR)Ctx->SsdtBaseline.ServiceTableBase;
        HkIntegrityEmit(216u, HK_INTEGRITY_SSDT_BASE_SWAP, delta);
    }

    /* The base must still point into ntoskrnl; a base outside the image is itself
     * the swap signal even if it happened to match a (tampered) baseline. */
    if (!HkKernelImageContains(Img, (uint64_t)(ULONG_PTR)nowBase)) {
        HkIntegrityEmit(216u, HK_INTEGRITY_SSDT_BASE_SWAP, 0ull);
    }
}

#else
_Use_decl_annotations_
void HkSsdtBaselineCheck(PHK_DEVICE_CONTEXT Ctx, const HK_KERNEL_IMAGE* Img)
{
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(Img);
}
#endif /* HK_WIN_SYSCALL_SSDT */

/* =========================================================================
 * Signal 210 — IA32_LSTAR MSR per-CPU validation.
 * ========================================================================= */
#if defined(HK_WIN_SYSCALL_LSTAR)

/* IPI callback (IPI level). Does NOTHING but read IA32_LSTAR and store it into the
 * per-CPU slot. NO allocation, NO lock, NO logging — any of those deadlock or
 * bugcheck at IPI level (plan Risk 3). */
_Function_class_(KIPI_BROADCAST_WORKER)
static ULONG_PTR HkLstarIpi(_In_ ULONG_PTR Argument)
{
    PHK_PERCPU_READ pcr = (PHK_PERCPU_READ)Argument;
    ULONG cpu = KeGetCurrentProcessorNumberEx(NULL);

    if (pcr != NULL && cpu < HK_PERCPU_MAX_CPUS) {
        pcr->Lstar[cpu] = __readmsr(HK_MSR_IA32_LSTAR);
    }
    return 0;
}

_Use_decl_annotations_
void HkLstarValidate(PHK_DEVICE_CONTEXT Ctx, const HK_KERNEL_IMAGE* Img)
{
    PHK_PERCPU_READ pcr;
    ULONG  count;
    ULONG  cpu;
    ULONG64 first;
    uint64_t expected;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (Ctx == NULL || Img == NULL || !Img->Valid) {
        return;
    }

    count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (count == 0 || count > HK_PERCPU_MAX_CPUS) {
        HkIntegrityEmit(210u, HK_INTEGRITY_UNVERIFIABLE, (uint64_t)count);
        return;
    }

    pcr = (PHK_PERCPU_READ)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*pcr),
                                           HK_POOL_TAG);
    if (pcr == NULL) {
        InterlockedExchange(&Ctx->IntegrityScanFaulted, 1);
        return;
    }
    pcr->ProcessorCount = count;

    /* KeIpiGenericCall raises to IPI level on every processor, runs HkLstarIpi,
     * returns at PASSIVE. The broadcast is from the periodic work item, never the
     * syscall hot path (plan: "run the IPI off the hot path"). */
    (void)KeIpiGenericCall(HkLstarIpi, (ULONG_PTR)pcr);

    /* Per-CPU divergence: every CPU should hold the SAME LSTAR. This half needs no
     * unexported global and is meaningful even without the absolute expected value
     * (plan Risk 2 — divergence is safe regardless of KVA-shadow detection). */
    first = pcr->Lstar[0];
    for (cpu = 1; cpu < count; ++cpu) {
        if (pcr->Lstar[cpu] != first) {
            HkIntegrityEmit(210u, HK_INTEGRITY_LSTAR_CPU_DIVERGE, (uint64_t)cpu);
        }
    }

    /* Absolute match against the expected entry. HK-UNCERTAIN(lstar-expected):
     * &KiSystemCall64 / &KiSystemCall64Shadow are unexported and the KVA-shadow
     * state must be detected to pick between them (plan Risk 1 + 2). The arm-time
     * baseline leaves ExpectedLstar NULL until the offset-table + KVA-shadow
     * detection are agreed on-box; until then we emit UNVERIFIABLE for the
     * absolute half and rely on the divergence half above. Do NOT hardcode an
     * expected address. */
    expected = (uint64_t)(ULONG_PTR)Ctx->SsdtBaseline.ExpectedLstar;
    if (expected == 0) {
        HkIntegrityEmit(210u, HK_INTEGRITY_UNVERIFIABLE, 0ull);
    } else {
        /* The pure selector is exercised once the candidates resolve; the call
         * site keeps the contract visible even while ExpectedLstar is gated. */
        for (cpu = 0; cpu < count; ++cpu) {
            if ((uint64_t)pcr->Lstar[cpu] != expected) {
                HkIntegrityEmit(210u, HK_INTEGRITY_LSTAR_MISMATCH, (uint64_t)cpu);
            }
        }
    }

    ExFreePoolWithTag(pcr, HK_POOL_TAG);
}

#else
_Use_decl_annotations_
void HkLstarValidate(PHK_DEVICE_CONTEXT Ctx, const HK_KERNEL_IMAGE* Img)
{
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(Img);
}
#endif /* HK_WIN_SYSCALL_LSTAR */

/* =========================================================================
 * Signal 214 — IDT gate handler bounds (per-CPU via __sidt inside the IPI).
 * ========================================================================= */
#if defined(HK_WIN_SYSCALL_IDT)

/* x64 interrupt-gate descriptor (KIDTENTRY64). Declared locally — the documented
 * layout is stable. The handler VA is split across three offset fields. */
#pragma pack(push, 1)
typedef struct _HK_KIDTENTRY64 {
    USHORT OffsetLow;
    USHORT Selector;
    USHORT Attributes;
    USHORT OffsetMiddle;
    ULONG  OffsetHigh;
    ULONG  Reserved;
} HK_KIDTENTRY64;

typedef struct _HK_IDTR {
    USHORT Limit;
    ULONG64 Base;
} HK_IDTR;
#pragma pack(pop)

/* IPI callback (IPI level). __sidt to get the IDTR, then reconstruct the first N
 * gate handlers into the per-CPU slot. READ + STORE ONLY — no alloc, no lock
 * (plan Risk 3 + 11: prefer __sidt over poking the version-fragile KPCR). */
_Function_class_(KIPI_BROADCAST_WORKER)
static ULONG_PTR HkIdtIpi(_In_ ULONG_PTR Argument)
{
    PHK_PERCPU_READ pcr = (PHK_PERCPU_READ)Argument;
    ULONG cpu = KeGetCurrentProcessorNumberEx(NULL);
    HK_IDTR idtr;
    ULONG gate;

    if (pcr == NULL || cpu >= HK_PERCPU_MAX_CPUS) {
        return 0;
    }

    /* __sidt stores the 10-byte IDTR (limit + base). The intrinsic writes to the
     * provided buffer. */
    __sidt(&idtr);

    /* HK-UNCERTAIN(idt-ipi-read): walking IDT entries from idtr.Base at IPI level
     * dereferences the IDT pages. The IDT is non-paged and resident so the read
     * does not fault in practice, and __try/__except is NOT used here because
     * structured exception handling at IPI level is itself unsafe — the discipline
     * is "touch only resident memory, never guard". The plan flags confirming this
     * __sidt-based path on-box before enabling 214 (Risk 11); a zero handler is
     * skipped by the PASSIVE consumer rather than treated as a bound violation. */
    for (gate = 0; gate < HK_IDT_GATES_CHECKED; ++gate) {
        const HK_KIDTENTRY64* e =
            (const HK_KIDTENTRY64*)(ULONG_PTR)(idtr.Base + (ULONG64)gate * sizeof(HK_KIDTENTRY64));
        pcr->IdtHandler[cpu][gate] =
            HkIdtReconstructHandler(e->OffsetLow, e->OffsetMiddle, e->OffsetHigh);
    }
    return 0;
}

_Use_decl_annotations_
void HkIdtValidate(PHK_DEVICE_CONTEXT Ctx, const HK_KERNEL_IMAGE* Img)
{
    PHK_PERCPU_READ pcr;
    ULONG count;
    ULONG cpu;
    ULONG gate;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (Ctx == NULL || Img == NULL || !Img->Valid) {
        return;
    }

    count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (count == 0 || count > HK_PERCPU_MAX_CPUS) {
        HkIntegrityEmit(214u, HK_INTEGRITY_UNVERIFIABLE, (uint64_t)count);
        return;
    }

    pcr = (PHK_PERCPU_READ)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*pcr),
                                           HK_POOL_TAG);
    if (pcr == NULL) {
        InterlockedExchange(&Ctx->IntegrityScanFaulted, 1);
        return;
    }
    pcr->ProcessorCount = count;

    (void)KeIpiGenericCall(HkIdtIpi, (ULONG_PTR)pcr);

    for (cpu = 0; cpu < count; ++cpu) {
        for (gate = 0; gate < HK_IDT_GATES_CHECKED; ++gate) {
            uint64_t handler = (uint64_t)pcr->IdtHandler[cpu][gate];
            if (handler == 0) {
                continue; /* unset / unread gate — skip, do not FP. */
            }
            /* In-guest IDT handlers still resolve into the kernel image under a
             * hypervisor (plan), so out-of-image is high-confidence. */
            if (!HkKernelImageContains(Img, handler)) {
                /* detail = (cpu << 8 | gate): both small indices, no KASLR. */
                HkIntegrityEmit(214u, HK_INTEGRITY_IDT_OOI,
                                ((uint64_t)cpu << 8) | (uint64_t)gate);
            }
        }
    }

    ExFreePoolWithTag(pcr, HK_POOL_TAG);
}

#else
_Use_decl_annotations_
void HkIdtValidate(PHK_DEVICE_CONTEXT Ctx, const HK_KERNEL_IMAGE* Img)
{
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(Img);
}
#endif /* HK_WIN_SYSCALL_IDT */

/* =========================================================================
 * Signal 213 — syscall-entry prologue tamper scan.
 * ========================================================================= */
#if defined(HK_WIN_SYSCALL_PROLOGUE)

_Use_decl_annotations_
void HkSyscallPrologueScan(PHK_DEVICE_CONTEXT Ctx, const HK_KERNEL_IMAGE* Img)
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (Ctx == NULL || Img == NULL || !Img->Valid) {
        return;
    }

    /* HK-UNCERTAIN(syscall-prologue): the stable-window byte selection (which
     * KiSystemCall64 bytes survive retpoline/Spectre-thunk/KVA-shadow/hotpatch
     * boot self-patching, plan Risk 5) is build-sensitive and unvalidated. With
     * PrologueLen==0 (arm-time capture deferred) there is no clean baseline to
     * diff against, so this sensor emits UNVERIFIABLE rather than risk false-
     * positiving on legitimate boot self-patches. Default-OFF; do NOT enable a
     * disk-vs-memory diff until the window is validated against a clean-machine
     * corpus across mitigation states. */
    if (Ctx->SsdtBaseline.PrologueLen == 0) {
        HkIntegrityEmit(213u, HK_INTEGRITY_UNVERIFIABLE, 0ull);
        return;
    }

    /* When the validated baseline exists, the compare is an in-memory vs in-memory
     * RtlCompareMemory over the stable window; the first differing offset (image-
     * relative) is the detail. Left unreachable until PrologueLen is populated by a
     * validated arm-time capture. */
}

#else
_Use_decl_annotations_
void HkSyscallPrologueScan(PHK_DEVICE_CONTEXT Ctx, const HK_KERNEL_IMAGE* Img)
{
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(Img);
}
#endif /* HK_WIN_SYSCALL_PROLOGUE */

/* =========================================================================
 * Signal 209 — shadow SSDT / W32pServiceTable bounds (HIGHEST RISK, default-OFF).
 * ========================================================================= */
#if defined(HK_WIN_SYSCALL_SHADOW_SSDT)

_Use_decl_annotations_
void HkShadowSsdtValidate(PHK_DEVICE_CONTEXT Ctx, const HK_KERNEL_IMAGE* Img)
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (Ctx == NULL || Img == NULL || !Img->Valid) {
        return;
    }

    /* HK-UNCERTAIN(shadow-ssdt): KeServiceDescriptorTableShadow is NOT exported,
     * and reading W32pServiceTable requires KeStackAttachProcess into a GUI
     * process (csrss) then decoding a per-build table layout. The attach/detach
     * must be perfectly paired on the same KAPC_STATE or the thread is corrupted
     * (plan Risk 4). Both the table location and the attach lifetime are
     * undocumented/version-fragile — exactly the territory the guardrail forbids
     * guessing on. This sensor stays a clearly-flagged stub emitting UNVERIFIABLE
     * until the shadow-table resolution and the attach pairing are reviewed on-box.
     * Do NOT add an offset-based W32pServiceTable resolver or a KeStackAttachProcess
     * walk without that review. */
    HkIntegrityEmit(209u, HK_INTEGRITY_UNVERIFIABLE, 0ull);
}

#else
_Use_decl_annotations_
void HkShadowSsdtValidate(PHK_DEVICE_CONTEXT Ctx, const HK_KERNEL_IMAGE* Img)
{
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(Img);
}
#endif /* HK_WIN_SYSCALL_SHADOW_SSDT */
