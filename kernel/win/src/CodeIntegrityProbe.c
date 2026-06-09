/*
 * kernel/win/src/CodeIntegrityProbe.c
 * Role: Signal 30 — code-integrity / DSE / HVCI state probe. Snapshots
 *       SYSTEM_CODEINTEGRITY_INFORMATION (the CodeIntegrityOptions bitfield) at
 *       scan init as a baseline, re-reads it on each rescan, and emits a
 *       CI_STATE_DELTA only when a flag flipped vs. the baseline (a post-boot
 *       flip — e.g. DSE turned off — is far more suspicious than a stable dev
 *       config). Read-only; no parsing of ci.dll internals.
 * Target platforms: Windows kernel mode (KMDF).
 * Interface: implements HkCodeIntegrityBaseline / HkCodeIntegrityRescan declared
 *       in kernel/win/include/horkos_kernel.h. No-op when HK_WIN_INTEGRITY_CISTATE
 *       is not defined. Emits hk_event_integrity_finding.
 */

#include <ntddk.h>
#include <wdf.h>

#include "horkos_kernel.h"

#if defined(HK_WIN_INTEGRITY_CISTATE)

/* SystemCodeIntegrityInformation == 103. The documented shape: a Length-prefixed
 * struct whose CodeIntegrityOptions bitfield carries CODEINTEGRITY_OPTION_*
 * flags (ENABLED, TESTSIGN, HVCI_KMCI_ENABLED, ...). */
#ifndef SystemCodeIntegrityInformation
#  define SystemCodeIntegrityInformation 103
#endif

typedef struct _HK_SYSTEM_CODEINTEGRITY_INFORMATION {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} HK_SYSTEM_CODEINTEGRITY_INFORMATION;

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Inout_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

/* Read the current CodeIntegrityOptions, or return a failure NTSTATUS. */
static NTSTATUS HkCiReadOptions(_Out_ ULONG* Options)
{
    NTSTATUS status;
    HK_SYSTEM_CODEINTEGRITY_INFORMATION info;

    *Options = 0;
    RtlZeroMemory(&info, sizeof(info));
    info.Length = sizeof(info);

    status = ZwQuerySystemInformation(SystemCodeIntegrityInformation,
                                      &info, sizeof(info), NULL);
    if (!NT_SUCCESS(status)) {
        return status; /* guardrail #5: checked, caller degrades cleanly. */
    }
    *Options = info.CodeIntegrityOptions;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
void HkCodeIntegrityBaseline(PHK_DEVICE_CONTEXT Ctx)
{
    ULONG    options = 0;
    NTSTATUS status;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (Ctx == NULL) {
        return;
    }

    status = HkCiReadOptions(&options);
    if (!NT_SUCCESS(status)) {
        /* No baseline this round — leave CiBaselineValid clear; the rescan will
         * skip the delta until a baseline is captured (an absent baseline is not
         * a tamper signal). */
        InterlockedExchange(&Ctx->CiBaselineValid, 0);
        return;
    }
    Ctx->CiBaselineOptions = options;
    InterlockedExchange(&Ctx->CiBaselineValid, 1);
}

_Use_decl_annotations_
void HkCodeIntegrityRescan(PHK_DEVICE_CONTEXT Ctx)
{
    ULONG    options = 0;
    NTSTATUS status;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (Ctx == NULL) {
        return;
    }

    /* If we never captured a baseline, try to capture one now rather than emit a
     * spurious delta against zero. */
    if (Ctx->CiBaselineValid == 0) {
        HkCodeIntegrityBaseline(Ctx);
        return;
    }

    status = HkCiReadOptions(&options);
    if (!NT_SUCCESS(status)) {
        return; /* transient query failure is not a delta. */
    }

    if (options != Ctx->CiBaselineOptions) {
        /* A flag flipped post-boot. detail = the raw CodeIntegrityOptions so the
         * server scores the exact bits (this is a state bitfield, NOT an address —
         * no KASLR concern). Ratchet the baseline to the new value so we report
         * the flip once, not every rescan. */
        HkIntegrityEmit(30u, HK_INTEGRITY_CI_STATE_DELTA, (uint64_t)options);
        Ctx->CiBaselineOptions = options;
    }
}

#else /* HK_WIN_INTEGRITY_CISTATE not defined — compile to no-ops. */

_Use_decl_annotations_
void HkCodeIntegrityBaseline(PHK_DEVICE_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
}

_Use_decl_annotations_
void HkCodeIntegrityRescan(PHK_DEVICE_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
}

#endif /* HK_WIN_INTEGRITY_CISTATE */
