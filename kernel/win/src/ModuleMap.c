/*
 * kernel/win/src/ModuleMap.c
 * Role: Loaded-module address-range map — the shared scan cache consumed by
 *       integrity signals 29/31/32/34/35. Builds ONCE per integrity scan (in the
 *       PASSIVE_LEVEL work item) from ZwQuerySystemInformation(
 *       SystemModuleInformation), then sensors range-lookup addresses against it
 *       via the pure HkModuleRange* helpers (module_map_resolve.h). Building it
 *       once here avoids each sensor independently re-querying the module list.
 * Target platforms: Windows kernel mode (KMDF).
 * Interface: implements HkModuleMapBuild / HkModuleMapResolve / HkModuleMapFree
 *       declared in kernel/win/include/horkos_kernel.h.
 */

#include <ntddk.h>
#include <wdf.h>

#include "horkos_kernel.h"

/* SystemModuleInformation == 11. Not in every public ntddk.h, so define the
 * class number and the documented RTL_PROCESS_MODULES shapes locally; these are
 * the long-stable public layouts (winternl / RTL_PROCESS_MODULE_INFORMATION). */
#ifndef SystemModuleInformation
#  define SystemModuleInformation 11
#endif

typedef struct _HK_RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} HK_RTL_PROCESS_MODULE_INFORMATION;

typedef struct _HK_RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    HK_RTL_PROCESS_MODULE_INFORMATION Modules[1];
} HK_RTL_PROCESS_MODULES;

/* ZwQuerySystemInformation is documented for kernel use (wdm.h on recent WDKs);
 * declare it defensively in case the target headers gate it behind a version
 * macro. The signature matches the public WDK prototype exactly. */
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Inout_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

_Use_decl_annotations_
NTSTATUS HkModuleMapBuild(PHK_MODULE_MAP Map)
{
    NTSTATUS  status;
    ULONG     needed = 0;
    PVOID     buffer = NULL;
    ULONG     bufLen;
    HK_RTL_PROCESS_MODULES* mods;
    ULONG     i;
    ULONG     n;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    if (Map == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Map, sizeof(*Map));

    /* Size probe: the call returns STATUS_INFO_LENGTH_MISMATCH and the needed
     * length. The list can grow between the probe and the real read, so over-
     * allocate with a margin and re-probe-on-grow once. */
    status = ZwQuerySystemInformation(SystemModuleInformation, &needed, 0, &needed);
    if (status != STATUS_INFO_LENGTH_MISMATCH || needed == 0) {
        /* Some builds return STATUS_INFO_LENGTH_MISMATCH; if we got anything else
         * and no size, abort cleanly (emit nothing). */
        return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
    }

    /* Sanity cap before the margin arithmetic: if `needed` is already implausibly
     * large (> 64 MB for a module list is unheard of) treat it as a corrupt or
     * adversarial response and bail rather than let the addition wrap a ULONG. */
    if (needed > 64u * 1024u * 1024u) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    bufLen = needed + (needed / 4) + 4096u; /* 25% + page margin for growth. */
    /* ExAllocatePool2 (not the deprecated ExAllocatePoolWithTag) — requires the
     * WDK for Windows 10 2004+ (build 19041); the CMake/vcxproj target SDKs
     * (10.0.22000+) all satisfy this. Paged pool is correct: this runs only in
     * the PASSIVE_LEVEL scan work item. */
    buffer = ExAllocatePool2(POOL_FLAG_PAGED, bufLen, HK_POOL_TAG);
    if (buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQuerySystemInformation(SystemModuleInformation, buffer, bufLen, &needed);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buffer, HK_POOL_TAG);
        return status; /* guardrail #5: checked, abort cleanly. */
    }

    mods = (HK_RTL_PROCESS_MODULES*)buffer;
    n = mods->NumberOfModules;
    if (n > HK_MODULEMAP_MAX) {
        n = HK_MODULEMAP_MAX;
        Map->Truncated = TRUE;
    }

    for (i = 0; i < n; ++i) {
        HK_RTL_PROCESS_MODULE_INFORMATION* m = &mods->Modules[i];
        Map->Ranges[i].base = (uint64_t)(ULONG_PTR)m->ImageBase;
        Map->Ranges[i].size = (uint64_t)m->ImageSize;
        Map->Ranges[i].index = i;
        /* HK-UNCERTAIN(modmap-signed): RTL_PROCESS_MODULE_INFORMATION (returned
         * by SystemModuleInformation, class 11) carries no "image is signed" bit
         * (documented struct: learn.microsoft.com/windows-hardware/drivers/ddi/
         * aux_klib/ns-aux_klib-_aux_module_extended_info). A per-image signing
         * verdict requires either SystemCodeIntegrityVerificationInformation (class
         * 0x86, available Win10+, undocumented struct shape) or a userspace
         * Authenticode cross-check via WinVerifyTrust. Leaving the SIGNED flag
         * CLEAR here is conservative: sensors fall back to "in the owning image"
         * rather than "in any signed module", which is stricter and may raise FPs
         * on legitimate cross-module thunks. Do NOT fabricate a signed verdict;
         * wire a real CI query or userspace Authenticode check before setting this.
         * (docs: RTL_PROCESS_MODULE_INFORMATION documented — no signed bit present;
         * still needs on-box: signing verdict path selection across WDK versions) */
        Map->Ranges[i].flags = 0u;
    }
    Map->Count = n;

    ExFreePoolWithTag(buffer, HK_POOL_TAG);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
size_t HkModuleMapResolve(const HK_MODULE_MAP* Map, uint64_t Addr)
{
    if (Map == NULL) {
        return HK_MODRANGE_NONE;
    }
    return HkModuleRangeResolve(Map->Ranges, (size_t)Map->Count, Addr);
}

_Use_decl_annotations_
void HkModuleMapFree(PHK_MODULE_MAP Map)
{
    /* The map is an embedded fixed-size struct (no heap), so freeing is just a
     * zeroize for hygiene. Kept as an explicit lifecycle hook so a future heap-
     * backed map (if HK_MODULEMAP_MAX proves too small) has a place to free. */
    if (Map != NULL) {
        RtlZeroMemory(Map, sizeof(*Map));
    }
}
