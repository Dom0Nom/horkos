/*
 * kernel/win/src/KernelImageMap.c
 * Role: Per-scan cache of the ntoskrnl/hal kernel-image ranges, consumed by the
 *       syscall/ETW surface-integrity sensors (208/209/211/213/214) to bounds-
 *       check decoded targets against the core kernel images. Built once per scan
 *       from the already-built shared ModuleMap (range half) plus a documented
 *       RtlPcToFileHeader resolve of ntoskrnl/hal bases off known exported
 *       symbols, so it does not re-query the module list. READ-ONLY: it only reads
 *       image headers; it never writes kernel memory. A thin adapter over the
 *       sibling ModuleMap.c — the only genuinely new substrate (on-disk ntoskrnl
 *       .text view for signal 213) is captured by HkSyscallPrologueScan itself at
 *       PASSIVE_LEVEL, not here.
 * Target platforms: Windows kernel mode (KMDF).
 * Interface: implements HkKernelImageMapBuild / HkKernelImageContains /
 *       HkKernelImageMapFree declared in kernel/win/include/horkos_kernel.h.
 *       Always compiled (shared substrate).
 */

#include <ntddk.h>
#include <wdf.h>

#include "horkos_kernel.h"

/* RtlPcToFileHeader is documented for kernel use: given any address inside a
 * loaded image it returns that image's base. We pass the address of an exported
 * ntoskrnl routine (IoCreateDevice) to recover the ntoskrnl base, then read its
 * SizeOfImage from the PE header. This avoids guessing an offset or pattern-
 * scanning — every input is a documented export. */
NTSYSAPI PVOID NTAPI RtlPcToFileHeader(_In_ PVOID PcValue, _Out_ PVOID* BaseOfImage);

/* Minimal PE header projection: we only need SizeOfImage from the optional
 * header. The full headers are in ntimage.h on the WDK; we read the field through
 * the documented IMAGE_* layout, guarded by __try because a tampered/paged header
 * read must not bugcheck (guardrail #13). Offsets are the stable, documented PE
 * layout (e_lfanew at 0x3C; OptionalHeader.SizeOfImage). */
static NTSTATUS HkReadImageSize(_In_ PVOID base, _Out_ uint64_t* sizeOut)
{
    *sizeOut = 0;
    if (base == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    __try {
        const UCHAR* p = (const UCHAR*)base;
        /* IMAGE_DOS_HEADER.e_magic == 'MZ'. */
        if (p[0] != 'M' || p[1] != 'Z') {
            return STATUS_INVALID_IMAGE_FORMAT;
        }
        LONG e_lfanew = *(const LONG*)(p + 0x3C);
        if (e_lfanew <= 0 || e_lfanew > 0x1000) {
            return STATUS_INVALID_IMAGE_FORMAT; /* sanity-bounded. */
        }
        const UCHAR* nt = p + e_lfanew;
        /* IMAGE_NT_HEADERS64.Signature == 'PE\0\0'. */
        if (nt[0] != 'P' || nt[1] != 'E' || nt[2] != 0 || nt[3] != 0) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }
        /* OptionalHeader starts at Signature(4) + FileHeader(20) = +24.
         * SizeOfImage is at OptionalHeader offset 56 (IMAGE_OPTIONAL_HEADER64). */
        ULONG sizeOfImage = *(const ULONG*)(nt + 24 + 56);
        if (sizeOfImage == 0) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }
        *sizeOut = (uint64_t)sizeOfImage;
        return STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_UNSUCCESSFUL; /* guardrail #5: checked, abort cleanly. */
    }
}

_Use_decl_annotations_
NTSTATUS HkKernelImageMapBuild(const HK_MODULE_MAP* Map, PHK_KERNEL_IMAGE Img)
{
    PVOID    ntBase = NULL;
    PVOID    hdr;
    uint64_t ntSize = 0;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    if (Img == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Img, sizeof(*Img));

    /* ntoskrnl base via a documented export. IoCreateDevice is exported by
     * ntoskrnl and never forwarded, so its address resolves to the ntoskrnl
     * image. */
    hdr = RtlPcToFileHeader((PVOID)(ULONG_PTR)&IoCreateDevice, &ntBase);
    if (hdr == NULL || ntBase == NULL) {
        return STATUS_NOT_FOUND; /* cannot bound-check without ntoskrnl range. */
    }
    if (!NT_SUCCESS(HkReadImageSize(ntBase, &ntSize))) {
        return STATUS_UNSUCCESSFUL;
    }
    Img->NtoskrnlBase = (uint64_t)(ULONG_PTR)ntBase;
    Img->NtoskrnlSize = ntSize;

    /* HAL base. HK-UNCERTAIN(hal-image-resolve): on Windows 10+ hal.dll is a stub
     * forwarder and HAL code lives in ntoskrnl.exe (this is public knowledge, e.g.
     * Windows Internals 7th Ed. and MS blog posts on HAL refactoring, but there is
     * no single normative WDK doc page). A HAL "export" address therefore resolves
     * into ntoskrnl on merged-HAL builds. Resolving a genuinely hal-resident
     * routine's base is build-fragile. We OPTIONALLY fill the hal range from the
     * ModuleMap by index only if a future map carries names; until ModuleMap exposes
     * module names, HalBase stays 0 and HkKernelImageContains treats "inside
     * ntoskrnl" as sufficient for perf-interrupt/IDT checks (their handlers live in
     * ntoskrnl on merged-HAL builds). Do NOT pattern-scan for HAL or assume a fixed
     * export; confirm the HAL image resolution on-box before relying on a separate
     * hal range.
     * (docs: HAL merge into ntoskrnl on Win10+ is publicly known but not in a single
     * normative WDK page; still needs on-box: confirm hal range from ModuleMap) */
    UNREFERENCED_PARAMETER(Map);
    Img->HalBase = 0;
    Img->HalSize = 0;

    Img->Valid = TRUE;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
int HkKernelImageContains(const HK_KERNEL_IMAGE* Img, uint64_t Addr)
{
    if (Img == NULL || !Img->Valid) {
        return 0;
    }
    if (Img->NtoskrnlSize != 0 && Addr >= Img->NtoskrnlBase &&
        (Addr - Img->NtoskrnlBase) < Img->NtoskrnlSize) {
        return 1;
    }
    if (Img->HalSize != 0 && Addr >= Img->HalBase &&
        (Addr - Img->HalBase) < Img->HalSize) {
        return 1;
    }
    return 0;
}

_Use_decl_annotations_
void HkKernelImageMapFree(PHK_KERNEL_IMAGE Img)
{
    /* No heap: the cache is a caller-owned struct. Zeroize for hygiene so a stale
     * range cannot be reused after the scan. */
    if (Img != NULL) {
        RtlZeroMemory(Img, sizeof(*Img));
    }
}
