/*
 * Role: Signal 29 — in-memory vs on-disk driver .text hash audit. For each loaded
 *       driver, parse the in-memory PE (RtlImageNtHeader + IMAGE_SECTION_HEADER),
 *       find the executable sections, read the on-disk file (PASSIVE_LEVEL,
 *       ZwCreateFile/ZwReadFile), normalize base relocations + IAT thunks, and
 *       compare the section hashes. A non-reloc, non-import-thunk byte delta is
 *       reported as HK_INTEGRITY_TEXT_HASH_DELTA with detail = the image-relative
 *       offset of the first delta. Read-only.
 * Target platforms: Windows kernel mode (KMDF).
 * Interface: implements HkImageHashAudit declared in
 *       kernel/win/include/horkos_kernel.h. Depends on the shared ModuleMap.
 *       No-op when HK_WIN_INTEGRITY_IMAGEHASH is not defined (DEFAULT OFF —
 *       plan Risk 4: reloc/IAT normalization unproven). Emits
 *       hk_event_integrity_finding.
 */

#include <ntddk.h>
#include <wdf.h>

#include "horkos_kernel.h"

#if defined(HK_WIN_INTEGRITY_IMAGEHASH)

_Use_decl_annotations_
void HkImageHashAudit(PHK_DEVICE_CONTEXT Ctx, const HK_MODULE_MAP* Map)
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    UNREFERENCED_PARAMETER(Ctx);

    if (Map == NULL || Map->Count == 0) {
        return;
    }

    /* HK-UNCERTAIN(reloc-iat-normalization): the plan flags (Risk 4) that
     * correctly normalizing base relocations, IAT thunks, hotpatch regions, and
     * CFG/retpoline rewrites BEFORE hashing is error-prone — a wrong normalization
     * produces a false TEXT_HASH_DELTA on a clean machine. The catalog says this
     * signal must NEVER auto-ban and must be validated against a clean-machine
     * corpus first. Per guardrail #13 the normalization + hashing is left
     * UNIMPLEMENTED; this sensor ships DEFAULT OFF and report-only.
     *
     * The intended PASSIVE-only body (each step PASSIVE; file I/O is illegal at
     * raised IRQL — this whole TU runs in the scan work item):
     *
     *   for each module m in Map (skip our own image and known-good kernel):
     *       in-memory PE: nt = RtlImageNtHeader(m.base);
     *       for each IMAGE_SECTION_HEADER with IMAGE_SCN_MEM_EXECUTE:
     *           open on-disk file via FullPathName: ZwCreateFile + ZwReadFile;
     *           apply on-disk base-reloc delta (m.base - OptionalHeader.ImageBase)
     *               to the disk bytes so legitimate fixups match;
     *           neutralize IAT thunk targets (compare structurally, not byte-eq);
     *           exclude hotpatch padding + CFG/retpoline thunk regions;
     *           hash both; on a residual byte delta:
     *               HkIntegrityEmit(29, HK_INTEGRITY_TEXT_HASH_DELTA,
     *                               first_delta_rva);   // image-relative, no VA leak
     *           ZwClose(file);    // checked
     *
     * Do NOT ship the hash compare until reloc/IAT normalization is validated on a
     * clean-machine corpus — false deltas on legitimate fixups would be worse than
     * no signal. */
    (void)0;
}

#else /* HK_WIN_INTEGRITY_IMAGEHASH not defined — compile to a no-op. */

_Use_decl_annotations_
void HkImageHashAudit(PHK_DEVICE_CONTEXT Ctx, const HK_MODULE_MAP* Map)
{
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(Map);
}

#endif /* HK_WIN_INTEGRITY_IMAGEHASH */
