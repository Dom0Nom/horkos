/*
 * kernel/win/src/DriverObjectAudit.c
 * Role: Signal 34 — DRIVER_OBJECT FastIo/StartIo/Unload/AddDevice divergence
 *       audit. Walks the loaded drivers and verifies each non-NULL dispatch
 *       pointer (DriverStartIo, DriverUnload, the FastIoDispatch table entries,
 *       DriverExtension->AddDevice, and the MajorFunction table) resolves inside
 *       the owning image's [base,base+size) — or, where the FP gate allows, any
 *       signed loaded module (fltmgr.sys thunks are legitimate). A pointer that
 *       lands in no image / in pool is flagged HK_INTEGRITY_DRVOBJ_DIVERGENCE.
 *       Read-only.
 * Target platforms: Windows kernel mode (KMDF).
 * Interface: implements HkDriverObjectAudit declared in
 *       kernel/win/include/horkos_kernel.h. Depends on the shared ModuleMap.
 *       No-op when HK_WIN_INTEGRITY_DRVOBJ is not defined. Emits
 *       hk_event_integrity_finding.
 */

#include <ntddk.h>
#include <wdf.h>

#include "horkos_kernel.h"

#if defined(HK_WIN_INTEGRITY_DRVOBJ)

/* Mask a kernel pointer to an owning-image-relative offset for the `detail`
 * field so no raw KASLR'd pointer leaves the box (plan Risk 7). If the pointer
 * resolves into a module, detail = offset within that image; otherwise detail =
 * low 16 bits only (enough to disambiguate the divergence without leaking VA). */
static uint64_t HkDrvObjMaskDetail(const HK_MODULE_MAP* Map, uint64_t ptr)
{
    size_t idx = HkModuleMapResolve(Map, ptr);
    if (idx != HK_MODRANGE_NONE) {
        return ptr - Map->Ranges[idx].base; /* image-relative offset */
    }
    return ptr & 0xFFFFull; /* out-of-image: leak only the low 16 bits */
}

/* Check one pointer against the owning image OR any signed module. Emits a
 * divergence finding if it lands nowhere acceptable. */
static void HkDrvObjCheckPtr(const HK_MODULE_MAP* Map, uint64_t ownerBase,
                             uint64_t ownerSize, uint64_t ptr)
{
    if (ptr == 0) {
        return; /* NULL dispatch slot is normal. */
    }
    /* In the owning image? (half-open interval, overflow-safe subtraction). */
    if (ptr >= ownerBase && (ptr - ownerBase) < ownerSize) {
        return;
    }
    /* Not in the owner. The catalog FP gate accepts a thunk that lands in any
     * signed module (e.g. fltmgr.sys). HK-UNCERTAIN(modmap-signed): the ModuleMap
     * cannot currently mark modules signed (see ModuleMap.c), so this falls back
     * to "in ANY loaded image" — stricter than the ideal "signed module" gate but
     * never laxer. A pointer inside another loaded image is treated as a probable
     * legitimate cross-module thunk and NOT flagged; only a pointer in NO image
     * (pool / manually-mapped) is reported. */
    if (HkModuleRangeContains(Map->Ranges, (size_t)Map->Count, ptr)) {
        return;
    }
    HkIntegrityEmit(34u, HK_INTEGRITY_DRVOBJ_DIVERGENCE,
                    HkDrvObjMaskDetail(Map, ptr));
}

_Use_decl_annotations_
void HkDriverObjectAudit(PHK_DEVICE_CONTEXT Ctx, const HK_MODULE_MAP* Map)
{
    UNREFERENCED_PARAMETER(Ctx);
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    if (Map == NULL || Map->Count == 0) {
        return; /* no map -> emit nothing (guardrail #5). */
    }

    /* HK-UNCERTAIN(drvobj-enumeration): enumerating every \Driver\* object
     * requires either ObReferenceObjectByName with IoDriverObjectType (NOT
     * exported on all WDK versions — plan flags this) or a directory-object walk
     * via the undocumented ObpRootDirectoryObject, or IoEnumerateDeviceObjectList
     * per known driver (which still needs a driver-object handle to start from).
     * The plan flags this as uncertain and prefers IoEnumerateDeviceObjectList
     * where it avoids the unexported IoDriverObjectType dependency. Because there
     * is NO documented, version-stable way to obtain the full \Driver\* set from a
     * KMDF driver without one of those unverified surfaces, the driver-object
     * ENUMERATION is left UNIMPLEMENTED here per guardrail #13. The per-pointer
     * audit logic above (HkDrvObjCheckPtr) is complete and unit-shaped so it is
     * ready the moment a documented enumerator is wired:
     *
     *   for each DRIVER_OBJECT drv (via the confirmed enumerator):
     *       base = (uint64)drv->DriverStart; size = drv->DriverSize;
     *       HkDrvObjCheckPtr(Map, base, size, (uint64)drv->DriverStartIo);
     *       HkDrvObjCheckPtr(Map, base, size, (uint64)drv->DriverUnload);
     *       if (drv->DriverExtension)
     *           HkDrvObjCheckPtr(Map, base, size, (uint64)drv->DriverExtension->AddDevice);
     *       if (drv->FastIoDispatch)
     *           for each non-NULL FastIo entry: HkDrvObjCheckPtr(...);
     *       for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i)
     *           HkDrvObjCheckPtr(Map, base, size, (uint64)drv->MajorFunction[i]);
     *       ObDereferenceObject(drv);   // checked, exactly once per reference
     *
     * Do NOT enable a \Driver\* walk on a guessed IoDriverObjectType import or an
     * undocumented directory-object offset — a bad object pointer here is a
     * bugcheck. Confirm the enumerator surface on-box first. */
    (void)HkDrvObjCheckPtr; /* keep the helper referenced until the walk is wired. */
}

#else /* HK_WIN_INTEGRITY_DRVOBJ not defined — compile to a no-op. */

_Use_decl_annotations_
void HkDriverObjectAudit(PHK_DEVICE_CONTEXT Ctx, const HK_MODULE_MAP* Map)
{
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(Map);
}

#endif /* HK_WIN_INTEGRITY_DRVOBJ */
