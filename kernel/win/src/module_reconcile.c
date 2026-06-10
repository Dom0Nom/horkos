/*
 * kernel/win/src/module_reconcile.c
 * Role: Signal 202 kernel half — maintains the authoritative loader-loaded module
 *       set from PsSetLoadImageNotifyRoutine (base + size + FILE_OBJECT presence)
 *       per PID, so userspace (region_walk.cpp) can diff its executable-region
 *       enumeration against it. A region executable + absent from BOTH the kernel
 *       image-load set and the PEB Ldr is a manual-map artifact. The reconcile
 *       (the diff) is server-side; the kernel emits hk_event_image_load with
 *       HK_IMAGE_FLAG_MANUAL_MAP_SUSPECT left for the server to confirm against
 *       the userspace region report.
 *       READ-ONLY.
 * Target platforms: Windows kernel (KMDF). Builds only with the WDK.
 *
 *       HK-UNCERTAIN: a per-PID authoritative module set requires a bounded,
 *       lifetime-managed table keyed by PID+create-time (to survive PID reuse).
 *       The absence of a backing FILE_OBJECT in IMAGE_INFO is a precursor, not
 *       conclusive. Until the table sizing/eviction policy is settled on the box,
 *       this records nothing and emits no manual-map suspect flag — the userspace
 *       region walk + server reconcile carry the signal.
 * Interface: implements HkModuleReconcileOnImage (horkos_kernel.h); called from
 *       the image-load notify in Notify.c.
 */

#include <ntddk.h>

#include "horkos_kernel.h"
#include "horkos/event_schema.h"

void HkModuleReconcileOnImage(HANDLE ProcessId, PVOID ImageBase, SIZE_T ImageSize,
                              BOOLEAN HasBackingFile)
{
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ImageBase);
    UNREFERENCED_PARAMETER(ImageSize);
    UNREFERENCED_PARAMETER(HasBackingFile);
    /* HK-UNCERTAIN (box): record (base, size, HasBackingFile) into a bounded
     * per-PID set keyed by PID+create-time; the server diffs it against the
     * userspace region walk to confirm a manual-mapped module. No flag is emitted
     * from the kernel alone — a missing FILE_OBJECT is a precursor, not proof. */
}
