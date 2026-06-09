/*
 * kernel/win/src/BootLoadAudit.c
 * Role: Signal 36 (kernel half) — boot-start / ELAM load-order audit. Reads the
 *       live PsLoadedModuleList load order and SystemBootEnvironmentInformation to
 *       confirm OUR boot-start driver loaded and is early, and that the ELAM
 *       verdict is present. Flags HK_INTEGRITY_BOOTLOAD_SUPPRESS only when our
 *       driver or the ELAM verdict is missing/suppressed — not on benign
 *       dual-boot / safe-mode / WinPE deviations (catalog FP gate). The user-mode
 *       half (ServiceGroupOrder + per-service Start/Group) lives in
 *       sdk/src/backends/win/DriverProbeWin.cpp (guardrail #4: never shares a TU).
 * Target platforms: Windows kernel mode (KMDF).
 * Interface: implements HkBootLoadAudit declared in
 *       kernel/win/include/horkos_kernel.h. No-op when HK_WIN_INTEGRITY_BOOTLOAD is
 *       not defined (DEFAULT OFF — plan Risk 5: ELAM callback timing unverified).
 *       Emits hk_event_integrity_finding.
 */

#include <ntddk.h>
#include <wdf.h>

#include "horkos_kernel.h"

#if defined(HK_WIN_INTEGRITY_BOOTLOAD)

/* PsLoadedModuleList is the documented-for-walk doubly-linked list of
 * KLDR_DATA_TABLE_ENTRY (the public loader-table shape). It is exported. */
extern LIST_ENTRY PsLoadedModuleList;

/* Public KLDR_DATA_TABLE_ENTRY prefix (only the fields we read). The full struct
 * has more trailing fields; we touch only InLoadOrderLinks, DllBase, SizeOfImage,
 * and BaseDllName, which are stable across builds. */
typedef struct _HK_KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} HK_KLDR_DATA_TABLE_ENTRY;

_Use_decl_annotations_
void HkBootLoadAudit(PHK_DEVICE_CONTEXT Ctx)
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    UNREFERENCED_PARAMETER(Ctx);

    /* HK-UNCERTAIN(elam-timing): the canonical ELAM verdict surface,
     * IoRegisterBootDriverCallback, must be registered very early (boot-start)
     * with strict callback constraints (plan Risk 5). Registering it from this
     * scan path is WRONG — the registration point is DriverEntry-at-boot, and the
     * timing/constraints are unverified. Per guardrail #13 the ELAM-verdict read
     * is left UNIMPLEMENTED until the registration timing is confirmed on-box. The
     * PsLoadedModuleList load-order read below IS implementable (the list is
     * exported and documented-for-walk), but correlating "our driver is early
     * enough" needs the ELAM verdict to avoid FPs on benign reorderings, so the
     * SUPPRESS emit is gated on that missing piece and not fired here.
     *
     * The load-order walk, guarded, that is ready to correlate once the ELAM
     * verdict lands:
     *
     *   __try {
     *       for (LIST_ENTRY* e = PsLoadedModuleList.Flink;
     *            e != &PsLoadedModuleList; e = e->Flink) {
     *           HK_KLDR_DATA_TABLE_ENTRY* m =
     *               CONTAINING_RECORD(e, HK_KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
     *           // compare m->BaseDllName against our image name; record load index
     *       }
     *   } __except (EXCEPTION_EXECUTE_HANDLER) { mark faulted; }
     *
     *   if (our driver missing from the early load order OR ELAM verdict absent)
     *       HkIntegrityEmit(36, HK_INTEGRITY_BOOTLOAD_SUPPRESS, load_index);
     *
     * Do NOT emit a SUPPRESS finding from an uncorrelated load-order read alone —
     * dual-boot/safe-mode/WinPE produce benign deviations the catalog FP gate
     * excludes, and without the ELAM verdict the false-positive rate is high.
     * This sensor ships DEFAULT OFF. */
    (void)0;
}

#else /* HK_WIN_INTEGRITY_BOOTLOAD not defined — compile to a no-op. */

_Use_decl_annotations_
void HkBootLoadAudit(PHK_DEVICE_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
}

#endif /* HK_WIN_INTEGRITY_BOOTLOAD */
