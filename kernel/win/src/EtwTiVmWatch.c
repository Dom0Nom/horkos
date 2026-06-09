/*
 * kernel/win/src/EtwTiVmWatch.c
 * Role: External-memory-access watch (win-handle-memory-access, catalog signals
 *       64/69/71-input/72). Two parts:
 *         (1) A per-module section-flag cache for the PROTECTED process so a runtime
 *             VA from a cross-process ReadVm/WriteVm/AllocVm/ProtectVm event can be
 *             classified back to its IMAGE_SCN_* section characteristics without a
 *             per-event VAD walk. This is REAL, compilable kernel logic.
 *         (2) The ETW Threat-Intelligence consumer SURFACE (HkEtwTiArm/Disarm) that
 *             would filter TI events to the protected pid, classify the target VA,
 *             assemble alloc->protect->write staging tuples (#72), and set
 *             HK_VM_ETWTI_SILENT on a working-set page-in with no matching ReadVm
 *             (#69). Under current signing this consumer CANNOT exist in the kernel
 *             (see HK-UNCERTAIN below) — it is a documented STATUS_NOT_SUPPORTED stub.
 *       Read-only telemetry; nothing here blocks. Guardrail #5: every NTSTATUS
 *       checked; RtlZeroMemory only; no raw string APIs.
 * Target platforms: Windows kernel mode (KMDF).
 * Interface: implements HkEtwTiArm/HkEtwTiDisarm + the HkVmSection* cache helpers
 *       declared in kernel/win/include/horkos_kernel.h.
 */

#include <ntddk.h>
#include <wdf.h>

#include "horkos_kernel.h"

/* The whole TU is gated by HK_WIN_VMWATCH (default OFF in CMake). When OFF it
 * compiles to the no-op-stub branch, exactly like the integrity sensors, so the
 * driver links with or without the VM-watch feature. */
#if defined(HK_WIN_VMWATCH)

/* -------------------------------------------------------------------------
 * Section-flag cache (#64/#71 input). Pure range bookkeeping; no platform
 * uncertainty here. Serialized by Cache->Lock (acquired at <= DISPATCH).
 * ------------------------------------------------------------------------- */

_Use_decl_annotations_
void HkVmSectionCacheReset(PHK_VM_SECTION_CACHE Cache)
{
    KIRQL irql;
    if (Cache == NULL) {
        return;
    }
    KeAcquireSpinLock(&Cache->Lock, &irql);
    /* Zero only the count/flag; the Ranges array is overwritten on add, and
     * RtlZeroMemory over 256*24B under the lock would needlessly extend the
     * critical section. */
    Cache->Count = 0;
    Cache->Truncated = FALSE;
    KeReleaseSpinLock(&Cache->Lock, irql);
}

_Use_decl_annotations_
NTSTATUS HkVmSectionCacheAdd(PHK_VM_SECTION_CACHE Cache, uint32_t owner_pid,
                             uint64_t base, uint64_t size, uint32_t characteristics)
{
    KIRQL irql;
    NTSTATUS status = STATUS_SUCCESS;

    if (Cache == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    /* A zero-size range can never contain a VA; reject it rather than store a
     * row the resolver must skip. */
    if (size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&Cache->Lock, &irql);
    if (Cache->Count >= HK_VM_SECTION_CACHE_MAX) {
        Cache->Truncated = TRUE;
        status = STATUS_INSUFFICIENT_RESOURCES;
    } else {
        PHK_VM_SECTION_RANGE r = &Cache->Ranges[Cache->Count];
        r->Base = base;
        r->Size = size;
        r->Characteristics = characteristics;
        r->OwnerPid = owner_pid;
        Cache->Count += 1;
    }
    KeReleaseSpinLock(&Cache->Lock, irql);
    return status;
}

_Use_decl_annotations_
uint32_t HkVmSectionResolve(PHK_VM_SECTION_CACHE Cache, uint64_t target_va)
{
    KIRQL irql;
    uint32_t flags = 0;
    ULONG i;

    if (Cache == NULL) {
        return 0;
    }

    KeAcquireSpinLock(&Cache->Lock, &irql);
    for (i = 0; i < Cache->Count; ++i) {
        const HK_VM_SECTION_RANGE* r = &Cache->Ranges[i];
        /* [Base, Base+Size). The add path rejects Size==0, and (va - Base) is
         * computed only after va >= Base so it cannot wrap. */
        if (target_va >= r->Base && (target_va - r->Base) < r->Size) {
            flags = r->Characteristics;
            break;
        }
    }
    KeReleaseSpinLock(&Cache->Lock, irql);
    return flags;
}

/* -------------------------------------------------------------------------
 * ETW-TI consumer surface (#64/#69/#72).
 *
 * HK-UNCERTAIN(etw-ti): Microsoft-Windows-Threat-Intelligence is a PROTECTED
 * provider. An ordinary KMDF driver CANNOT open a real-time consumer session on
 * it; only a PPL/PP (anti-malware/ELAM-signed) USER-MODE process may. The kernel
 * EMITS to it (via EtwRegister); it does not let a third-party driver CONSUME it.
 * Horkos holds no anti-malware/ELAM certificate today, so there is NO valid
 * in-kernel path to subscribe to ReadVm/WriteVm/AllocVm/ProtectVm keywords here.
 *
 * Therefore, per guardrail #13, this arm installs NOTHING. The full consumer
 * (keyword set KERNEL_THREATINT_KEYWORD_{READVM,WRITEVM,ALLOCVM,PROTECTVM}_
 * {LOCAL,REMOTE}, the TargetProcessId==protected-pid filter, the per-event
 * classify->staging->emit pipeline) belongs in a PPL user-mode session that bumps
 * the kernel keepalive through an IOCTL (see HkEtwTiKeepaliveBump in Notify.c).
 * The classify/staging LOGIC is implemented and host-tested userspace-side
 * (VmAccessLogicWin.h / EtwTiConsumer.cpp), ready to drive from that session. Do
 * NOT write a kernel ETW-TI consumer against guessed keyword encodings.
 * ------------------------------------------------------------------------- */
_Use_decl_annotations_
NTSTATUS HkEtwTiArm(PHK_DEVICE_CONTEXT Ctx)
{
    if (Ctx == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    KeInitializeSpinLock(&Ctx->VmSectionCache.Lock);
    HkVmSectionCacheReset(&Ctx->VmSectionCache);
    InterlockedExchange(&Ctx->VmWatchArmed, 0);
    /* No kernel TI consumer under current signing — see HK-UNCERTAIN above. The
     * section cache is initialized so a (future) PPL session's classify path has a
     * populated lookup, but nothing is subscribed here. */
    return STATUS_NOT_SUPPORTED;
}

_Use_decl_annotations_
void HkEtwTiDisarm(PHK_DEVICE_CONTEXT Ctx)
{
    if (Ctx == NULL) {
        return;
    }
    /* Nothing was armed (arm is a stub); reset the cache so a re-arm starts clean. */
    HkVmSectionCacheReset(&Ctx->VmSectionCache);
    InterlockedExchange(&Ctx->VmWatchArmed, 0);
}

#else /* !HK_WIN_VMWATCH — feature OFF: link-safe no-op stubs. */

_Use_decl_annotations_
void HkVmSectionCacheReset(PHK_VM_SECTION_CACHE Cache) { UNREFERENCED_PARAMETER(Cache); }

_Use_decl_annotations_
NTSTATUS HkVmSectionCacheAdd(PHK_VM_SECTION_CACHE Cache, uint32_t owner_pid,
                             uint64_t base, uint64_t size, uint32_t characteristics)
{
    UNREFERENCED_PARAMETER(Cache);
    UNREFERENCED_PARAMETER(owner_pid);
    UNREFERENCED_PARAMETER(base);
    UNREFERENCED_PARAMETER(size);
    UNREFERENCED_PARAMETER(characteristics);
    return STATUS_NOT_SUPPORTED;
}

_Use_decl_annotations_
uint32_t HkVmSectionResolve(PHK_VM_SECTION_CACHE Cache, uint64_t target_va)
{
    UNREFERENCED_PARAMETER(Cache);
    UNREFERENCED_PARAMETER(target_va);
    return 0;
}

_Use_decl_annotations_
NTSTATUS HkEtwTiArm(PHK_DEVICE_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
    return STATUS_NOT_SUPPORTED;
}

_Use_decl_annotations_
void HkEtwTiDisarm(PHK_DEVICE_CONTEXT Ctx) { UNREFERENCED_PARAMETER(Ctx); }

#endif /* HK_WIN_VMWATCH */
