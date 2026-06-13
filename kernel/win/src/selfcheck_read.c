/*
 * Role: Windows KMDF handler for HK_IOCTL_SELF_READ_VA (memory-integrity-selfcheck,
 *       signals 145/146/148/151/152). Foreign-reads the CALLING AC process's OWN VA
 *       range (145 bytes), page-share/CoW state (146), leaf-PTE write/NX bits (152),
 *       per-thread DR0-DR7 (148), and the kernel section-object FILE name (151).
 *       Reads ONLY the verified AC caller's own address space and refuses any VA
 *       outside that process's image mapping — a foreign-read primitive is a
 *       privilege boundary.
 * Target platforms: Windows kernel mode (KMDF). Built behind HK_WIN_SELFCHECK_READ
 *       (DEFAULT OFF) — the caller-identity binding that makes this safe is unsettled,
 *       and a mis-scoped foreign read is worse than shipping fewer signals.
 * Interface: implements HkHandleSelfRead (horkos_kernel.h); routed from IrpDispatch.c.
 *
 * Guardrail compliance: #5 (every NTSTATUS checked; safe string fns only — none used
 * here), #13 (every risky kernel path is an HK-UNCERTAIN stub, NOT a guess).
 */

#include <ntddk.h>
#include <wdf.h>

#include "horkos_kernel.h"

#if defined(HK_WIN_SELFCHECK_READ)

_Use_decl_annotations_
NTSTATUS HkHandleSelfRead(WDFREQUEST Request,
                          PHK_DEVICE_CONTEXT Ctx,
                          size_t InputBufferLength,
                          size_t OutputBufferLength,
                          size_t* BytesReturned)
{
    NTSTATUS                    status;
    PVOID                       inBuf = NULL;
    const hk_self_read_request* req;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    *BytesReturned = 0;

    if (Ctx == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }
    if (InputBufferLength < sizeof(hk_self_read_request)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(hk_self_read_request),
                                           &inBuf, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    req = (const hk_self_read_request*)inBuf;
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(req);

    /* =====================================================================
     * HK-UNCERTAIN(selfcheck-caller-identity): the driver MUST prove the
     * requesting process IS the legitimate AC (not malware asking the driver to
     * foreign-read another process under cover of "self") AND bound
     * [va_base, va_base+va_len) inside that process's OWN image mapping. The
     * intended gate validates the IRP-issuing FILE_OBJECT / PsGetCurrentProcessId
     * against the AC image identity established at driver load, then range-checks
     * the request against the caller's VAD/image extent. The EXACT secure binding
     * (signed IOCTL, per-session token, image-hash check at \\.\Horkos open) is
     * NOT settled. Per guardrail #12 we do NOT expose a foreign-read primitive on a
     * guess — the handler refuses until the binding is confirmed on-box.
     *
     * HK-UNCERTAIN(selfcheck-read-path 145): once gated, the byte read uses the
     * DOCUMENTED MmCopyVirtualMemory against the caller process (PASSIVE_LEVEL,
     * target referenced), or an IoAllocateMdl + MmProbeAndLockPages (SEH-guarded) +
     * MmGetSystemAddressForMdlSafe path — confirm which is correct from the IOCTL
     * dispatch context and the exact locking/IRQL requirements before reading.
     *
     * HK-UNCERTAIN(selfcheck-pte 152): deriving the leaf PTE
     * (MiGetPteAddress-equivalent) relies on the non-exported, build-varying
     * PTE_BASE. Prefer a documented path (MmGetPhysicalAddress per sampled page) if
     * it exposes the protection bits; if the NX/write bits are not reachable through
     * a documented API on a target build, 152 ships sampled-only or is deferred.
     * Do NOT hand-roll a PTE walk on a guess.
     *
     * HK-UNCERTAIN(selfcheck-dr 148): saved DR0-DR7 in the thread context /
     * _KTRAP_FRAME are not stable documented ABI; offsets vary by build. Prefer a
     * documented context-capture path; the raw _KTRAP_FRAME field goes behind a
     * per-build offset allow-list (fail closed) only if no documented path exists.
     *
     * FLAGGED GAP (large-record plane): even when these reads are safe, the replies
     * (hk_event_self_crossview is 120 bytes) exceed the frozen HK_EVENT_PAYLOAD_MAX
     * and need the large-record drain plane, which is pre-Schema. Do NOT truncate a
     * reply into the 40-byte envelope.
     * ===================================================================== */
    return STATUS_NOT_SUPPORTED;
}

#else /* HK_WIN_SELFCHECK_READ not defined — link-safe refusing stub. */

_Use_decl_annotations_
NTSTATUS HkHandleSelfRead(WDFREQUEST Request,
                          PHK_DEVICE_CONTEXT Ctx,
                          size_t InputBufferLength,
                          size_t OutputBufferLength,
                          size_t* BytesReturned)
{
    UNREFERENCED_PARAMETER(Request);
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    if (BytesReturned != NULL) {
        *BytesReturned = 0;
    }
    /* Feature OFF: refuse the foreign-read IOCTL outright (fail-closed). */
    return STATUS_NOT_SUPPORTED;
}

#endif /* HK_WIN_SELFCHECK_READ */
