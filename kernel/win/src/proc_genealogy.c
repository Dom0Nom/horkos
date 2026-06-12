/*
 * Role: Signal 199 sensor — in the process-create notify, captures the TRUE
 *       creator (PsGetCurrentProcessId, the creating thread's owning process) and
 *       compares it against the inherited ParentProcessId; emits the v5
 *       hk_event_process_create_ex with true_creator_pid and the
 *       HK_PROC_FLAG_REPARENT_SUSPECT flag (via the host-tested pure helper
 *       hk_proc_reparent_suspect). Gating is server-side (the signed-launcher
 *       pair). The notify runs at PASSIVE_LEVEL in the creating thread's context,
 *       where PsGetCurrentProcessId is valid; every value is a copy of an
 *       already-validated CreateInfo field — no new probe.
 *       READ-ONLY.
 * Target platforms: Windows kernel (KMDF). Builds only with the WDK.
 * Interface: implements HkGenealogyClassify (horkos_kernel.h), called from the
 *       create-process notify in Notify.c; emits via HkRingEmit.
 */

#include <ntddk.h>

#include "horkos_kernel.h"
#include "horkos/event_schema.h"
#include "horkos/genealogy_logic.h"

void HkGenealogyClassify(HANDLE ProcessId, HANDLE ParentProcessId,
                         LONG64 CreateTimeNs)
{
    hk_event_process_create_ex ev;
    uint32_t true_creator;
    uint32_t declared_parent;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    RtlZeroMemory(&ev, sizeof(ev));

    /* The creating thread's owning process is the TRUE creator; CreateInfo's
     * ParentProcessId is the inherited/assigned parent (forgeable via
     * UpdateProcThreadAttribute PROC_THREAD_ATTRIBUTE_PARENT_PROCESS). */
    true_creator = (uint32_t)(ULONG_PTR)PsGetCurrentProcessId();
    declared_parent = (uint32_t)(ULONG_PTR)ParentProcessId;

    ev.pid = (uint32_t)(ULONG_PTR)ProcessId;
    ev.parent_pid = declared_parent;
    ev.create_time_ns = (uint64_t)CreateTimeNs;
    ev.true_creator_pid = true_creator;
    if (hk_proc_reparent_suspect(true_creator, declared_parent)) {
        ev.proc_flags |= HK_PROC_FLAG_REPARENT_SUSPECT;
    }

    HkRingEmit(HK_EVENT_PROCESS_CREATE_EX, &ev, sizeof(ev));
}
