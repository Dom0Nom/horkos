/*
 * Role: Signal 200 sensor — correlates the create-process timestamp with the
 *       initial thread's creation and pre-resume image-loads so the server can
 *       compute a suspended-launch window. Per the plan's UNCERTAINTY resolution,
 *       the kernel ONLY timestamps create + thread-create + first-image-load; the
 *       suspend->resume gap is computed server-side from those plus a userspace
 *       thread-state sample. There is NO documented kernel notify for
 *       NtResumeThread and inspecting KTHREAD state at IRQL is unsafe — so this
 *       sensor never attempts a kernel resume hook (guardrail #12).
 *       READ-ONLY.
 * Target platforms: Windows kernel (KMDF). Builds only with the WDK.
 *
 *       HK-UNCERTAIN: the create<->first-image-load ordering that suggests a
 *       suspended launch is correlated SERVER-SIDE. This TU emits the image-load
 *       suspect flag only when the existing image-notify path observes a pre-first-
 *       thread image-load; that ordering hook is wired with module_reconcile.c on
 *       the box. Until then it sets no flag and only marks the timing sensor armed.
 * Interface: implements HkLaunchTimingArm/Disarm + HkLaunchTimingOnImage
 *       (horkos_kernel.h); the suspend flag rides hk_event_process_create_ex.
 */

#include <ntddk.h>

#include "horkos_kernel.h"
#include "horkos/event_schema.h"

static BOOLEAN g_LaunchTimingArmed;

NTSTATUS HkLaunchTimingArm(void)
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    g_LaunchTimingArmed = TRUE;
    return STATUS_SUCCESS;
}

void HkLaunchTimingDisarm(void)
{
    g_LaunchTimingArmed = FALSE;
}

/* Called from the image-load notify (HkImageNotify). The kernel only records
 * that an image load arrived for a PID; the suspend->resume gap is a server
 * computation over the create/thread-create/image-load timestamps + a userspace
 * thread-state sample. HK-UNCERTAIN: the "image-load before initial-thread-resume"
 * inference is not safe from kernel callbacks alone, so no flag is set here yet. */
void HkLaunchTimingOnImage(HANDLE ProcessId, PVOID ImageBase)
{
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ImageBase);
    if (!g_LaunchTimingArmed) {
        return;
    }
    /* Timestamps are already on each event's header; the server correlates. No
     * kernel resume hook, no KTHREAD-state probe (guardrail #12). */
}
