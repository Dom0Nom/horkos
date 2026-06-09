/*
 * sdk/src/backends/win/WorkingSetWatchWin.cpp
 * Role: Windows userspace working-set residency sampler (win-handle-memory-access,
 *       catalog signal 65). One tick: QueryWorkingSetEx over the game's address
 *       space to count newly-resident pages, correlated with the game's owning-thread
 *       CPU delta (GetProcessTimes). A residency burst with no owning-thread CPU
 *       advance is the foreign-read signature (a foreign ReadProcessMemory faults
 *       pages in without the game's threads running). Read-only; high-FP alone, so it
 *       reports at low base confidence and the server weights it up only when a kernel
 *       VM/Ob event coincides (#69 correlation). Ships dark (HK_WIN_VMWATCH OFF).
 * Target platforms: Windows userspace. Guardrail #1: the working-set Win32 API is
 *       confined here; the residency_burst_is_foreign decision core is platform-free
 *       in VmWatchWin.h and host-tested.
 * Interface: implements hk::sdk::vmaccess::sample_working_set from VmWatchWin.h.
 */

#include "VmWatchWin.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

namespace hk { namespace sdk { namespace vmaccess {

/* -------------------------------------------------------------------------
 * HK-UNCERTAIN(workingset-enumeration): turning a per-page QueryWorkingSetEx sweep
 * over a foreign process's full committed range into a stable "newly-resident this
 * sample" delta needs an on-box-validated page-set diff (the working set churns under
 * normal execution; the burst threshold + sample cadence are tuned with real
 * captures, not guessed). The owning-thread CPU pairing (GetProcessTimes kernel+user
 * delta across the same interval) is straightforward, but the page-residency delta is
 * the unproven half. This sampler is therefore SCAFFOLD ONLY: it lays out the read +
 * correlate sequence and emits through the pure residency_burst_is_foreign core, but
 * the actual QueryWorkingSetEx sweep is left as a documented stub rather than coded
 * against an unvalidated diff/cadence. The pure core (the tested part) is unaffected.
 * ------------------------------------------------------------------------- */
int sample_working_set(uint32_t game_pid)
{
    /* Steps the verified implementation performs (NOT coded here — see HK-UNCERTAIN):
     *   1. OpenProcess(PROCESS_QUERY_INFORMATION, game_pid) (the GAME's own pid; the
     *      AC samples the process it protects, not a foreign one).
     *   2. GetProcessTimes(kernel+user) -> owning CPU delta vs the previous sample.
     *   3. QueryWorkingSetEx over the committed regions -> count pages that flipped to
     *      Valid since the previous sample (the residency burst).
     *   4. ResidencyBurstInput{ newly_resident_pages, owning_cpu_delta_ns,
     *      cpu_delta_valid, burst_threshold } -> residency_burst_is_foreign(...).
     *   5. On true, queue a low-confidence finding (the server fuses #69: correlate
     *      with a kernel ReadVm in the window; a burst with NO matching ReadVm sets
     *      HK_VM_ETWTI_SILENT). HK-TODO(schema): the report-queue type is the
     *      kernel-private mirror until the Schema phase appends it.
     */
    (void)game_pid;
    return -1; /* not sampled: working-set residency diff is an on-box-verified stub */
}

} } } // namespace hk::sdk::vmaccess

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
