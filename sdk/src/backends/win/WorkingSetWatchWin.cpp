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
 * HK-UNCERTAIN(workingset-enumeration): QueryWorkingSetEx and GetProcessTimes are
 * both fully documented Win32 APIs (QueryWorkingSetEx:
 * https://learn.microsoft.com/windows/win32/api/psapi/nf-psapi-queryworkingsetex;
 * PSAPI_WORKING_SET_EX_INFORMATION.VirtualAttributes.Valid is the residency bit).
 * The API contract is not uncertain. What IS uncertain is the ALGORITHM tuning:
 * turning a per-page sweep into a stable "newly-resident this sample" delta requires
 * an on-box-validated burst threshold + sample cadence against real ReadProcessMemory
 * captures (the working set churns under normal execution; a too-low threshold
 * fires on paging activity, too-high misses real scans). The owning-thread CPU
 * pairing (GetProcessTimes) is straightforward. This sampler is SCAFFOLD ONLY:
 * the read + correlate sequence is laid out through the pure residency_burst_is_foreign
 * core, but the QueryWorkingSetEx sweep is left as a documented stub pending
 * on-box burst-threshold calibration. (docs: API documented — still needs on-box
 * burst-threshold + cadence calibration before enabling)
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
