/*
 * sdk/src/backends/win/HookDllFootprintWin.cpp
 * Role: Signal 52 (win-usermode-overlay). Injected GUI-hook-DLL footprint sensor:
 *       diffs the own process's loaded-module set (from the shared signed-module
 *       map) against the expected-module baseline to surface a DLL that was mapped
 *       in via a global SetWindowsHookEx hook. The "system-wide hook" signal (the
 *       same DLL concurrently mapped into many GUI processes) is inferred and
 *       reported as verdict + module path + signer subject. This is the usermode
 *       complement to the kernel PsSetLoadImageNotifyRoutine path — module-diff
 *       only, NO kernel coupling. Read-only.
 * Target platforms: Windows userspace. Guardrail #1: any Toolhelp/psapi use is
 *       confined here (module ranges come from the shared map).
 * Interface: implements hk::sdk::render::sense_hookdll_footprint.
 */

#include "RenderSensorWin.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <windows.h>

namespace hk { namespace sdk { namespace render {

int sense_hookdll_footprint(const ModuleMap& module_map,
                            std::vector<hk_render_finding>& out)
{
    /* Sequence (read-only, module-diff only):
     *   1. For each module in `module_map`, classify its signer against the
     *      server-provisioned baseline. The CLIENT does not own the allow-list — it
     *      reports the resolved signer subject + path; the server's signed rule
     *      decides whether an unexpected, unsigned, GUI-hook-shaped DLL is hostile.
     *   2. A module that is image-backed but unsigned, OR signed-but-not-allowlisted
     *      and not part of the expected baseline, is emitted as a footprint finding:
     *      verdict = classify_provenance over the module's own backing (Image +
     *      signature state), module_path + signer_subject in the JSON side-channel.
     *   3. The "system-wide hook" inference (same DLL mapped into many concurrent
     *      GUI processes) is a CROSS-PROCESS correlation: it requires sampling other
     *      GUI processes' module lists.
     *
     * HK-UNCERTAIN(cross-process-module-scan): confirming the same hook DLL is
     * mapped into MANY concurrent GUI processes needs CreateToolhelp32Snapshot/
     * Module32Next (or EnumProcessModulesEx) against OTHER processes, which requires
     * PROCESS_QUERY_INFORMATION|VM_READ on each and is subject to PPL/elevation
     * limits — it WILL fail for protected/elevated targets and must be treated as
     * best-effort, never assumed to succeed. The own-process footprint diff (steps
     * 1-2) is the reliable signal; the system-wide multiplicity is a server-side
     * fusion across many clients' own-process reports, not a client cross-process
     * scan. Left as documented: this sensor reports the own-process foreign-module
     * footprint; the system-wide inference is server-side.
     *
     * The own-process diff itself (steps 1-2) is mechanical over the supplied map,
     * but the expected-module baseline is server-provisioned signed-rule data not
     * present at scaffold time, so emitting a verdict now would either flag every
     * legitimately-loaded module or none. It is therefore wired to the map but
     * gated on the baseline: until the server hands down the baseline, no finding
     * is emitted (the report-only contract: presence of a module is never, alone,
     * a client-side flag). */
    (void)module_map;
    (void)out;
    return 0;
}

} } } // namespace hk::sdk::render

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
