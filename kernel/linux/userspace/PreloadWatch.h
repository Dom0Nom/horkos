/*
 * Role: Signal 85 correlator — transient preload (env/file) divergence. Watches
 *       /etc/ld.so.preload via inotify (IN_MODIFY|IN_CLOSE_WRITE|IN_DELETE) for
 *       the steady-state file content and correlates it against the at-exec
 *       env/file state captured by bprm_env.bpf.c, attributing the env-setting
 *       ancestor PID. A LD_PRELOAD/LD_AUDIT/LD_LIBRARY_PATH seen at exec that is
 *       NOT reflected in the steady-state /etc/ld.so.preload (a transient,
 *       per-launch injection) is the anomaly.
 * Target platform: Linux userspace.
 * Interface: consumes BprmEnvEvent (+ optional inotify content); emits
 *            InjectionFinding (kEvtPreloadAnomaly). The inotify FD plumbing is
 *            owned by the loader; the scoring/correlation logic here is pure and
 *            testable on a fixture.
 */

#pragma once

#include <string>
#include <vector>

#include "InjectionEvents.h"
#include "OverlayAllowlist.h"

namespace horkos::inject {

/* Userspace mirror of bprm_env.bpf.c's record. The env_flags bitmask uses the
 * same HK_ENV_* bits as the BPF side. */
struct BprmEnvEvent {
    uint32_t pid = 0;
    uint32_t env_flags = 0;       /* HK_ENV_* */
    uint32_t ancestor_pid = 0;    /* env-setting ancestor (userspace-attributed) */
    /* Raw values (JSON-only side channel), populated by the userspace
     * /proc/<pid>/environ read since the BPF side only reports presence. */
    std::string ld_preload_value;
    std::string ld_audit_value;
    std::string ld_library_path_value;
};

/* Mirror of the BPF env-presence bits. */
inline constexpr uint32_t HK_ENV_LD_PRELOAD      = 0x1u;
inline constexpr uint32_t HK_ENV_LD_AUDIT        = 0x2u;
inline constexpr uint32_t HK_ENV_LD_LIBRARY_PATH = 0x4u;

class PreloadWatch {
public:
    PreloadWatch(const allowlist::OverlayAllowlist& allow, std::string scope);

    /* Update the steady-state /etc/ld.so.preload content (called from the inotify
     * handler in the loader; tests call it directly). Each non-empty,
     * non-comment line is a preloaded soname/path. */
    void SetSteadyStatePreload(const std::string& file_content);

    /* Correlate one at-exec env capture. If LD_PRELOAD (or LD_AUDIT) was present
     * at exec but the named module is NOT in the steady-state preload file AND
     * not allowlisted, it is a transient per-launch injection — fill `out` and
     * return true. */
    bool OnExecEnv(const BprmEnvEvent& ev, InjectionFinding* out);

private:
    const allowlist::OverlayAllowlist& allow_;
    std::string scope_;
    std::vector<std::string> steady_preload_;
};

}  // namespace horkos::inject
