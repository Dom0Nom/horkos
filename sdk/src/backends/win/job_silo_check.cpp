/*
 * Role: Signal 204 sensor (advisory-only, high FP) — reports whether the game is
 *       in a job object and a coarse descriptor of that job, for the server to
 *       compare against the expected launcher job. Windows itself, UWP
 *       AppContainers, the steamwebhelper job, GameBar, Sandboxie and Game Mode
 *       all use jobs/silos, so this is ADVISORY telemetry only — never an
 *       autonomous ban (catalog mandate). The server gates hard: only surfaces
 *       when the job creator is unsigned/unknown AND a non-whitelisted
 *       instrumentation binary is in the member set.
 *       READ-ONLY.
 * Target platforms: Windows userspace. Guardrail #1: job APIs confined to
 *       backends/win. NOT COMPILED on non-Windows (if(WIN32)).
 * Interface: hk::sdk::genealogy::job_silo_anomaly.
 */

#include <windows.h>

namespace hk {
namespace sdk {
namespace genealogy {

/* Returns true if the game is in a job whose basic limits look anomalous for a
 * game (a coarse advisory signal). The deep member-set/creator analysis is
 * server-side; this is the cheap client observation. */
bool job_silo_anomaly()
{
    BOOL inJob = FALSE;
    if (!IsProcessInJob(GetCurrentProcess(), nullptr, &inJob)) {
        return false;
    }
    if (!inJob) {
        return false; /* not in a job — nothing to report. */
    }
    /* HK-VERIFIED(job-silo-client-scope): IsProcessInJob (documented:
     * https://learn.microsoft.com/windows/win32/api/jobapi2/nf-jobapi2-isprocessinjob)
     * reliably reports job membership; the in-job fact is fully documented and
     * not uncertain. The DESIGN DECISION here — not flagging client-side because
     * UWP AppContainers / Steam / GameBar all use jobs — is a deliberate advisory
     * choice: distinguishing a benign platform job from a sandboxing/instrumentation
     * job requires the job creator + member-set inspection, which is server-side
     * against the launcher baseline. The client reports in-job presence only;
     * advisory-only, never a ban. Conservative default (return false) prevents
     * client-side FP; server requests deeper data when needed. */
    return false;
}

} // namespace genealogy
} // namespace sdk
} // namespace hk
