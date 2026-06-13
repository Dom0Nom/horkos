/*
 * Role: Signal 120 — dynamic SecCode validity probe. Periodically resolves the
 *       game's running SecCode (SecCodeCopyGuestWithAttributes by pid) and runs
 *       SecCodeCheckValidity against Horkos's own designated requirement, with
 *       N-of-M confirmation across consecutive scans before emitting
 *       HK_CS_DYNAMIC_INVALID (JIT / unsigned plugins / lazily-paged code
 *       transiently fail — plan FP gate).
 * Target platform: macOS only (built behind if(APPLE) + HK_MACOS_CS_DYNAMIC,
 *       Security.framework).
 * Interface: implements the N-of-M confirmation core (PURE, host-tested) and the
 *            probe sample registered by the orchestrator. Standalone probe;
 *            emits HK_CS_FINDING via the orchestrator. Userspace daemon TU
 *            (guardrail #4).
 *
 * Guardrail compliance:
 *   #1  No platform #ifdef — CMake gates the TU.
 *   #13 The SecCodeCopyGuestWithAttributes + SecCodeCheckValidity live calls and
 *       the designated-requirement string are HK-UNCERTAIN (the DR is a
 *       build/sign-pipeline artifact, and the transient-failure taxonomy
 *       errSecCSGuestInvalid/errSecCSVmwMapping is unverified) and left
 *       unimplemented; the PURE N-of-M confirmation core IS implemented + tested.
 *   #14 hk_nofm_confirm is pure and host-tested.
 */

#include "CsScan.h"

#include <stdint.h>
#include <stdbool.h>

/* -------------------------------------------------------------------------
 * N-of-M confirmation core (PURE, host-runnable).
 *
 * A single transient SecCodeCheckValidity failure must NOT emit (JIT regions,
 * unsigned plugin bundles, lazily-paged code). Only N failures within the last M
 * consecutive scans confirm a real invalidation. The caller maintains a small
 * ring of the last M outcomes (1 = failed, 0 = passed); this counts the failures
 * and returns true iff the count reaches the threshold N.
 * ------------------------------------------------------------------------- */
#define HK_DV_WINDOW_M 5u   /* consider the last 5 consecutive scans */
#define HK_DV_THRESHOLD_N 3u /* confirm only at 3 failures within the window */

extern "C" bool hk_nofm_confirm(const uint8_t *outcomes, size_t count,
                                uint32_t threshold_n)
{
    if (outcomes == nullptr || count == 0 || threshold_n == 0) {
        return false;
    }
    uint32_t fails = 0;
    for (size_t i = 0; i < count; ++i) {
        if (outcomes[i]) {
            ++fails;
        }
    }
    return fails >= threshold_n;
}

/* -------------------------------------------------------------------------
 * Impure probe body (excluded from the pure host-test TU).
 * ------------------------------------------------------------------------- */
#ifndef HK_CS_PROBE_PURE_ONLY

#include <os/log.h>

namespace {
os_log_t hk_log() {
    static os_log_t log = os_log_create("io.horkos.daemon", "cs-dynamic-validity");
    return log;
}

/* Per-PID ring of the last M validity outcomes. A single live deployment tracks
 * one game; a small fixed map suffices. Kept here so the orchestrator's serial
 * timer thread is the only writer (no locking needed). */
struct DvState {
    uint32_t pid;
    uint8_t  ring[HK_DV_WINDOW_M];
    uint32_t head;
    uint32_t filled;
};
DvState g_dv = { 0, {0,0,0,0,0}, 0, 0 };

void dv_push(uint32_t pid, uint8_t failed) {
    if (g_dv.pid != pid) {                 /* reset the ring on a new PID */
        g_dv = DvState{ pid, {0,0,0,0,0}, 0, 0 };
    }
    g_dv.ring[g_dv.head] = failed;
    g_dv.head = (g_dv.head + 1u) % HK_DV_WINDOW_M;
    if (g_dv.filled < HK_DV_WINDOW_M) {
        ++g_dv.filled;
    }
}
}  // namespace

extern "C" bool hk_nofm_confirm(const uint8_t *outcomes, size_t count,
                                uint32_t threshold_n);  /* fwd (pure, above) */

extern "C" bool HkDynamicValidityProbeSample(const HkCsProbeTarget *target,
                                             HkCsFinding *out)
{
    if (target == nullptr || out == nullptr || target->pid == 0) {
        return false;
    }

    /* HK-UNCERTAIN(cs-dynamic-validity): the live path is unimplemented pending:
     *   1. Horkos's own DESIGNATED REQUIREMENT string (a build/sign artifact, not
     *      a constant we can hardcode — SecRequirementCreateWithString of the DR),
     *   2. the exact transient-failure taxonomy (errSecCSGuestInvalid /
     *      errSecCSVmwMapping vs a real tamper) so a JIT region is not miscounted,
     *   3. SecCodeCopyGuestWithAttributes pid-attribute semantics on macOS 12-15.
     * Per guardrail #12 these Security.framework calls are NOT guessed.
     * (docs: SecCodeCopyGuestWithAttributes, SecCodeCheckValidity, and
     * kSecCSEnforceRevocation ARE all in the public SDK (Security/SecCode.h:135,
     * 217, 237). SecRequirementCreateWithString is in SecRequirement.h. The DR
     * string is a build artifact; errSecCSGuestInvalid is in Security/CSCommon.h.
     * Still needs on-box verification of transient-failure taxonomy and DR string.)
     * When wired, run SecCodeCheckValidity(code, kSecCSEnforceRevocation, dr), push
     * the pass/fail into the ring, and confirm with hk_nofm_confirm before emitting:
     *   uint8_t failed = (status != errSecSuccess) ? 1 : 0;
     *   dv_push(target->pid, failed);
     *   if (hk_nofm_confirm(g_dv.ring, g_dv.filled, HK_DV_THRESHOLD_N)) {
     *       emit HK_CS_DYNAMIC_INVALID (detail = fail count); }
     * Until then the ring stays empty and the probe emits nothing. */
    (void)&dv_push;  /* silence unused-helper warning until the live path lands */
    os_log_debug(hk_log(),
        "HKDynamicValidityProbe: pid %u SecCodeCheckValidity HK-UNCERTAIN "
        "(designated-requirement + transient taxonomy unverified) — no emit",
        target->pid);
    return false;
}

#endif /* HK_CS_PROBE_PURE_ONLY */
