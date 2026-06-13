/*
 * Role: Signal 122 (daemon half) — per-dylib team-id / library-validation
 *       divergence. Consumes ES NOTIFY_MMAP observations (Option A in-process
 *       HkEsObservation), classifies each loaded dylib's team-id against the
 *       game's main-binary team-id and the Apple/Steam/AU allowlist, and emits
 *       HK_CS_LV_TEAMID_DIVERGENCE when a foreign-team dylib loads into an
 *       LV-enabled game (LV bypass). The team-id classification core is PURE.
 * Target platform: macOS only (built behind if(APPLE) + HK_MACOS_CS_DYLIB_LV,
 *       requires HORKOS_MACOS_ES).
 * Interface: implements cs_teamid_classify() (PURE, host-tested, declared in
 *            CsIntegrityProbe.h) and the ES-consume entry point registered by the
 *            orchestrator. Userspace daemon TU (guardrail #4).
 *
 * Guardrail compliance:
 *   #1  No platform #ifdef — CMake gates the TU.
 *   #13 The host-main-binary team-id read (csops CS_REQUIRE_LST) and the
 *       allowlist membership are HK-UNCERTAIN / corpus-dependent and left to the
 *       orchestrator's verified path; the PURE classifier is implemented + tested.
 *   #14 cs_teamid_classify is pure and host-tested.
 */

#include "CsIntegrityProbe.h"

#include <string.h>

/* Length of a NUL-padded fixed team-id buffer up to its first NUL. */
static size_t teamid_strlen(const uint8_t *p, size_t cap)
{
    size_t n = 0;
    while (n < cap && p[n] != 0) {
        ++n;
    }
    return n;
}

/* Compare two NUL-padded fixed team-id buffers by their NUL-terminated content.
 * Empty (all-NUL) team ids never compare equal — an unsigned/ad-hoc dylib has no
 * team and must not be treated as same-team as the host. */
static bool teamid_equal(const uint8_t *a, size_t a_len,
                         const uint8_t *b, size_t b_len)
{
    if (a == nullptr || b == nullptr) {
        return false;
    }
    size_t an = teamid_strlen(a, a_len);
    size_t bn = teamid_strlen(b, b_len);
    if (an == 0 || an != bn) {
        return false;
    }
    return memcmp(a, b, an) == 0;
}

extern "C" uint32_t cs_teamid_classify(const uint8_t *dylib_team_id, size_t dylib_team_len,
                                       const uint8_t *host_team_id, size_t host_team_len,
                                       bool is_platform, bool allowlisted)
{
    if (is_platform) {
        return HK_CS_TEAMID_APPLE_PLATFORM;   /* Apple platform binary — fine */
    }
    if (allowlisted) {
        return HK_CS_TEAMID_ALLOWLISTED;       /* known-good Apple/Steam/AU id */
    }
    if (teamid_equal(dylib_team_id, dylib_team_len, host_team_id, host_team_len)) {
        return HK_CS_TEAMID_SAME_TEAM;         /* same team as the game — fine */
    }
    return HK_CS_TEAMID_FOREIGN;               /* differing team, not allowlisted */
}

/* -------------------------------------------------------------------------
 * Impure ES-consume body (excluded from the pure host-test TU).
 * ------------------------------------------------------------------------- */
#ifndef HK_CS_PROBE_PURE_ONLY

#include <os/log.h>

namespace {
os_log_t hk_log() {
    static os_log_t log = os_log_create("io.horkos.daemon", "cs-dylib-teamid");
    return log;
}
}  // namespace

extern "C" bool HkDylibTeamIdProbeConsume(const HkEsObservation *obs, HkCsFinding *out)
{
    if (obs == nullptr || out == nullptr || obs->kind != HK_ES_OBS_MMAP) {
        return false;
    }

    /* HK-UNCERTAIN(cs-dylib-lv): the FP gates this needs to be a real finding are
     * NOT fully resolvable from the ES observation alone (plan Risk 4 + FP gate):
     *   - the HOST's main-binary team-id and its CS_REQUIRE_LST (library-
     *     validation) bit, read via csops CS_OPS_STATUS on the game — only then is
     *     a foreign-team dylib load an LV BYPASS rather than a normal differently-
     *     signed plugin,
     *   - the Apple/Steam/AU signing-id ALLOWLIST (OBS virtual-cam, audio AU
     *     plugins, accessibility tools legitimately inject differently-signed
     *     dylibs) — a corpus dependency,
     *   - that the host is the GAME itself, not its launcher.
     * The es_event_mmap_t field availability of source-FD signing_id across ES
     * message versions is also unverified. Per guardrail #12 these are not
     * guessed; the pure classifier above is ready, but the orchestrator must
     * supply the verified host team-id + LV bit + allowlist hit before this
     * emits. Until then, classify and log only — emit nothing. */
    uint32_t cls = cs_teamid_classify(obs->signing_id, sizeof(obs->signing_id),
                                      /*host_team_id*/nullptr, 0,
                                      obs->is_platform_src != 0,
                                      /*allowlisted*/false);
    (void)cls;
    os_log_debug(hk_log(),
        "HKDylibTeamIdProbe: mmap obs src pid %u into pid %u — host team-id + LV "
        "bit + allowlist HK-UNCERTAIN, not emitting",
        obs->source_pid, obs->target_pid);
    return false;
}

#endif /* HK_CS_PROBE_PURE_ONLY */
