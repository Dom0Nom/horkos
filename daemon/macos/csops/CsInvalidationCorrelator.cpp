/*
 * Role: Signal 121 (daemon half) — CS_INVALIDATED <-> exec-mmap correlation.
 *       Joins an ES NOTIFY_CS_INVALIDATED on the game's audit_token with a recent
 *       PROT_EXEC mmap from a NON-platform FD within a short window, then (in the
 *       real path) confirms via csops CS_OPS_STATUS that CS_VALID actually
 *       cleared. Emits HK_CS_INVALIDATED_TAMPER for the correlated pair.
 *       Sparkle/self-updaters and shared-cache repaging legitimately invalidate,
 *       so the join is gated on a non-platform exec mmap (plan FP gate).
 * Target platform: macOS only (built behind if(APPLE) + HK_MACOS_CS_INVALIDATION,
 *       requires HORKOS_MACOS_ES).
 * Interface: implements the PURE correlation-window core (host-tested) and the
 *            ES-consume entry point registered by the orchestrator. Userspace
 *            daemon TU (guardrail #4).
 *
 * Guardrail compliance:
 *   #1  No platform #ifdef — CMake gates the TU.
 *   #13 The csops CS_VALID-cleared confirmation read is HK-UNCERTAIN (Risk 1) and
 *       deferred; the PURE in-window join is implemented + host-tested.
 *   #14 hk_cs_invalidation_correlates is pure and host-tested.
 */

#include "CsScan.h"

#include <stdint.h>
#include <stdbool.h>

/* Correlation window: an exec mmap within this many ns BEFORE a CS_INVALIDATED on
 * the same target is treated as the cause. Tuned conservatively; the server may
 * re-score. (The mmap normally precedes the invalidation: a foreign exec page is
 * mapped, then the signature goes invalid.) */
#define HK_CS_INVAL_WINDOW_NS (2ull * 1000ull * 1000ull * 1000ull)  /* 2 s */

/* -------------------------------------------------------------------------
 * PURE correlation core (host-runnable).
 *
 * Given a CS_INVALIDATED observation and a candidate recent MMAP observation,
 * decide whether they form a tamper pair:
 *   - same target_pid (the invalidated image is the one the mmap targeted),
 *   - the mmap is PROT_EXEC,
 *   - the mmap source is NON-platform (a platform-FD repage / shared-cache COW is
 *     legitimate — plan FP gate),
 *   - the mmap is within the window preceding the invalidation.
 * Returns true iff all hold.
 * ------------------------------------------------------------------------- */
#ifndef PROT_EXEC
#  define PROT_EXEC 0x4   /* mirror of <sys/mman.h>; PURE core builds host-side */
#endif

extern "C" bool hk_cs_invalidation_correlates(const HkEsObservation *invalidated,
                                              const HkEsObservation *mmap_obs,
                                              uint64_t window_ns)
{
    if (invalidated == nullptr || mmap_obs == nullptr) {
        return false;
    }
    if (invalidated->kind != HK_ES_OBS_CS_INVALIDATED ||
        mmap_obs->kind != HK_ES_OBS_MMAP) {
        return false;
    }
    if (invalidated->target_pid == 0 ||
        invalidated->target_pid != mmap_obs->target_pid) {
        return false;
    }
    if ((mmap_obs->protection & PROT_EXEC) == 0) {
        return false;   /* not an executable mapping — irrelevant */
    }
    if (mmap_obs->is_platform_src != 0) {
        return false;   /* platform-FD repage / shared-cache COW — legitimate */
    }
    /* mmap must precede the invalidation and fall inside the window. */
    if (mmap_obs->timestamp_ns > invalidated->timestamp_ns) {
        return false;
    }
    return (invalidated->timestamp_ns - mmap_obs->timestamp_ns) <= window_ns;
}

/* -------------------------------------------------------------------------
 * Impure ES-consume body (excluded from the pure host-test TU).
 * ------------------------------------------------------------------------- */
#ifndef HK_CS_PROBE_PURE_ONLY

#include <os/log.h>
#include <string.h>

namespace {
os_log_t hk_log() {
    static os_log_t log = os_log_create("io.horkos.daemon", "cs-invalidation");
    return log;
}

/* Most-recent exec mmap per target, kept so a later CS_INVALIDATED can join it.
 * Single-writer (orchestrator ES tap thread); one game tracked at a time. */
HkEsObservation g_last_exec_mmap = {};
bool            g_have_mmap = false;
}  // namespace

extern "C" bool hk_cs_invalidation_correlates(const HkEsObservation *invalidated,
                                              const HkEsObservation *mmap_obs,
                                              uint64_t window_ns);  /* fwd (pure) */

extern "C" bool HkCsInvalidationConsume(const HkEsObservation *obs, HkCsFinding *out)
{
    if (obs == nullptr || out == nullptr) {
        return false;
    }

    if (obs->kind == HK_ES_OBS_MMAP) {
        /* Remember the most recent non-platform exec mmap as a join candidate. */
        if ((obs->protection & PROT_EXEC) != 0 && obs->is_platform_src == 0) {
            g_last_exec_mmap = *obs;
            g_have_mmap = true;
        }
        return false;  /* an mmap alone is never a finding */
    }

    if (obs->kind != HK_ES_OBS_CS_INVALIDATED) {
        return false;
    }

    if (!g_have_mmap ||
        !hk_cs_invalidation_correlates(obs, &g_last_exec_mmap, HK_CS_INVAL_WINDOW_NS)) {
        return false;
    }

    /* HK-UNCERTAIN(cs-invalidated-confirm): the plan's confirming read — a csops
     * CS_OPS_STATUS on the exact audit_token verifying CS_VALID actually cleared,
     * plus the gate that the invalidated image is the game's OWN signed binary
     * (not a helper) — is unverified (Risk 1 + Risk 4: whether NOTIFY_CS_INVALIDATED
     * carries enough context to attribute the image). Per guardrail #12 the
     * confirming csops read is NOT guessed here; when wired, gate the emit on it.
     * The in-window join below is sound and host-tested; it produces the finding
     * pending the confirmation gate. */
    out->signal_id   = 121;
    out->finding     = HK_CS_INVALIDATED_TAMPER;
    out->target_pid  = obs->target_pid;
    out->detail      = 0;   /* compact: no extra discriminant for this signal */
    out->evidence    = nullptr;
    out->evidence_len = 0;
    g_have_mmap = false;    /* consume the join candidate */
    os_log(hk_log(),
        "HKCsInvalidationCorrelator: CS_INVALIDATED joined exec mmap for pid %u "
        "(confirming csops read HK-UNCERTAIN — server re-scores)",
        obs->target_pid);
    return true;
}

#endif /* HK_CS_PROBE_PURE_ONLY */
