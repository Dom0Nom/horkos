/*
 * Role: macOS code-signing scan orchestrator (signals 118-126). Owns the
 *       CsIntegrityProbe registry (only flag-enabled probes are live), enumerates
 *       the game-PID set, runs the poll-based probes (118/119/120/122/124/125/126)
 *       on a serial timer, fans the ES-driven probes (121/122/123) off the
 *       in-process ES-observation tap, throttles + dedups findings, and applies
 *       the corroborating-only gate for signal 125 (suppress unless a 119/126
 *       finding co-occurred for the same PID). Compacts each HkCsFinding into the
 *       16-byte hk_event_cs_finding wire record and hands it (plus the opaque
 *       evidence blob for the JSON report plane) to the daemon's emit callback.
 * Target platform: macOS only (built behind if(APPLE); always compiled — the
 *       shared substrate — fanning out only to enabled probes).
 * Interface: implements HkCsScanInit/Stop/PollOnce/OnEsObservation +
 *            HkCsScanProbeTable (test seam) from CsScan.h. Userspace daemon TU
 *            (guardrail #4).
 *
 * Guardrail compliance:
 *   #1  No platform #ifdef — CMake gates the TU; OS API stays in the probes /
 *       platform helpers, not here.
 *   #8-adjacent: the ES tap must not block the ES delivery queue; this
 *       orchestrator only folds the already-copied HkEsObservation (the heavy
 *       async hand-off is EsClient.mm's sSinkQueue). The poll pass runs on the
 *       orchestrator's own serial timer, never the ES queue (plan shared rule).
 *   #13 Game-PID enumeration + the live timer are HK-UNCERTAIN scaffolding here
 *       (the daemon supplies the real game-PID source); PollOnce is exposed so
 *       host tests drive it deterministically.
 */

#include "CsScan.h"
#include "CsIntegrityProbe.h"

#include <stddef.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * Per-signal feature flags. The build maps each HK_MACOS_CS_* CMake option to a
 * target_compile_definition; a probe whose flag is OFF is registered as a no-op
 * (its .cpp may be compiled to a stub). Default the macros so the orchestrator
 * compiles standalone (e.g. host test) with the plan's default ON/OFF tuning.
 * ------------------------------------------------------------------------- */
#ifndef HK_MACOS_CS_FLAGS
#  define HK_MACOS_CS_FLAGS 1        /* signal 118 — default ON */
#endif
#ifndef HK_MACOS_CS_CDHASH
#  define HK_MACOS_CS_CDHASH 1       /* signal 119 — default ON */
#endif
#ifndef HK_MACOS_CS_ENTITLEMENT
#  define HK_MACOS_CS_ENTITLEMENT 1  /* signal 126 — default ON */
#endif
#ifndef HK_MACOS_CS_DYNAMIC
#  define HK_MACOS_CS_DYNAMIC 1      /* signal 120 — default ON */
#endif
#ifndef HK_MACOS_CS_AMFI_POSTURE
#  define HK_MACOS_CS_AMFI_POSTURE 1 /* signal 124 — default ON (report-only) */
#endif
#ifndef HK_MACOS_CS_GATEKEEPER
#  define HK_MACOS_CS_GATEKEEPER 0   /* signal 125 — default OFF */
#endif
#ifndef HK_MACOS_CS_INVALIDATION
#  define HK_MACOS_CS_INVALIDATION 0 /* signal 121 — default OFF (needs ES) */
#endif
#ifndef HK_MACOS_CS_DYLIB_LV
#  define HK_MACOS_CS_DYLIB_LV 0     /* signal 122 — default OFF (needs ES) */
#endif
#ifndef HK_MACOS_CS_AMFID
#  define HK_MACOS_CS_AMFID 0        /* signal 123 — default OFF (needs ES) */
#endif

/* Probe sample/consume entry points implemented in the per-signal TUs. Declared
 * here so the registry references them; a flag-OFF probe's TU is not compiled, so
 * its entry is guarded by the matching macro below. */
extern "C" {
bool HkCsFlagsProbeSample(const HkCsProbeTarget *, HkCsFinding *);          /* 118 */
bool HkCdHashProbeSample(const HkCsProbeTarget *, HkCsFinding *);           /* 119 */
bool HkEntitlementDiffProbeSample(const HkCsProbeTarget *, HkCsFinding *);  /* 126 */
bool HkDynamicValidityProbeSample(const HkCsProbeTarget *, HkCsFinding *);  /* 120 */
bool HkAmfiPostureProbeSample(const HkCsProbeTarget *, HkCsFinding *);      /* 124 */
bool HkGatekeeperProbeSample(const HkCsProbeTarget *, HkCsFinding *);       /* 125 */
bool HkCsInvalidationConsume(const HkEsObservation *, HkCsFinding *);       /* 121 */
bool HkDylibTeamIdProbeConsume(const HkEsObservation *, HkCsFinding *);     /* 122 */
bool HkAmfidWatchConsume(const HkEsObservation *, HkCsFinding *);           /* 123 */
}

/* -------------------------------------------------------------------------
 * Static probe registry. Each row is present only if its feature flag is ON; a
 * flag-OFF row registers NULL sample/consume + enabled=false so the table length
 * is stable and host tests can assert which signals are wired. The poll-based
 * probes set `sample`; the ES-driven probes set `consume`.
 * ------------------------------------------------------------------------- */
static HkCsProbe g_probes[] = {
    { 118, "cs-flags",
#if HK_MACOS_CS_FLAGS
      HkCsFlagsProbeSample, nullptr, true },
#else
      nullptr, nullptr, false },
#endif
    { 119, "cs-cdhash",
#if HK_MACOS_CS_CDHASH
      HkCdHashProbeSample, nullptr, true },
#else
      nullptr, nullptr, false },
#endif
    { 120, "cs-dynamic-validity",
#if HK_MACOS_CS_DYNAMIC
      HkDynamicValidityProbeSample, nullptr, true },
#else
      nullptr, nullptr, false },
#endif
    { 124, "cs-amfi-posture",
#if HK_MACOS_CS_AMFI_POSTURE
      HkAmfiPostureProbeSample, nullptr, true },
#else
      nullptr, nullptr, false },
#endif
    { 126, "cs-entitlement",
#if HK_MACOS_CS_ENTITLEMENT
      HkEntitlementDiffProbeSample, nullptr, true },
#else
      nullptr, nullptr, false },
#endif
    { 125, "cs-gatekeeper",
#if HK_MACOS_CS_GATEKEEPER
      HkGatekeeperProbeSample, nullptr, true },
#else
      nullptr, nullptr, false },
#endif
    { 121, "cs-invalidation",
#if HK_MACOS_CS_INVALIDATION
      nullptr, HkCsInvalidationConsume, true },
#else
      nullptr, nullptr, false },
#endif
    { 122, "cs-dylib-lv",
#if HK_MACOS_CS_DYLIB_LV
      nullptr, HkDylibTeamIdProbeConsume, true },
#else
      nullptr, nullptr, false },
#endif
    { 123, "cs-amfid",
#if HK_MACOS_CS_AMFID
      nullptr, HkAmfidWatchConsume, true },
#else
      nullptr, nullptr, false },
#endif
};

/* -------------------------------------------------------------------------
 * Orchestrator state. Single-threaded by construction: PollOnce runs on the
 * serial timer queue, OnEsObservation on the ES tap; the daemon serializes the
 * two onto one queue (the real daemon wires a single serial dispatch_queue —
 * see CMake/daemon notes). No locking is taken here; a future concurrent design
 * must add it (HK-TODO).
 * ------------------------------------------------------------------------- */
namespace {
HkCsEmitFn g_emit = nullptr;
void      *g_emit_ctx = nullptr;
bool       g_inited = false;

/* Dedup: last finding (signal_id, finding, target_pid, detail) emitted, to
 * suppress an identical repeat within a poll cadence. A one-slot cache suffices
 * for the single-game bring-up; a real deployment widens this. */
struct DedupKey { uint32_t sig, find, pid, detail; };
DedupKey g_last_emit = { 0, 0, 0, 0 };
bool     g_have_last = false;

/* Corroboration tracking for signal 125 (Gatekeeper): the probe never emits
 * standalone; 125 surfaces only if a 119/126 finding co-occurred for the same
 * PID within the current pass. Recorded per poll pass. */
uint32_t g_corroborated_pid = 0;
bool     g_have_corroboration = false;

bool dedup_should_emit(const HkCsFinding *f) {
    if (g_have_last &&
        g_last_emit.sig == f->signal_id && g_last_emit.find == f->finding &&
        g_last_emit.pid == f->target_pid && g_last_emit.detail == f->detail) {
        return false;
    }
    g_last_emit = { f->signal_id, f->finding, f->target_pid, f->detail };
    g_have_last = true;
    return true;
}

void emit_finding(const HkCsFinding *f) {
    if (g_emit == nullptr || f == nullptr) {
        return;
    }
    if (!dedup_should_emit(f)) {
        return;
    }
    hk_event_cs_finding rec;
    memset(&rec, 0, sizeof(rec));
    rec.signal_id  = f->signal_id;
    rec.finding    = f->finding;
    rec.target_pid = f->target_pid;
    rec.detail     = f->detail;
    g_emit(&rec, f->evidence, f->evidence_len, g_emit_ctx);
}

/* Enumerate the current game-PID set the poll probes run against. HK-UNCERTAIN /
 * HK-TODO: the real game-PID source is the daemon's session registry (which game
 * sessions are live). This scaffold returns an empty set — PollOnce becomes a
 * no-op in a bring-up build and the host test injects targets directly via the
 * probe seam. Wiring the live registry is a daemon-integration step, not a
 * code-signing-domain guess. */
size_t enumerate_game_targets(HkCsProbeTarget *out, size_t cap) {
    (void)out;
    (void)cap;
    return 0;
}
}  // namespace

extern "C" bool HkCsScanInit(HkCsEmitFn emit, void *ctx) {
    if (g_inited) {
        return false;
    }
    g_emit = emit;
    g_emit_ctx = ctx;
    g_have_last = false;
    g_have_corroboration = false;
    g_corroborated_pid = 0;
    g_inited = true;
    return true;
}

extern "C" void HkCsScanStop(void) {
    g_emit = nullptr;
    g_emit_ctx = nullptr;
    g_inited = false;
    g_have_last = false;
}

extern "C" void HkCsScanPollOnce(void) {
    if (!g_inited) {
        return;
    }

    HkCsProbeTarget targets[8];
    size_t n = enumerate_game_targets(targets, sizeof(targets) / sizeof(targets[0]));

    /* First pass: run every non-Gatekeeper poll probe, tracking 119/126
     * co-occurrence so the corroborating-only 125 gate can fire afterward. */
    g_have_corroboration = false;
    for (size_t t = 0; t < n; ++t) {
        for (size_t p = 0; p < sizeof(g_probes) / sizeof(g_probes[0]); ++p) {
            const HkCsProbe *probe = &g_probes[p];
            if (!probe->enabled || probe->sample == nullptr) {
                continue;
            }
            if (probe->signal_id == 125) {
                continue;   /* deferred to the corroboration pass below */
            }
            HkCsFinding f;
            memset(&f, 0, sizeof(f));
            if (probe->sample(&targets[t], &f)) {
                if (f.signal_id == 119 || f.signal_id == 126) {
                    g_have_corroboration = true;
                    g_corroborated_pid = f.target_pid;
                }
                emit_finding(&f);
            }
        }
    }

    /* Corroboration pass: signal 125 only surfaces when a 119/126 finding
     * co-occurred for the same PID this pass (plan: corroborating-only). */
    for (size_t t = 0; t < n; ++t) {
        for (size_t p = 0; p < sizeof(g_probes) / sizeof(g_probes[0]); ++p) {
            const HkCsProbe *probe = &g_probes[p];
            if (!probe->enabled || probe->sample == nullptr ||
                probe->signal_id != 125) {
                continue;
            }
            if (!g_have_corroboration ||
                g_corroborated_pid != targets[t].pid) {
                continue;   /* suppressed: no co-occurring 119/126 for this PID */
            }
            HkCsFinding f;
            memset(&f, 0, sizeof(f));
            if (probe->sample(&targets[t], &f)) {
                emit_finding(&f);
            }
        }
    }
}

extern "C" void HkCsScanOnEsObservation(const HkEsObservation *obs) {
    if (!g_inited || obs == nullptr) {
        return;
    }
    for (size_t p = 0; p < sizeof(g_probes) / sizeof(g_probes[0]); ++p) {
        const HkCsProbe *probe = &g_probes[p];
        if (!probe->enabled || probe->consume == nullptr) {
            continue;
        }
        HkCsFinding f;
        memset(&f, 0, sizeof(f));
        if (probe->consume(obs, &f)) {
            emit_finding(&f);
        }
    }
}

extern "C" const HkCsProbe *HkCsScanProbeTable(size_t *out_count) {
    if (out_count != nullptr) {
        *out_count = sizeof(g_probes) / sizeof(g_probes[0]);
    }
    return g_probes;
}
