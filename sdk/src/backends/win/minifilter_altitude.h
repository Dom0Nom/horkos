/*
 * sdk/src/backends/win/minifilter_altitude.h
 * Role: Pure, platform-free classifier for the minifilter altitude census
 *       (signal 6). Decides whether a neighboring minifilter is SUSPECT given
 *       its altitude, Authenticode result, and position relative to Horkos —
 *       WITHOUT any FltMgr / Win32 dependency, so the decision is unit-testable
 *       on the host build (tests/unit/test_minifilter_altitude.cpp). The live
 *       FilterFindFirst/FilterInstanceFindFirst enumeration lives in
 *       MinifilterCensusWin.cpp and feeds rows into this classifier.
 *       FP discipline: altitude-occupancy alone is NEVER a verdict — only an
 *       UNALLOCATED altitude OR a FAILED Authenticode chain on a filter sitting
 *       numerically adjacent-above Horkos counts. Defender/OneDrive/Carbon Black
 *       at allocated altitudes are legitimate and must not trip this.
 * Target platforms: all (decision math only; the enumerator is Windows-only).
 * Interface: header-only inline classifier; no I/O, no platform API
 *       (guardrail #1 — the live enumeration stays in this backends/ dir).
 */

#pragma once

#include <cstdint>

namespace hk { namespace sdk { namespace mf {

/* Authenticode verdict for a filter's backing image. */
enum class AuthResult {
    Trusted = 0,   /* signed, chain validates to a trusted root */
    Failed  = 1,   /* signature absent or chain does not validate */
    Unknown = 2,   /* could not be determined (treated conservatively) */
};

/* One enumerated minifilter instance, reduced to the fields the classifier uses.
 * altitude is the FltMgr altitude as a numeric value (FltMgr altitudes are
 * decimal strings; the enumerator parses them to double to preserve fractional
 * altitudes like 385201.5). */
struct FilterRow {
    double     altitude;        /* parsed numeric altitude */
    bool       altitude_valid;  /* false if the altitude string failed to parse */
    bool       altitude_allocated; /* true if found in Microsoft's allocated table */
    AuthResult auth;            /* Authenticode result for the backing image */
    bool       publisher_allowlisted; /* signed by a known-good AV/backup/cloud vendor */
};

/* Verdict for one neighbor. */
enum class Verdict {
    Benign  = 0,
    Suspect = 1,
};

/*
 * Classify ONE neighbor relative to Horkos's own altitude.
 *
 *   row          : the neighbor.
 *   horkos_alt   : Horkos's own minifilter altitude (numeric).
 *
 * A neighbor is SUSPECT iff it sits numerically ADJACENT-ABOVE Horkos (a higher
 * altitude that could intercept I/O before Horkos sees it) AND one of:
 *   - its altitude is UNALLOCATED (squatting in a range Microsoft never assigned),
 *   - or its Authenticode chain FAILED and it is NOT on the publisher allowlist.
 * Altitude-occupancy alone — a legitimately-allocated, signed, allowlisted filter
 * sitting above Horkos — is NEVER suspect.
 *
 * "adjacent-above" is modeled here as "strictly above Horkos"; the caller passes
 * only the immediate higher neighbor(s) it wants judged, so this predicate does
 * not need the full neighbor set.
 */
inline Verdict ClassifyNeighbor(const FilterRow& row, double horkos_alt)
{
    if (!row.altitude_valid) {
        /* An unparseable altitude on a filter above us is itself suspicious
         * (no legitimate filter has a malformed altitude). Treat as suspect only
         * if it also is not publisher-allowlisted. */
        return row.publisher_allowlisted ? Verdict::Benign : Verdict::Suspect;
    }

    /* Only judge filters strictly above Horkos (they can pre-empt our I/O). */
    if (row.altitude <= horkos_alt) {
        return Verdict::Benign;
    }

    /* Unallocated altitude above us = squat. */
    if (!row.altitude_allocated) {
        return row.publisher_allowlisted ? Verdict::Benign : Verdict::Suspect;
    }

    /* Allocated altitude but failed signature and not an allowlisted publisher. */
    if (row.auth == AuthResult::Failed && !row.publisher_allowlisted) {
        return Verdict::Suspect;
    }

    /* Allocated + (trusted OR allowlisted) = legitimate neighbor. */
    return Verdict::Benign;
}

}}} // namespace hk::sdk::mf
