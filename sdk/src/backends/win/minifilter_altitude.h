/*
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

/* Microsoft's system-defined minifilter load-order group altitude bands
 * (inclusive [min, max]). Source: Microsoft Learn, "Load Order Groups and
 * Altitudes for Minifilter Drivers" (ms.date 2025-04-24). A legitimate filter's
 * altitude falls within one of these bands (Microsoft allocates the first
 * altitude per company per group; fractional altitudes like 325000.3 stay
 * within the band). An altitude squatting in a GAP between bands was never
 * allocated by Microsoft — the signal-6 tell. */
struct AltitudeBand { double min; double max; };

inline constexpr AltitudeBand kAllocatedBands[] = {
    {420000.0, 429999.0}, // Filter
    {400000.0, 409999.0}, // FSFilter Top
    {360000.0, 389999.0}, // FSFilter Activity Monitor
    {340000.0, 349999.0}, // FSFilter Undelete
    {320000.0, 329999.0}, // FSFilter Anti-Virus
    {300000.0, 309999.0}, // FSFilter Replication
    {280000.0, 289999.0}, // FSFilter Continuous Backup
    {260000.0, 269999.0}, // FSFilter Content Screener
    {240000.0, 249999.0}, // FSFilter Quota Management
    {220000.0, 229999.0}, // FSFilter System Recovery
    {200000.0, 209999.0}, // FSFilter Cluster File System
    {180000.0, 189999.0}, // FSFilter HSM
    {170000.0, 175000.0}, // FSFilter Imaging
    {160000.0, 169999.0}, // FSFilter Compression
    {140000.0, 149999.0}, // FSFilter Encryption
    {130000.0, 139999.0}, // FSFilter Virtualization
    {120000.0, 129999.0}, // FSFilter Physical Quota Management
    {100000.0, 109999.0}, // FSFilter Open File
    { 80000.0,  89999.0}, // FSFilter Security Enhancer
    { 60000.0,  69999.0}, // FSFilter Copy Protection
    { 40000.0,  49999.0}, // FSFilter Bottom
    { 20000.0,  29999.0}, // FSFilter System (reserved)
};

/* True iff `altitude` lies in a Microsoft-allocated load-order group band (or
 * the reserved Infrastructure band below 20000). A positive altitude in a gap
 * between bands is UNALLOCATED — a squat. Pure; host-tested. */
inline bool is_allocated_altitude(double altitude)
{
    if (altitude <= 0.0) {
        return false; // not a real altitude
    }
    if (altitude < 20000.0) {
        return true; // FSFilter Infrastructure (<20000), reserved-internal range
    }
    for (const AltitudeBand& b : kAllocatedBands) {
        if (altitude >= b.min && altitude <= b.max) {
            return true;
        }
    }
    return false; // squatting in a gap Microsoft never allocated
}

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
