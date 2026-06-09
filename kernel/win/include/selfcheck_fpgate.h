/*
 * kernel/win/include/selfcheck_fpgate.h
 * Role: Pure, platform-free false-positive-gate decision logic for the Windows
 *       object/notify self-integrity sensors (CallbackSelfCheck.c / Registry-
 *       Callback.c). Factored out of the kernel TUs so the gate decisions can be
 *       unit-tested on the host build (tests/unit/test_selfcheck_fpgate.cpp)
 *       without a WDK — the plan's "FP-gate logic unit-tested where extractable"
 *       requirement. Contains NO kernel/Win32 API: plain C99, includes only
 *       <stdint.h>, so it is includable from a kernel C TU and a host C++ TU
 *       alike (never the same TU — guardrail #4; these are header-only inline
 *       helpers, not a shared object file).
 * Target platforms: all (decision math only; the sensors that call it are
 *       Windows-kernel-only).
 * Interface: declares HkFp* pure predicates consumed by the self-check work
 *       item; no event emission, no I/O.
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Documented hard cap on Ps* create-process notify slots (ntddk public value).
 * Used only as an upper bound for the census floor sanity check. */
#define HK_PSP_MAX_NOTIFY 64u

/* Default number of consecutive missed Ob liveness self-polls required before
 * the sensor emits a _MISSING verdict. A single miss is never a verdict: a
 * scheduler hiccup or a transient self-disarm race can drop one poll. */
#define HK_SELFCHECK_MISS_THRESHOLD 3u

/*
 * Signal 1 (Ob liveness) FP gate. Decide whether an Ob-callback _MISSING verdict
 * is warranted.
 *
 *   consecutive_misses : count of back-to-back polls where the pre-callback did
 *                        NOT stamp the nonce.
 *   heartbeat_advanced : nonzero iff the DISPATCH-level DPC heartbeat counter
 *                        advanced across the same window. If the heartbeat did
 *                        NOT advance, the WHOLE self-check engine (timer/DPC/work
 *                        item) is starved — that is scheduler starvation, NOT a
 *                        removed callback, so we must NOT cry tamper.
 *
 * Returns nonzero (verdict: callback missing/removed) only when we have at least
 * HK_SELFCHECK_MISS_THRESHOLD consecutive misses AND the engine demonstrably ran
 * (heartbeat advanced) during those misses.
 */
static inline int HkFpObMissingVerdict(uint32_t consecutive_misses,
                                       int heartbeat_advanced)
{
    if (!heartbeat_advanced) {
        return 0; /* engine starved — indistinguishable from a stall, suppress */
    }
    return consecutive_misses >= HK_SELFCHECK_MISS_THRESHOLD ? 1 : 0;
}

/*
 * Signal 4 (notify census) FP gate. Decide whether a census drop is a real
 * tamper signal vs. benign churn.
 *
 *   floor          : per-host post-boot floor count (settled count of populated
 *                    notify slots once boot churn ends).
 *   current        : current populated count this tick.
 *   own_slot_present: nonzero iff OUR own notify slot is still accounted for.
 *
 * A verdict requires BOTH (a) a monotone drop below the established floor AND
 * (b) OUR own slot is the one missing. A drop that does not include our slot is
 * some other component deregistering and is not our concern; a count at/above
 * floor is normal. floor==0 means "not yet established" → never a verdict.
 */
static inline int HkFpCensusDropVerdict(uint32_t floor,
                                        uint32_t current,
                                        int own_slot_present)
{
    if (floor == 0u) {
        return 0; /* floor not established yet (boot not settled) */
    }
    if (floor > HK_PSP_MAX_NOTIFY) {
        return 0; /* impossible floor — reject rather than trust a bad baseline */
    }
    if (own_slot_present) {
        return 0; /* our slot is fine; foreign churn is not our signal */
    }
    return current < floor ? 1 : 0;
}

/*
 * Signal 5/9 (Cm registry-tamper) writer-trust gate. Returns nonzero if the
 * RegNt* write to one of Horkos's own keys should be treated as HIGH weight.
 *
 *   writer_is_system : nonzero iff the requester token is SYSTEM/TrustedInstaller
 *                      (a servicing window — low weight, allow-list leaning).
 *
 * Observe-only Phase 3: this never blocks the write; it only classifies weight
 * for the server-side ban path. A non-SYSTEM writer touching our protected keys
 * is the high-weight case.
 */
static inline int HkFpRegTamperHighWeight(int writer_is_system)
{
    return writer_is_system ? 0 : 1;
}

#ifdef __cplusplus
} /* extern "C" */
#endif
