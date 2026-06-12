/*
 * Role: Pure, platform-free decision/decode math for the x64 syscall-/ETW-surface
 *       integrity sensors (SyscallIntegrity.c signals 210/213/214, EtwIntegrity.c
 *       signals 212/215). The kernel TUs perform the unsafe reads (MSR, IDTR,
 *       descriptor walks, logger-table query); the *arithmetic and FP-gate
 *       verdicts* are factored here so they are unit-testable on the host build
 *       (tests/unit/test_syscall_etw_logic.cpp) without a WDK. Contains NO
 *       kernel/Win32 API: plain C99, includes only <stdint.h>, so it is includable
 *       from a kernel C TU and a host C++ TU alike (never the same TU —
 *       guardrail #4; header-only inline helpers, not a shared object file).
 *       READ-ONLY: every helper only decodes/compares; none writes a table, MSR,
 *       or descriptor.
 * Target platforms: all (decision math only; the sensors that call it are
 *       Windows-kernel-only).
 * Interface: declares HkIdtReconstructHandler / HkLstarExpected /
 *       HkKeepaliveStale / HkEtwProviderSuppressed pure helpers consumed by
 *       SyscallIntegrity.c and EtwIntegrity.c; no event emission, no I/O.
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Signal 214 — reconstruct the 64-bit interrupt-gate handler address from the
 * three split offset fields of a KIDTENTRY64. The x64 interrupt-gate descriptor
 * scatters the handler VA across OffsetLow (bits 0..15), OffsetMiddle (bits
 * 16..31) and OffsetHigh (bits 32..63). This is the pure recombination; the
 * caller (HkIdtValidate) reads the descriptor inside the IPI and then range-checks
 * the result against the ntoskrnl/hal image map at PASSIVE_LEVEL.
 */
static inline uint64_t HkIdtReconstructHandler(uint16_t offset_low,
                                               uint16_t offset_middle,
                                               uint32_t offset_high)
{
    return (uint64_t)offset_low
         | ((uint64_t)offset_middle << 16)
         | ((uint64_t)offset_high << 32);
}

/*
 * Signal 210 — choose the expected IA32_LSTAR value. Under KVA-shadow (Meltdown
 * mitigation) the CPU enters at KiSystemCall64Shadow; otherwise at KiSystemCall64.
 * Mis-detecting the KVA-shadow state would false-positive on every clean machine
 * (plan Risk 2), so this selection is isolated and tested. Both candidate
 * addresses are resolved by the caller (they are unexported — see the sensor's
 * HK-UNCERTAIN note); a zero candidate means "unresolved", which the caller must
 * treat as UNVERIFIABLE rather than a mismatch.
 *
 *   kva_shadow_active : nonzero iff KVA-shadow / kernel-page-table-isolation is on.
 * Returns the expected LSTAR VA, or 0 if the needed candidate is unresolved.
 */
static inline uint64_t HkLstarExpected(uint64_t kisystemcall64,
                                       uint64_t kisystemcall64_shadow,
                                       int kva_shadow_active)
{
    if (kva_shadow_active) {
        return kisystemcall64_shadow; /* may be 0 => caller emits UNVERIFIABLE */
    }
    return kisystemcall64;
}

/*
 * Signal 212 — ETW-TI consumer keepalive staleness predicate. Horkos's own
 * ETW-TI consumer bumps a monotonic counter on each TI event; the periodic scan
 * checks the counter advanced since the previous scan. A stale counter means the
 * TI feed went silent (provider torn down / consumer starved), which the
 * version-independent half of signal 212 reports without touching any unexported
 * global.
 *
 *   last_count, now_count : the keepalive counter at the previous and current
 *                           scan. Monotonic; a wrap is treated as advance (any
 *                           change is liveness).
 *   min_expected_delta    : the minimum number of TI events expected within the
 *                           scan interval before the feed is considered dead. 0
 *                           means "any advance is enough"; the sensor passes the
 *                           per-interval floor it computed.
 * Returns nonzero iff the counter is STALE (a finding).
 */
static inline int HkKeepaliveStale(uint64_t last_count, uint64_t now_count,
                                   uint64_t min_expected_delta)
{
    uint64_t delta;
    if (now_count == last_count) {
        return 1; /* no advance at all => stale. */
    }
    /* now_count != last_count: treat any change (incl. wrap) as advance, then
     * require the per-interval floor. Unsigned subtraction wraps cleanly so a
     * counter rollover still yields a positive delta. */
    delta = now_count - last_count;
    return delta < min_expected_delta ? 1 : 0;
}

/*
 * Signal 215 — ETW logger-session census diff. Given the boot baseline mask of
 * enabled security-relevant providers, the currently-enabled mask, and the mask
 * of providers Horkos actually DEPENDS on, return the set of dependency providers
 * that were enabled at boot but are now disabled. Keyed by provider-GUID bit
 * (version-independent), so this is the half that can ship without resolving any
 * unexported global.
 *
 * FP gate (plan, catalog medium): profiling/EDR toggles ETW constantly, so a
 * disable of a NON-dependency provider must NOT alert. The dependency mask is
 * intersected last, so a stopped xperf/WPR session that Horkos does not depend on
 * yields 0.
 *
 * Returns the suppressed-dependency bitmask (0 => nothing Horkos depends on was
 * disabled).
 */
static inline uint32_t HkEtwProviderSuppressed(uint32_t baseline_mask,
                                               uint32_t current_mask,
                                               uint32_t dependency_mask)
{
    /* enabled-at-boot AND now-disabled AND in-our-dependency-set. */
    uint32_t disabled = baseline_mask & ~current_mask;
    return disabled & dependency_mask;
}

#ifdef __cplusplus
} /* extern "C" */
#endif
