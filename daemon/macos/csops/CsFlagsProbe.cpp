/*
 * daemon/macos/csops/CsFlagsProbe.cpp
 * Role: Signal 118 — csflags (CS_HARD/CS_KILL/CS_RUNTIME...) drift probe. Reads
 *       the kernel-held code-signing status bitmask for a game PID via
 *       csops(pid, CS_OPS_STATUS) and compares it against the known-good csflags
 *       Horkos baked into its OWN shipped, notarized signature (a baseline
 *       constant, NOT an absolute mask — Rosetta/debug/VM carry legitimate
 *       variants). Emits HK_CS_FLAGS_DRIFT only when CS_KILL or CS_HARD is
 *       cleared on a binary whose baseline had it set.
 * Target platform: macOS only (built behind if(APPLE) + HK_MACOS_CS_FLAGS).
 * Interface: implements cs_flags_drifted() (PURE, host-tested) and
 *            HkCsFlagsProbeSample() from CsIntegrityProbe.h. Userspace daemon TU
 *            (guardrail #4); emits HK_EVENT_CS_FINDING via the orchestrator.
 *
 * Guardrail compliance:
 *   #1  No platform #ifdef for OS selection — CMake gates the TU.
 *   #14 The FP-gate decision (cs_flags_drifted) is a PURE function, host-unit-
 *       tested behind the csops() syscall seam.
 *
 * The pure core compiles host-side (plain integer logic, no macOS headers); the
 * impure csops() read is compiled only in the real probe body below the seam.
 */

#include "CsIntegrityProbe.h"

#include <string.h>

/* -------------------------------------------------------------------------
 * csflags bit values — mirror of <sys/codesign.h>. Defined locally so the PURE
 * core (cs_flags_drifted) builds host-side where <sys/codesign.h> is absent.
 * These values are ABI-stable across macOS versions. (Plan Risk 1 notes the
 * SPI-adjacency of some CS_OPS operations, NOT of these flag bit values.)
 * ------------------------------------------------------------------------- */
#ifndef CS_VALID
#  define CS_VALID        0x00000001u
#  define CS_HARD         0x00000100u
#  define CS_KILL         0x00000200u
#  define CS_RESTRICT     0x00000800u
#  define CS_ENFORCEMENT  0x00001000u
#  define CS_REQUIRE_LST  0x00002000u  /* CS_REQUIRE_LV — library validation */
#  define CS_RUNTIME      0x00010000u  /* hardened runtime */
#endif

/* Critical bits whose CLEARING (present in baseline, absent in observed) is the
 * signal. CS_KILL / CS_HARD are the kill-on-invalidation enforcement bits a
 * cheat strips to keep a tampered process alive. */
static const uint32_t kCsCriticalBits = (CS_KILL | CS_HARD);

extern "C" uint32_t cs_flags_drifted(uint32_t baseline_mask, uint32_t observed_mask)
{
    /* Bits set in baseline but cleared in observed, restricted to the critical
     * set. A bit cleared that the baseline never had (e.g. CS_RUNTIME on a debug
     * baseline) contributes nothing — only baseline-present-now-absent matters. */
    uint32_t missing = baseline_mask & ~observed_mask;
    return missing & kCsCriticalBits;
}

/* -------------------------------------------------------------------------
 * Impure probe body. Compiled only in the real macOS daemon build (the host
 * unit-test TU defines HK_CS_PROBE_PURE_ONLY to exclude it and link just the
 * pure core).
 * ------------------------------------------------------------------------- */
#ifndef HK_CS_PROBE_PURE_ONLY

/* HK-UNCERTAIN(csops-header): <sys/codesign.h> is NOT in the public macOS SDK on
 * the target toolchain (csops is the SYS_csops=169 syscall and its op constants
 * are effectively SPI — plan Risk 1). Per guardrail #13 we do NOT hardcode a
 * guessed CS_OPS_STATUS op number and invoke the raw syscall against it. The live
 * status read is routed through hk_csops_status_read(), which is stubbed to
 * "unavailable" until the op-constant contract is verified against the target SDK
 * on each macOS 12-15 box. The probe then emits nothing (clean abort), exactly as
 * a real read failure would. */
#include <unistd.h>
#include <os/log.h>

/* Returns 0 on a successful read (filling *out_flags), non-zero on failure /
 * unavailable. See HK-UNCERTAIN above — the body is the verified-on-box seam. */
static int hk_csops_status_read(pid_t /*pid*/, uint32_t * /*out_flags*/)
{
    return -1;  /* unavailable until the CS_OPS_STATUS op number is verified */
}

/*
 * HK-UNCERTAIN(cs-flags-baseline): the known-good baseline csflags MUST be the
 * csflags of Horkos's own shipped, notarized signature, captured at build/sign
 * time (plan Risk 7). That capture is a build/sign-pipeline dependency, not a
 * constant we can hardcode here — a wrong baseline false-positives on every
 * clean install. Until the sign pipeline injects it, the probe reads the live
 * flags but has no baseline to compare against and therefore emits NOTHING.
 * Do NOT substitute an absolute expected mask here (the exact thing the plan
 * forbids). The build/sign step will replace this 0 with the captured value.
 */
static uint32_t hk_cs_flags_baseline(const HkCsProbeTarget * /*target*/)
{
    return 0u;  /* 0 = "no baseline captured yet" — see HK-UNCERTAIN above. */
}

extern "C" bool HkCsFlagsProbeSample(const HkCsProbeTarget *target, HkCsFinding *out)
{
    if (target == nullptr || out == nullptr || target->pid == 0) {
        return false;
    }

    uint32_t baseline = hk_cs_flags_baseline(target);
    if (baseline == 0u) {
        /* No captured baseline (see HK-UNCERTAIN). Emit nothing rather than a
         * garbage finding against an absolute mask. */
        return false;
    }

    uint32_t flags = 0;
    /* Read the kernel's code-signing status bitmask. A non-zero return means the
     * read failed or is unavailable (see HK-UNCERTAIN on the header) — abort
     * cleanly, emit nothing. */
    if (hk_csops_status_read(static_cast<pid_t>(target->pid), &flags) != 0) {
        return false;
    }

    uint32_t missing = cs_flags_drifted(baseline, flags);
    if (missing == 0u) {
        return false;  /* no critical-bit drift — clean */
    }

    out->signal_id   = 118;
    out->finding     = HK_CS_FLAGS_DRIFT;
    out->target_pid  = target->pid;
    out->detail      = missing;   /* masked delta bitmask, never the raw flags */
    out->evidence    = nullptr;
    out->evidence_len = 0;
    return true;
}

#endif /* HK_CS_PROBE_PURE_ONLY */
