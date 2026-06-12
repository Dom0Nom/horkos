/*
 * Role: Pure, platform-free decision helpers for the process-genealogy client
 *       sensors (signals 199, 203). The reparent test (true creator vs inherited
 *       parent) and the token-integrity delta are structural comparisons with no
 *       OS dependency, factored here so they are host-unit-tested
 *       (tests/unit/test_genealogy_logic.cpp) and shared identically by the kernel
 *       sensor (proc_genealogy.c, signal 199) and the userspace token sensor
 *       (token_check.cpp, signal 203). These produce RAW observations; all FP
 *       gating (signed-launcher pairs, per-launcher baseline integrity) is
 *       server-side. NO verdict, NO ban.
 *       READ-ONLY: compares already-sampled values; mutates nothing.
 * Target platforms: all (decision math; the sampling is per-OS).
 * Interface: consumed by kernel/win proc_genealogy.c + sdk token_check.cpp.
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Signal 199 — reparent suspect: the true creating process (PsGetCurrentProcessId
 * in the create notify) differs from the inherited/assigned parent. A spoofed
 * parent (UpdateProcThreadAttribute PROC_THREAD_ATTRIBUTE_PARENT_PROCESS) makes
 * these diverge. Returns 1 when both are nonzero and differ. The server still
 * gates the flag against the (true_creator_image, declared_parent_image)
 * signed-launcher pair to suppress the benign relaunch cases.
 */
static inline int hk_proc_reparent_suspect(uint32_t true_creator_pid,
                                           uint32_t declared_parent_pid)
{
    if (true_creator_pid == 0u || declared_parent_pid == 0u) {
        return 0; /* incomplete data — never a guess. */
    }
    return (true_creator_pid != declared_parent_pid) ? 1 : 0;
}

/*
 * Signal 203 — token integrity delta game vs recorded launcher. Windows mandatory
 * integrity levels are ordered constants (Untrusted < Low < Medium < High <
 * System); the raw signed delta of the two levels is shipped. The server
 * baselines the EXPECTED delta per known launcher (a UAC-elevated admin launcher
 * legitimately yields a positive delta) and flags only divergence from that
 * baseline — never an absolute level. game_il / parent_il are the integers the
 * sampler read from TokenIntegrityLevel (the RID, e.g. 0x2000 Medium, 0x3000
 * High); the delta is (game - parent) in RID units.
 */
static inline int32_t hk_token_integrity_delta(uint32_t game_il, uint32_t parent_il)
{
    return (int32_t)((int64_t)game_il - (int64_t)parent_il);
}

#ifdef __cplusplus
} /* extern "C" */
#endif
