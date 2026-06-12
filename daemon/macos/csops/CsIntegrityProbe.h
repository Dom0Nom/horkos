/*
 * Role: Stable daemon-internal interface + PURE decision cores for the
 *       csops-based code-signing probes (signals 118/119/122/126). Declares the
 *       per-probe sample entry points the orchestrator registers, and — crucially
 *       — the host-runnable pure functions each probe's false-positive logic
 *       factors into (csflags baseline diff, cdhash fold/compare, team-id
 *       classification, entitlement canonical diff). The pure cores let the FP
 *       gates be unit-tested host-side behind the csops() syscall seam
 *       (guardrail #14: logic where testable).
 * Target platform: macOS (userspace daemon). The PURE cores are host-runnable.
 * Interface: implemented by Cs*Probe.cpp / EntitlementDiffProbe.cpp; consumed by
 *            the orchestrator (CsScanOrchestrator.cpp). Userspace TU (guardrail #4).
 */

#pragma once

#include "CsScan.h"   /* HkCsFinding, HkCsProbeTarget, HK_CS_* */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Signal 118 — csflags drift. PURE core.
 *
 * Compare an observed csflags mask against the known-good baseline csflags
 * Horkos captured from its OWN shipped, notarized signature (NOT an absolute
 * expected mask — Rosetta/debug/VM carry different-but-legitimate flag sets,
 * plan FP gate + Risk 7). Returns the set of CRITICAL bits (CS_KILL|CS_HARD)
 * that were set in the baseline but are CLEARED in the observed mask. A non-zero
 * result is a drift finding; the value doubles as the wire `detail` (a masked
 * delta bitmask, never the raw flags).
 *
 * Only CS_KILL / CS_HARD clearing is reported (per the plan); a CS_RUNTIME bit
 * cleared on a baseline that lacked it is NOT a finding (returns 0).
 * ------------------------------------------------------------------------- */
uint32_t cs_flags_drifted(uint32_t baseline_mask, uint32_t observed_mask);

/* -------------------------------------------------------------------------
 * Signal 119 — cdhash fold. PURE core.
 *
 * Fold a cdhash (20 or 32 bytes) into the low-32-bit discriminant carried in the
 * wire `detail`. NEVER ships the raw digest on the compact plane (the full hex
 * rides the CsEvidence report). A simple XOR-fold over 4-byte words; the server
 * uses it only as a coarse change discriminant, not for verification.
 *
 * cs_cdhash_equal compares two cdhashes for the FP-gated live-vs-disk check; it
 * is length-aware (a length mismatch is a mismatch, not a crash).
 * ------------------------------------------------------------------------- */
uint32_t cs_cdhash_fold(const uint8_t *cdhash, size_t len);
bool     cs_cdhash_equal(const uint8_t *a, size_t a_len,
                         const uint8_t *b, size_t b_len);

/* -------------------------------------------------------------------------
 * Signal 122 — team-id / library-validation classification. PURE core.
 *
 * Classify a loaded dylib relative to the host's main-binary team-id and the
 * Apple/Steam/AU allowlist. Returns one of HK_CS_TEAMID_* (also the wire
 * `detail`). The orchestrator only treats HK_CS_TEAMID_FOREIGN as a finding, and
 * only when LV is nominally enabled on an actual game main binary (the host-side
 * gate lives in the orchestrator; this is the pure classifier).
 *
 * `dylib_signing_id` / `dylib_team_id` / `host_team_id` are NUL-padded fixed
 * buffers (truncated copies out of the es_message_t). `is_platform` short-circuits
 * to APPLE_PLATFORM. `allowlisted` is a precomputed allowlist hit (the allowlist
 * lookup itself is the orchestrator's, kept out of the pure classifier).
 * ------------------------------------------------------------------------- */
uint32_t cs_teamid_classify(const uint8_t *dylib_team_id, size_t dylib_team_len,
                            const uint8_t *host_team_id, size_t host_team_len,
                            bool is_platform, bool allowlisted);

/* -------------------------------------------------------------------------
 * Signal 126 — entitlement canonical diff. PURE core.
 *
 * Decide whether a security-relevant entitlement was ADDED in the kernel-granted
 * blob relative to the on-disk signed blob. The inputs are two bitmasks over the
 * HK_ENT_* security keys (the caller parses the plists into these masks; the
 * parse is impure and stays in the probe, the diff is pure here). Returns the set
 * of security bits present in `kernel_mask` but absent in `disk_mask`, EXCEPT the
 * OS-injected allowlist bits (Rosetta / Apple-shimmed processes legitimately gain
 * kernel-added entitlements — plan FP gate). A non-zero result is a drift finding.
 * ------------------------------------------------------------------------- */
#define HK_ENT_GET_TASK_ALLOW    0x01u  /* com.apple.security.get-task-allow */
#define HK_ENT_DISABLE_LV        0x02u  /* ...cs.disable-library-validation */
#define HK_ENT_DEBUGGER          0x04u  /* ...cs.debugger */
#define HK_ENT_ALLOW_DYLD_ENV    0x08u  /* ...cs.allow-dyld-environment-variables */

uint32_t cs_entitlement_added(uint32_t disk_mask, uint32_t kernel_mask,
                              uint32_t os_injected_allowlist);

/* -------------------------------------------------------------------------
 * Probe sample entry points (registered by the orchestrator). Each performs the
 * impure csops()/Sec* read for its signal, applies the pure core above, and on a
 * finding fills *out. Returns false (emit nothing) on any read failure or clean
 * result — the shared "abort cleanly, never a garbage finding" rule.
 * ------------------------------------------------------------------------- */
bool HkCsFlagsProbeSample(const HkCsProbeTarget *target, HkCsFinding *out);     /* 118 */
bool HkCdHashProbeSample(const HkCsProbeTarget *target, HkCsFinding *out);      /* 119 */
bool HkEntitlementDiffProbeSample(const HkCsProbeTarget *target, HkCsFinding *out); /* 126 */

#ifdef __cplusplus
}  /* extern "C" */
#endif
