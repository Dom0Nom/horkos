/*
 * Role: Signal 126 — kernel-granted vs signed entitlement-blob diff. Reads the
 *       kernel-held entitlement blob for a game PID via csops(pid,
 *       CS_OPS_ENTITLEMENTS_BLOB / CS_OPS_DER_ENTITLEMENTS_BLOB) and compares the
 *       SECURITY-relevant keys against the on-disk signed entitlements from
 *       SecCodeCopySigningInformation (kSecCodeInfoEntitlementsDict). Emits
 *       HK_CS_ENTITLEMENT_DRIFT when a security entitlement (get-task-allow,
 *       disable-library-validation, debugger, allow-dyld-env) was ADDED in the
 *       kernel blob and is not an OS-injected allowlist key.
 * Target platform: macOS only (built behind if(APPLE) + HK_MACOS_CS_ENTITLEMENT).
 * Interface: implements cs_entitlement_added() (PURE, host-tested) and
 *            HkEntitlementDiffProbeSample() from CsIntegrityProbe.h. Userspace
 *            daemon TU (guardrail #4).
 *
 * Guardrail compliance:
 *   #1  No platform #ifdef — CMake gates the TU.
 *   #13 The blob read + plist canonicalization are HK-UNCERTAIN (plan Risk 1)
 *       and left unimplemented; the PURE security-key diff is implemented and
 *       host-unit-tested.
 *   #14 cs_entitlement_added is pure and host-tested.
 */

#include "CsIntegrityProbe.h"

extern "C" uint32_t cs_entitlement_added(uint32_t disk_mask, uint32_t kernel_mask,
                                         uint32_t os_injected_allowlist)
{
    /* Security bits present in the kernel-granted blob but absent on disk, minus
     * the OS-injected allowlist (Rosetta / Apple-shimmed processes legitimately
     * gain kernel-added entitlements — plan FP gate). Only the four security keys
     * are ever set in these masks (the impure parser restricts to them). */
    uint32_t added = kernel_mask & ~disk_mask;
    return added & ~os_injected_allowlist;
}

/* -------------------------------------------------------------------------
 * Impure probe body (excluded from the pure host-test TU).
 * ------------------------------------------------------------------------- */
#ifndef HK_CS_PROBE_PURE_ONLY

/* HK-UNCERTAIN(csops-header): <sys/codesign.h> is not in the public SDK (plan
 * Risk 1); the CS_OPS_ENTITLEMENTS_BLOB / CS_OPS_DER_ENTITLEMENTS_BLOB op numbers
 * + blob form vary across macOS 12-15 and are SPI. No raw syscall is issued
 * against a guessed op number; the blob parse stays unimplemented below.
 * (docs: confirmed NOT in MacOSX.sdk/usr/include/sys/ through macOS 15.5 SDK —
 * still needs on-box SPI verification of blob op numbers and format) */
#include <unistd.h>
#include <os/log.h>

namespace {
os_log_t hk_log() {
    static os_log_t log = os_log_create("io.horkos.daemon", "cs-entitlement");
    return log;
}

/* The OS-injected entitlement allowlist: keys the kernel legitimately adds for
 * Rosetta / Apple shims that are NOT on the on-disk signature. HK-TODO(allowlist):
 * the concrete membership is an on-box-verified corpus dependency (plan FP gate);
 * start permissive (allow none flagged spuriously) by treating all four security
 * keys as NON-injected until the corpus confirms which the OS adds. A real
 * deployment captures this from a clean-machine Rosetta corpus. */
constexpr uint32_t kOsInjectedAllowlist = 0u;
}  // namespace

extern "C" bool HkEntitlementDiffProbeSample(const HkCsProbeTarget *target,
                                             HkCsFinding *out)
{
    if (target == nullptr || out == nullptr || target->pid == 0) {
        return false;
    }

    /* HK-UNCERTAIN(cs-entitlements-blob): the CS_OPS_ENTITLEMENTS_BLOB /
     * CS_OPS_DER_ENTITLEMENTS_BLOB buffer-sizing contract and which form is
     * present varies across macOS 12-15 (plan Risk 1); and the on-disk comparand
     * requires SecCodeCopySigningInformation(kSecCSRequirementInformation) ->
     * kSecCodeInfoEntitlementsDict plist parsing into the HK_ENT_* mask. Both the
     * blob parse and the dict parse are unverified, so the probe does NOT guess
     * them (guardrail #12).
     * (docs: kSecCodeInfoEntitlementsDict IS in the public SDK (Security/SecCode.h:
     * line 399,482) and SecCodeCopySigningInformation is publicly declared; the
     * csops blob op numbers and buffer format remain SPI — still needs on-box
     * verification of CS_OPS_ENTITLEMENTS_BLOB constant and blob form on macOS 12-15)
     * When wired:
     *   uint32_t disk_mask   = parse_disk_entitlements(target->bundle_path);
     *   uint32_t kernel_mask = parse_kernel_blob(target->pid);   // csops
     *   uint32_t added = cs_entitlement_added(disk_mask, kernel_mask,
     *                                         kOsInjectedAllowlist);
     *   if (added) { emit HK_CS_ENTITLEMENT_DRIFT, detail = added,
     *                evidence = diffed-key-set }
     * Until both parsers are verified, emit nothing. */
    (void)kOsInjectedAllowlist;
    os_log_debug(hk_log(),
        "HKEntitlementDiffProbe: pid %u entitlement blob parse HK-UNCERTAIN "
        "(csops blob form + kSecCodeInfoEntitlementsDict unverified) — not compared",
        target->pid);
    return false;
}

#endif /* HK_CS_PROBE_PURE_ONLY */
