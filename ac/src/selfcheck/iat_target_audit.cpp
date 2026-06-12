/*
 * Role: Signal 149 (Windows) — IAT / delay-IAT resolution-target signature audit.
 *       Walks our IMAGE_IMPORT_DESCRIPTOR + IMAGE_DELAYLOAD_DESCRIPTOR, resolves each
 *       scoped slot's target, attributes the owning module, recomputes the expected
 *       export VA from that module's EAT, and asserts equality (or forwarder). Scoped
 *       to security-relevant imports (Nt/crypto/file/attestation) per the catalog FP
 *       gate; the server allow-lists signed-overlay redirects.
 * Target platforms: Windows-format userspace; the live body is HK_PLATFORM_WINDOWS-
 *       guarded (the POSIX analog is got_target_audit.cpp). The pure classifier is
 *       host-tested. Compiled into hk_ac behind HK_SELFCHECK (guardrail #1).
 * Interface: emits HK_EVENT_SELF_IAT_TARGET (hk_event_self_iat_target). Uses the pure
 *       iat_target_flags core in self_logic.cpp and the pe_parse walker.
 */

#include "horkos/selfcheck.h"
#include "self_wire.h"
#include "pe_parse.h"
#include "platform.h"

namespace hk {
namespace selfcheck {

#if defined(HK_SELFCHECK)

uint32_t iat_target_audit_run(uint64_t image_base, uint32_t import_dir_rva) {
    (void)image_base;
    (void)import_dir_rva;

#if defined(HK_PLATFORM_WINDOWS)
    /* HK-UNCERTAIN(iat-resolve): the live IAT/delay-IAT walk + owning-module
     * attribution (GetModuleHandleEx GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS) +
     * Authenticode/cert-pin verify (WinVerifyTrust via a signing backend) + EAT
     * re-parse are not wired. The pure classifier IS wired and tested: per scoped
     * slot, once {slot_target_va, expected_va, owning module range, signed?,
     * image-backed?, forwarder?} are resolved:
     *   uint32_t f = iat_target_flags(target, expected, mod_base, mod_size,
     *                                 in_image, signed_, forwarder);
     *   if (f && f != HK_SELF_TGT_FORWARDER) emit hk_event_self_iat_target;
     * Scope the walk to HK_SELF_IMPCLASS_{NT,CRYPTO,FILE,ATTESTATION} only. Left
     * unimplemented per guardrail #13 until the WinVerifyTrust signing backend +
     * EAT-recompute path are confirmed; the server allow-lists overlay redirects. */
    return HK_SELF_FLAG_NONE;
#else
    /* The POSIX GOT/PLT analog lives in got_target_audit.cpp. */
    return HK_SELF_FLAG_NONE;
#endif
}

#endif /* HK_SELFCHECK */

} // namespace selfcheck
} // namespace hk
