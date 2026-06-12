/*
 * Role: Signal 149 (Linux/macOS) — the .got.plt/.rela.plt (Linux) and
 *       __la_symbol_ptr/__got (macOS) analog of the Windows IAT audit: resolve each
 *       scoped slot via dladdr/dynsym, verify the target lands inside the expected
 *       signed DSO/dylib, and flag displaced / wrong-module / private targets. Scoped
 *       to security-relevant imports per the catalog FP gate.
 * Target platforms: POSIX userspace; the live body is HK_PLATFORM_LINUX/MACOS-
 *       guarded (the Windows analog is iat_target_audit.cpp). Compiled into hk_ac
 *       behind HK_SELFCHECK (guardrail #1).
 * Interface: emits HK_EVENT_SELF_IAT_TARGET (hk_event_self_iat_target). Uses the same
 *       pure iat_target_flags core in self_logic.cpp.
 */

#include "horkos/selfcheck.h"
#include "self_wire.h"
#include "platform.h"

namespace hk {
namespace selfcheck {

#if defined(HK_SELFCHECK)

uint32_t got_target_audit_run(uint64_t image_base) {
    (void)image_base;

#if defined(HK_PLATFORM_LINUX) || defined(HK_PLATFORM_MACOS)
    /* HK-UNCERTAIN(got-resolve): the live .got.plt/.rela.plt (Linux) or
     * __la_symbol_ptr/__got (macOS) walk + dladdr/dynsym attribution + DSO/dylib
     * signing verify are not wired. The pure classifier is shared with the Windows
     * path (iat_target_flags) and tested host-side. Left unimplemented per guardrail
     * #13 until the per-OS dynamic-symbol resolution + signing verify are confirmed;
     * the server allow-lists overlay redirects (LD_PRELOAD'd signed overlays, etc.). */
    return HK_SELF_FLAG_NONE;
#else
    return HK_SELF_FLAG_NONE;
#endif
}

#endif /* HK_SELFCHECK */

} // namespace selfcheck
} // namespace hk
