/*
 * daemon/macos/trust/AmfiPostureProbe.cpp
 * Role: Signal 124 — AMFI / SIP / Developer-Mode / boot-arg posture probe.
 *       Samples the host's trust posture (CSR/SIP config, boot-args presence,
 *       Developer-Mode state) via the hk::platform helpers and reports it
 *       VERBATIM as a trust-tier input — NEVER a standalone ban. Emits
 *       HK_CS_AMFI_POSTURE_WEAK with a CSR-config bitfield in `detail`.
 * Target platform: macOS only (built behind if(APPLE) + HK_MACOS_CS_AMFI_POSTURE).
 * Interface: probe sample registered by the orchestrator. Uses platform_macos
 *            IORegistry/csr helpers (guardrail #1 — no OS API in this TU).
 *            Userspace daemon TU (guardrail #4).
 *
 * Guardrail compliance:
 *   #1  No platform #ifdef and no OS API here — the csr / IORegistry reads live
 *       in platform/platform_macos.cpp behind hk::platform.
 *   #13 csr_get_active_config is private SPI (plan Risk 2); the platform helper
 *       degrades to "unavailable" rather than guess the bit layout, so this probe
 *       ships report-only and degraded. No ban is gated on it.
 */

#include "CsScan.h"
#include "platform.h"

/* Boot-arg substrings whose PRESENCE weakens AMFI/SIP posture. Reported as a
 * trust-tier input; legitimate devs set these (plan FP gate), so they never ban
 * on their own — the server decides whether a weakened boot may play. */
static const char kAmfiWeakBootArg[]   = "amfi_get_out_of_my_way";
static const char kAmfiAllowBootArg[]  = "amfi=";

/* detail bitfield (signal 124). Compact discriminant only. */
#define HK_AMFI_DETAIL_CSR_UNAVAIL   0x00000001u  /* CSR/SIP read unavailable (SPI) */
#define HK_AMFI_DETAIL_SIP_OFF       0x00000002u  /* SIP determined disabled */
#define HK_AMFI_DETAIL_BOOTARG_AMFI  0x00000004u  /* an amfi-weakening boot-arg set */

#ifndef HK_CS_PROBE_PURE_ONLY

#include <string.h>
#include <os/log.h>

namespace {
os_log_t hk_log() {
    static os_log_t log = os_log_create("io.horkos.daemon", "cs-amfi-posture");
    return log;
}

bool contains(const char *haystack, const char *needle) {
    return haystack[0] != '\0' && strstr(haystack, needle) != nullptr;
}
}  // namespace

extern "C" bool HkAmfiPostureProbeSample(const HkCsProbeTarget * /*target*/,
                                         HkCsFinding *out)
{
    if (out == nullptr) {
        return false;
    }

    uint32_t detail = 0;

    uint32_t csr_config = 0;
    if (hk::platform::csr_active_config(&csr_config)) {
        /* HK-UNCERTAIN(csr-bit-layout): csr_config interpretation depends on the
         * confirmed CSR bit layout (Risk 2) — fold the raw config into detail's
         * high bits once the layout is verified. Until csr_active_config returns
         * a real value this branch is unreachable.
         * (docs: csr_get_active_config is NOT in the public SDK through macOS 15.5;
         * it is a private SPI — still needs on-box/SIP verification of bit layout) */
        if (!hk::platform::sip_enabled()) {
            detail |= HK_AMFI_DETAIL_SIP_OFF;
        }
    } else {
        detail |= HK_AMFI_DETAIL_CSR_UNAVAIL;
    }

    char boot_args[1024];
    if (hk::platform::read_boot_args(boot_args, sizeof(boot_args)) > 0) {
        if (contains(boot_args, kAmfiWeakBootArg) ||
            contains(boot_args, kAmfiAllowBootArg)) {
            detail |= HK_AMFI_DETAIL_BOOTARG_AMFI;
        }
    }

    /* Developer-Mode state: HK-UNCERTAIN(developer-mode) — the AMFI Developer-Mode
     * query API is not clearly public across macOS 12-15 (plan Risk 2). Not read
     * here; do not guess the API.
     * (docs: no public API for AMFI Developer Mode state found in MacOSX.sdk
     * through 15.5; Security/SecTask.h has no such API; IOKit/MobileDevice paths
     * are not present in the desktop SDK — still needs on-box/SPI verification)
     * When confirmed, fold a DEV_MODE bit into detail.
     *
     * Report-only contract (plan): a weakened posture is emitted VERBATIM as a
     * trust-tier input. Only emit when SOMETHING notable is present (an actual
     * weakening signal or an unavailable SPI read worth recording); a fully clean,
     * fully readable posture is not a finding. The server, not this probe, decides
     * whether a reduced-security boot may play — NEVER a standalone ban. */
    if (detail == 0) {
        return false;
    }

    out->signal_id   = 124;
    out->finding     = HK_CS_AMFI_POSTURE_WEAK;
    out->target_pid  = 0;        /* host-wide posture */
    out->detail      = detail;   /* CSR/boot-arg bitfield */
    out->evidence    = nullptr;
    out->evidence_len = 0;
    os_log(hk_log(),
        "HKAmfiPostureProbe: posture detail=0x%x (trust-tier input, never a ban)",
        detail);
    return true;
}

#endif /* HK_CS_PROBE_PURE_ONLY */
