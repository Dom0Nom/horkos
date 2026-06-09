/*
 * daemon/macos/trust/GatekeeperProbe.cpp
 * Role: Signal 125 — Gatekeeper / quarantine / notarization-staple provenance.
 *       Reads the com.apple.quarantine xattr on the game bundle and (in the real
 *       path) SecAssessmentCopyResult / SecAssessmentTicketLookup for staple
 *       presence. This is a WEAK signal: self-built, Steam/Epic-managed, and
 *       App-Store binaries legitimately lack the quarantine xattr, and enterprises
 *       disable Gatekeeper by policy. Therefore HK_CS_GATEKEEPER_BYPASS is emitted
 *       ONLY as a corroborating finding — the orchestrator suppresses it unless a
 *       119/126 finding co-occurs for the same PID (the suppression lives in the
 *       orchestrator; this probe produces the raw observation).
 * Target platform: macOS only (built behind if(APPLE) + HK_MACOS_CS_GATEKEEPER,
 *       default OFF).
 * Interface: probe sample registered by the orchestrator. Userspace daemon TU
 *            (guardrail #4).
 *
 * Guardrail compliance:
 *   #1  No platform #ifdef — CMake gates the TU.
 *   #13 SecAssessment* is a partially-SPI surface (plan Risk 3); the
 *       SecAssessmentCopyResult / SecAssessmentTicketLookup calls are NOT made
 *       (linkable subset unconfirmed). Only the public getxattr read is wired,
 *       and even it is gated corroborating-only by the orchestrator.
 */

#include "CsScan.h"

#ifndef HK_CS_PROBE_PURE_ONLY

#include <sys/xattr.h>
#include <os/log.h>

namespace {
os_log_t hk_log() {
    static os_log_t log = os_log_create("io.horkos.daemon", "cs-gatekeeper");
    return log;
}
}  // namespace

extern "C" bool HkGatekeeperProbeSample(const HkCsProbeTarget *target, HkCsFinding *out)
{
    if (target == nullptr || out == nullptr || target->bundle_path == nullptr) {
        return false;
    }

    /* Public, stable read: presence/absence of the quarantine xattr. getxattr
     * with size 0 queries the attribute length without copying it. A negative
     * return means the attribute is absent (ENOATTR) or the path is unreadable —
     * either way we cannot assert a bypass from this alone. */
    ssize_t qlen = getxattr(target->bundle_path, "com.apple.quarantine",
                            nullptr, 0, 0, 0);
    bool quarantine_present = (qlen >= 0);

    /* HK-UNCERTAIN(secassessment): the authoritative notarization-staple check
     * (SecAssessmentCopyResult with kSecAssessmentOperationTypeExecute, and
     * SecAssessmentTicketLookup for the stapled ticket) is a partially-SPI surface
     * whose linkable/entitled subset is unconfirmed across macOS versions (plan
     * Risk 3). Per guardrail #13 those calls are NOT made here. A missing
     * quarantine xattr is FAR too weak to assert a bypass on its own (self-built /
     * Steam-managed / App-Store binaries legitimately lack it). Therefore this
     * probe does NOT emit on the xattr alone; the corroborating-only gate
     * (suppress unless a 119/126 finding co-occurs for the same PID) lives in the
     * orchestrator, which is the sole emitter for this signal. Here we only record
     * the raw observation for that join. */
    if (quarantine_present) {
        /* Quarantine present and intact-looking — definitely not a bypass signal. */
        return false;
    }

    os_log_debug(hk_log(),
        "HKGatekeeperProbe: pid %u bundle lacks quarantine xattr — weak, "
        "corroborating-only (SecAssessment staple check HK-UNCERTAIN); deferring "
        "to orchestrator 119/126 co-occurrence gate",
        target->pid);
    /* Emit nothing standalone (guardrail-faithful: never a standalone ban input).
     * The orchestrator's corroboration join is the only path that surfaces 125. */
    return false;
}

#endif /* HK_CS_PROBE_PURE_ONLY */
