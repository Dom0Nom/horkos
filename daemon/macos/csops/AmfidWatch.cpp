/*
 * daemon/macos/csops/AmfidWatch.cpp
 * Role: Signal 123 (daemon half) — amfid task-port acquisition watch. Consumes
 *       ES NOTIFY_GET_TASK / NOTIFY_GET_TASK_READ observations whose target
 *       resolves to /usr/libexec/amfid and emits HK_CS_AMFID_TASKPORT, cross-
 *       checked against SIP state: a get-task on amfid is high-signal only with
 *       SIP ON; on a SIP-disabled dev box lldb/Apple tools can task_for_pid
 *       daemons, so those are reported SEPARATELY (tagged), not as cheating.
 * Target platform: macOS only (built behind if(APPLE) + HK_MACOS_CS_AMFID,
 *       requires HORKOS_MACOS_ES).
 * Interface: implements the ES-consume entry point registered by the
 *            orchestrator. Userspace daemon TU (guardrail #4); cross-checks the
 *            SIP probe (signal 124, platform_macos helper).
 *
 * Guardrail compliance:
 *   #1  No platform #ifdef — CMake gates the TU; SIP read routed through
 *       hk::platform (guardrail #1), not done inline here.
 *   #13 Whether NOTIFY_GET_TASK fires for amfid acquisition on the target macOS
 *       versions (Risk 4), and the privileged task_get_exception_ports variant
 *       (Risk 5) are HK-UNCERTAIN. This watch is the PURELY OBSERVATIONAL variant
 *       (watch get-task ON amfid; never acquire amfid's port ourselves) the plan
 *       prefers — it needs no debug entitlement / SIP-off and is self-contained.
 */

#include "CsScan.h"
#include "platform.h"   /* hk::platform::sip_enabled (guardrail #1) */

#include <string.h>

/* amfid's canonical path. The orchestrator resolves the get-task target's path
 * and stamps the observation's signing_id; here we match the daemon's resolved
 * amfid identity. HK-TODO: the orchestrator currently passes the target signing-id
 * in obs->signing_id; amfid's signing-id is "com.apple.amfid". We match on that. */
static const char kAmfidSigningId[] = "com.apple.amfid";

/* -------------------------------------------------------------------------
 * Impure ES-consume body (excluded from the pure host-test TU).
 * ------------------------------------------------------------------------- */
#ifndef HK_CS_PROBE_PURE_ONLY

#include <os/log.h>

namespace {
os_log_t hk_log() {
    static os_log_t log = os_log_create("io.horkos.daemon", "cs-amfid");
    return log;
}

/* Bounded match of a NUL-padded signing-id buffer against a C string. */
bool signing_id_is(const uint8_t *buf, size_t cap, const char *want) {
    size_t wn = strlen(want);
    if (wn >= cap) {
        return false;
    }
    if (memcmp(buf, want, wn) != 0) {
        return false;
    }
    return buf[wn] == 0;   /* exact, NUL-terminated within the buffer */
}
}  // namespace

extern "C" bool HkAmfidWatchConsume(const HkEsObservation *obs, HkCsFinding *out)
{
    if (obs == nullptr || out == nullptr || obs->kind != HK_ES_OBS_GET_TASK) {
        return false;
    }
    if (!signing_id_is(obs->signing_id, sizeof(obs->signing_id), kAmfidSigningId)) {
        return false;   /* not a get-task on amfid */
    }

    /* SIP cross-check (signal 124's surface, routed through the platform helper
     * per guardrail #1). With SIP ON, a get-task on amfid is high-signal. With
     * SIP OFF (dev box), Apple tools can task_for_pid system daemons — report it
     * but TAG it via detail so the server scores it separately, never as a ban.
     *
     * HK-UNCERTAIN(amfid-get-task): plan Risk 4 — whether NOTIFY_GET_TASK actually
     * fires for amfid task-port acquisition on macOS 12-15 is unverified. The
     * observational consume is wired (no privileged port needed — the preferred
     * variant per Risk 5); the firing assumption is the open item, flagged. */
    bool sip_on = hk::platform::sip_enabled();

    out->signal_id   = 123;
    out->finding     = HK_CS_AMFID_TASKPORT;
    out->target_pid  = obs->target_pid;          /* amfid's pid */
    /* detail low bit: 1 = SIP enabled (high-signal), 0 = SIP off (dev box —
     * server scores separately, the plan's SIP-disabled tag). */
    out->detail      = sip_on ? 1u : 0u;
    out->evidence    = nullptr;
    out->evidence_len = 0;
    os_log(hk_log(),
        "HKAmfidWatch: get-task on amfid by pid %u (sip_on=%d — server gates)",
        obs->source_pid, sip_on ? 1 : 0);
    return true;
}

#endif /* HK_CS_PROBE_PURE_ONLY */
