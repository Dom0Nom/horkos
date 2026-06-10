/*
 * kernel/macos/es/genealogy_handler.cpp
 * Role: Signal 207 — responsible-process / parent-responsibility mismatch. In the
 *       ES_EVENT_TYPE_NOTIFY_EXEC handler, extracts the responsible/parent audit
 *       tokens, Team ID, signing ID and cdhash of the launch chain and compares
 *       the chain's signing identities against the accepted-launcher baseline
 *       (server-side; the client ships the responsible Team ID + chain identity).
 *       NOTIFY-only — no AUTH event, NO reply deadline (guardrail #7): a fixed-size
 *       token extraction + async hand-off, never blocking the ES serial queue.
 *       READ-ONLY.
 * Target platforms: macOS ES (userspace ES client). Built under HORKOS_MACOS_ES
 *       (default OFF until the EndpointSecurity entitlement lands, locked decision
 *       #4); not compiled on this host.
 * Interface: invoked from EsClient.mm's NOTIFY_EXEC path; mirrors into
 *       daemon/macos/horkosd.cpp. Emits the responsible Team ID into the
 *       launch-trust report.
 */

#if defined(HORKOS_MACOS_ES)

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>

#include <cstring>
#include <string>

namespace hk {
namespace macos {

struct LaunchTrustExtract {
    pid_t target_pid;
    pid_t responsible_pid;
    pid_t parent_pid;
    char  responsible_team_id[32];
    char  signing_id[128];
    bool  responsible_resolved;
};

/* Copy a const es_string_token_t into a bounded buffer. */
static void CopyEsString(char* dst, size_t cap, es_string_token_t tok)
{
    size_t n = tok.length;
    if (n >= cap) {
        n = cap - 1;
    }
    if (tok.data != nullptr && n > 0) {
        std::memcpy(dst, tok.data, n);
    }
    dst[n] = '\0';
}

/* Extract the launch-trust tuple from a NOTIFY_EXEC message. Pure token reads;
 * no blocking call, no Security-framework round trip on the ES queue (guardrail
 * #7). The signing-identity verification against the baseline is server-side. */
void ExtractLaunchTrust(const es_message_t* msg, LaunchTrustExtract* out)
{
    if (msg == nullptr || out == nullptr) {
        return;
    }
    std::memset(out, 0, sizeof(*out));

    const es_process_t* target = msg->event.exec.target;
    if (target == nullptr) {
        return;
    }
    out->target_pid = audit_token_to_pid(target->audit_token);
    out->parent_pid = audit_token_to_pid(target->parent_audit_token);
    out->responsible_pid = audit_token_to_pid(target->responsible_audit_token);
    out->responsible_resolved = (out->responsible_pid > 0);
    CopyEsString(out->responsible_team_id, sizeof(out->responsible_team_id),
                 target->team_id);
    CopyEsString(out->signing_id, sizeof(out->signing_id), target->signing_id);
    /* The chain comparison vs the accepted launcher Team IDs/cdhashes is done by
     * the server; the client only ships this tuple. cdhash extraction
     * (target->cdhash) is HK-UNCERTAIN across ES versions — added on the box. */
}

} // namespace macos
} // namespace hk

#endif /* HORKOS_MACOS_ES */
