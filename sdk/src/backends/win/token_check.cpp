/*
 * Role: Signal 203 sensor — opens the game's token and the recorded parent's
 *       token, reads the mandatory integrity level / elevation / session, and
 *       emits the raw token_integrity_delta via the host-tested pure helper
 *       hk_token_integrity_delta. The server baselines the EXPECTED delta per
 *       known launcher (a UAC-elevated admin launcher legitimately yields a
 *       positive delta) and flags only divergence — never an absolute level.
 *       READ-ONLY.
 * Target platforms: Windows userspace. Guardrail #1: token APIs confined to
 *       backends/win. NOT COMPILED on non-Windows (gated under if(WIN32)).
 * Interface: hk::sdk::genealogy::token_integrity_delta (consumed by the SDK
 *       launch-trust report assembler).
 */

#include <windows.h>

#include "horkos/genealogy_logic.h"

namespace hk {
namespace sdk {
namespace genealogy {

/* Read the integrity-level RID from a process token. Returns 0 on failure (the
 * caller treats a 0 as "not collected" via the reparent/delta guards). */
static uint32_t IntegrityLevelRid(DWORD pid)
{
    HANDLE proc = nullptr;
    HANDLE token = nullptr;
    DWORD len = 0;
    uint32_t rid = 0;

    proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (proc == nullptr) {
        return 0;
    }
    if (OpenProcessToken(proc, TOKEN_QUERY, &token) && token != nullptr) {
        GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &len);
        if (len > 0) {
            TOKEN_MANDATORY_LABEL* label = (TOKEN_MANDATORY_LABEL*)LocalAlloc(LPTR, len);
            if (label != nullptr) {
                if (GetTokenInformation(token, TokenIntegrityLevel, label, len, &len)) {
                    DWORD subAuthCount = *GetSidSubAuthorityCount(label->Label.Sid);
                    if (subAuthCount > 0) {
                        rid = (uint32_t)*GetSidSubAuthority(label->Label.Sid,
                                                            subAuthCount - 1);
                    }
                }
                LocalFree(label);
            }
        }
        CloseHandle(token);
        token = nullptr;
    }
    CloseHandle(proc);
    return rid;
}

/* Compute the signed game-vs-launcher integrity delta. Pure core does the math;
 * this only sources the two RIDs. */
int32_t token_integrity_delta(DWORD game_pid, DWORD launcher_pid)
{
    uint32_t game_il = IntegrityLevelRid(game_pid);
    uint32_t parent_il = IntegrityLevelRid(launcher_pid);
    return hk_token_integrity_delta(game_il, parent_il);
}

} // namespace genealogy
} // namespace sdk
} // namespace hk
