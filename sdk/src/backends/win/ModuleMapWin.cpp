/*
 * sdk/src/backends/win/ModuleMapWin.cpp
 * Role: Builds the per-process signed-module map shared by the render provenance
 *       sensors (catalog signals 46/47/52/54, win-usermode-overlay). Enumerates
 *       the own process's loaded modules (EnumProcessModulesEx, LIST_MODULES_ALL)
 *       with their [base, base+SizeOfImage) ranges and on-disk paths, then
 *       resolves each module's Authenticode signer subject. Read-only: it only
 *       observes loaded-module + signature state, never writes/loads/unloads.
 * Target platforms: Windows userspace. Guardrail #1: the psapi / wintrust /
 *       crypt32 calls are confined to this backends/win/ TU. The provenance
 *       decision logic is in RenderSensorWin.h (pure, host-tested).
 * Interface: implements hk::sdk::render::build_module_map from RenderSensorWin.h.
 */

#include "RenderSensorWin.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <windows.h>
#include <psapi.h>
#include <algorithm>

namespace hk { namespace sdk { namespace render {

namespace {

/* Resolve the Authenticode signer subject for an on-disk module and whether its
 * chain validates. Returns false (signer empty) when verification could not be
 * completed — which maps to "unverified", NEVER to a false "unsigned" verdict
 * (plan R5): the caller leaves module_signed=false only when WinVerifyTrust
 * affirmatively reported an invalid/absent signature, and records the
 * unverified-due-to-timeout case as signer-unknown so the sensor downgrades to
 * HK_PROV_UNRESOLVED rather than fabricating an "unsigned" flag. */
bool ResolveSigner(const wchar_t* /*path*/, std::string& subject_out, bool& chain_valid)
{
    subject_out.clear();
    chain_valid = false;

    /* HK-UNCERTAIN(authenticode-cost): WinVerifyTrust + CryptQueryObject/
     * CryptMsgGetParam is the documented signer-subject path, but it is expensive
     * and can hit the network for revocation (plan R5). The verified
     * implementation MUST:
     *   - run off the hot AC tick and cache the (path -> signer, chain_valid)
     *     result per module per session;
     *   - use WTD_CACHE_ONLY / WTD_REVOCATION_NONE-style flags or a bounded
     *     timeout so a slow revocation check maps to "unverified" (signer empty,
     *     chain_valid=false treated as UNRESOLVED upstream), not a false
     *     "unsigned" verdict.
     * The exact WINTRUST_DATA flag combination + CryptMsgGetParam(CMSG_SIGNER_*)
     * struct walk to extract the subject CN are version-sensitive and need on-box
     * confirmation, so this is left as a documented stub returning "unverified".
     * The pure classifier (classify_provenance) is unaffected and host-tested. */
    return false;
}

} // namespace

bool build_module_map(ModuleMap& out)
{
    out.entries.clear();

    const HANDLE self = GetCurrentProcess();

    /* First call sizes the array; loop because modules can load between calls. */
    DWORD needed = 0;
    if (!EnumProcessModulesEx(self, nullptr, 0, &needed, LIST_MODULES_ALL) ||
        needed == 0) {
        return false; /* enumeration failed: caller degrades to no-map */
    }

    std::vector<HMODULE> mods(needed / sizeof(HMODULE));
    DWORD got = 0;
    if (!EnumProcessModulesEx(self, mods.data(),
                              static_cast<DWORD>(mods.size() * sizeof(HMODULE)),
                              &got, LIST_MODULES_ALL)) {
        return false;
    }
    const size_t count = std::min<size_t>(mods.size(), got / sizeof(HMODULE));

    out.entries.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        MODULEINFO mi{};
        if (!GetModuleInformation(self, mods[i], &mi, sizeof(mi))) {
            continue; /* skip a module we cannot size rather than aborting the map */
        }

        wchar_t pathW[MAX_PATH];
        /* GetMappedFileName attributes the mapped VA to a backing file; it returns
         * an NT device path, which the server normalizes. 0 return => skip. */
        if (GetMappedFileNameW(self, mi.lpBaseOfDll, pathW,
                               static_cast<DWORD>(std::size(pathW))) == 0) {
            pathW[0] = L'\0';
        }

        ModuleEntry e{};
        e.base = reinterpret_cast<uint64_t>(mi.lpBaseOfDll);
        e.size = mi.SizeOfImage;

        /* Narrow the wide path to UTF-8 for the JSON side-channel. A failed
         * conversion leaves the path empty (still a usable range entry). */
        if (pathW[0] != L'\0') {
            int len = WideCharToMultiByte(CP_UTF8, 0, pathW, -1,
                                          nullptr, 0, nullptr, nullptr);
            if (len > 1) {
                std::string p(static_cast<size_t>(len - 1), '\0');
                WideCharToMultiByte(CP_UTF8, 0, pathW, -1, p.data(), len,
                                    nullptr, nullptr);
                e.path = std::move(p);
            }
        }

        bool chain_valid = false;
        ResolveSigner(pathW, e.signer_subject, chain_valid);
        e.signed_ok = chain_valid;
        /* allowlisted is a SERVER decision; the client never sets it true here.
         * It stays false and the resolved signer subject travels to the server,
         * which applies the signed allow-list rule. */
        e.allowlisted = false;

        out.entries.push_back(std::move(e));
    }

    std::sort(out.entries.begin(), out.entries.end(),
              [](const ModuleEntry& a, const ModuleEntry& b) {
                  return a.base < b.base;
              });
    return !out.entries.empty();
}

} } } // namespace hk::sdk::render

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
