/*
 * Role: Implementation of the signal-100 WINEDLLOVERRIDES classifier declared in
 *       ProtonOverrideCheck.h. The manifest diff is here (userspace), per the
 *       by design: the BPF side only hashes the offending token; this
 *       holds the per-Proton override allowlist + builtin-only set and turns one
 *       override into the HK_PW_PROTON_* flag bitmask.
 * Target platform: Linux userspace.
 * Interface: implements horkos::proton.
 *
 * Guardrail compliance: #1, #3, #4 (no BPF headers).
 */

#include "ProtonOverrideCheck.h"

#include <algorithm>
#include <cctype>

namespace horkos::proton {

namespace {

std::string Lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

/* Strip a trailing ".dll" (case-insensitive) and any directory so the key is the
 * bare module basename ("ntdll", "d3d11"). */
std::string DllKey(std::string dll) {
    dll = Lower(std::move(dll));
    auto slash = dll.find_last_of("/\\");
    if (slash != std::string::npos)
        dll = dll.substr(slash + 1);
    const std::string ext = ".dll";
    if (dll.size() > ext.size() &&
        dll.compare(dll.size() - ext.size(), ext.size(), ext) == 0)
        dll = dll.substr(0, dll.size() - ext.size());
    return dll;
}

}  // namespace

bool ParseOverrideToken(const std::string& raw, OverrideToken* out) {
    auto eq = raw.find('=');
    if (eq == std::string::npos)
        return false;
    std::string dll = DllKey(raw.substr(0, eq));
    if (dll.empty())
        return false;
    out->dll = dll;
    out->order = Lower(raw.substr(eq + 1));
    return true;
}

bool OrderPrefersNative(const std::string& order) {
    /* The load order is a comma-separated list of 'n' (native) / 'b' (builtin).
     * Native is preferred iff the FIRST listed entry is 'n'. An empty order
     * ("dll=") disables the DLL — not native-first. */
    for (char c : order) {
        if (c == ' ') continue;
        return c == 'n';
    }
    return false;  // empty/disabled
}

uint32_t ProtonOverrideClassifier::ClassifyOverride(const std::string& raw_token,
                                                    bool on_dist_path) const {
    OverrideToken tok;
    if (!ParseOverrideToken(raw_token, &tok))
        return 0;  // malformed token — nothing to flag (server sees the raw hash)

    if (!OrderPrefersNative(tok.order))
        return 0;  // builtin-first or disabled — benign

    uint32_t flags = 0;

    /* Native shadowing a builtin-only DLL (ntdll/kernel32/...) has no legitimate
     * use: strongest signal. */
    if (builtin_only_.count(tok.dll) != 0)
        flags |= kProtonNativeShadowsBuiltin;

    /* A native override NOT on the DXVK/VKD3D/reshade FP allowlist is off-manifest.
     * A builtin-only native override is also off-manifest by construction (it is
     * never on the FP allowlist). */
    if (fp_allowlist_.count(tok.dll) == 0)
        flags |= kProtonOffManifest;

    /* The resolved native DLL not living under the Proton dist tree is a further
     * tell (a /tmp or home-dir native DLL). */
    if (!on_dist_path)
        flags |= kProtonNonDistPath;

    return flags;
}

}  // namespace horkos::proton
