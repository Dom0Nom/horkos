/*
 * Role: Signal 100 verifier — classify a WINEDLLOVERRIDES override token (emitted
 *       as an FNV64 hash by proton_env.bpf.c, re-resolved to a string from
 *       /proc/<pid>/environ here) against the per-Proton-version override manifest
 *       and the DXVK/VKD3D/reshade FP allowlist. Produces the HK_PW_PROTON_* flags
 *       the loader stamps onto the reported record. Decision-only; never bans
 *       (server adjudicates).
 * Target platform: Linux userspace.
 * Interface: ClassifyOverride() returns the flag bitmask for one override token.
 *            The manifest/allowlist are injected (test seam) so the classifier is
 *            host-testable without a live Proton install.
 */

#pragma once

#include <cstdint>
#include <string>
#include <unordered_set>

namespace horkos::proton {

/* HK_PW_PROTON_* flag bits (mirror hk_bpf_shared.h / event_schema.h). */
inline constexpr uint32_t kProtonNativeShadowsBuiltin = 0x1u;
inline constexpr uint32_t kProtonOffManifest          = 0x2u;
inline constexpr uint32_t kProtonNonDistPath          = 0x4u;

/* One parsed override token: "<dll>=<order>" e.g. "ntdll=n", "d3d11=n,b". */
struct OverrideToken {
    std::string dll;     /* lowercased dll basename, no extension */
    std::string order;   /* the load-order string after '=' (e.g. "n", "n,b") */
};

/* Parse a single "dll=order" token. Returns false if it is not a well-formed
 * override (no '=', empty dll). Multiple comma-separated dlls sharing one order
 * ("d3d11,d3d10=n") are split by the caller; this parses one dll=order pair. */
bool ParseOverrideToken(const std::string& raw, OverrideToken* out);

/* True if `order` requests the NATIVE (non-builtin) DLL to load first ("n" or
 * "n,b"): native shadowing a builtin is the cheating vector. "b" / "b,n" /
 * "" (disabled) are not native-first. */
bool OrderPrefersNative(const std::string& order);

/* The classifier holds the FP allowlist (DLLs whose native override is benign:
 * dxvk's d3d9/d3d10/d3d11/dxgi, vkd3d's d3d12, reshade's dxgi, etc.) and the set
 * of BUILTIN-ONLY DLLs (ntdll/kernel32/.. — a native override of these has no
 * legitimate use and is the strong signal). Both sets are server-supplied per
 * Proton build; tests inject fixtures. */
class ProtonOverrideClassifier {
public:
    ProtonOverrideClassifier(std::unordered_set<std::string> fp_allowlist,
                             std::unordered_set<std::string> builtin_only)
        : fp_allowlist_(std::move(fp_allowlist)),
          builtin_only_(std::move(builtin_only)) {}

    /* Classify one raw "dll=order" token. Returns the HK_PW_PROTON_* bitmask.
     * - native-first override of a builtin-only DLL -> NATIVE_SHADOWS_BUILTIN
     * - native-first override of a DLL NOT on the FP allowlist -> OFF_MANIFEST
     * - a DXVK/VKD3D allowlisted native override -> 0 (no flag)
     * `on_dist_path` is whether the resolved native DLL the override points at
     * lives under the Proton dist tree (false -> NON_DIST_PATH). */
    uint32_t ClassifyOverride(const std::string& raw_token,
                              bool on_dist_path) const;

private:
    std::unordered_set<std::string> fp_allowlist_;
    std::unordered_set<std::string> builtin_only_;
};

}  // namespace horkos::proton
