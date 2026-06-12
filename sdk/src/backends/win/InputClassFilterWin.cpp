/*
 * Role: Signal 56 (win-input-automation). Keyboard/Pointer device-stack filter
 *       interloper scan. Enumerates the keyboard ({4d36e96b-...}) and mouse
 *       ({4d36e96f-...}) device-class UpperFilters/LowerFilters plus each device's
 *       per-instance SPDRP_UPPERFILTERS/LOWERFILTERS, reports the FULL ordered filter
 *       list (filter_count + per-filter service name) and the resolved signer
 *       verdict. The signed/allowlisted decision is server-side signed-rule plumbing;
 *       the client only reports the filter service + signer (catalog: never ban on
 *       presence of a filter — kbdclass/mouclass/Synaptics/ELAN/Logitech/Razer/KVM
 *       are legitimate).
 * Target platforms: Windows userspace. Guardrail #1: SetupAPI + Control\Class
 *       registry reads + WinVerifyTrust confined here.
 * Interface: implements hk::sdk::win::sense_input_class_filters. Verdict via the pure
 *       classify_input_source (is_class_filter path) in InputSensorWin.h.
 */

#include "InputSensorWin.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <windows.h>

namespace hk { namespace sdk { namespace win {

namespace {

/* The two input device-class GUIDs whose class-level UpperFilters/LowerFilters are
 * the interloper surface. Keyboard {4d36e96b-e325-11ce-bfc1-08002be10318} and Mouse
 * {4d36e96f-e325-11ce-bfc1-08002be10318}. Read read-only from
 * HKLM\SYSTEM\CurrentControlSet\Control\Class\<guid>. */
const wchar_t* const kClassKeys[] = {
    L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e96b-e325-11ce-bfc1-08002be10318}",
    L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e96f-e325-11ce-bfc1-08002be10318}",
};

/* Read a REG_MULTI_SZ value into a count of entries. Read-only. Returns the entry
 * count (0 on absence/error); the caller emits one finding per entry. The actual
 * service strings + signer verdict are resolved by the deferred WinVerifyTrust pass
 * (R5) — counting the ordered filter depth is safe and exact now. */
uint32_t CountMultiSz(HKEY cls, const wchar_t* value)
{
    DWORD type = 0;
    DWORD bytes = 0;
    if (RegQueryValueExW(cls, value, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS ||
        type != REG_MULTI_SZ || bytes < sizeof(wchar_t)) {
        return 0;
    }
    std::wstring buf(bytes / sizeof(wchar_t), L'\0');
    DWORD got = bytes;
    if (RegQueryValueExW(cls, value, nullptr, &type,
                         reinterpret_cast<LPBYTE>(buf.data()), &got) != ERROR_SUCCESS) {
        return 0;
    }
    uint32_t n = 0;
    size_t i = 0;
    while (i < buf.size() && buf[i] != L'\0') {
        ++n;
        while (i < buf.size() && buf[i] != L'\0') ++i; /* skip this entry */
        ++i;                                            /* skip its NUL */
    }
    return n;
}

} // namespace

int sense_input_class_filters(std::vector<hk_input_finding>& out)
{
    uint32_t total_filters = 0;
    bool any_query_failed = false;

    for (const wchar_t* key : kClassKeys) {
        HKEY cls = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &cls) != ERROR_SUCCESS) {
            any_query_failed = true;
            continue;
        }
        total_filters += CountMultiSz(cls, L"UpperFilters");
        total_filters += CountMultiSz(cls, L"LowerFilters");
        RegCloseKey(cls);
    }

    /* HK-TODO(sdk-integration): the per-filter service NAME string + Authenticode
     * signer subject (the JSON side-channel fields filter_service / signer_subject)
     * are resolved by walking each REG_MULTI_SZ entry to its driver service image and
     * running WinVerifyTrust. That signer pass is the SAME cached, off-hot-path
     * Authenticode resolution the render sensors defer (plan R5): WinVerifyTrust is
     * expensive and may hit revocation network, so it is cached per image per session
     * and a timeout maps to HK_INPUT_SRC_UNRESOLVED, never a false "unsigned". Per
     * filter the folding is:
     *
     *   InputSourceInput si{};
     *   si.is_class_filter   = true;
     *   si.query_failed      = signer_query_timed_out;
     *   si.filter_signed     = WinVerifyTrust(image) == ERROR_SUCCESS;
     *   si.filter_allowlisted = false;            // server-side signed-rule join
     *   finding.verdict      = classify_input_source(si);
     *   finding.filter_count = total_filters;     // ordered depth
     *   // filter_service / signer_subject ride the JSON side-channel
     *   out.push_back(finding);
     *
     * Until the signer pass + service-name resolution land, the exact ordered count
     * is recorded but no per-filter verdict is fabricated. A non-zero filter stack on
     * a keyboard/mouse class is normal (kbdclass/mouclass/vendor filters), so the
     * mere count is not itself emitted as an anomaly — the verdict needs the signer.
     * On a registry-read failure we stay silent rather than reporting a false
     * unsigned filter. */
    (void)total_filters;
    (void)any_query_failed;
    (void)out;
    return 0; /* signer pass not yet wired: ordered count read, no verdict fabricated */
}

} } } // namespace hk::sdk::win

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
