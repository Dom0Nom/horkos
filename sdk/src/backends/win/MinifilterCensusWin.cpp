/*
 * sdk/src/backends/win/MinifilterCensusWin.cpp
 * Role: Userspace minifilter altitude census (signal 6). Enumerates loaded
 *       minifilters and their instances via fltlib (FilterFindFirst /
 *       FilterInstanceFindFirst), parses each altitude, and runs the pure
 *       classifier (minifilter_altitude.h) to flag filters at an UNALLOCATED
 *       altitude OR with a FAILED Authenticode chain that sit numerically
 *       adjacent-above Horkos. Feeds the SDK report plane — NOT the kernel ring.
 *       Read-only: it only observes FltMgr state, never attaches/detaches/loads.
 * Target platforms: Windows userspace (guardrail #1: the only Win32/fltlib use
 *       lives here, under backends/win/).
 * Interface: declares hk::sdk::minifilter_census() in sdk_backend.h (Windows-only
 *       symbol). The pure classification lives in minifilter_altitude.h.
 */

#include <windows.h>
#include <fltuser.h>   /* FilterFindFirst / FilterInstanceFindFirst */

#include <cstdint>
#include <cstdlib>
#include <cwchar>
#include <vector>

#include "minifilter_altitude.h"
#include "sdk_backend.h"

namespace hk { namespace sdk {

namespace {

/* Horkos's own minifilter altitude (numeric). Mirrors the kernel-side
 * HK_OB_ALTITUDE group; the production value comes from an Allocated Altitude. */
constexpr double kHorkosAltitude = 385201.0;

/* Parse a FltMgr altitude string (a decimal, possibly fractional) to double.
 * Returns false on a malformed string. Uses wcstod with full end-pointer check
 * so trailing garbage is rejected. */
bool ParseAltitude(const wchar_t* s, double& out)
{
    if (s == nullptr || s[0] == L'\0') {
        return false;
    }
    wchar_t* end = nullptr;
    errno = 0;
    double v = std::wcstod(s, &end);
    if (errno != 0 || end == s || (end != nullptr && *end != L'\0')) {
        return false;
    }
    out = v;
    return true;
}

/* Allocated-altitude lookup: delegates to the pure, host-tested band table in
 * minifilter_altitude.h (Microsoft's published load-order-group altitude
 * ranges). A filter squatting in a gap between bands reads as unallocated. */
bool IsAllocatedAltitude(double altitude)
{
    return hk::sdk::mf::is_allocated_altitude(altitude);
}

/* Authenticode verification of a filter's backing image. Not yet wired to
 * WinVerifyTrust; returns Unknown so the classifier treats it conservatively
 * (Unknown is never, on its own, a Failed verdict). The host unit tests cover
 * the Failed/Trusted branches directly. */
mf::AuthResult VerifyFilterImage(const wchar_t* /*filterName*/)
{
    return mf::AuthResult::Unknown; /* TODO(authenticode): WinVerifyTrust path */
}

/* Publisher allowlist check (Defender / OneDrive / Carbon Black / backup vendors).
 * Stubbed to false; real builds match the image's signer CN against the list. */
bool IsAllowlistedPublisher(const wchar_t* /*filterName*/)
{
    return false; /* TODO(publisher-allowlist): signer-CN match */
}

} // namespace

/*
 * Enumerate minifilter instances and count those the classifier flags as suspect
 * relative to Horkos's altitude. Returns the suspect count, or -1 on enumeration
 * failure (e.g. FltMgr not present / insufficient privilege). Read-only.
 */
int minifilter_census()
{
    HANDLE findHandle = INVALID_HANDLE_VALUE;
    std::vector<unsigned char> buffer(2048);
    DWORD bytesReturned = 0;
    int suspectCount = 0;

    /* FilterInstanceFindFirst enumerates instances (which carry the altitude).
     * Passing nullptr filterName enumerates instances across all filters via the
     * INSTANCE_FULL_INFORMATION class. */
    HRESULT hr = FilterInstanceFindFirst(
        nullptr,
        InstanceFullInformation,
        buffer.data(),
        static_cast<DWORD>(buffer.size()),
        &bytesReturned,
        &findHandle);

    if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS)) {
        return 0; /* no instances — nothing to flag */
    }
    if (FAILED(hr) || findHandle == INVALID_HANDLE_VALUE) {
        return -1; /* enumeration failed (FltMgr absent / not enough rights) */
    }

    do {
        auto* info =
            reinterpret_cast<PINSTANCE_FULL_INFORMATION>(buffer.data());

        /* Altitude is a counted WCHAR run at AltitudeBufferOffset; it is NOT
         * null-terminated, so copy into a bounded, null-terminated scratch buffer
         * before parsing (safe-string discipline mirrored from the kernel side). */
        wchar_t altBuf[64];
        const DWORD altBytes = info->AltitudeLength;
        const DWORD altChars = altBytes / sizeof(wchar_t);
        if (altChars > 0 && altChars < (sizeof(altBuf) / sizeof(altBuf[0]))) {
            const auto* altSrc = reinterpret_cast<const wchar_t*>(
                reinterpret_cast<const unsigned char*>(info) +
                info->AltitudeBufferOffset);
            std::memcpy(altBuf, altSrc, altChars * sizeof(wchar_t));
            altBuf[altChars] = L'\0';
        } else {
            altBuf[0] = L'\0';
        }

        mf::FilterRow row{};
        row.altitude_valid = ParseAltitude(altBuf, row.altitude);
        row.altitude_allocated =
            row.altitude_valid && IsAllocatedAltitude(row.altitude);

        /* Filter name lives at FilterNameBufferOffset; for the auth/publisher
         * stubs we pass nullptr (they ignore it until wired). */
        row.auth = VerifyFilterImage(nullptr);
        row.publisher_allowlisted = IsAllowlistedPublisher(nullptr);

        if (mf::ClassifyNeighbor(row, kHorkosAltitude) == mf::Verdict::Suspect) {
            ++suspectCount;
        }

        bytesReturned = 0;
        hr = FilterInstanceFindNext(
            findHandle,
            InstanceFullInformation,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            &bytesReturned);

        if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER)) {
            /* The current instance's full info exceeds the buffer. Grow to the
             * reported size (cursor has not advanced on ERROR_INSUFFICIENT_BUFFER)
             * and retry so one long filter name cannot truncate the census. Cap at
             * a sanity limit to avoid unbounded allocation on a bogus return value. */
            const DWORD grow_to = (bytesReturned > 0 && bytesReturned <= 65536u)
                                      ? bytesReturned
                                      : 65536u;
            buffer.resize(grow_to);
            bytesReturned = 0;
            hr = FilterInstanceFindNext(
                findHandle,
                InstanceFullInformation,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                &bytesReturned);
        }
    } while (SUCCEEDED(hr));

    FilterInstanceFindClose(findHandle);
    return suspectCount;
}

}} // namespace hk::sdk
