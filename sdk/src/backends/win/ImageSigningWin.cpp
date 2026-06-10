/*
 * sdk/src/backends/win/ImageSigningWin.cpp
 * Role: Signal-18 userspace half (win-kernel-memory-injection). The kernel
 *       (ModuleStomp.c) ships a backing file path + SHA-256 with
 *       signer_verdict = HK_SIGN_UNKNOWN on the mem ring; this backend computes
 *       the Authenticode signer verdict for that path via WinVerifyTrust and
 *       overwrites signer_verdict before the record is forwarded to the server.
 *       Provenance enrichment only — never a standalone ban (server decides).
 *       Read-only: it only verifies a signature; it never loads/maps the image
 *       as code.
 * Target platforms: Windows userspace. Guardrail #1: the wintrust/crypt32 calls
 *       are confined to this backends/win/ TU; guardrail #10: it fills the
 *       event_schema.h signer_verdict field, it does not change any interface.
 * Interface: implements hk::sdk::verify_image_signing (declared in sdk_backend.h);
 *       NOT COMPILED on non-Windows hosts (gated under sdk/CMakeLists.txt if(WIN32)).
 */

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>

#include <string>

#include "horkos/event_schema.h"

namespace hk {
namespace sdk {

/* Verify the Authenticode signature of the file at `wpath` and map the result to
 * the wire HK_SIGN_* enum. Pure WinVerifyTrust usage; no caching here (the server
 * dedups). Returns HK_SIGN_UNKNOWN on any setup failure so an indeterminate
 * verdict is never reported as trusted. */
static uint32_t VerifyAuthenticode(const wchar_t* wpath)
{
    WINTRUST_FILE_INFO fileInfo;
    WINTRUST_DATA winTrustData;
    GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status;
    uint32_t verdict;

    if (wpath == nullptr || wpath[0] == L'\0') {
        return HK_SIGN_UNKNOWN;
    }

    ZeroMemory(&fileInfo, sizeof(fileInfo));
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = wpath;

    ZeroMemory(&winTrustData, sizeof(winTrustData));
    winTrustData.cbStruct = sizeof(winTrustData);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    winTrustData.dwProvFlags = WTD_SAFER_FLAG;
    winTrustData.pFile = &fileInfo;

    status = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &actionGuid, &winTrustData);

    switch (status) {
    case ERROR_SUCCESS:
        verdict = HK_SIGN_TRUSTED;
        break;
    case TRUST_E_NOSIGNATURE:
        verdict = HK_SIGN_UNSIGNED;
        break;
    case TRUST_E_EXPLICIT_DISTRUST:
    case CERT_E_UNTRUSTEDROOT:
    case CERT_E_CHAINING:
        verdict = HK_SIGN_UNTRUSTED;
        break;
    case TRUST_E_SUBJECT_NOT_TRUSTED:
        verdict = HK_SIGN_SELF;
        break;
    default:
        verdict = HK_SIGN_UNKNOWN;
        break;
    }

    /* Always release the verifier state regardless of the verdict. */
    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    (void)WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &actionGuid, &winTrustData);

    return verdict;
}

/* Take a kernel-shipped unsigned-image record (UTF-8 path), compute the signer
 * verdict, and write it back into the record's signer_verdict field. The kernel
 * ships HK_SIGN_UNKNOWN; we overwrite it. */
void verify_image_signing(hk_event_mem_unsigned_image* rec)
{
    if (rec == nullptr) {
        return;
    }
    /* Bound the path to its declared length and the fixed buffer. */
    uint16_t len = rec->path_len;
    if (len > sizeof(rec->file_path)) {
        len = static_cast<uint16_t>(sizeof(rec->file_path));
    }
    std::string utf8(reinterpret_cast<const char*>(rec->file_path), len);

    int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
    if (wlen <= 0) {
        return; /* leave HK_SIGN_UNKNOWN. */
    }
    std::wstring wpath(static_cast<size_t>(wlen), L'\0');
    if (MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &wpath[0], wlen) <= 0) {
        return;
    }
    rec->signer_verdict = VerifyAuthenticode(wpath.c_str());
}

} // namespace sdk
} // namespace hk
