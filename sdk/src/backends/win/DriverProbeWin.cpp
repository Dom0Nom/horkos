/*
 * Role: Windows implementation of the SDK driver probe. Opens the Horkos
 *       control device; success means the kernel driver is loaded (active
 *       mode). This is the only place the SDK touches the Win32 API
 *       (guardrail #1: platform API confined to a backends/ folder).
 * Target platforms: Windows.
 * Interface: implements hk::sdk::probe_driver from sdk/src/sdk_backend.h.
 */

#include <windows.h>

#include "horkos/ioctl.h"   /* HK_DEVICE_PATH_USER */
#include "sdk_backend.h"

namespace hk { namespace sdk {

bool probe_driver()
{
    HANDLE h = CreateFileA(HK_DEVICE_PATH_USER,
                           GENERIC_READ | GENERIC_WRITE,
                           0,
                           nullptr,
                           OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL,
                           nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return false;
    }
    CloseHandle(h);
    return true;
}

/* Signal 36 (user-mode half). Read ServiceGroupOrder\List and the Horkos service
 * Start/Group from the registry, read-only, to correlate with the kernel
 * BootLoadAudit verdict. Boot-start services are Start == SERVICE_BOOT_START (0).
 * Demotion (a higher Start value) or a missing service entry is "suppression
 * suspect". The catalog FP gate (dual-boot / safe-mode / WinPE benign deviations)
 * is applied SERVER-side; this returns a raw verdict, never a ban. */
int probe_service_group_order()
{
    static const wchar_t kServiceKey[] =
        L"SYSTEM\\CurrentControlSet\\Services\\Horkos";

    HKEY  hKey = nullptr;
    LSTATUS ls = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kServiceKey, 0,
                               KEY_READ | KEY_WOW64_64KEY, &hKey);
    if (ls != ERROR_SUCCESS || hKey == nullptr) {
        if (ls == ERROR_FILE_NOT_FOUND) {
            /* Service entry absent entirely — suppression suspect. */
            return 1;
        }
        /* Could not read (access denied, transient) — indeterminate, not a verdict. */
        return -1;
    }

    DWORD start = 0xFFFFFFFFu;
    DWORD type = 0;
    DWORD cb = sizeof(start);
    ls = RegQueryValueExW(hKey, L"Start", nullptr, &type,
                          reinterpret_cast<LPBYTE>(&start), &cb);
    RegCloseKey(hKey);

    if (ls != ERROR_SUCCESS || type != REG_DWORD) {
        /* No Start value where one is required for a driver — suppression suspect. */
        return 1;
    }

    /* SERVICE_BOOT_START == 0, SERVICE_SYSTEM_START == 1. Our boot-start driver
     * should be 0 (or 1 at worst on a non-Deck/self-host config). A higher value
     * (auto/demand/disabled) on a boot-start AC is the suppression case. */
    if (start <= 1u) {
        return 0;  /* boot/early start — expected. */
    }
    return 1;      /* demoted Start — suppression suspect (server scores it). */
}

} } // namespace hk::sdk
