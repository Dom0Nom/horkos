/*
 * sdk/src/backends/win/DriverProbeWin.cpp
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

} } // namespace hk::sdk
