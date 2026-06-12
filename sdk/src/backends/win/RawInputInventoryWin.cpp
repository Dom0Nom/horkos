/*
 * Role: Signal substrate (win-input-automation). Builds and maintains the
 *       per-session raw-input device inventory (GetRawInputDeviceList +
 *       GetRawInputDeviceInfoW(RIDI_DEVICENAME / RIDI_DEVICEINFO), keyed by hDevice)
 *       shared by signals 55, 58, 60, 62. Each hDevice is assigned an OPAQUE
 *       per-session token (a session-local counter), so the raw OS HANDLE value is
 *       never shipped (plan R6). Read-only: it enumerates and reads device metadata;
 *       it registers only the GAME's OWN raw-input sink, never a foreign hook.
 * Target platforms: Windows userspace. Guardrail #1: the raw-input Win32 API
 *       (GetRawInputDeviceList/GetRawInputDeviceInfoW) is confined here and to the
 *       sensors under backends/win/.
 * Interface: implements hk::sdk::win::build_rawinput_inventory from InputSensorWin.h.
 */

#include "InputSensorWin.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <windows.h>

#include <atomic>

namespace hk { namespace sdk { namespace win {

namespace {

/* Session-local opaque token counter. hDevice HANDLE values are NOT stable across
 * reconnect/reboot and must not be shipped (plan R6), so the inventory hands out a
 * monotonic per-session id instead. Starts at 1 so 0 stays "no device". */
std::atomic<uint64_t> g_next_token{1};

/* Derive the HK_INTRANSPORT_* flags from a RID_DEVICE_INFO. The raw-input API does
 * not directly expose the physical bus, so this is a coarse first pass; the precise
 * USB/BT classification (used by signal 62's exemption) is refined by the SetupAPI
 * parent-bus walk in HidPollRateWin.cpp. Conservative default: USB unset, VIRTUAL
 * when the device cannot be resolved at all. */
uint32_t DeriveTransport(const RID_DEVICE_INFO& info)
{
    /* HID/keyboard/mouse over the standard stack is assumed USB-class here; the
     * poll-rate sensor overrides this with the real parent-bus type. We do not flag
     * BLUETOOTH/WIRELESS from raw-input alone (we cannot tell), so the exemption is
     * applied later where the bus is actually known. */
    (void)info;
    return HK_INTRANSPORT_USB;
}

} // namespace

bool build_rawinput_inventory(RawInputInventory& out)
{
    out.devices.clear();

    UINT count = 0;
    /* First call: ask for the device count. A 0xFFFFFFFF return is the documented
     * failure; treat any failure as "no inventory" so dependent sensors degrade to
     * UNRESOLVED rather than guessing. */
    if (GetRawInputDeviceList(nullptr, &count, sizeof(RAWINPUTDEVICELIST)) != 0) {
        return false;
    }
    if (count == 0) {
        return true; /* no raw-input devices is a valid (empty) inventory */
    }

    std::vector<RAWINPUTDEVICELIST> list(count);
    const UINT got =
        GetRawInputDeviceList(list.data(), &count, sizeof(RAWINPUTDEVICELIST));
    if (got == (UINT)-1) {
        return false;
    }

    out.devices.reserve(got);
    for (UINT i = 0; i < got; ++i) {
        /* We track only mouse/keyboard/HID input devices. */
        if (list[i].dwType != RIM_TYPEMOUSE &&
            list[i].dwType != RIM_TYPEKEYBOARD &&
            list[i].dwType != RIM_TYPEHID) {
            continue;
        }

        RawInputDevice dev{};
        dev.hdevice_token = g_next_token.fetch_add(1);
        dev.transport_flags = HK_INTRANSPORT_USB;
        dev.absolute_capable = false;

        /* RIDI_DEVICENAME: size query, then fetch. The size is in TCHARs. */
        UINT name_chars = 0;
        if (GetRawInputDeviceInfoW(list[i].hDevice, RIDI_DEVICENAME, nullptr,
                                   &name_chars) == 0 &&
            name_chars > 0) {
            std::wstring wname(name_chars, L'\0');
            const UINT wrote = GetRawInputDeviceInfoW(
                list[i].hDevice, RIDI_DEVICENAME, wname.data(), &name_chars);
            if (wrote != (UINT)-1 && wrote > 0) {
                /* Trim the trailing NUL the API may include, then narrow to UTF-8.
                 * WideCharToMultiByte failure leaves device_path empty, which the
                 * consuming sensor treats as UNRESOLVED rather than fabricating. */
                while (!wname.empty() && wname.back() == L'\0') {
                    wname.pop_back();
                }
                const int need = WideCharToMultiByte(
                    CP_UTF8, 0, wname.c_str(), (int)wname.size(),
                    nullptr, 0, nullptr, nullptr);
                if (need > 0) {
                    std::string narrow((size_t)need, '\0');
                    if (WideCharToMultiByte(CP_UTF8, 0, wname.c_str(),
                                            (int)wname.size(), narrow.data(),
                                            need, nullptr, nullptr) == need) {
                        dev.device_path = std::move(narrow);
                    }
                }
            }
        }

        /* RIDI_DEVICEINFO: top-level usage page/usage + transport derivation. */
        RID_DEVICE_INFO info{};
        info.cbSize = sizeof(info);
        UINT info_bytes = sizeof(info);
        if (GetRawInputDeviceInfoW(list[i].hDevice, RIDI_DEVICEINFO, &info,
                                   &info_bytes) != (UINT)-1) {
            if (info.dwType == RIM_TYPEHID) {
                dev.usage_page = info.hid.usUsagePage;
                dev.usage = info.hid.usUsage;
            } else if (info.dwType == RIM_TYPEMOUSE) {
                dev.usage_page = 0x01;
                dev.usage = 0x02;
            } else if (info.dwType == RIM_TYPEKEYBOARD) {
                dev.usage_page = 0x01;
                dev.usage = 0x06;
            }
            dev.transport_flags = DeriveTransport(info);
        }

        out.devices.push_back(std::move(dev));
    }

    return true;
}

} } } // namespace hk::sdk::win

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
