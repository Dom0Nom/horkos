/*
 * Role: Userspace smoke test for the kernel IOCTL bridge. Opens the Horkos
 *       control device and exercises GET_STATUS, DRAIN_EVENTS, and PUSH_POLICY,
 *       asserting each returns successfully. Lives under tests/integration/ —
 *       never under kernel/ — to keep the kernel-vs-userspace TU split visible
 *       (guardrail #4). Requires the driver loaded; skips cleanly if absent.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/ioctl.h.
 */

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <vector>

#include "horkos/ioctl.h"

static HANDLE open_device(void)
{
    return CreateFileA(HK_DEVICE_PATH_USER,
                       GENERIC_READ | GENERIC_WRITE,
                       0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
}

static bool test_get_status(HANDLE h)
{
    hk_status st{};
    DWORD returned = 0;
    BOOL ok = DeviceIoControl(h, HK_IOCTL_GET_STATUS, nullptr, 0,
                              &st, sizeof(st), &returned, nullptr);
    if (!ok || returned != sizeof(st)) {
        std::printf("GET_STATUS failed (gle=%lu, returned=%lu)\n",
                    GetLastError(), returned);
        return false;
    }
    std::printf("status: version=0x%08x notify_armed=%u ob_armed=%u total=%llu\n",
                st.driver_version, st.notify_routines_armed, st.ob_callbacks_armed,
                (unsigned long long)st.events_total);
    return st.driver_version == HK_DRIVER_VERSION;
}

static bool test_push_policy(HANDLE h)
{
    hk_policy pol{};
    pol.enable_byovd_block = 0;
    pol.enable_ob_strip = 0;
    DWORD returned = 0;
    BOOL ok = DeviceIoControl(h, HK_IOCTL_PUSH_POLICY, &pol, sizeof(pol),
                              nullptr, 0, &returned, nullptr);
    if (!ok) {
        std::printf("PUSH_POLICY failed (gle=%lu)\n", GetLastError());
        return false;
    }
    return true;
}

static bool test_drain(HANDLE h)
{
    /* Room for the envelope plus 64 records. */
    std::vector<uint8_t> buf(sizeof(hk_drain_header) + 64 * sizeof(hk_event_record));
    DWORD returned = 0;
    BOOL ok = DeviceIoControl(h, HK_IOCTL_DRAIN_EVENTS, nullptr, 0,
                              buf.data(), (DWORD)buf.size(), &returned, nullptr);
    if (!ok || returned < sizeof(hk_drain_header)) {
        std::printf("DRAIN failed (gle=%lu, returned=%lu)\n",
                    GetLastError(), returned);
        return false;
    }
    auto* hdr = reinterpret_cast<hk_drain_header*>(buf.data());
    std::printf("drain: written=%u remaining=%u dropped=%u\n",
                hdr->records_written, hdr->records_remaining, hdr->records_dropped);
    return true;
}

int main(void)
{
    HANDLE h = open_device();
    if (h == INVALID_HANDLE_VALUE) {
        /* Driver not loaded: not a test failure on a host without it. */
        std::printf("SKIP: control device not present (driver not loaded).\n");
        return 0;
    }

    bool ok = true;
    ok &= test_get_status(h);
    ok &= test_push_policy(h);
    ok &= test_drain(h);

    CloseHandle(h);

    std::printf("ioctl_smoke: %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
