/*
 * Role: Windows PCIe hot-plug arrival monitor (sig 134). Subscribes to PnP
 *       device-interface arrival notifications via CM_Register_Notification on the
 *       PCI device-interface class and emits a timestamped arrival per device —
 *       subscribe, do NOT poll. A post-AC-start arrival of an unbound bus-master
 *       device with an ID anomaly is the catch; Thunderbolt/USB4 root-port domains
 *       are recognised benign by the server.
 * Target platforms: Windows only. Selected by CMake if(WIN32); linked into
 *       hk_dma_detect.
 * Implements: dma_detect/include/horkos/dma_forensics.h
 *       (hk_dma_forensics_subscribe / _unsubscribe).
 *
 * This is a PnP matching/notification path, NOT an ES auth event — guardrail #7
 * (ES auth-reply deadline) does not apply. The callback is invoked on the PnP
 * notification thread; it must be cheap and non-blocking.
 *
 * API ref: CM_Register_Notification
 *   https://learn.microsoft.com/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_register_notification
 * The notification filter uses CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE so we receive
 * CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL for new PCI device interfaces.
 */

#include <windows.h>
#include <cfgmgr32.h>
#include <cstdint>
#include <cstring>

#pragma comment(lib, "cfgmgr32.lib")

#include "../../include/horkos/dma_forensics.h"

namespace {

/* GUID_DEVINTERFACE_* for the PCI bus is not a single fixed public GUID for "any
 * PCIe device"; PnP device-interface arrival is filtered per interface class.
 * We register on the generic device-interface notification (filter with the
 * all-devices flag) and post-filter to PCI by the symbolic-link prefix, which the
 * callback inspects. */
struct HotplugHandle {
    HCMNOTIFICATION h = nullptr;
    hk_dma_arrival_cb cb = nullptr;
    void *ctx = nullptr;
};

uint64_t mono_ns() {
    LARGE_INTEGER freq, ctr;
    if (!QueryPerformanceFrequency(&freq) || freq.QuadPart == 0) return 0;
    QueryPerformanceCounter(&ctr);
    /* Scale to ns without overflow: (ctr / freq) seconds -> ns. */
    long double secs =
        static_cast<long double>(ctr.QuadPart) /
        static_cast<long double>(freq.QuadPart);
    return static_cast<uint64_t>(secs * 1000000000.0L);
}

/* -------------------------------------------------------------------------
 * parse_bdf_from_symlink
 *
 * A PCI device-interface symbolic link embeds the instance path; the BDF is not
 * directly present in the link string in a stable documented form. We mark the
 * arrival with a zero BDF when it cannot be parsed (the server still gets the
 * timestamped arrival fact; a full BDF resolve requires a CM_Get_Device_ID +
 * BUSNUMBER/ADDRESS lookup, done lazily server-side or in a follow-up scan).
 *
 * HK-UNCERTAIN(win-hotplug-bdf): extracting domain:bus:dev.fn directly from the
 * CM_NOTIFY_EVENT_DATA device-interface symbolic link is not a documented stable
 * format. We do NOT guess the link layout; the arrival is reported with the BDF
 * left zero, and the next forensic scan correlates the new device by VID/DID. The
 * arrival TIMESTAMP — the load-bearing fact for sig 134 — is exact regardless.
 * ------------------------------------------------------------------------- */
bool parse_bdf_from_symlink(const wchar_t *symlink, hk_pci_bdf *out) {
    std::memset(out, 0, sizeof(*out));
    if (symlink == nullptr) return false;
    /* Only treat PCI-class interfaces as in-scope; ignore others (USB, HID...). */
    /* PCI device-interface links contain "PCI#" in the instance segment. */
    for (const wchar_t *p = symlink; *p; ++p) {
        if (p[0] == L'P' && p[1] == L'C' && p[2] == L'I') return true;
    }
    return false;
}

DWORD CALLBACK notify_cb(HCMNOTIFICATION /*hNotify*/, PVOID Context,
                         CM_NOTIFY_ACTION Action,
                         PCM_NOTIFY_EVENT_DATA EventData, DWORD /*EventDataSize*/) {
    HotplugHandle *h = static_cast<HotplugHandle *>(Context);
    if (h == nullptr || h->cb == nullptr) return ERROR_SUCCESS;
    if (Action != CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL) return ERROR_SUCCESS;
    if (EventData == nullptr) return ERROR_SUCCESS;

    hk_pci_bdf bdf;
    const wchar_t *link =
        EventData->u.DeviceInterface.SymbolicLink;
    if (!parse_bdf_from_symlink(link, &bdf)) {
        return ERROR_SUCCESS; /* not a PCI interface — ignore. */
    }
    h->cb(&bdf, mono_ns(), h->ctx);
    return ERROR_SUCCESS;
}

} /* anonymous namespace */

/* -------------------------------------------------------------------------
 * hk_dma_forensics_subscribe — register a PnP device-interface arrival monitor.
 * ------------------------------------------------------------------------- */
extern "C" int hk_dma_forensics_subscribe(hk_dma_arrival_cb cb, void *ctx,
                                          void **out_handle) {
    if (cb == nullptr || out_handle == nullptr) return -1;

    HotplugHandle *h = new (std::nothrow) HotplugHandle();
    if (h == nullptr) return -1;
    h->cb = cb;
    h->ctx = ctx;

    CM_NOTIFY_FILTER filter;
    std::memset(&filter, 0, sizeof(filter));
    filter.cbSize = sizeof(filter);
    filter.FilterType = CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE;
    filter.Flags = CM_NOTIFY_FILTER_FLAG_ALL_INTERFACE_CLASSES;

    CONFIGRET cr =
        CM_Register_Notification(&filter, h, notify_cb, &h->h);
    if (cr != CR_SUCCESS) {
        delete h;
        return -1;
    }

    *out_handle = h;
    return 0;
}

/* -------------------------------------------------------------------------
 * hk_dma_forensics_unsubscribe — unregister and free.
 * ------------------------------------------------------------------------- */
extern "C" void hk_dma_forensics_unsubscribe(void *handle) {
    if (handle == nullptr) return;
    HotplugHandle *h = static_cast<HotplugHandle *>(handle);
    if (h->h != nullptr) {
        /* CM_Unregister_Notification waits for in-flight callbacks to drain. */
        CM_Unregister_Notification(h->h);
        h->h = nullptr;
    }
    delete h;
}
