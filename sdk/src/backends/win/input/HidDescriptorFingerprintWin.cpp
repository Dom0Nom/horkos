/*
 * Role: Signal 136 — HID report-descriptor structural-fingerprint sensor. Enumerates
 *       GUID_DEVINTERFACE_HID, opens each device path, pulls the preparsed data
 *       (HidD_GetPreparsedData + HidP_GetCaps / HidP_GetButtonCaps /
 *       HidP_GetValueCaps), canonicalizes the structure (usage pages + report IDs
 *       sorted, field count) via the pure canonicalize_hid_descriptor fold, and
 *       SHA-256s the canonical buffer (CNG / BCrypt) into hk_event_hid_descriptor. The
 *       fingerprint is NEVER a local verdict — the server does the corpus/reputation
 *       clustering (QMK/ZMK vs Arduino-HID/V-USB/LUFA template classes).
 * Target platforms: Windows userspace (IRQL PASSIVE_LEVEL; usermode HID API).
 * Interface: implements hk::sdk::win::sense_hid_descriptor from input/DeviceTrustWin.h;
 *       emits hk_event_hid_descriptor (device_trust_schema.h). Read-only: it opens HID
 *       collections for metadata only, never writes a report.
 */

#include "input/DeviceTrustWin.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <windows.h>
#include <setupapi.h>
#include <hidsdi.h>
#include <bcrypt.h>

#include <vector>

namespace hk { namespace sdk { namespace win {

namespace {

/* SHA-256 a buffer via CNG into out32[32]. Returns false on any CNG failure (the
 * caller then sets HK_HIDFP_PREPARSED_FAILED and ships an inconclusive record rather
 * than a zeroed hash that would collide across devices). Every BCRYPT return is
 * checked; the algorithm/hash handles are always released, including on error paths. */
bool Sha256(const uint8_t *data, size_t len, uint8_t out32[32])
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
        return false;
    }
    BCRYPT_HASH_HANDLE hash = nullptr;
    bool ok = false;
    if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) == 0) {
        if (BCryptHashData(hash, const_cast<PUCHAR>(data), (ULONG)len, 0) == 0 &&
            BCryptFinishHash(hash, out32, 32, 0) == 0) {
            ok = true;
        }
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

/* Emit one inconclusive fingerprint record (HidD/HidP failed or device exclusively
 * opened). Inconclusive is reported, never treated as an anomaly (catalog FP gate). */
void EmitInconclusive(uint16_t vid, uint16_t pid,
                      std::vector<hk_event_hid_descriptor> &out)
{
    hk_event_hid_descriptor rec{};
    rec.schema_version = HK_DEVICE_TRUST_SCHEMA_VERSION;
    rec.vendor_id = vid;
    rec.product_id = pid;
    rec.flags = HK_HIDFP_PREPARSED_FAILED;
    out.push_back(rec);
}

} // namespace

int sense_hid_descriptor(std::vector<hk_event_hid_descriptor> &out)
{
    GUID hid_guid;
    HidD_GetHidGuid(&hid_guid);

    HDEVINFO dev_info = SetupDiGetClassDevsW(
        &hid_guid, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (dev_info == INVALID_HANDLE_VALUE) {
        return -1;
    }

    int emitted = 0;
    SP_DEVICE_INTERFACE_DATA iface{};
    iface.cbSize = sizeof(iface);
    for (DWORD i = 0;
         SetupDiEnumDeviceInterfaces(dev_info, nullptr, &hid_guid, i, &iface);
         ++i) {
        DWORD detail_size = 0;
        SetupDiGetDeviceInterfaceDetailW(dev_info, &iface, nullptr, 0,
                                         &detail_size, nullptr);
        if (detail_size == 0) {
            continue;
        }
        std::vector<uint8_t> detail_buf(detail_size);
        auto *detail =
            reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W *>(detail_buf.data());
        detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
        if (!SetupDiGetDeviceInterfaceDetailW(dev_info, &iface, detail, detail_size,
                                              nullptr, nullptr)) {
            continue;
        }

        /* Open for metadata only (no GENERIC_READ/WRITE data access). An exclusively
         * opened device (e.g. a gaming mouse held by its vendor service) fails
         * CreateFile; that is INCONCLUSIVE, never an anomaly. */
        HANDLE dev = CreateFileW(detail->DevicePath, 0,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                 OPEN_EXISTING, 0, nullptr);
        if (dev == INVALID_HANDLE_VALUE) {
            continue; /* cannot open -> skip silently (not an anomaly) */
        }

        HIDD_ATTRIBUTES attrs{};
        attrs.Size = sizeof(attrs);
        HidD_GetAttributes(dev, &attrs);

        PHIDP_PREPARSED_DATA preparsed = nullptr;
        if (!HidD_GetPreparsedData(dev, &preparsed) || preparsed == nullptr) {
            EmitInconclusive(attrs.VendorID, attrs.ProductID, out);
            ++emitted;
            CloseHandle(dev);
            continue;
        }

        HIDP_CAPS caps{};
        if (HidP_GetCaps(preparsed, &caps) != HIDP_STATUS_SUCCESS) {
            HidD_FreePreparsedData(preparsed); /* always freed, incl. error path */
            EmitInconclusive(attrs.VendorID, attrs.ProductID, out);
            ++emitted;
            CloseHandle(dev);
            continue;
        }

        HidCanonicalInput cin{};
        cin.usage_pages.push_back(caps.UsagePage);
        uint16_t flags = 0;

        /* Button caps across the three report types. */
        const USHORT cap_counts[3] = {caps.NumberInputButtonCaps,
                                      caps.NumberOutputButtonCaps,
                                      caps.NumberFeatureButtonCaps};
        const HIDP_REPORT_TYPE rtypes[3] = {HidP_Input, HidP_Output, HidP_Feature};
        uint32_t field_count = 0;
        bool has_report_id = false;
        for (int t = 0; t < 3; ++t) {
            USHORT n = cap_counts[t];
            if (n == 0) {
                continue;
            }
            std::vector<HIDP_BUTTON_CAPS> bcaps(n);
            if (HidP_GetButtonCaps(rtypes[t], bcaps.data(), &n, preparsed) ==
                HIDP_STATUS_SUCCESS) {
                for (USHORT k = 0; k < n; ++k) {
                    cin.usage_pages.push_back(bcaps[k].UsagePage);
                    if (bcaps[k].ReportID != 0) {
                        cin.report_ids.push_back(bcaps[k].ReportID);
                        has_report_id = true;
                    }
                    ++field_count;
                    if (bcaps[k].UsagePage >= 0xFF00u) {
                        flags |= HK_HIDFP_VENDOR_USAGE;
                    }
                }
            }
        }

        /* Value caps across the three report types. */
        const USHORT val_counts[3] = {caps.NumberInputValueCaps,
                                      caps.NumberOutputValueCaps,
                                      caps.NumberFeatureValueCaps};
        for (int t = 0; t < 3; ++t) {
            USHORT n = val_counts[t];
            if (n == 0) {
                continue;
            }
            std::vector<HIDP_VALUE_CAPS> vcaps(n);
            if (HidP_GetValueCaps(rtypes[t], vcaps.data(), &n, preparsed) ==
                HIDP_STATUS_SUCCESS) {
                for (USHORT k = 0; k < n; ++k) {
                    cin.usage_pages.push_back(vcaps[k].UsagePage);
                    if (vcaps[k].ReportID != 0) {
                        cin.report_ids.push_back(vcaps[k].ReportID);
                        has_report_id = true;
                    }
                    ++field_count;
                    if (vcaps[k].UsagePage >= 0xFF00u) {
                        flags |= HK_HIDFP_VENDOR_USAGE;
                    }
                }
            }
        }

        cin.field_count = (uint16_t)(field_count > 0xFFFFu ? 0xFFFFu : field_count);

        HidD_FreePreparsedData(preparsed); /* freed before the hash; no further use */

        const std::vector<uint8_t> canon = canonicalize_hid_descriptor(cin);

        hk_event_hid_descriptor rec{};
        rec.schema_version = HK_DEVICE_TRUST_SCHEMA_VERSION;
        rec.vendor_id = attrs.VendorID;
        rec.product_id = attrs.ProductID;
        rec.field_count = cin.field_count;
        /* canonicalize_hid_descriptor de-duped; recover the distinct counts from the
         * canonical header (bytes 0..1 = usage_page_count, 4..5 = report_id_count). */
        if (canon.size() >= 6) {
            rec.usage_page_count =
                (uint16_t)(canon[0] | ((uint16_t)canon[1] << 8));
            rec.report_id_count =
                (uint16_t)(canon[4] | ((uint16_t)canon[5] << 8));
        }
        if (has_report_id) {
            flags |= HK_HIDFP_HAS_REPORT_IDS;
        }
        if (rec.usage_page_count > 1) {
            flags |= HK_HIDFP_MULTI_USAGE_PAGE;
        }
        if (!Sha256(canon.data(), canon.size(), rec.fingerprint)) {
            flags |= HK_HIDFP_PREPARSED_FAILED; /* hash failed -> inconclusive */
        }
        rec.flags = flags;

        out.push_back(rec);
        ++emitted;
        CloseHandle(dev);
    }

    SetupDiDestroyDeviceInfoList(dev_info);
    return emitted;
}

} } } // namespace hk::sdk::win

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
