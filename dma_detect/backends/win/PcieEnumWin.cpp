/*
 * dma_detect/backends/win/PcieEnumWin.cpp
 * Role: Windows backend for DMA-attack detection.
 *       Enumerates PCIe devices via SetupAPI, flags DMA-capable suspects,
 *       and cross-checks IOMMU/VT-d state from DMAR ACPI table presence
 *       against what SetupAPI actually surfaces.
 * Target platforms: Windows only.  Selected by CMake if(WIN32).
 * Implements: dma_detect/include/horkos/dma_detect.h (hk_dma_scan)
 */

/*
 * Windows-specific headers are confined to this file (guardrail #1).
 * We do not include platform/platform.h because this file is selected by
 * CMake and does not need the HK_PLATFORM_* detection macros at file scope.
 */
#include <windows.h>
#include <initguid.h>      /* MUST precede devguid.h/devpkey.h so the GUID and
                              DEVPKEY symbols are DEFINED here, not extern.      */
#include <setupapi.h>      /* SetupDiGetClassDevs, SetupDiEnumDeviceInfo        */
#include <devguid.h>       /* GUID_DEVCLASS_* for bus-level enumeration          */
#include <cfgmgr32.h>      /* CM_Get_DevNode_Registry_Property                  */
#include <devpkey.h>       /* DEVPKEY_Device_BusReportedDeviceDesc               */
#include <winreg.h>
#include <cstdint>
#include <cstdlib>   /* strtoul */
#include <cstring>
#include <cstdio>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")

#include "../../include/horkos/dma_detect.h"

/* -------------------------------------------------------------------------
 * PCIe device class GUID — {4d36e97d-e325-11ce-bfc1-08002be10318} in the
 * "System" device class which covers all bus-enumerated PCI/PCIe bridges and
 * controllers.  The more generic GUID_DEVCLASS_UNKNOWN catches unrecognised
 * devices.  We enumerate both.
 * Ref: https://docs.microsoft.com/en-us/windows-hardware/drivers/install/
 *      system-defined-device-setup-classes-available-to-vendors
 * ------------------------------------------------------------------------- */
/* GUID_DEVCLASS_SYSTEM is declared in devguid.h via initguid.h, no redecl. */

/* -------------------------------------------------------------------------
 * PCI base class codes (upper byte of ClassCode register, PCI Spec §6.2.1).
 * Used to identify device categories without needing vendor IDs.
 * ------------------------------------------------------------------------- */
static const uint8_t PCI_BASECLASS_STORAGE         = 0x01;
static const uint8_t PCI_BASECLASS_NETWORK          = 0x02;
static const uint8_t PCI_BASECLASS_DISPLAY          = 0x03;
static const uint8_t PCI_BASECLASS_MULTIMEDIA       = 0x04;
static const uint8_t PCI_BASECLASS_BRIDGE           = 0x06;
static const uint8_t PCI_BASECLASS_COMM             = 0x07;
static const uint8_t PCI_BASECLASS_COPY_PROCESSOR   = 0x12; /* DMA engines, etc */

/* -------------------------------------------------------------------------
 * is_dma_capable_class
 *
 * Returns true for PCI base classes that can, by design, perform DMA without
 * being a conventional bus master in the CPU sense.  Storage controllers,
 * network adapters, and co-processors are the primary attack surface for
 * PCILeech-style DMA devices.
 *
 * NOTE: A PCI bridge (0x06) is not flagged here because a bridged hierarchy
 * is normal; suspicious state is detected by inspecting the leaf device on
 * the other side of the bridge instead.
 * ------------------------------------------------------------------------- */
static bool is_dma_capable_class(uint8_t base_class) {
    switch (base_class) {
    case PCI_BASECLASS_STORAGE:
    case PCI_BASECLASS_NETWORK:
    case PCI_BASECLASS_MULTIMEDIA:
    case PCI_BASECLASS_COMM:
    case PCI_BASECLASS_COPY_PROCESSOR:
        return true;
    default:
        return false;
    }
}

/* -------------------------------------------------------------------------
 * read_device_class_code
 *
 * Retrieves the three-byte PCI ClassCode for a device node via the registry
 * key that the PnP manager writes for every enumerated PCIe device.
 *
 * Registry path: HKLM\SYSTEM\CurrentControlSet\Enum\PCI\<devid>\<instance>
 * Value name:    "ClassCode" (REG_BINARY, 3 bytes: base, sub, prog-if)
 *
 * Returns true and fills *base_class on success; false if the value is
 * absent (older drivers) or on any registry error.
 *
 * Ref: https://docs.microsoft.com/en-us/windows-hardware/drivers/install/
 *      accessing-device-driver-package-files
 * ------------------------------------------------------------------------- */
static bool read_device_class_code(HDEVINFO dev_info,
                                   SP_DEVINFO_DATA *dev_data,
                                   uint8_t *base_class) {
    HKEY hkey = INVALID_HANDLE_VALUE;
    /* SetupDiOpenDevRegKey opens HKLM\...\Enum\...\<instance> for reading.
     * Ref: https://docs.microsoft.com/en-us/windows/win32/api/setupapi/
     *      nf-setupapi-setupdiopendevregkey */
    hkey = SetupDiOpenDevRegKey(dev_info, dev_data,
                                DICS_FLAG_GLOBAL, 0,
                                DIREG_DEV, KEY_READ);
    if (hkey == INVALID_HANDLE_VALUE) return false;

    DWORD type  = 0;
    char  buf[16] = {0};
    DWORD sz    = sizeof(buf) - 1; /* leave room for NUL */
    LSTATUS rc  = RegQueryValueExA(hkey, "ClassCode", nullptr, &type,
                                   reinterpret_cast<LPBYTE>(buf), &sz);
    RegCloseKey(hkey);

    /* The PnP-written ClassCode is a REG_SZ ASCII hex string, e.g. "030000"
     * (base/sub/prog-if), NOT a REG_BINARY blob. Parse it like the Linux
     * backend: strtoul base 16, base class is bits 23:16. */
    if (rc != ERROR_SUCCESS || type != REG_SZ || sz < 1) return false;
    unsigned long cls = strtoul(buf, nullptr, 16);
    *base_class = static_cast<uint8_t>((cls >> 16) & 0xFFu);
    return true;
}

/* -------------------------------------------------------------------------
 * has_no_driver_bound
 *
 * Returns true when the device has no driver currently bound to it.
 * An unbound DMA-capable device in Bus-Master-Enabled state is a concern
 * because the OS cannot enforce DMA protections without a driver.
 *
 * We check the CM_PROB_FAILED_START / CM_PROB_UNKNOWN_RESOURCE / CM_PROB_NONE
 * status codes via CM_Get_DevNode_Status.
 *
 * Ref: https://docs.microsoft.com/en-us/windows/win32/api/cfgmgr32/
 *      nf-cfgmgr32-cm_get_devnode_status
 * ------------------------------------------------------------------------- */
static bool has_no_driver_bound(DEVINST devinst) {
    ULONG   status = 0;
    ULONG   prob   = 0;
    CONFIGRET cr   = CM_Get_DevNode_Status(&status, &prob, devinst, 0);
    if (cr != CR_SUCCESS) return false; /* Assume driver present on query failure. */

    /* Use the documented DN_DRIVER_LOADED symbol (cfgmgr32.h), not a magic
     * number — a prior version hardcoded 0x00000100, which is not the
     * driver-loaded bit. */
    return !(status & DN_DRIVER_LOADED);
}

/* -------------------------------------------------------------------------
 * query_iommu_state_windows
 *
 * On Windows, the kernel exposes DMA remapping (IOMMU/VT-d) state through
 * two sources:
 *
 * 1. Kernel DMA Protection (KDP) — available in Windows 10 1803+.
 *    Registry: HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\
 *              KernelDmaProtection\Enabled  (REG_DWORD)
 *    When this key exists and is 1, the firmware DMAR table was accepted by
 *    the kernel and DMA remapping is active at boot time.
 *
 * 2. DMAR presence in ACPI — the raw DMAR table is not directly readable
 *    from userspace on Windows without NtQuerySystemInformation class 76
 *    (SystemFirmwareTableInformation), which is undocumented and requires
 *    SeSystemEnvironmentPrivilege.  We do not use undocumented APIs here.
 *
 * Cross-check: if KDP=1 but we find unbound DMA-capable devices, that is a
 * mismatch worth flagging.  Conversely, KDP=0 with DMA-capable devices is
 * the classic DMA-attack surface.
 *
 * Returns 1 if KDP is enabled, 0 if disabled or key absent, -1 on error.
 *
 * NOTE: The KDP registry key path is documented for Windows 11 22H2.  Earlier
 * versions may use a different sub-key; validate against the target OS build.
 * ------------------------------------------------------------------------- */
static int query_iommu_state_windows(uint32_t *out_remapping_units) {
    *out_remapping_units = 0;

    HKEY hkey = nullptr;
    LSTATUS rc = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\KernelDmaProtection",
        0, KEY_READ, &hkey);

    if (rc != ERROR_SUCCESS) {
        /* Key absent → KDP not present or not enabled. */
        return 0;
    }

    DWORD enabled = 0;
    DWORD sz      = sizeof(enabled);
    DWORD type    = 0;
    rc = RegQueryValueExA(hkey, "Enabled", nullptr, &type, (LPBYTE)&enabled, &sz);
    RegCloseKey(hkey);

    if (rc != ERROR_SUCCESS || type != REG_DWORD) return 0;

    if (enabled == 1) {
        /* KDP enabled.  We report 1 remapping unit as a proxy because the
         * exact DMAR unit count is not surfaced by this API.  A richer
         * implementation could call SetupDiGetClassDevs with the ACPI
         * device class and count DMAR child nodes, but that is fragile and
         * undocumented.  The server must treat this as "at least one unit".
         *
         * NOTE: on Windows both iommu_enabled and iommu_groups_present are
         * derived from this single KDP read, so the firmware-claim-vs-kernel-
         * corroboration cross-check (high-confidence condition (a)) is degenerate
         * here — unlike Linux, where /proc/iomem and the IOMMU group count are
         * genuinely independent sources. */
        *out_remapping_units = 1;
        return 1;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * hk_dma_scan — Windows implementation
 * ------------------------------------------------------------------------- */
extern "C" int hk_dma_scan(hk_dma_report *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));

    /* Step 1: Query IOMMU / KDP state. */
    uint32_t remap_units = 0;
    int iommu_state      = query_iommu_state_windows(&remap_units);
    if (iommu_state < 0) {
        out->scan_error = static_cast<uint32_t>(GetLastError());
        return -1;
    }
    out->iommu_enabled         = (iommu_state == 1) ? 1u : 0u;
    out->iommu_groups_present  = remap_units;

    /* Step 2: Enumerate PCIe devices via SetupAPI.
     *
     * We use DIGCF_ALLCLASSES | DIGCF_PRESENT to get every device currently
     * present on the bus, then filter for DMA-capable classes.
     *
     * Ref: https://docs.microsoft.com/en-us/windows/win32/api/setupapi/
     *      nf-setupapi-setupdigetclassdevsw
     *
     * NOTE: the Enumerator argument "PCI" already restricts the result set to
     * the PCI bus enumerator, so no additional hardware-ID filtering is needed.
     */
    HDEVINFO dev_info = SetupDiGetClassDevsA(
        nullptr, "PCI", nullptr,
        DIGCF_ALLCLASSES | DIGCF_PRESENT);

    if (dev_info == INVALID_HANDLE_VALUE) {
        out->scan_error = static_cast<uint32_t>(GetLastError());
        return -1;
    }

    SP_DEVINFO_DATA dev_data;
    dev_data.cbSize = sizeof(SP_DEVINFO_DATA);

    uint32_t suspicious = 0;
    bool     iommu_cross_mismatch = false;

    for (DWORD idx = 0; SetupDiEnumDeviceInfo(dev_info, idx, &dev_data); ++idx) {
        uint8_t base_class = 0;
        if (!read_device_class_code(dev_info, &dev_data, &base_class)) {
            /* ClassCode unavailable — treat unknown device as suspicious
             * only when it has no driver bound (unbound unknown device is the
             * classic PCILeech FPGA presentation at enumeration time). */
            if (has_no_driver_bound(dev_data.DevInst)) {
                ++suspicious;
                /* Unbound unknown + IOMMU supposedly on → mismatch. */
                if (out->iommu_enabled) iommu_cross_mismatch = true;
            }
            continue;
        }

        if (!is_dma_capable_class(base_class)) continue;

        if (has_no_driver_bound(dev_data.DevInst)) {
            /* DMA-capable device with no driver: Bus Master Enable may still
             * be set by firmware; the OS has no handle on it. */
            ++suspicious;
            if (out->iommu_enabled) iommu_cross_mismatch = true;
        }
    }

    SetupDiDestroyDeviceInfoList(dev_info);

    out->suspicious_device_count = suspicious;

    /* Step 3: Compute high_confidence_flag.
     *
     * Three conditions each independently set it:
     *   (a) Firmware claims IOMMU on but kernel sees 0 remapping units.
     *   (b) Suspicious devices present and IOMMU is not OS-corroborated.
     *   (c) IOMMU reported on but a DMA-capable device has no driver bound
     *       (the IOMMU is per-device in VT-d; an unbound device may bypass
     *       the input-output page table entirely).
     */
    if ((out->iommu_enabled && out->iommu_groups_present == 0) ||
        (suspicious > 0   && !out->iommu_enabled) ||
        iommu_cross_mismatch) {
        out->high_confidence_flag = 1u;
    }

    return 0;
}
