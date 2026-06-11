/*
 * dma_detect/backends/win/ConfigSpaceForensics.cpp
 * Role: Windows config-space forensics backend and the Windows
 *       hk_dma_forensics_scan entry point. Enumerates PCIe devices via SetupAPI,
 *       resolves VID/DID/subsystem and the structural gates (bus master / driver
 *       bound) from PnP, and is the intended home of the legacy + extended config
 *       reads (sig 127/128) via the PCI BusInterfaceStandard. The sibling Windows
 *       arms (MSI-X 129, option-ROM 130, BAR 131, ACS 133) are invoked here.
 * Target platforms: Windows only (SetupAPI + PCI bus interface). Selected by
 *       CMake if(WIN32).
 * Implements: dma_detect/include/horkos/dma_forensics.h (hk_dma_forensics_scan).
 *
 * *** HK-VERIFIED(win-ext-config): HalGetBusDataByOffset is a KERNEL-ONLY HAL
 * export (documented in the WDK: https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/nf-wdm-halgetbusdatabyoffset).
 * It is NOT callable from userspace. The BusInterfaceStandard (GUID_BUS_INTERFACE_STANDARD)
 * is a kernel-mode bus-driver interface obtained via IRP_MN_QUERY_INTERFACE; it is
 * also not accessible from a userspace process. Therefore, reading PCIe EXTENDED
 * config (offset >= 256) from a userspace AC component requires routing through a
 * kernel driver (the Horkos KMDF driver via a DeviceIoControl IOCTL).
 * (docs: kernel API restriction confirmed — still needs KMDF IOCTL design + on-box
 * test to verify the IOCTL path for ext-config reads)
 * Per guardrail #13 the extended-config-dependent arms (DSN walk 127, ext-cfg
 * aliasing/stability 128, ACS 133) are left UNIMPLEMENTED here — the structural
 * gates + legacy-config facts that DO have a documented userspace path are filled,
 * and the ext-config arms set scan_error to signal "needs kernel routing". ***
 */

#include <windows.h>
#include <initguid.h>
#include <setupapi.h>
#include <devguid.h>
#include <cfgmgr32.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")

#include "../../include/horkos/dma_forensics.h"

/* Sibling Windows arms (defined in the same backend folder). */
extern "C" void hk_dma_win_fill_bar(DEVINST devinst, hk_dma_device_forensics *d);
extern "C" void hk_dma_win_fill_msix(DEVINST devinst, hk_dma_device_forensics *d);
extern "C" void hk_dma_win_fill_rom(DEVINST devinst, hk_dma_device_forensics *d);

/* -------------------------------------------------------------------------
 * parse_pci_hwid — extract VEN/DEV/SUBSYS from a "PCI\VEN_8086&DEV_1234&..."
 * hardware id string. Returns true on a parse hit.
 * ------------------------------------------------------------------------- */
static bool parse_pci_hwid(const char *hwid, hk_dma_device_forensics *d) {
    const char *ven = std::strstr(hwid, "VEN_");
    const char *dev = std::strstr(hwid, "DEV_");
    const char *sub = std::strstr(hwid, "SUBSYS_");
    bool got = false;
    if (ven) { d->vendor_id = static_cast<uint16_t>(std::strtoul(ven + 4, nullptr, 16)); got = true; }
    if (dev) { d->device_id = static_cast<uint16_t>(std::strtoul(dev + 4, nullptr, 16)); }
    if (sub) {
        /* SUBSYS is "SSSSVVVV" — low 16 bits are the subsystem vendor. */
        unsigned long s = std::strtoul(sub + 7, nullptr, 16);
        d->subsys_vendor_id = static_cast<uint16_t>(s & 0xFFFFu);
    }
    return got;
}

/* -------------------------------------------------------------------------
 * read_bdf_from_devinst — resolve domain/bus/dev/fn via the PnP bus number and
 * address properties. Bus number is CM_DRP_BUSNUMBER; the address packs
 * (device << 16) | function in DEVPKEY_Device_Address.
 * ------------------------------------------------------------------------- */
static void read_bdf_from_devinst(DEVINST devinst, hk_pci_bdf *bdf) {
    DWORD bus = 0, addr = 0, sz = sizeof(DWORD);
    /* CM_Get_DevNode_Registry_Property with CM_DRP_BUSNUMBER (1-based index 23).*/
    if (CM_Get_DevNode_Registry_PropertyA(devinst, CM_DRP_BUSNUMBER, nullptr,
                                          &bus, &sz, 0) == CR_SUCCESS) {
        bdf->bus = static_cast<uint8_t>(bus & 0xFFu);
    }
    sz = sizeof(DWORD);
    if (CM_Get_DevNode_Registry_PropertyA(devinst, CM_DRP_ADDRESS, nullptr,
                                          &addr, &sz, 0) == CR_SUCCESS) {
        uint8_t dev = static_cast<uint8_t>((addr >> 16) & 0x1Fu);
        uint8_t fn  = static_cast<uint8_t>(addr & 0x07u);
        bdf->devfn  = static_cast<uint8_t>((dev << 3) | fn);
    }
    /* Domain is not surfaced by these legacy props; default 0 (single-segment).
     * Multi-segment systems need the ACPI _SEG, which is not available here
     * without the driver — left 0 (the common case). */
    bdf->domain = 0u;
}

static bool driver_bound(DEVINST devinst) {
    ULONG status = 0, prob = 0;
    if (CM_Get_DevNode_Status(&status, &prob, devinst, 0) != CR_SUCCESS) return true;
    return (status & DN_DRIVER_LOADED) != 0;
}

/* -------------------------------------------------------------------------
 * fill_extconfig_arms — sig 127/128/133 ext-config-dependent facts.
 *
 * HK-VERIFIED(win-ext-config): see file header. Kernel-only HAL API confirmed;
 * userspace extended-config requires KMDF IOCTL routing. The scan_error sentinel
 * tells the server that dsn_*/extcfg_*/acs_* are "unknown", never "clean".
 * ------------------------------------------------------------------------- */
static const uint32_t HK_DMA_WIN_EXTCFG_UNAVAILABLE = 0xE0000001u;

static void fill_extconfig_arms(hk_dma_device_forensics *d) {
    /* dsn_*, extcfg_*, acs_* deliberately left zero (unknown). */
    (void)d;
    /* HK-VERIFIED(win-ext-config): see file header. KMDF IOCTL route confirmed
     * required. Implement once the KMDF ext-config IOCTL lands. */
}

/* -------------------------------------------------------------------------
 * hk_dma_forensics_scan — Windows implementation.
 * ------------------------------------------------------------------------- */
extern "C" int hk_dma_forensics_scan(hk_dma_device_forensics *out,
                                     uint32_t *inout_count) {
    if (out == nullptr || inout_count == nullptr) return -1;
    const uint32_t cap = *inout_count;
    *inout_count = 0u;

    HDEVINFO di = SetupDiGetClassDevsA(nullptr, "PCI", nullptr,
                                       DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (di == INVALID_HANDLE_VALUE) return -1;

    SP_DEVINFO_DATA dd;
    dd.cbSize = sizeof(dd);
    uint32_t written = 0;

    for (DWORD idx = 0; SetupDiEnumDeviceInfo(di, idx, &dd) && written < cap; ++idx) {
        hk_dma_device_forensics *d = &out[written];
        std::memset(d, 0, sizeof(*d));

        char hwid[512] = {0};
        DWORD rt = 0, need = 0;
        if (SetupDiGetDeviceRegistryPropertyA(di, &dd, SPDRP_HARDWAREID, &rt,
                reinterpret_cast<PBYTE>(hwid), sizeof(hwid) - 1, &need)) {
            parse_pci_hwid(hwid, d);
        }

        read_bdf_from_devinst(dd.DevInst, &d->bdf);
        d->driver_bound = driver_bound(dd.DevInst) ? 1u : 0u;

        /* HK-VERIFIED(win-bme): Bus Master Enable lives in PCI_COMMAND (offset 0x04,
         * bit 2). Per PCIe Base Spec §7.5.1.1, this is in the LEGACY config space
         * (first 256 bytes). However, reading legacy PCI config from Windows userspace
         * has the same kernel-API restriction as extended config: HalGetBusDataByOffset
         * is kernel-only (see file header win-ext-config note). There is no documented
         * userspace Win32 API to read raw PCI config registers; the SetupAPI SPDRP_*
         * properties do not expose PCI_COMMAND. So bus_master_enabled stays 0 (unknown)
         * until a KMDF IOCTL for legacy config reads is confirmed on-box. The structural
         * gate degrades to driver-bound-only on Windows — documented, not silently wrong. */
        d->bus_master_enabled = 0u;

        /* BAR geometry has a documented userspace path (CM translated resources),
         * so it is filled; MSI-X/ROM that need config reads are best-effort. */
        hk_dma_win_fill_bar(dd.DevInst, d);
        hk_dma_win_fill_msix(dd.DevInst, d);
        hk_dma_win_fill_rom(dd.DevInst, d);

        fill_extconfig_arms(d);
        d->scan_error = HK_DMA_WIN_EXTCFG_UNAVAILABLE;

        ++written;
    }

    SetupDiDestroyDeviceInfoList(di);
    *inout_count = written;
    return 0;
}
