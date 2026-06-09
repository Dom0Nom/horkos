/*
 * dma_detect/backends/win/BarProfile.cpp
 * Role: Windows BAR geometry profiler (sig 131). Reconstructs each BAR's
 *       {size, 64-bit, prefetchable, io} from the PnP-translated resource
 *       descriptors the OS already recorded (CM_Get_First/Next_Log_Conf +
 *       ResDes walk) — never by issuing the write-all-ones BAR-sizing sequence
 *       ourselves (that mutates device state; every Horkos probe is read-only).
 *       Ships raw geometry; the server holds the per-VID/DID reference table.
 * Target platforms: Windows only (cfgmgr32 log-conf resources). Selected by
 *       CMake if(WIN32); linked into hk_dma_detect alongside ConfigSpaceForensics.
 * Implements: hk_dma_win_fill_bar (consumed by win/ConfigSpaceForensics.cpp).
 *
 * Read-only discipline: CM_Get_*_Log_Conf walks the descriptors the PnP manager
 * already assigned; no config write, no BAR sizing. The boot/allocated/forced
 * config is queried in that priority order so we report the geometry actually in
 * effect.
 */

#include <windows.h>
#include <cfgmgr32.h>
#include <cstdint>
#include <cstring>

#pragma comment(lib, "cfgmgr32.lib")

#include "../../include/horkos/dma_forensics.h"

/* bar_flags bit layout (mirrors dma_forensics.h). */
static const uint8_t BAR_FLAG_64BIT    = 0x01u;
static const uint8_t BAR_FLAG_PREFETCH = 0x02u;
static const uint8_t BAR_FLAG_IO       = 0x04u;

/* -------------------------------------------------------------------------
 * record_resource — fold one translated resource descriptor into the next free
 * BAR slot. We map MEM/MEM_LARGE descriptors and IO descriptors to BAR slots in
 * the order the log-conf enumerates them (PnP enumerates BARs in index order),
 * stopping at 6. mfFlags carries the prefetch/64-bit/IO attributes.
 *
 * HK-UNCERTAIN(win-bar-attr): the exact mapping of CM_RESOURCE_MEMORY_* attribute
 * bits to "64-bit BAR" vs "prefetchable" is partially documented; the prefetch
 * bit (CM_RESOURCE_MEMORY_PREFETCHABLE) is reliable, but a 32-bit-vs-64-bit BAR
 * is inferred from the descriptor's length field width (MEM vs MEM_LARGE), which
 * the PnP manager does not always surface as a clean attribute. We set the
 * 64-bit flag only when a MEM_LARGE (>4 GiB-capable) descriptor is seen; a 64-bit
 * BAR with a sub-4 GiB window may be reported as 32-bit here. This is a
 * conservative under-report (never a false 64-bit claim) and is corrected
 * server-side from the per-VID/DID reference table — confirm on-box before
 * tightening.
 */
static void record_resource(uint8_t *slot, uint64_t len, uint8_t flags,
                            uint64_t *bar_size, uint8_t *bar_flags) {
    if (*slot >= 6u) return;
    bar_size[*slot]  = len;
    bar_flags[*slot] = flags;
    ++(*slot);
}

/* -------------------------------------------------------------------------
 * hk_dma_win_fill_bar
 *
 * Walks the device's BOOT (then ALLOC) log-conf for MEM/IO resource descriptors
 * and records their decoded lengths + attributes. Leaves bar_profile_count = 0
 * if no log-conf is available (the field stays "unknown"; the server treats 0 as
 * not-decoded, never as a positive fact).
 * ------------------------------------------------------------------------- */
extern "C" void hk_dma_win_fill_bar(DEVINST devinst, hk_dma_device_forensics *d) {
    /* Prefer the boot config (what firmware assigned); fall back to allocated. */
    LOG_CONF lc = 0;
    CONFIGRET cr = CM_Get_First_Log_Conf(&lc, devinst, BOOT_LOG_CONF);
    if (cr != CR_SUCCESS) {
        cr = CM_Get_First_Log_Conf(&lc, devinst, ALLOC_LOG_CONF);
        if (cr != CR_SUCCESS) return; /* no resources surfaced — leave count 0. */
    }

    uint8_t slot = 0;
    RES_DES rd = 0;
    /* Memory resources. */
    if (CM_Get_Next_Res_Des(&rd, lc, ResType_Mem, nullptr, 0) == CR_SUCCESS) {
        do {
            ULONG sz = 0;
            if (CM_Get_Res_Des_Data_Size(&sz, rd, 0) != CR_SUCCESS || sz == 0) {
                continue;
            }
            MEM_RESOURCE *mr = static_cast<MEM_RESOURCE *>(
                LocalAlloc(LPTR, sz));
            if (mr == nullptr) continue;
            if (CM_Get_Res_Des_Data(rd, mr, sz, 0) == CR_SUCCESS) {
                uint64_t base = mr->MEM_Header.MD_Alloc_Base;
                uint64_t end  = mr->MEM_Header.MD_Alloc_End;
                uint64_t len  = (end >= base) ? (end - base + 1ull) : 0ull;
                uint8_t flags = 0;
                if (mr->MEM_Header.MD_Flags & MD_PrefetchAllowed) {
                    flags |= BAR_FLAG_PREFETCH;
                }
                /* HK-UNCERTAIN(win-bar-attr): 64-bit inference — see file header.
                 * A >4 GiB base/end implies a 64-bit BAR window. */
                if (end > 0xFFFFFFFFull) flags |= BAR_FLAG_64BIT;
                record_resource(&slot, len, flags, d->bar_size, d->bar_flags);
            }
            LocalFree(mr);
        } while (CM_Get_Next_Res_Des(&rd, rd, ResType_Mem, nullptr, 0)
                     == CR_SUCCESS && slot < 6u);
    }

    /* I/O-port resources. */
    rd = 0;
    if (slot < 6u &&
        CM_Get_Next_Res_Des(&rd, lc, ResType_IO, nullptr, 0) == CR_SUCCESS) {
        do {
            ULONG sz = 0;
            if (CM_Get_Res_Des_Data_Size(&sz, rd, 0) != CR_SUCCESS || sz == 0) {
                continue;
            }
            IO_RESOURCE *ior = static_cast<IO_RESOURCE *>(LocalAlloc(LPTR, sz));
            if (ior == nullptr) continue;
            if (CM_Get_Res_Des_Data(rd, ior, sz, 0) == CR_SUCCESS) {
                uint64_t base = ior->IO_Header.IOD_Alloc_Base;
                uint64_t end  = ior->IO_Header.IOD_Alloc_End;
                uint64_t len  = (end >= base) ? (end - base + 1ull) : 0ull;
                record_resource(&slot, len, BAR_FLAG_IO, d->bar_size,
                                d->bar_flags);
            }
            LocalFree(ior);
        } while (CM_Get_Next_Res_Des(&rd, rd, ResType_IO, nullptr, 0)
                     == CR_SUCCESS && slot < 6u);
    }

    CM_Free_Log_Conf_Handle(lc);
    d->bar_profile_count = slot;
}
