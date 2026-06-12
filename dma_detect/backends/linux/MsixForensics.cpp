/*
 * Role: Linux MSI-X BIR/PBA containment forensics (sig 129). Reads the MSI-X
 *       capability (cap ID 0x11) from legacy config: Message Control (table
 *       size), Table Offset/BIR, and PBA Offset/BIR; resolves each referenced
 *       BAR's decoded length (passed in from BarProfile) and checks containment
 *       via the shared 64-bit-correct helper. Read-only.
 * Target platforms: Linux only. Selected by CMake elseif(UNIX).
 * Implements: hk_dma_linux_fill_msix (consumed by ConfigSpaceForensics.cpp).
 */

#include <cstdint>
#include <cstring>

#include "../../include/horkos/dma_forensics.h"

/* Shared 64-bit-correct containment check (forensics_report.cpp). */
extern "C" int hk_dma_msix_containment_violation(
    uint64_t table_bar_len, uint64_t table_offset,
    uint64_t pba_bar_len,   uint64_t pba_offset,
    uint16_t table_size_entries);

static const uint8_t PCI_CAP_ID_MSIX = 0x11u;

static uint16_t cfg_le16(const uint8_t *cfg, uint32_t len, uint32_t off) {
    if (off + 2u > len) return 0u;
    return static_cast<uint16_t>(cfg[off] | (cfg[off + 1] << 8));
}
static uint32_t cfg_le32(const uint8_t *cfg, uint32_t len, uint32_t off) {
    if (off + 4u > len) return 0u;
    return static_cast<uint32_t>(cfg[off]) |
           (static_cast<uint32_t>(cfg[off + 1]) << 8) |
           (static_cast<uint32_t>(cfg[off + 2]) << 16) |
           (static_cast<uint32_t>(cfg[off + 3]) << 24);
}

/* -------------------------------------------------------------------------
 * find_msix_cap — walk the legacy capability list (starts at config 0x34's
 * pointer) for cap ID 0x11. Returns the cap offset, or 0 if absent.
 *
 * The capabilities-pointer at 0x34 gives the first cap offset; each cap is
 * {u8 id, u8 next, ...}. Status register bit 4 (0x10) indicates a cap list is
 * present. Bounded walk so a corrupt list cannot loop.
 * ------------------------------------------------------------------------- */
static uint32_t find_msix_cap(const uint8_t *cfg, uint32_t len) {
    if (len < 0x40u) return 0u;
    uint16_t status = cfg_le16(cfg, len, 0x06u);
    if ((status & 0x0010u) == 0u) return 0u; /* no capability list. */
    uint32_t off = cfg[0x34] & 0xFCu; /* lower 2 bits reserved. */
    int guard = 0;
    while (off >= 0x40u && off + 2u <= len && guard++ < 64) {
        uint8_t id   = cfg[off];
        uint8_t next = cfg[off + 1];
        if (id == PCI_CAP_ID_MSIX) return off;
        if (next == 0u || (next & 0xFCu) <= off) break;
        off = next & 0xFCu;
    }
    return 0u;
}

/* -------------------------------------------------------------------------
 * hk_dma_linux_fill_msix
 *
 * MSI-X cap layout (PCIe spec 7.7.2):
 *   +0x00: cap id (0x11), next ptr
 *   +0x02: Message Control (bits 10:0 = Table Size minus one)
 *   +0x04: Table Offset/BIR (bits 2:0 = BIR, bits 31:3 = offset, dword-aligned)
 *   +0x08: PBA Offset/BIR  (same encoding)
 * ------------------------------------------------------------------------- */
extern "C" void hk_dma_linux_fill_msix(const char *dev_dir,
                                       const uint8_t *cfg, uint32_t cfg_len,
                                       const uint64_t *bar_len, uint8_t bar_count,
                                       hk_dma_device_forensics *d) {
    (void)dev_dir;
    uint32_t cap = find_msix_cap(cfg, cfg_len);
    if (cap == 0u) {
        d->msix_table_size = 0u;
        d->msix_containment_violation = 0u;
        return;
    }

    uint16_t msg_ctrl = cfg_le16(cfg, cfg_len, cap + 0x02u);
    uint16_t entries  = static_cast<uint16_t>((msg_ctrl & 0x07FFu) + 1u);
    d->msix_table_size = entries;

    uint32_t table_dword = cfg_le32(cfg, cfg_len, cap + 0x04u);
    uint32_t pba_dword   = cfg_le32(cfg, cfg_len, cap + 0x08u);

    uint8_t  table_bir = static_cast<uint8_t>(table_dword & 0x7u);
    uint64_t table_off = static_cast<uint64_t>(table_dword & ~0x7u);
    uint8_t  pba_bir   = static_cast<uint8_t>(pba_dword & 0x7u);
    uint64_t pba_off   = static_cast<uint64_t>(pba_dword & ~0x7u);

    uint64_t table_bar_len = (table_bir < bar_count && table_bir < 6)
                                 ? bar_len[table_bir] : 0ull;
    uint64_t pba_bar_len   = (pba_bir < bar_count && pba_bir < 6)
                                 ? bar_len[pba_bir] : 0ull;

    d->msix_containment_violation = static_cast<uint8_t>(
        hk_dma_msix_containment_violation(table_bar_len, table_off,
                                          pba_bar_len, pba_off, entries));
}
