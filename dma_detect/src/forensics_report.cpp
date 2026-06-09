/*
 * dma_detect/src/forensics_report.cpp
 * Role: Platform-agnostic forensics aggregation + wire-serialization helpers.
 *       Merges the per-backend hk_dma_device_forensics records into the
 *       telemetry-plane payload bytes and computes the structural gate
 *       (bus_master_enabled && !driver_bound) the server uses to decide which
 *       devices to score. NO platform API here (guardrail #1) — pure C++17 over
 *       the platform-clean dma_forensics.h interface.
 * Target platforms: all.
 * Implements: parts of dma_detect/include/horkos/dma_forensics.h
 *       (serialization + gate helpers; the scan/subscribe entry points live in
 *       the per-OS backends).
 *
 * Wire decision (per impl-plan): DMA forensics ride the per-tick JSON telemetry
 * plane, NOT the fixed 40-byte hk_event_record kernel ring. This file therefore
 * produces a little-endian flat byte image of each record (stable field order)
 * that the client's telemetry uploader hands to the server's serde mirror
 * (server/telemetry/src/dma_forensics.rs). The byte layout here is the contract
 * that the Rust decoder pins against.
 *
 * HK-TODO(schema): the wire event-type discriminants HK_EVENT_DMA_FORENSICS(=5)
 * and HK_EVENT_DMA_HOTPLUG(=6), the hk_event_dma_hotplug 16-byte compact form,
 * and the SCHEMA_VERSION 2->3 bump are owned by the Schema phase and are NOT yet
 * present in sdk/include/horkos/event_schema.h. This file does not depend on the
 * fixed ring at all (forensics are userspace telemetry-plane), so it only needs
 * the flat serializer below; the compact ring form is provided for the future
 * kernel arm and is gated behind that schema landing.
 */

#include <cstdint>
#include <cstddef>
#include <cstring>

#include "../include/horkos/dma_forensics.h"

namespace {

/* Little-endian appenders. The server's serde mirror reads the same order. */
inline void put_u8(uint8_t *&p, uint8_t v) { *p++ = v; }

inline void put_u16(uint8_t *&p, uint16_t v) {
    *p++ = static_cast<uint8_t>(v & 0xFFu);
    *p++ = static_cast<uint8_t>((v >> 8) & 0xFFu);
}

inline void put_u32(uint8_t *&p, uint32_t v) {
    for (int i = 0; i < 4; ++i) {
        *p++ = static_cast<uint8_t>((v >> (8 * i)) & 0xFFu);
    }
}

inline void put_u64(uint8_t *&p, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        *p++ = static_cast<uint8_t>((v >> (8 * i)) & 0xFFu);
    }
}

} /* anonymous namespace */

/* -------------------------------------------------------------------------
 * HK_DMA_FORENSICS_WIRE_BYTES — flat serialized size of one device record.
 *
 * Field-by-field LE layout (must match dma_forensics.rs::DEVICE_WIRE_BYTES):
 *   bdf.domain        u16   (2)
 *   bdf.bus           u8    (1)
 *   bdf.devfn         u8    (1)
 *   vendor_id         u16   (2)
 *   device_id         u16   (2)
 *   subsys_vendor_id  u16   (2)
 *   dsn_present       u8    (1)
 *   dsn_oui_matches   u8    (1)
 *   extcfg_aliases    u8    (1)
 *   rsvdp_nonzero     u8    (1)
 *   extcfg_unstable   u8    (1)
 *   msix_violation    u8    (1)
 *   msix_table_size   u16   (2)
 *   rom_present       u8    (1)
 *   rom_pcir_mismatch u8    (1)
 *   bar_profile_count u8    (1)
 *   bar_size[6]       u64x6 (48)
 *   bar_flags[6]      u8x6  (6)
 *   acs_source_valid  u8    (1)
 *   acs_p2p_redirect  u8    (1)
 *   iommu_group_mem   u32   (4)
 *   bus_master_en     u8    (1)
 *   driver_bound      u8    (1)
 *   tlp_median_ns     u32   (4)
 *   tlp_iqr_ns        u32   (4)
 *   tlp_root_group    u8    (1)
 *   iommu_fault_count u32   (4)
 *   scan_error        u32   (4)
 * Total = 4(bdf) +6(ids) +5(127/128) +3(129) +2(130) +1(bar_count) +48(bar_size)
 *         +6(bar_flags) +2(acs) +4(iommu_group) +2(gates) +8(tlp ns) +1(tlp group)
 *         +4(iommu_fault) +4(scan_error) = 100 bytes.
 * (The earlier "113" annotation here was an arithmetic miscount; the field walk
 *  above and the byte image the serializer below emits are 100 bytes. The Rust
 *  mirror dma_forensics.rs::DEVICE_WIRE_BYTES pins the same 100.)
 * ------------------------------------------------------------------------- */
#define HK_DMA_FORENSICS_WIRE_BYTES 100u

/* -------------------------------------------------------------------------
 * hk_dma_forensics_structural_suspect
 *
 * The catalog's structural pre-requisite: a device that can master the bus but
 * has no OS driver managing its IOVA space. The server gates nearly every DMA
 * signal on this conjunction — a flagged config-space anomaly on a normal,
 * driver-bound device is far more likely a quirk than a DMA-inspection board.
 * This is evidence, NOT a verdict; the server decides.
 * ------------------------------------------------------------------------- */
extern "C" int hk_dma_forensics_structural_suspect(
    const hk_dma_device_forensics *d) {
    if (d == nullptr) return 0;
    if (d->scan_error != 0u) return 0; /* untrustworthy record: never assert. */
    return (d->bus_master_enabled != 0u && d->driver_bound == 0u) ? 1 : 0;
}

/* -------------------------------------------------------------------------
 * hk_dma_forensics_serialize_device
 *
 * Serializes one record into out (capacity cap bytes). Returns the number of
 * bytes written (HK_DMA_FORENSICS_WIRE_BYTES) on success, or 0 if out is null
 * or cap is too small (caller must size the buffer; no truncation).
 * ------------------------------------------------------------------------- */
extern "C" uint32_t hk_dma_forensics_serialize_device(
    const hk_dma_device_forensics *d, uint8_t *out, uint32_t cap) {
    if (d == nullptr || out == nullptr || cap < HK_DMA_FORENSICS_WIRE_BYTES) {
        return 0u;
    }

    uint8_t *p = out;
    put_u16(p, d->bdf.domain);
    put_u8(p, d->bdf.bus);
    put_u8(p, d->bdf.devfn);
    put_u16(p, d->vendor_id);
    put_u16(p, d->device_id);
    put_u16(p, d->subsys_vendor_id);

    put_u8(p, d->dsn_present);
    put_u8(p, d->dsn_oui_matches_vendor);
    put_u8(p, d->extcfg_aliases_low);
    put_u8(p, d->rsvdp_nonzero);
    put_u8(p, d->extcfg_read_unstable);

    put_u8(p, d->msix_containment_violation);
    put_u16(p, d->msix_table_size);

    put_u8(p, d->rom_present);
    put_u8(p, d->rom_pcir_id_mismatch);

    put_u8(p, d->bar_profile_count);
    for (int i = 0; i < 6; ++i) put_u64(p, d->bar_size[i]);
    for (int i = 0; i < 6; ++i) put_u8(p, d->bar_flags[i]);

    put_u8(p, d->acs_source_validation);
    put_u8(p, d->acs_p2p_redirect);
    put_u32(p, d->iommu_group_membership);

    put_u8(p, d->bus_master_enabled);
    put_u8(p, d->driver_bound);

    put_u32(p, d->tlp_latency_median_ns);
    put_u32(p, d->tlp_latency_iqr_ns);
    put_u8(p, d->tlp_same_root_port_group);

    put_u32(p, d->iommu_fault_count);
    put_u32(p, d->scan_error);

    return static_cast<uint32_t>(p - out);
}

/* -------------------------------------------------------------------------
 * MSI-X containment helper (shared BAR-sizing FP source — sig 129/131).
 *
 * The catalog names the 64-bit-BAR high-dword combination as the dominant false
 * positive: a Table/PBA offset that "overflows" a 32-bit-only view of a BAR is
 * fine once the high dword is combined. This helper performs the containment
 * check with the already-reconstructed 64-bit BAR length so callers cannot get
 * the dword combination wrong independently.
 *
 * Each MSI-X table entry is 16 bytes (PCIe spec). Containment requires
 *   table_offset + table_size_entries * 16 <= bar_len
 * AND the same for the PBA (1 bit per entry, rounded up to dwords). Returns 1
 * when EITHER structure escapes its referenced BAR (a violation), else 0.
 * bar_len of 0 means the referenced BAR was not decodable — return 0 (unknown,
 * never assert) so a missing BAR is not mistaken for an overflow.
 * ------------------------------------------------------------------------- */
extern "C" int hk_dma_msix_containment_violation(
    uint64_t table_bar_len, uint64_t table_offset,
    uint64_t pba_bar_len,   uint64_t pba_offset,
    uint16_t table_size_entries) {
    if (table_size_entries == 0u) return 0;

    const uint64_t entries = static_cast<uint64_t>(table_size_entries);
    const uint64_t table_span = entries * 16u;            /* 16 bytes/entry. */
    /* PBA: 1 bit/entry, accessed in 64-bit qwords per spec; round up to qword. */
    const uint64_t pba_qwords = (entries + 63u) / 64u;
    const uint64_t pba_span   = pba_qwords * 8u;

    if (table_bar_len != 0u) {
        if (table_offset > table_bar_len) return 1;
        if (table_span > table_bar_len - table_offset) return 1;
    }
    if (pba_bar_len != 0u) {
        if (pba_offset > pba_bar_len) return 1;
        if (pba_span > pba_bar_len - pba_offset) return 1;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * DSN OUI matcher (sig 127).
 *
 * A Device Serial Number ext-cap carries an EUI-64. Its top 24 bits are the
 * IEEE OUI, which for a genuine ASIC matches the OUI block the vendor (VID)
 * registered. An FPGA DMA board that clones a NIC's VID/DID but synthesizes a
 * serial typically gets the OUI wrong (or omits DSN). The server holds the
 * VID->OUI table; this helper just extracts the OUI so the backend can stash
 * dsn_oui (and the server compares). Returns the 24-bit OUI from the EUI-64.
 *
 * EUI-64 byte order in the DSN cap (PCIe spec 7.9.3): the lower dword is at
 * offset 0x04 of the cap, the upper dword at 0x08; the OUI occupies the most-
 * significant 3 bytes of the 64-bit serial.
 * ------------------------------------------------------------------------- */
extern "C" uint32_t hk_dma_dsn_oui(uint64_t eui64) {
    return static_cast<uint32_t>((eui64 >> 40) & 0xFFFFFFu);
}

/* -------------------------------------------------------------------------
 * ext-config aliasing detector (sig 128).
 *
 * Many FPGA "shadow config" implementations back the extended config region
 * (0x100-0xFFF) with the same memory as legacy config (0x000-0xFF), so the
 * first 256 bytes of extended space mirror legacy space byte-for-byte. A real
 * device has independent ext-cap structures there. Returns 1 if buf[0x100..]
 * mirrors buf[0x000..] over the first 256 bytes. buf must be >= 0x200 bytes;
 * returns 0 (cannot assert) otherwise.
 * ------------------------------------------------------------------------- */
extern "C" int hk_dma_extcfg_aliases_low(const uint8_t *buf, uint32_t len) {
    if (buf == nullptr || len < 0x200u) return 0;
    return std::memcmp(buf, buf + 0x100, 0x100) == 0 ? 1 : 0;
}
