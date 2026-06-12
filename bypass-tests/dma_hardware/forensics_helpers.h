/*
 * Role: extern "C" declarations of the host-buildable, platform-clean aggregator
 *       helpers defined in dma_detect/src/forensics_report.cpp, shared by the
 *       DMA-hardware bypass-test fixtures (guardrail #12). These are the same
 *       containment / OUI / aliasing / structural-gate / serialization helpers the
 *       server scoring path pins against, so the bypass tests exercise the REAL
 *       decision functions — not a re-implementation.
 * Target platforms: all (the helpers carry no platform API).
 * Interface: mirrors the extern "C" surface of forensics_report.cpp; the bypass
 *            CMakeLists compiles that TU directly into each fixture.
 */

#ifndef HK_DMA_BYPASS_FORENSICS_HELPERS_H
#define HK_DMA_BYPASS_FORENSICS_HELPERS_H

#include <cstdint>
#include "horkos/dma_forensics.h"

extern "C" {

/* Structural gate: bus_master_enabled && !driver_bound && scan_error==0. */
int hk_dma_forensics_structural_suspect(const hk_dma_device_forensics *d);

/* Flat LE serialization of one device record (returns bytes written or 0). */
uint32_t hk_dma_forensics_serialize_device(const hk_dma_device_forensics *d,
                                           uint8_t *out, uint32_t cap);

/* MSI-X containment check over already-reconstructed 64-bit BAR lengths
 * (sig 129/131 shared FP source). Returns 1 on a containment violation. */
int hk_dma_msix_containment_violation(uint64_t table_bar_len, uint64_t table_offset,
                                      uint64_t pba_bar_len, uint64_t pba_offset,
                                      uint16_t table_size_entries);

/* Extract the 24-bit OUI from an EUI-64 DSN serial (sig 127). */
uint32_t hk_dma_dsn_oui(uint64_t eui64);

/* ext-config aliasing detector: 1 if buf[0x100..] mirrors buf[0x000..] (sig 128). */
int hk_dma_extcfg_aliases_low(const uint8_t *buf, uint32_t len);

} /* extern "C" */

/* The serializer's pinned wire size (mirrors HK_DMA_FORENSICS_WIRE_BYTES and the
 * Rust DEVICE_WIRE_BYTES). */
#define HK_DMA_FORENSICS_WIRE_BYTES 100u

#endif /* HK_DMA_BYPASS_FORENSICS_HELPERS_H */
