/*
 * dma_detect/include/horkos/page_hash.h
 * Role: Pure, platform-free page-hash helper shared across host sensors. The
 *       thread-provenance enrichment plane (sdk/src/backends/win/
 *       ThreadProvenanceWin.cpp) reuses this to compare a mapped entry page
 *       against its on-disk RVA bytes (module-stomping, catalog signal 24) and
 *       to derive a truncated backing-module-path id, instead of re-rolling a
 *       hasher. Lives in dma_detect because that library already ships a
 *       platform-neutral C core the rest of the host links.
 * Target platforms: all (plain C99, no platform headers).
 * Interface declares: hk_page_hash64(), hk_bytes_hash32(), hk_page_byte_delta().
 *
 * These are NON-CRYPTOGRAPHIC digests (FNV-1a). They are used for cheap
 * equality/identity fingerprints and a stable 32-bit module-path id, NOT for
 * any security decision that needs collision resistance. A real integrity
 * comparison (e.g. the kernel callback .text SHA-256 baseline) uses a crypto
 * hash elsewhere; do not substitute this for that.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 64-bit FNV-1a over `len` bytes at `data`. data may be NULL iff len == 0. */
uint64_t hk_page_hash64(const void *data, size_t len);

/* 32-bit FNV-1a — used for the truncated backing-module-path id
 * (hk_event_thread_provenance.backing_module_hash32). */
uint32_t hk_bytes_hash32(const void *data, size_t len);

/* Count of differing bytes between two equal-length buffers (the
 * entry_page_disk_delta for signal 24). Compares min(a_len, b_len) bytes and
 * counts the length difference as additional mismatches, so a truncated on-disk
 * read still yields a conservative (>0) delta rather than a false match. */
uint64_t hk_page_byte_delta(const void *a, size_t a_len,
                            const void *b, size_t b_len);

#ifdef __cplusplus
} /* extern "C" */
#endif
