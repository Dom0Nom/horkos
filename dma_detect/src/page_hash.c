/*
 * dma_detect/src/page_hash.c
 * Role: Implementation of the platform-free page-hash helper (page_hash.h).
 *       Non-cryptographic FNV-1a digests + a byte-delta counter, reused by the
 *       Windows thread-provenance enrichment plane for module-stomping checks
 *       (catalog signal 24) and the backing-module-path id.
 * Target platforms: all (plain C99, no platform headers).
 * Interface: implements horkos/page_hash.h.
 */

#include "horkos/page_hash.h"

/* FNV-1a constants (64- and 32-bit). */
#define HK_FNV64_OFFSET 1469598103934665603ull
#define HK_FNV64_PRIME  1099511628211ull
#define HK_FNV32_OFFSET 2166136261u
#define HK_FNV32_PRIME  16777619u

uint64_t hk_page_hash64(const void *data, size_t len)
{
    const unsigned char *p = (const unsigned char *)data;
    uint64_t h = HK_FNV64_OFFSET;
    size_t i;

    if (p == NULL) {
        return h;
    }
    for (i = 0; i < len; ++i) {
        h ^= (uint64_t)p[i];
        h *= HK_FNV64_PRIME;
    }
    return h;
}

uint32_t hk_bytes_hash32(const void *data, size_t len)
{
    const unsigned char *p = (const unsigned char *)data;
    uint32_t h = HK_FNV32_OFFSET;
    size_t i;

    if (p == NULL) {
        return h;
    }
    for (i = 0; i < len; ++i) {
        h ^= (uint32_t)p[i];
        h *= HK_FNV32_PRIME;
    }
    return h;
}

uint64_t hk_page_byte_delta(const void *a, size_t a_len,
                            const void *b, size_t b_len)
{
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    size_t   n = (a_len < b_len) ? a_len : b_len;
    size_t   i;
    uint64_t delta = (a_len < b_len) ? (uint64_t)(b_len - a_len)
                                     : (uint64_t)(a_len - b_len);

    if (pa == NULL || pb == NULL) {
        /* No comparable bytes: report the full longer length as mismatched so
         * the caller never reads a NULL buffer as "matches on disk". */
        return (uint64_t)((a_len > b_len) ? a_len : b_len);
    }
    for (i = 0; i < n; ++i) {
        if (pa[i] != pb[i]) {
            ++delta;
        }
    }
    return delta;
}
