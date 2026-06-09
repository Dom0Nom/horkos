/*
 * kernel/win/include/module_map_resolve.h
 * Role: Pure, platform-free address-range resolver for the loaded-module map
 *       (ModuleMap.c, shared by integrity signals 29/31/32/34/35). The kernel TU
 *       builds the map from ZwQuerySystemInformation(SystemModuleInformation);
 *       the *lookup* (is address A inside any [base,base+size) range, and which
 *       one) is pure arithmetic factored here so it is unit-testable on the host
 *       build (tests/unit/test_module_map_resolve.cpp) without a WDK — the plan's
 *       "ModuleMap resolve logic unit-tested host-side" requirement. Contains NO
 *       kernel/Win32 API: plain C99, includes only <stdint.h>/<stddef.h>, so it
 *       is includable from a kernel C TU and a host C++ TU alike (never the same
 *       TU — guardrail #4; header-only inline helpers, not a shared object file).
 * Target platforms: all (decision math only; the map builder is Win-kernel-only).
 * Interface: declares HkModuleRangeResolve / HkModuleRangeContains pure helpers
 *       consumed by ModuleMap.c and the sensors; no I/O, no allocation.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* One loaded-module range, reduced to what the resolver needs. The kernel-side
 * map (ModuleMap.c) holds richer per-entry data (image name, signed flag); this
 * is the lookup-only projection so the math stays pure. */
typedef struct hk_module_range {
    uint64_t base;   /* image base (DllBase). */
    uint64_t size;   /* image size in bytes (SizeOfImage). */
    uint32_t index;  /* caller-defined index back into the full kernel-side table. */
    uint32_t flags;  /* HK_MODRANGE_* bits (e.g. signed). Opaque to the resolver. */
} hk_module_range;

/* Resolver index for "address resolved to no module". */
#define HK_MODRANGE_NONE ((size_t)-1)

/* hk_module_range.flags bits. The resolver does not interpret these; callers
 * (e.g. DriverObjectAudit) read them on the resolved entry. */
#define HK_MODRANGE_FLAG_SIGNED 0x00000001u

/*
 * Resolve `addr` against `count` ranges. Returns the array index of the first
 * range whose [base, base+size) interval contains `addr`, or HK_MODRANGE_NONE if
 * none does. Interval is half-open: base+size is EXCLUSIVE (an address exactly at
 * the next module's base is not "inside" this one). Overflow-safe: a range whose
 * base+size wraps uint64_t is treated as extending to UINT64_MAX (a module
 * mapped at the very top of the address space still resolves its own bytes).
 */
static inline size_t HkModuleRangeResolve(const hk_module_range* ranges,
                                          size_t count, uint64_t addr)
{
    size_t i;
    if (ranges == NULL || count == 0) {
        return HK_MODRANGE_NONE;
    }
    for (i = 0; i < count; ++i) {
        uint64_t base = ranges[i].base;
        uint64_t size = ranges[i].size;
        if (size == 0) {
            continue; /* a zero-size range contains nothing. */
        }
        if (addr < base) {
            continue;
        }
        /* offset = addr - base is now >= 0; compare against size without forming
         * base+size (which could overflow). offset < size => inside, half-open. */
        if ((addr - base) < size) {
            return i;
        }
    }
    return HK_MODRANGE_NONE;
}

/* TRUE iff `addr` lands inside any range. */
static inline int HkModuleRangeContains(const hk_module_range* ranges,
                                        size_t count, uint64_t addr)
{
    return HkModuleRangeResolve(ranges, count, addr) != HK_MODRANGE_NONE ? 1 : 0;
}

/* TRUE iff `addr` lands inside any range whose HK_MODRANGE_FLAG_SIGNED bit is set.
 * Signals 34 (DriverObject) and 35 (SSDT) accept a pointer that resolves into ANY
 * signed loaded module (e.g. fltmgr.sys thunks), not only the owning image. */
static inline int HkModuleRangeContainsSigned(const hk_module_range* ranges,
                                              size_t count, uint64_t addr)
{
    size_t idx = HkModuleRangeResolve(ranges, count, addr);
    if (idx == HK_MODRANGE_NONE) {
        return 0;
    }
    return (ranges[idx].flags & HK_MODRANGE_FLAG_SIGNED) ? 1 : 0;
}

#ifdef __cplusplus
} /* extern "C" */
#endif
