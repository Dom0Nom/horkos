/*
 * Role: Pure, platform-free decoder for the x64 packed System Service Descriptor
 *       Table entry form (SsdtIntegrity.c, signal 35). On x64 each KiServiceTable
 *       entry is a 32-bit value encoding a signed 28-bit offset (entry >> 4) added
 *       to the table base; the low 4 bits are the argument-stack count. Decoding
 *       that to an absolute target is pure arithmetic, factored here so it is
 *       unit-testable on the host build (tests/unit/test_ssdt_decode.cpp) without
 *       a WDK — the plan's "SSDT decode tested host-side" requirement. Contains NO
 *       kernel/Win32 API: plain C99, includes only <stdint.h>, includable from a
 *       kernel C TU and a host C++ TU alike (never the same TU — guardrail #4).
 *       READ-ONLY: this header only decodes; it never writes a table entry.
 * Target platforms: all (decode math only; the table walk is Win-kernel-only).
 * Interface: HkSsdtDecodeTarget pure function consumed by SsdtIntegrity.c.
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Decode one x64 KiServiceTable entry into the absolute target address.
 *
 * x64 encoding (documented across the RE literature, stable since Vista x64):
 *   target = TableBase + (int32_t)(RawEntry >> 4)
 * The arithmetic shift on a SIGNED 32-bit value sign-extends the 28-bit offset,
 * so entries pointing "below" the table base (negative offset) resolve correctly.
 * The low 4 bits (RawEntry & 0xF) are the number of stack-spilled arguments and
 * are NOT part of the address — masked off via the shift.
 *
 * `raw` is the table entry as read; `table_base` is the KiServiceTable address.
 * Returns the absolute target VA. Caller (SsdtIntegrity.c) then range-checks the
 * result against the ntoskrnl/win32k ModuleMap entries.
 */
static inline uint64_t HkSsdtDecodeTarget(uint32_t raw, uint64_t table_base)
{
    /* Cast to signed 32-bit BEFORE the shift so it is an arithmetic shift that
     * sign-extends the 28-bit offset; (int64_t) widens it before adding to the
     * 64-bit base so a negative offset subtracts cleanly. */
    int32_t offset = (int32_t)raw >> 4;
    return (uint64_t)((int64_t)table_base + (int64_t)offset);
}

/* The argument-count nibble (low 4 bits), exposed for completeness; the integrity
 * check only uses the target, but a decoder caller may sanity-check this. */
static inline uint32_t HkSsdtArgCount(uint32_t raw)
{
    return raw & 0xFu;
}

#ifdef __cplusplus
} /* extern "C" */
#endif
