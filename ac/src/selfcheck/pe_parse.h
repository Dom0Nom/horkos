/*
 * Role: Shared PE structure parser (sections / export-directory / import / TLS /
 *       exception-unwind data-directory locations) used by the Windows-format
 *       self-integrity signals (149/150/151/153) and image_baseline. It is a pure
 *       struct walk over a caller-supplied mapped buffer — NO windows.h, NO Win32
 *       calls — so it compiles and is unit-tested on every host (guardrail #1: no
 *       platform API; the format constants are reproduced here, not #included).
 * Target platforms: all (cross-platform-buildable PE parser). Consumed by the
 *       149/150/151/153 sensors + image_baseline on Windows targets; built and
 *       tested everywhere.
 * Interface: declares hk::selfcheck::pe::* over a buffer the caller maps (a file
 *       view for disk parsing, or the live image for in-memory parsing).
 */

#pragma once

#include <cstddef>
#include <cstdint>

namespace hk {
namespace selfcheck {
namespace pe {

/* Data-directory indices we care about (reproduced from winnt.h; values are ABI). */
constexpr uint32_t HK_DIR_EXPORT    = 0u;
constexpr uint32_t HK_DIR_IMPORT    = 1u;
constexpr uint32_t HK_DIR_EXCEPTION = 3u;  /* .pdata RUNTIME_FUNCTION table */
constexpr uint32_t HK_DIR_TLS       = 9u;
constexpr uint32_t HK_DIR_DELAY_IMPORT = 13u;

/* IMAGE_SCN_MEM_EXECUTE (section is executable). */
constexpr uint32_t HK_SCN_MEM_EXECUTE = 0x20000000u;

constexpr uint32_t HK_PE_MAX_SECTIONS = 96u; /* PE hard cap on section count. */

struct SectionRange {
    uint32_t rva;          /* VirtualAddress */
    uint32_t virtual_size; /* VirtualSize    */
    uint32_t raw_ptr;      /* PointerToRawData (file offset) */
    uint32_t raw_size;     /* SizeOfRawData  */
    uint32_t characteristics;
    char     name[9];      /* NUL-terminated section name (8 + terminator) */
};

struct DataDir {
    uint32_t rva;
    uint32_t size;
};

/* Parsed PE header view. All offsets are validated against `len` during parse so a
 * truncated/forged buffer cannot induce an over-read. `valid` is false on any
 * malformed structure — the caller emits nothing rather than trusting partial data
 * (fail-closed). */
struct Headers {
    bool     valid = false;
    bool     is_64bit = false;
    uint64_t image_base = 0;     /* OptionalHeader.ImageBase (preferred load base) */
    uint32_t size_of_image = 0;
    uint32_t entry_point_rva = 0;
    uint32_t section_count = 0;
    SectionRange sections[HK_PE_MAX_SECTIONS];
    DataDir  dirs[16];           /* the 16 IMAGE_DATA_DIRECTORY entries */
};

/* Parse the DOS/NT headers + section table + data directories from `buf`/`len`.
 * Returns Headers{valid=false} on any inconsistency. Pure; no allocation. */
Headers parse(const uint8_t* buf, size_t len) noexcept;

/* Return the section containing `rva`, or nullptr. */
const SectionRange* section_for_rva(const Headers& h, uint32_t rva) noexcept;

/* Convert an RVA to a file offset using the section table (for disk-buffer reads).
 * Returns false if the RVA is not inside any section's raw range. */
bool rva_to_file_offset(const Headers& h, uint32_t rva, uint32_t* out_off) noexcept;

/* Find the first executable section (typically .text). Returns nullptr if none. */
const SectionRange* first_exec_section(const Headers& h) noexcept;

} // namespace pe
} // namespace selfcheck
} // namespace hk
