/*
 * ac/src/selfcheck/pe_parse.cpp
 * Role: Implementation of the pure PE structure parser (pe_parse.h) for the
 *       Windows-format self-integrity signals (149/150/151/153) + image_baseline.
 *       Pure struct walk over a mapped buffer with strict bounds checks — no
 *       windows.h, no Win32 calls (guardrail #1). Every offset is validated
 *       against the buffer length before dereference so a truncated or hostile
 *       image cannot induce an over-read; a malformed structure yields
 *       Headers{valid=false} (fail-closed) rather than partial trust.
 * Target platforms: all (compiled into hk_ac and the host unit-test target).
 * Interface: implements hk::selfcheck::pe::* from pe_parse.h.
 */

#include "pe_parse.h"

#include <cstring>

namespace hk {
namespace selfcheck {
namespace pe {

namespace {

/* Bounds-checked little-endian readers. Each returns false on out-of-range. */
bool rd_u16(const uint8_t* b, size_t len, size_t off, uint16_t* out) noexcept {
    if (off + 2 > len) return false;
    *out = static_cast<uint16_t>(b[off] | (b[off + 1] << 8));
    return true;
}
bool rd_u32(const uint8_t* b, size_t len, size_t off, uint32_t* out) noexcept {
    if (off + 4 > len) return false;
    *out = static_cast<uint32_t>(b[off]) | (static_cast<uint32_t>(b[off + 1]) << 8) |
           (static_cast<uint32_t>(b[off + 2]) << 16) | (static_cast<uint32_t>(b[off + 3]) << 24);
    return true;
}
bool rd_u64(const uint8_t* b, size_t len, size_t off, uint64_t* out) noexcept {
    uint32_t lo, hi;
    if (!rd_u32(b, len, off, &lo) || !rd_u32(b, len, off + 4, &hi)) return false;
    *out = (static_cast<uint64_t>(hi) << 32) | lo;
    return true;
}

constexpr uint16_t HK_DOS_MAGIC = 0x5A4D;        /* "MZ" */
constexpr uint32_t HK_NT_MAGIC  = 0x00004550;    /* "PE\0\0" */
constexpr uint16_t HK_OPT_MAGIC_PE32     = 0x010B;
constexpr uint16_t HK_OPT_MAGIC_PE32PLUS = 0x020B;

} // namespace

Headers parse(const uint8_t* buf, size_t len) noexcept {
    Headers h;
    if (buf == nullptr || len < 0x40) {
        return h;
    }

    uint16_t dos_magic = 0;
    if (!rd_u16(buf, len, 0, &dos_magic) || dos_magic != HK_DOS_MAGIC) {
        return h;
    }
    uint32_t e_lfanew = 0;
    if (!rd_u32(buf, len, 0x3C, &e_lfanew)) {
        return h;
    }

    /* NT headers: 4 (signature) + 20 (file header) + optional header. */
    uint32_t nt_sig = 0;
    if (!rd_u32(buf, len, e_lfanew, &nt_sig) || nt_sig != HK_NT_MAGIC) {
        return h;
    }

    const size_t file_hdr = static_cast<size_t>(e_lfanew) + 4;
    uint16_t machine = 0, num_sections = 0, opt_size = 0;
    uint16_t opt_magic = 0;
    if (!rd_u16(buf, len, file_hdr + 0, &machine) ||
        !rd_u16(buf, len, file_hdr + 2, &num_sections) ||
        !rd_u16(buf, len, file_hdr + 16, &opt_size)) {
        return h;
    }
    const size_t opt_hdr = file_hdr + 20;
    if (!rd_u16(buf, len, opt_hdr + 0, &opt_magic)) {
        return h;
    }

    /* Field offsets within the optional header differ between PE32 and PE32+. */
    size_t base_off, dir_count_off, dirs_off, entry_off, image_base_off;
    if (opt_magic == HK_OPT_MAGIC_PE32PLUS) {
        h.is_64bit = true;
        entry_off       = opt_hdr + 16;  /* AddressOfEntryPoint */
        image_base_off  = opt_hdr + 24;  /* ImageBase (u64)     */
        base_off        = opt_hdr + 56;  /* SizeOfImage         */
        dir_count_off   = opt_hdr + 108; /* NumberOfRvaAndSizes */
        dirs_off        = opt_hdr + 112; /* DataDirectory[]     */
    } else if (opt_magic == HK_OPT_MAGIC_PE32) {
        h.is_64bit = false;
        entry_off       = opt_hdr + 16;
        image_base_off  = opt_hdr + 28;  /* ImageBase (u32)     */
        base_off        = opt_hdr + 56;  /* SizeOfImage         */
        dir_count_off   = opt_hdr + 92;
        dirs_off        = opt_hdr + 96;
    } else {
        return h;
    }

    uint32_t entry = 0, size_of_image = 0, dir_count = 0;
    if (!rd_u32(buf, len, entry_off, &entry) ||
        !rd_u32(buf, len, base_off, &size_of_image) ||
        !rd_u32(buf, len, dir_count_off, &dir_count)) {
        return h;
    }
    if (h.is_64bit) {
        if (!rd_u64(buf, len, image_base_off, &h.image_base)) return h;
    } else {
        uint32_t b32 = 0;
        if (!rd_u32(buf, len, image_base_off, &b32)) return h;
        h.image_base = b32;
    }
    h.entry_point_rva = entry;
    h.size_of_image = size_of_image;

    /* Data directories (cap at 16). */
    if (dir_count > 16u) dir_count = 16u;
    for (uint32_t i = 0; i < dir_count; ++i) {
        const size_t off = dirs_off + static_cast<size_t>(i) * 8u;
        if (!rd_u32(buf, len, off, &h.dirs[i].rva) ||
            !rd_u32(buf, len, off + 4, &h.dirs[i].size)) {
            return h; /* truncated directory table */
        }
    }

    /* Section table immediately follows the optional header. */
    if (num_sections > HK_PE_MAX_SECTIONS) {
        return h; /* impossible section count — reject */
    }
    const size_t sect_table = opt_hdr + opt_size;
    for (uint16_t i = 0; i < num_sections; ++i) {
        const size_t off = sect_table + static_cast<size_t>(i) * 40u; /* sizeof IMAGE_SECTION_HEADER */
        if (off + 40u > len) {
            return h; /* truncated section table */
        }
        SectionRange& s = h.sections[i];
        std::memset(s.name, 0, sizeof(s.name));
        std::memcpy(s.name, buf + off, 8); /* 8-byte name, may be non-NUL-terminated */
        s.name[8] = '\0';
        if (!rd_u32(buf, len, off + 8,  &s.virtual_size) ||
            !rd_u32(buf, len, off + 12, &s.rva) ||
            !rd_u32(buf, len, off + 16, &s.raw_size) ||
            !rd_u32(buf, len, off + 20, &s.raw_ptr) ||
            !rd_u32(buf, len, off + 36, &s.characteristics)) {
            return h;
        }
    }
    h.section_count = num_sections;
    h.valid = true;
    return h;
}

const SectionRange* section_for_rva(const Headers& h, uint32_t rva) noexcept {
    if (!h.valid) return nullptr;
    for (uint32_t i = 0; i < h.section_count; ++i) {
        const SectionRange& s = h.sections[i];
        if (rva >= s.rva && rva < s.rva + s.virtual_size) {
            return &s;
        }
    }
    return nullptr;
}

bool rva_to_file_offset(const Headers& h, uint32_t rva, uint32_t* out_off) noexcept {
    const SectionRange* s = section_for_rva(h, rva);
    if (s == nullptr || out_off == nullptr) {
        return false;
    }
    const uint32_t delta = rva - s->rva;
    if (delta >= s->raw_size) {
        return false; /* RVA is in the section's zero-fill tail (no file bytes) */
    }
    *out_off = s->raw_ptr + delta;
    return true;
}

const SectionRange* first_exec_section(const Headers& h) noexcept {
    if (!h.valid) return nullptr;
    for (uint32_t i = 0; i < h.section_count; ++i) {
        if (h.sections[i].characteristics & HK_SCN_MEM_EXECUTE) {
            return &h.sections[i];
        }
    }
    return nullptr;
}

} // namespace pe
} // namespace selfcheck
} // namespace hk
