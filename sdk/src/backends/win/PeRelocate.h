/*
 * sdk/src/backends/win/PeRelocate.h
 * Role: Pure PE export-RVA + base-relocation math reused by the Present-prologue
 *       reconciliation sensor (signal 47). Given a module's on-disk image bytes
 *       and the live load base, it (a) resolves an export's RVA, (b) maps an RVA
 *       to its raw file offset through the section table, and (c) rewrites a
 *       prologue byte window to the value it WOULD have at the live base by
 *       applying IMAGE_BASE_RELOCATION deltas — so an ASLR-relocated absolute
 *       branch is recognised as a benign relocation, NOT misread as a patch
 *       (catalog FP guard). No OS calls, no allocation beyond caller-owned
 *       buffers; deterministic and host-unit-testable.
 * Target platforms: all (header-only, pure). Compiled SEPARATELY in this SDK TU
 *       and (independently) in the kernel image-load path — never the same object,
 *       so guardrail #4 (no shared kernel/userspace TU) holds.
 * Interface: included by PresentPrologueReconcileWin.cpp and the host unit test
 *       tests/unit/test_pe_relocate.cpp.
 *
 * NOTE: this parses UNTRUSTED on-disk PE bytes; every field offset is bounds-
 * checked against the supplied image length before use. A malformed header makes
 * a function fail (false / 0), never read out of bounds.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace hk { namespace sdk { namespace pe {

/* Minimal PE constants (named locally so this header needs no <windows.h>; the
 * values are the fixed on-disk PE format, identical kernel and userspace). */
constexpr uint16_t kDosMagic = 0x5A4D;          /* 'MZ' */
constexpr uint32_t kNtSignature = 0x00004550;   /* 'PE\0\0' */
constexpr uint16_t kOptMagicPE32  = 0x010B;
constexpr uint16_t kOptMagicPE32Plus = 0x020B;
constexpr int kDirExport = 0;
constexpr int kDirBaseReloc = 5;
constexpr uint16_t kRelTypeAbsolute = 0;   /* padding entry, skip */
constexpr uint16_t kRelTypeHighLow  = 3;   /* 32-bit delta at offset */
constexpr uint16_t kRelTypeDir64    = 10;  /* 64-bit delta at offset */

/* A bounds-checked little-endian reader over the on-disk image buffer. Every
 * accessor verifies [off, off+width) lies within `len` and returns false on
 * overrun, so a truncated/hostile file cannot drive an OOB read. */
class ImageView {
public:
    ImageView(const uint8_t *data, size_t len) : data_(data), len_(len) {}

    bool u16(size_t off, uint16_t &v) const {
        if (data_ == nullptr || off + 2 > len_) return false;
        v = static_cast<uint16_t>(data_[off]) |
            (static_cast<uint16_t>(data_[off + 1]) << 8);
        return true;
    }
    bool u32(size_t off, uint32_t &v) const {
        if (data_ == nullptr || off + 4 > len_) return false;
        v = static_cast<uint32_t>(data_[off]) |
            (static_cast<uint32_t>(data_[off + 1]) << 8) |
            (static_cast<uint32_t>(data_[off + 2]) << 16) |
            (static_cast<uint32_t>(data_[off + 3]) << 24);
        return true;
    }
    bool u64(size_t off, uint64_t &v) const {
        uint32_t lo, hi;
        if (!u32(off, lo) || !u32(off + 4, hi)) return false;
        v = static_cast<uint64_t>(lo) | (static_cast<uint64_t>(hi) << 32);
        return true;
    }
    const uint8_t *ptr(size_t off, size_t need) const {
        if (data_ == nullptr || off + need > len_) return nullptr;
        return data_ + off;
    }
    size_t len() const { return len_; }

private:
    const uint8_t *data_;
    size_t len_;
};

/* Parsed PE header coordinates needed by the sensor. All offsets are file
 * offsets into the on-disk buffer; preferred_base is the OptionalHeader ImageBase
 * (the delta baseline for relocations). */
struct PeHeaders {
    bool     is64 = false;
    uint64_t preferred_base = 0;
    uint32_t section_count = 0;
    uint32_t section_table_off = 0; /* file offset of the first IMAGE_SECTION_HEADER */
    uint32_t export_dir_rva = 0;
    uint32_t export_dir_size = 0;
    uint32_t reloc_dir_rva = 0;
    uint32_t reloc_dir_size = 0;
};

/* Parse just enough of the PE headers to drive export resolution + relocation.
 * Returns false on any malformed/short field. */
inline bool parse_headers(const ImageView &img, PeHeaders &out)
{
    uint16_t dos_magic = 0;
    if (!img.u16(0, dos_magic) || dos_magic != kDosMagic) return false;

    uint32_t e_lfanew = 0;
    if (!img.u32(0x3C, e_lfanew)) return false;

    uint32_t nt_sig = 0;
    if (!img.u32(e_lfanew, nt_sig) || nt_sig != kNtSignature) return false;

    /* IMAGE_FILE_HEADER follows the 4-byte signature. */
    const uint32_t file_hdr = e_lfanew + 4;
    uint16_t num_sections = 0, opt_size = 0;
    if (!img.u16(file_hdr + 2, num_sections)) return false;
    if (!img.u16(file_hdr + 16, opt_size)) return false;

    const uint32_t opt_hdr = file_hdr + 20; /* sizeof IMAGE_FILE_HEADER == 20 */
    uint16_t opt_magic = 0;
    if (!img.u16(opt_hdr, opt_magic)) return false;

    /* ImageBase and the data-directory array sit at different offsets in PE32 vs
     * PE32+. Directory entries are 8 bytes each (RVA, Size). */
    uint32_t dir_array_off = 0;
    if (opt_magic == kOptMagicPE32Plus) {
        out.is64 = true;
        if (!img.u64(opt_hdr + 24, out.preferred_base)) return false; /* ImageBase */
        dir_array_off = opt_hdr + 112;
    } else if (opt_magic == kOptMagicPE32) {
        out.is64 = false;
        uint32_t base32 = 0;
        if (!img.u32(opt_hdr + 28, base32)) return false;             /* ImageBase */
        out.preferred_base = base32;
        dir_array_off = opt_hdr + 96;
    } else {
        return false;
    }

    if (!img.u32(dir_array_off + kDirExport * 8, out.export_dir_rva)) return false;
    if (!img.u32(dir_array_off + kDirExport * 8 + 4, out.export_dir_size)) return false;
    if (!img.u32(dir_array_off + kDirBaseReloc * 8, out.reloc_dir_rva)) return false;
    if (!img.u32(dir_array_off + kDirBaseReloc * 8 + 4, out.reloc_dir_size)) return false;

    out.section_count = num_sections;
    out.section_table_off = opt_hdr + opt_size; /* section table follows the optional header */
    return true;
}

/* Map a virtual RVA to its raw file offset via the section table. Returns false
 * if the RVA falls in no section (or the section table is short). Each
 * IMAGE_SECTION_HEADER is 40 bytes; VirtualAddress at +12, SizeOfRawData at +16,
 * PointerToRawData at +20. */
inline bool rva_to_file_offset(const ImageView &img, const PeHeaders &h,
                               uint32_t rva, uint32_t &file_off)
{
    for (uint32_t i = 0; i < h.section_count; ++i) {
        const uint32_t sec = h.section_table_off + i * 40;
        uint32_t va = 0, raw_size = 0, raw_ptr = 0, virt_size = 0;
        if (!img.u32(sec + 8, virt_size)) return false;   /* VirtualSize */
        if (!img.u32(sec + 12, va)) return false;
        if (!img.u32(sec + 16, raw_size)) return false;
        if (!img.u32(sec + 20, raw_ptr)) return false;
        /* A section can be larger virtually than on disk; clamp to raw_size for
         * file-offset mapping (bytes beyond raw_size are zero-fill, not on disk). */
        const uint32_t span = raw_size > virt_size ? virt_size : raw_size;
        if (rva >= va && rva < va + span) {
            file_off = raw_ptr + (rva - va);
            return file_off <= img.len();
        }
    }
    return false;
}

/* Resolve an exported function's RVA by name from IMAGE_EXPORT_DIRECTORY. Returns
 * false if the export directory is absent/short or the name is not found. Layout:
 * NumberOfNames at +24, AddressOfFunctions at +28, AddressOfNames at +32,
 * AddressOfNameOrdinals at +36 (all RVAs). */
inline bool resolve_export_rva(const ImageView &img, const PeHeaders &h,
                               const char *name, uint32_t &out_rva)
{
    if (h.export_dir_rva == 0 || name == nullptr) return false;
    uint32_t exp_off = 0;
    if (!rva_to_file_offset(img, h, h.export_dir_rva, exp_off)) return false;

    uint32_t num_names = 0, funcs_rva = 0, names_rva = 0, ords_rva = 0;
    if (!img.u32(exp_off + 24, num_names)) return false;
    if (!img.u32(exp_off + 28, funcs_rva)) return false;
    if (!img.u32(exp_off + 32, names_rva)) return false;
    if (!img.u32(exp_off + 36, ords_rva)) return false;

    uint32_t names_off = 0, ords_off = 0, funcs_off = 0;
    if (!rva_to_file_offset(img, h, names_rva, names_off)) return false;
    if (!rva_to_file_offset(img, h, ords_rva, ords_off)) return false;
    if (!rva_to_file_offset(img, h, funcs_rva, funcs_off)) return false;

    const size_t want = std::strlen(name);
    for (uint32_t i = 0; i < num_names; ++i) {
        uint32_t name_rva = 0;
        if (!img.u32(names_off + i * 4, name_rva)) return false;
        uint32_t name_str_off = 0;
        if (!rva_to_file_offset(img, h, name_rva, name_str_off)) continue;
        const uint8_t *str = img.ptr(name_str_off, want + 1);
        if (str == nullptr) continue;
        if (std::memcmp(str, name, want) == 0 && str[want] == '\0') {
            uint16_t ordinal = 0;
            if (!img.u16(ords_off + i * 2, ordinal)) return false;
            if (!img.u32(funcs_off + ordinal * 4, out_rva)) return false;
            return true;
        }
    }
    return false;
}

/* Apply base-relocation deltas to a byte window the caller copied from the on-disk
 * image, rewriting any HIGHLOW/DIR64 fixups that fall inside [window_rva,
 * window_rva + window_len) so the bytes match what the loader produced at
 * `live_base`. This is the FP-critical step: an absolute branch target that the
 * loader relocated for ASLR will now agree with the live prologue, so signal 47
 * does not flag a relocation as a patch.
 *
 * `window` is modified in place; `window_rva` is the RVA the window starts at;
 * delta = live_base - preferred_base. Returns true on success (including the
 * no-reloc-needed case); false only on a malformed relocation table. Unknown
 * relocation types other than ABSOLUTE are skipped conservatively (we never write
 * a fixup we do not understand). */
inline bool relocate_window(const ImageView &img, const PeHeaders &h,
                            uint64_t live_base, uint32_t window_rva,
                            uint8_t *window, size_t window_len)
{
    if (h.reloc_dir_rva == 0 || h.reloc_dir_size == 0) {
        return true; /* nothing to relocate */
    }
    const int64_t delta =
        static_cast<int64_t>(live_base) - static_cast<int64_t>(h.preferred_base);
    if (delta == 0) {
        return true; /* loaded at preferred base; on-disk bytes already match */
    }

    uint32_t reloc_off = 0;
    if (!rva_to_file_offset(img, h, h.reloc_dir_rva, reloc_off)) return false;

    const uint32_t window_end_rva = window_rva + static_cast<uint32_t>(window_len);
    uint32_t cursor = reloc_off;
    const uint32_t reloc_end = reloc_off + h.reloc_dir_size;

    while (cursor + 8 <= reloc_end) {
        uint32_t page_rva = 0, block_size = 0;
        if (!img.u32(cursor, page_rva)) return false;
        if (!img.u32(cursor + 4, block_size)) return false;
        if (block_size < 8) return false;          /* malformed: must hold the header */
        if (cursor + block_size > reloc_end) return false;

        const uint32_t entry_count = (block_size - 8) / 2;
        for (uint32_t i = 0; i < entry_count; ++i) {
            uint16_t entry = 0;
            if (!img.u16(cursor + 8 + i * 2, entry)) return false;
            const uint16_t type = static_cast<uint16_t>(entry >> 12);
            const uint16_t offset = static_cast<uint16_t>(entry & 0x0FFF);
            if (type == kRelTypeAbsolute) continue;

            const uint32_t fixup_rva = page_rva + offset;
            if (fixup_rva < window_rva || fixup_rva >= window_end_rva) continue;
            const size_t in_window = fixup_rva - window_rva;

            if (type == kRelTypeDir64) {
                if (in_window + 8 > window_len) continue; /* fixup straddles window edge */
                uint64_t v = 0;
                std::memcpy(&v, window + in_window, 8);
                v = static_cast<uint64_t>(static_cast<int64_t>(v) + delta);
                std::memcpy(window + in_window, &v, 8);
            } else if (type == kRelTypeHighLow) {
                if (in_window + 4 > window_len) continue;
                uint32_t v = 0;
                std::memcpy(&v, window + in_window, 4);
                v = static_cast<uint32_t>(static_cast<int64_t>(v) +
                                          static_cast<int32_t>(delta));
                std::memcpy(window + in_window, &v, 4);
            }
            /* Other types (HIGH/LOW/HIGHADJ/THUMB/RISCV/etc.) are not expected in
             * an x64 prologue window and are skipped rather than mis-applied. */
        }
        cursor += block_size;
    }
    return true;
}

/* A tiny stable hash for the divergent-region fingerprint (region_hash in
 * hk_render_finding). The sensor reports the HASH of the bytes that differ after
 * relocation, never the bytes themselves (privacy + no signature material on the
 * wire). FNV-1a 64-bit — deterministic across client/server, not cryptographic. */
inline uint64_t region_hash(const uint8_t *bytes, size_t len)
{
    uint64_t h = 1469598103934665603ull; /* FNV offset basis */
    for (size_t i = 0; i < len; ++i) {
        h ^= bytes[i];
        h *= 1099511628211ull;           /* FNV prime */
    }
    return h;
}

} } } // namespace hk::sdk::pe
