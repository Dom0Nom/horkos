/*
 * ac/src/selfcheck/image_baseline.cpp
 * Role: The single "what disk says" source for client self-integrity. Parses our
 *       OWN backing file once at init (PE on Windows, ELF on Linux, Mach-O on macOS;
 *       format dispatched by HK_PLATFORM_*), recording expected code-section ranges,
 *       on-disk SHA-256 of code sections, and expected (pre-ASLR) IAT/TLS/unwind
 *       table RVAs. Read-only file parse; feeds signals 145/149/150/151/153.
 * Target platforms: all (format dispatch via HK_PLATFORM_*; no raw _WIN32/__linux__/
 *       __APPLE__ — guardrail #1). Compiled into hk_ac.
 * Interface: defines hk::selfcheck::ImageBaseline (forward-declared in selfcheck.h)
 *       and its loader; the orchestrator passes it to SelfCheck::arm().
 */

#include "horkos/selfcheck.h"
#include "pe_parse.h"

/* platform.h owns the HK_PLATFORM_* selection (guardrail #1). We branch on those
 * macros only — never the raw compiler predefines. */
#include "platform.h"

#include <cstdint>
#include <cstring>

namespace hk {
namespace selfcheck {

/* Definition of the opaque baseline. Holds the cached disk view the sensors compare
 * the live image against. Sized for one image (our own); no heap. */
struct ImageBaseline {
    bool     valid = false;
    uint64_t preferred_base = 0;   /* on-disk preferred load base (for relocation math) */
    uint32_t size_of_image = 0;
    uint32_t text_rva = 0;         /* first executable section RVA */
    uint32_t text_size = 0;        /* its virtual size */
    uint32_t entry_point_rva = 0;
    uint8_t  text_sha256[32] = {}; /* on-disk SHA-256 of the relocated-to-zero code */
    bool     text_sha256_valid = false;

    /* Expected (pre-ASLR) data-directory RVAs the format sensors re-derive against. */
    uint32_t import_dir_rva = 0;
    uint32_t tls_dir_rva = 0;
    uint32_t exception_dir_rva = 0;
};

namespace {

#if defined(HK_PLATFORM_WINDOWS)
/* Populate the baseline from a PE backing file already mapped at buf/len.
 * Pure over the buffer (the file read itself routes through a platform backend —
 * see HK-TODO below). */
bool fill_from_pe(ImageBaseline& bl, const uint8_t* buf, size_t len) noexcept {
    const pe::Headers h = pe::parse(buf, len);
    if (!h.valid) {
        return false;
    }
    bl.preferred_base = h.image_base;
    bl.size_of_image = h.size_of_image;
    bl.entry_point_rva = h.entry_point_rva;
    bl.import_dir_rva = h.dirs[pe::HK_DIR_IMPORT].rva;
    bl.tls_dir_rva = h.dirs[pe::HK_DIR_TLS].rva;
    bl.exception_dir_rva = h.dirs[pe::HK_DIR_EXCEPTION].rva;

    const pe::SectionRange* text = pe::first_exec_section(h);
    if (text != nullptr) {
        bl.text_rva = text->rva;
        bl.text_size = text->virtual_size;
    }
    /* HK-TODO(145-hash): compute text_sha256 over the disk bytes relocated to a
     * zero base, so View C matches the live image after rebasing. The SHA-256
     * primitive + the relocation walk land with text_crossview.cpp's disk view;
     * left uncomputed here so the baseline does not ship a hash it cannot yet
     * relocate correctly (a wrong relocation would forge a false 145 divergence —
     * same hazard the kernel ImageHashAudit flags). */
    bl.text_sha256_valid = false;
    bl.valid = (text != nullptr);
    return bl.valid;
}
#endif

} // namespace

/* Load the baseline from our own backing image. The actual file-read of our own
 * module path is a platform operation; it routes through the platform backend
 * (guardrail #1). Until that read shim lands this returns an INVALID baseline, so
 * SelfCheck::arm() stays disarmed and run_once() emits nothing (fail-closed) rather
 * than parsing an empty buffer.
 *
 * HK-TODO(self-image-read): add platform::read_self_image(buf, cap) to platform.h
 * (Win: GetModuleFileName + ReadFile of our own .exe/.dll; Linux: /proc/self/exe
 * pread; macOS: _dyld_get_image_name(0) + pread). Once present, map our backing
 * file and dispatch to the format parser below. */
bool image_baseline_load(ImageBaseline& out) noexcept {
    out = ImageBaseline{};

#if defined(HK_PLATFORM_WINDOWS)
    /* HK-TODO(self-image-read): read our own PE file into a buffer, then
     * fill_from_pe(out, buf, len). Stubbed invalid until the read shim lands. */
    (void)&out;  /* fill_from_pe referenced once the read shim provides a buffer */
    return false;
#elif defined(HK_PLATFORM_LINUX)
    /* HK-TODO(elf-baseline): parse /proc/self/exe (ELF): PT_LOAD r-x segment ->
     * text range; .init_array (DT_INIT_ARRAY) -> tls/init table; .rela.plt/.got.plt
     * -> import table; .eh_frame -> unwind. Mirror fill_from_pe's shape with an ELF
     * parser. Not implemented host-side here; returns invalid. */
    return false;
#elif defined(HK_PLATFORM_MACOS)
    /* HK-TODO(macho-baseline): parse our own Mach-O (_dyld_get_image_header(0) /
     * on-disk file): __TEXT,__text range; __DATA,__mod_init_func; __la_symbol_ptr /
     * __got; compact-unwind. Mirror fill_from_pe's shape. The daemon already has a
     * Mach-O __TEXT parser (daemon/macos/HKTextIntegrity.cpp) to model after.
     * Returns invalid host-side here. */
    return false;
#else
    return false;
#endif
}

} // namespace selfcheck
} // namespace hk
