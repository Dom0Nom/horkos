/*
 * Role: The stable self-check interface the detection catalog names for client
 *       self-integrity (memory-integrity-selfcheck, catalog signals 145-153).
 *       Declares the hk::selfcheck orchestrator (SelfCheck::arm/run_once/last_flag),
 *       the shared ImageBaseline, the per-signal pure decision cores, and the
 *       HK_GUARD_ENTRY macro for signal 147. Backends change behind this header;
 *       the header itself does not (guardrail #10).
 * Target platforms: all (cross-platform C++ header; pure declarations + the
 *       platform-free decision cores). Included by ac.cpp and every selfcheck TU.
 * Interface: this IS the self-integrity sensor surface; the ac/src/selfcheck TUs
 *       implement it. No platform API in this header (guardrail #1); the wire
 *       structs it references are the local HK-TODO(schema) mirrors in
 *       ac/src/selfcheck/self_wire.h until the Schema phase lands them.
 */

#pragma once

#include <cstddef>
#include <cstdint>

namespace hk {
namespace selfcheck {

/* -------------------------------------------------------------------------
 * Detection-catalog signal ids covered by this domain. Used as guarded_fn_id
 * / report tags; NOT wire event-type values (those live in the schema mirror).
 * ------------------------------------------------------------------------- */
enum class Signal : uint32_t {
    CrossView   = 145,
    PageCow     = 146,
    RetAddr     = 147,
    HwBp        = 148,
    IatTarget   = 149,
    VehUnwind   = 150,
    Loader      = 151,
    WxDrift     = 152,
    TlsInit     = 153,
};

/* last_flag() bitmask. One bit per signal that produced raw evidence this pass.
 * Consumed by ac_get_last_flag() so the Phase-5 bypass tests can assert a sensor
 * fired WITHOUT any client-side ban (all ban authority is server-side). These are
 * "evidence was emitted", never "player is cheating". */
enum LastFlag : uint32_t {
    HK_SELF_FLAG_NONE       = 0u,
    HK_SELF_FLAG_CROSSVIEW  = 1u << 0,  /* 145 */
    HK_SELF_FLAG_PAGE_COW   = 1u << 1,  /* 146 */
    HK_SELF_FLAG_RETADDR    = 1u << 2,  /* 147 */
    HK_SELF_FLAG_HWBP       = 1u << 3,  /* 148 */
    HK_SELF_FLAG_IAT_TARGET = 1u << 4,  /* 149 */
    HK_SELF_FLAG_VEH_UNWIND = 1u << 5,  /* 150 */
    HK_SELF_FLAG_LOADER     = 1u << 6,  /* 151 */
    HK_SELF_FLAG_WX_DRIFT   = 1u << 7,  /* 152 */
    HK_SELF_FLAG_TLS_INIT   = 1u << 8,  /* 153 */
};

/* -------------------------------------------------------------------------
 * 145 cross-view match matrix bits. Set bit = the two views AGREE.
 * The server flags on DISAGREEMENT (per the catalog FP gates), never on the
 * spoofable in-process view alone.
 * ------------------------------------------------------------------------- */
enum MatchMatrix : uint32_t {
    HK_SELF_MATCH_INPROC_KERNEL = 1u << 0, /* in-process hash == kernel foreign-read hash */
    HK_SELF_MATCH_KERNEL_DISK   = 1u << 1, /* kernel hash == relocated on-disk hash        */
    HK_SELF_MATCH_INPROC_DISK   = 1u << 2, /* in-process hash == relocated on-disk hash     */
};

/* 149 target_flags (one flagged IAT/GOT slot per record). */
enum TargetFlags : uint32_t {
    HK_SELF_TGT_PRIVATE      = 1u << 0, /* slot target is in MEM_PRIVATE / non-image memory */
    HK_SELF_TGT_UNSIGNED     = 1u << 1, /* owning module is unsigned / not cert-pinned       */
    HK_SELF_TGT_WRONG_MODULE = 1u << 2, /* resolved into a module other than the expected one */
    HK_SELF_TGT_DISPLACED    = 1u << 3, /* in expected module but != recomputed export VA     */
    HK_SELF_TGT_FORWARDER    = 1u << 4, /* benign: target is a documented export forwarder     */
};

/* 149 import_class — only security-relevant imports are audited (catalog FP gate). */
enum ImportClass : uint32_t {
    HK_SELF_IMPCLASS_OTHER       = 0u,
    HK_SELF_IMPCLASS_NT          = 1u, /* Nt / Zw syscall stubs            */
    HK_SELF_IMPCLASS_CRYPTO      = 2u, /* bcrypt/crypt32/openssl           */
    HK_SELF_IMPCLASS_FILE        = 3u, /* file/section/mapping APIs        */
    HK_SELF_IMPCLASS_ATTESTATION = 4u, /* TPM / attestation surface        */
};

constexpr uint32_t HK_SELF_MAX_FRAMES = 16u;
constexpr uint16_t HK_SELF_FRAME_NONE = 0xFFFFu; /* unsigned_frame_idx sentinel */

/* -------------------------------------------------------------------------
 * ImageBaseline — the single "what disk says" source. Parsed once at arm time
 * from our OWN backing file (PE / ELF / Mach-O, format dispatched by
 * HK_PLATFORM_*). Records expected code-section ranges, on-disk SHA-256 of code
 * sections, and the expected (pre-ASLR) IAT/TLS/unwind table RVAs. Feeds
 * 145/149/150/151/153. Read-only; never mutates after arm().
 *
 * This is a forward-declared opaque type here; its layout lives in
 * ac/src/selfcheck/image_baseline.cpp's translation unit so this header pulls in
 * no format headers. The orchestrator holds one by value through a small handle.
 * ------------------------------------------------------------------------- */
struct ImageBaseline;

/* Returns true if the baseline was successfully parsed and is usable. Callers
 * that hold only a forward-declared reference use this rather than accessing the
 * struct's valid field directly. Implemented in image_baseline.cpp. */
bool image_baseline_valid(const ImageBaseline& bl) noexcept;

/* -------------------------------------------------------------------------
 * 147 critical-function entry guard. Annotated for obfuscation (guardrail #9):
 * this is exactly an init/integrity/attestation symbol, NOT the game hot loop.
 * The annotate attribute is consumed by the opt-in LLVM-19 pass; on toolchains
 * without it the attribute is ignored (still valid C++).
 * ------------------------------------------------------------------------- */
#if defined(__clang__) || defined(__GNUC__)
#  define HK_SELF_ANNOTATE_OBFUSCATE __attribute__((annotate("hk_obfuscate")))
#else
#  define HK_SELF_ANNOTATE_OBFUSCATE
#endif

#define HK_GUARD_ENTRY(fn_id) ::hk::selfcheck::guard_entry((fn_id))
void guard_entry(uint32_t fn_id) HK_SELF_ANNOTATE_OBFUSCATE;

/* -------------------------------------------------------------------------
 * Orchestrator. Owns the scan cadence/budget, calls each sensor, batches raw
 * evidence into the large-record drain path, and feeds ac_get_last_flag.
 * Pure glue; no platform API in this class. Construction does nothing; arm()
 * caches disk state; run_once() does one budgeted pass over 145-153.
 * ------------------------------------------------------------------------- */
class SelfCheck {
public:
    SelfCheck() noexcept;
    ~SelfCheck();

    SelfCheck(const SelfCheck&) = delete;
    SelfCheck& operator=(const SelfCheck&) = delete;

    /* Parse our own backing image once; cache expected tables. Returns true on a
     * usable baseline. A failed parse leaves the orchestrator disarmed: run_once()
     * then emits nothing rather than guessing (fail-closed). */
    bool arm(const ImageBaseline& baseline) noexcept;

    /* One budgeted pass over signals 145-153. Returns the number of raw-evidence
     * records emitted this pass. Safe to call repeatedly on a worker thread; never
     * blocks a kernel-callback context (it runs on its own AC worker). */
    int run_once() noexcept;

    /* Most-recent evidence bitmask (LastFlag). Feeds ac_get_last_flag. */
    uint32_t last_flag() const noexcept;

private:
    bool     armed_;
    uint32_t last_flag_;
};

/* =========================================================================
 * Pure per-signal decision cores. These take already-sampled inputs (hashes,
 * resolved targets, table snapshots) and return the raw classification the
 * sensor ships. They contain NO platform API and NO I/O, so they are unit-
 * tested host-side — the "factor the divergence/attribution decision logic out
 * of the sensor TUs into pure functions" requirement. None of them decides a
 * ban.
 * ========================================================================= */

/* 145: given the three SHA-256s, compute the agreement matrix. A null pointer
 * for a view means that view was unavailable (e.g. kernel read refused) — its
 * comparison bits are left clear (treated as "not equal / unknown"), so an
 * unavailable kernel read never manufactures a false "in-process clean" pass. */
uint32_t crossview_match_matrix(const uint8_t* hash_inproc,
                                const uint8_t* hash_kernel,
                                const uint8_t* hash_disk) noexcept;

/* 145: classify whether the divergence pattern is an inline patch (in-process
 * diverges, kernel==disk) vs a CoW/redirect (in-process==disk, kernel diverges)
 * vs all-agree. Returned as a small enum for the server FP gate; purely derived
 * from match_matrix. */
enum class CrossViewClass : uint32_t {
    AllAgree     = 0, /* nothing to report */
    InlinePatch  = 1, /* inproc != (kernel==disk): a self-read-restoring hook */
    KernelDiverge= 2, /* (inproc==disk) != kernel: kernel sees a different page */
    Inconsistent = 3, /* no two agree — escalate as raw evidence, server decides */
};
CrossViewClass crossview_classify(uint32_t match_matrix) noexcept;

/* 146: decide whether a page-share report carries reportable evidence. Pure
 * threshold over the sampled counts; the FP allow-list (apphelp/shim, signed
 * hotpatch) is server-side, so this only answers "any code page went
 * private/dirty". */
bool page_cow_has_evidence(uint32_t private_pages, uint32_t dirty_pages) noexcept;

/* 147: frame-attribution. Given each captured frame's owning-module range and
 * whether that module is signed, decide if the IMMEDIATE caller frame is an
 * unsigned/private frame (the narrow, low-FP rule). Returns the index of the
 * first unsigned/private frame, or HK_SELF_FRAME_NONE. Deep JIT frames below the
 * immediate caller do NOT trip it (immediate-caller rule). */
uint16_t retaddr_first_unsigned_frame(const uint8_t* frame_is_signed,
                                      uint16_t frame_count) noexcept;

/* 148: bit i set iff DRi is enabled in dr7 AND its linear address lands inside
 * [text_base, text_base+text_size). The trustworthy DR values are kernel-side;
 * this is the pure range test over them. */
uint32_t hwbp_in_text_mask(const uint64_t dr[4], uint32_t dr7,
                           uint64_t text_base, uint64_t text_size) noexcept;

/* 149: classify one resolved IAT/GOT slot. Inputs are already-resolved facts
 * (target VA, the expected recomputed export VA, owning-module signedness,
 * whether the target is image-backed, whether it is a forwarder). Returns the
 * TargetFlags bitmask; 0 means the slot is clean. */
uint32_t iat_target_flags(uint64_t slot_target_va,
                          uint64_t expected_va,
                          uint64_t expected_module_base,
                          uint64_t expected_module_size,
                          bool target_in_image,
                          bool owning_module_signed,
                          bool is_forwarder) noexcept;

/* 150: VEH ordering. Given the index of OUR registered VEH within the handler
 * list (we register first, then re-read ordering — the hook-free approach), and
 * whether any foreign handler is ordered ahead of ours, decide if a hijack is
 * present. our_index==0 with no foreign-ahead is clean. */
bool veh_handler_ordered_ahead(uint32_t our_handler_index,
                               bool foreign_handler_ahead) noexcept;

/* 153: TLS/init table compare result. Distinguishes "clean" from "unavailable"
 * so callers can apply the correct evidence rule: absence of data is NEVER
 * evidence of tampering (Unavailable is never escalated as a detection signal). */
enum class TlsTamperResult : uint32_t {
    Clean       = 0, /* all checks passed */
    Tampered    = 1, /* a pointer mismatch or count delta was found */
    Unavailable = 2, /* comparison tables were null — no data, not a verdict */
};

/* 153: TLS/init table compare. Returns Clean when all pointer and count checks
 * pass, Tampered when the live count differs from disk or any pointer diverges or
 * any PC falls outside our text, and Unavailable when the pointer tables are null
 * and no comparison is possible. Absence of data is never evidence of tampering. */
TlsTamperResult tls_table_tampered(uint32_t live_count, uint32_t disk_count,
                                   const uint64_t* live_rebased,
                                   const uint64_t* expected_rebased,
                                   uint32_t compare_count,
                                   const uint8_t* live_pc_in_text) noexcept;

} // namespace selfcheck
} // namespace hk
