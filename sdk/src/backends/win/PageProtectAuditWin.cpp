/*
 * sdk/src/backends/win/PageProtectAuditWin.cpp
 * Role: Windows userspace page-protection audit (win-handle-memory-access, catalog
 *       signal 71). One tick: VirtualQueryEx-sweep the game's MEM_IMAGE code regions
 *       and compare each region's live MEMORY_BASIC_INFORMATION.Protect against the
 *       PE section characteristics cached for that VA. The high-confidence case is
 *       RWX on a section shipped as RX (write-was-added to executable code). Read-only;
 *       reported at low base confidence and fused server-side with a coinciding kernel
 *       ProtectVm event (HK_PROT_FOREIGN_INITIATED). Ships dark (HK_WIN_VMWATCH OFF).
 * Target platforms: Windows userspace. Guardrail #1: VirtualQueryEx and the PE-header
 *       walk are confined here; the protect_is_drift / classify_target_section cores
 *       are platform-free in VmWatchWin.h / VmAccessLogicWin.h and host-tested.
 * Interface: implements hk::sdk::vmaccess::sample_page_protect from VmWatchWin.h.
 */

#include "VmWatchWin.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <windows.h>

#include <vector>

namespace hk { namespace sdk { namespace vmaccess {

namespace {

/* Max sections we read from one module header. A real PE rarely exceeds ~32; the cap
 * bounds the fixed scratch array so the SEH-guarded read does no allocation. */
constexpr WORD kMaxModuleSections = 96;

/* Read up to kMaxModuleSections section ranges from a module's in-memory PE headers
 * into the caller's fixed array; returns the count read (0 on any malformed/torn
 * image). The DOS/NT headers + IMAGE_SECTION_HEADER table are public, documented
 * layout (winnt.h). The structured-exception guard wraps ONLY the raw header reads
 * into POD scratch — no C++ object with a destructor and no allocation occurs inside
 * __try (avoids MSVC C2712 object-unwinding restrictions); the vector push happens in
 * the caller, outside the guard. */
WORD ReadModuleSections(HMODULE mod, SectionRange *out, WORD cap)
{
    if (mod == nullptr || out == nullptr || cap == 0) {
        return 0;
    }
    WORD produced = 0;
    __try {
        const auto base = reinterpret_cast<const BYTE *>(mod);
        const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            return 0;
        }
        const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            return 0;
        }
        const IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
        WORD count = nt->FileHeader.NumberOfSections;
        if (count > cap) {
            count = cap;
        }
        for (WORD i = 0; i < count; ++i) {
            const IMAGE_SECTION_HEADER &s = sec[i];
            SectionRange r{};
            r.base = reinterpret_cast<uint64_t>(base) + s.VirtualAddress;
            /* Misc.VirtualSize is the section's loaded size; fall back to SizeOfRawData
             * if VirtualSize is zero (some toolchains emit 0 for it). */
            r.size = s.Misc.VirtualSize != 0 ? s.Misc.VirtualSize : s.SizeOfRawData;
            r.characteristics = s.Characteristics; /* IMAGE_SCN_* directly */
            out[produced++] = r;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* A malformed/torn image yields no ranges; the audit then classifies its VAs
         * as "not in a tracked section" (no false drift). */
        return 0;
    }
    return produced;
}

/* Append one module's section ranges (those with non-zero size) to the cache vector.
 * The vector push is outside the SEH region (see ReadModuleSections). */
void AppendModuleSections(HMODULE mod, std::vector<SectionRange> &out)
{
    SectionRange scratch[kMaxModuleSections];
    const WORD n = ReadModuleSections(mod, scratch, kMaxModuleSections);
    for (WORD i = 0; i < n; ++i) {
        if (scratch[i].size != 0) {
            out.push_back(scratch[i]);
        }
    }
}

} // namespace

/* -------------------------------------------------------------------------
 * HK-UNCERTAIN(self-vs-foreign-process-walk): VirtualQueryEx and in-memory PE
 * header access for the own process are fully documented. EnumProcessModulesEx
 * is also documented (requires PROCESS_QUERY_INFORMATION | PROCESS_VM_READ on the
 * target; ref: https://learn.microsoft.com/windows/win32/api/psapi/nf-psapi-enumprocessmodulesex).
 * The LIST_MODULES_32BIT / LIST_MODULES_64BIT flags for WOW64 targets are documented
 * in the same MSDN page. What is NOT settled is the on-box behavior in the presence
 * of concurrent module loads (churn between EnumProcessModulesEx and the PE-header
 * read) on the target Win11 25H2 build, and the correct WOW64 thunk-page handling
 * for 32-bit modules. For the in-process case AppendModuleSections above is exact.
 * The cross-process module enumeration is the documented stub below; the protection
 * compare + the pure cores are real.
 * (docs: EnumProcessModulesEx access rights and WOW64 flags documented — still needs
 * on-box validation of module-churn + WOW64 section-seeding behavior)
 * ------------------------------------------------------------------------- */
int sample_page_protect(uint32_t game_pid)
{
    std::vector<SectionRange> cache;

    /* In-process seeding (exact): the game's OWN main module sections. The AC ships
     * inside the protected process, so GetModuleHandle(NULL) is the game image and
     * its +X sections are the W^X-expected regions. Cross-process seeding for a
     * separate game pid is the HK-UNCERTAIN stub above. */
    AppendModuleSections(GetModuleHandleW(nullptr), cache);
    if (cache.empty()) {
        return -1; /* could not seed any shipped-section ranges -> no-signal */
    }

    int findings = 0;
    HANDLE self = GetCurrentProcess();

    /* Sweep each cached +X section's region and compare live protection. Only
     * executable shipped sections matter for the W^X drift check; classify_target_section
     * + protect_is_drift do the actual decision (host-tested). */
    for (const SectionRange &s : cache) {
        if (!target_is_executable(s.characteristics)) {
            continue;
        }
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T got = VirtualQueryEx(self, reinterpret_cast<LPCVOID>(s.base),
                                    &mbi, sizeof(mbi));
        if (got != sizeof(mbi)) {
            continue; /* unreadable region -> skip, never fabricate a finding */
        }
        ProtectDriftInput in{};
        in.live_protect = mbi.Protect;
        in.section_flags = classify_target_section(cache, s.base);
        uint32_t flags = 0;
        if (protect_is_drift(in, &flags)) {
            /* Queue an hk_event_protect_drift finding (region_base, live_protect,
             * expected_protect, flags). HK-TODO(schema): the report-queue type is the
             * kernel-private mirror until the Schema phase appends HK_EVENT_PROTECT_DRIFT
             * to event_schema.h; the server fuses HK_PROT_FOREIGN_INITIATED when a
             * kernel ProtectVm event coincides. */
            ++findings;
        }
    }
    return findings;
}

} } } // namespace hk::sdk::vmaccess

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
