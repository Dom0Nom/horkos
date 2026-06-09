/*
 * kernel/linux/userspace/SymbolMap.h
 * Role: Shared, refreshed-per-cycle view of the running kernel's text layout —
 *       the _stext.._etext core range and per-module .text bounds — built ONCE
 *       per audit cycle from /proc/kallsyms + /proc/iomem + /sys/module/<m>/
 *       sections/.text, and consumed by the kallsyms (91), ftrace (93) and
 *       kprobe (94) auditors so the three do not each re-parse kallsyms. This is
 *       the single source of truth for "which loaded object owns address X".
 * Target platform: Linux userspace (guardrail #4 — never shares a TU with any
 *                   BPF/kernel object; pure procfs/sysfs text parsing). No
 *                   platform #ifdef (guardrail #1; Linux isolation is by
 *                   directory + CMake CMAKE_SYSTEM_NAME).
 * Interface: declares HkSymbolMap (the built view) plus pure parse helpers that
 *            take captured file CONTENT (so they are fixture-testable on any
 *            host) and a thin BuildFromProc() convenience that reads the live
 *            procfs/sysfs. Audit-only / read-only.
 */

#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace horkos::modint {

/* A half-open [lo, hi) address range owned by a named object. `name` is empty
 * for the kernel core range. */
struct TextRange {
    uint64_t lo = 0;
    uint64_t hi = 0;
    std::string owner;   /* module name, or "" for the kernel core text */
};

/* The per-cycle text-layout snapshot. `core_valid` is false when kallsyms /
 * iomem addresses were zeroed by kptr_restrict (CAP_SYSLOG missing); callers
 * MUST treat an invalid map as a coverage gap (emit SENSOR_UNAVAILABLE), never
 * as drift. */
struct HkSymbolMap {
    bool core_valid = false;
    TextRange core;                      /* _stext.._etext */
    std::vector<TextRange> modules;      /* per-module .text ranges */

    /* Symbol-name -> resolved address, for the small sensitive-symbol set the
     * auditors care about (commit_creds, prepare_kernel_cred, the syscall-entry
     * functions, module-sig verify, etc.). Only sensitive symbols are retained;
     * the full table is not held (memory + PII minimisation). */
    std::map<std::string, uint64_t> sensitive_addr;

    /* True if every retained sensitive address parsed as non-zero. A zeroed
     * address means kptr_restrict hid it → coverage gap, not a detection. */
    bool addrs_visible = false;

    /* Return the owner range covering `addr`, or nullptr if none. Checks the
     * core range first, then each module range. */
    const TextRange* OwnerOf(uint64_t addr) const;

    /* True when `addr` falls inside the kernel core text or any module text. */
    bool InAnyText(uint64_t addr) const;
};

/* The sensitive kernel-symbol set this domain watches. Interned to a stable
 * index (func_id / symbol_id in the wire payloads) shared with the server. The
 * order is the wire contract: never reorder, only append. */
enum HkSensitiveSymbol : uint32_t {
    HK_SYM_COMMIT_CREDS        = 0,
    HK_SYM_PREPARE_KERNEL_CRED = 1,
    HK_SYM_SYS_EXECVE          = 2,   /* __x64_sys_execve */
    HK_SYM_SYS_EXECVEAT        = 3,
    HK_SYM_SYS_PTRACE          = 4,
    HK_SYM_MODULE_SIG_CHECK    = 5,   /* mod_verify_sig / module_sig_check */
    HK_SYM_SECURITY_BPRM_CHECK = 6,
    HK_SYM_KALLSYMS_LOOKUP     = 7,
    HK_SYM__COUNT              = 8,
};

/* Names matching the interned set, index-aligned with HkSensitiveSymbol. */
const std::vector<std::string>& HkSensitiveSymbolNames();

/* Map a symbol name to its interned index, or HK_SYM__COUNT if not sensitive. */
uint32_t HkSensitiveSymbolId(const std::string& name);

/* ---- Pure parsers (fixture-testable; take captured CONTENT) ---------------- */

/* Parse the "Kernel code" resource line from /proc/iomem content into the core
 * [lo, hi) range. Matches by RESOURCE NAME ("Kernel code"), not index (ordering
 * is not stable). Returns true and fills `out` on success; returns false if the
 * resource is absent OR its addresses are zeroed (kptr_restrict) — the caller
 * treats false as a coverage gap. */
bool ParseIomemKernelCode(const std::string& iomem_content, TextRange* out);

/* Parse /proc/kallsyms content. Retains only the sensitive-symbol addresses
 * (into out->sensitive_addr) and sets out->addrs_visible. Module-attributed
 * symbols ("... [modname]") are ignored here — per-module .text bounds come from
 * sysfs (ParseModuleSectionText) which is authoritative for module ranges.
 * Returns false only on an empty/garbage capture. */
bool ParseKallsymsSensitive(const std::string& kallsyms_content, HkSymbolMap* out);

/* Parse a single /sys/module/<m>/sections/.text value (one hex address) into a
 * module .text START. The section file carries only the start address; the END
 * is bounded by the next module's start or by an over-approximation, so the
 * caller pairs starts across modules. Returns false if the value is zeroed or
 * unparseable. */
bool ParseModuleSectionText(const std::string& name,
                            const std::string& section_value,
                            uint64_t* out_start);

/* ---- Live builder (reads procfs/sysfs) ------------------------------------ */

/* Build the map from the live /proc + /sys filesystem. Returns a map whose
 * core_valid / addrs_visible flags reflect what was actually readable; a
 * permission/ENOENT failure degrades a field rather than aborting. `proc_root`
 * and `sys_root` default to "/proc" and "/sys"; tests can repoint them at a
 * fixture tree. */
HkSymbolMap BuildFromProc(const std::string& proc_root = "/proc",
                          const std::string& sys_root = "/sys");

}  // namespace horkos::modint
