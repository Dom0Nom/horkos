/*
 * Role: Signal 194 (dynamic-instrumentation / DBI residency fingerprint)
 *       sampler. Read-only, own-process only. Gathers three combined observables
 *       and folds them through the pure confidence-tier core
 *       (instrumentation_confidence_tier, anti_analysis_logic.cpp):
 *         (a) thread starts inside anonymous RX mappings not backed by any module
 *             (an instrumentation runtime maps its agent as anon-RX and runs a
 *             worker thread out of it);
 *         (b) loaded modules whose export table carries a well-known
 *             instrumentation-runtime exported symbol name (client only COUNTS
 *             matches against a small static name table — the server allowlists
 *             and classifies);
 *         (c) Linux only: a listener on the framework's default control port
 *             owned by the process tree (`/proc/net/tcp`).
 *       `jit_module_present` is set when a known JIT runtime module is loaded
 *       (Java/V8/.NET/LuaJIT) — pure FP CONTEXT, reported so the server can
 *       allowlist; it NEVER raises the tier on its own (handled by the pure core).
 *       The sampler reports raw observations only; ALL classification and ban
 *       authority is server-side (no local verdict).
 * Target platforms: cross. Per-observable platform reads are HK_PLATFORM_*-gated
 *       (guardrail #1): Linux uses /proc/self/maps + the per-thread
 *       /proc/self/task stat files + /proc/net/tcp; macOS uses the dyld image
 *       list for the export-name scan
 *       (the thread-start-address walk is an HK-UNCERTAIN stub — see below);
 *       Windows is an HK-UNCERTAIN stub (NtQueryInformationThread is Nt-prefixed
 *       and its ThreadQuerySetWin32StartAddress semantics are not verified here,
 *       guardrails #2/#13). Degenerate input yields a zeroed "no signal" result,
 *       never UB (ARCHITECTURE principle 3).
 * Interface: implements anti_analysis_sample_instrumentation() declared in
 *       horkos/anti_analysis/anti_analysis_signals.h; folds via the pure core in
 *       horkos/anti_analysis/instrumentation.h.
 */

#include "horkos/anti_analysis/anti_analysis_signals.h"
#include "horkos/anti_analysis/instrumentation.h"

#include "platform.h"

#include <cstring>

#if defined(HK_PLATFORM_LINUX)
#  include <cstdio>
#  include <cstdlib>
#  include <dirent.h>
#endif

#if defined(HK_PLATFORM_MACOS)
#  include <mach-o/dyld.h>
#endif

namespace {

/* Well-known instrumentation-runtime exported symbol-name fragments. The client
 * only COUNTS substring matches; the server owns the allowlist/classifier. Kept
 * deliberately small and conservative (a fragment, matched case-sensitively,
 * against a module's path/exported-name set) so a benign module does not trip it.
 * These are the canonical residency markers of the common DBI runtimes. */
const char* const kRuntimeExportFragments[] = {
    "frida",         /* Frida gadget / agent */
    "gum_",          /* Frida's GumJS / gum runtime export prefix */
    "FridaGadget",   /* Frida gadget dylib/so name */
    "DynamoRIO",     /* DynamoRIO core */
    "dynamorio",
    "pin_",          /* Intel Pin pintool runtime */
    "qbdi",          /* QBDI dynamic binary instrumentation */
    "QBDI",
};
const unsigned kRuntimeExportFragmentCount =
    sizeof(kRuntimeExportFragments) / sizeof(kRuntimeExportFragments[0]);

/* Known JIT runtime module-name fragments. Presence is FP CONTEXT only — JIT
 * runtimes also create anon-RX mappings with worker threads, the principal FP
 * for observable (a). Reported via jit_module_present; never scored client-side. */
const char* const kJitModuleFragments[] = {
    "libjvm",        /* Java HotSpot */
    "jvm.dll",
    "node",          /* V8 (Node) */
    "v8",
    "libv8",
    "coreclr",       /* .NET CoreCLR */
    "clrjit",
    "libluajit",     /* LuaJIT */
    "luajit",
    "mono",          /* Mono runtime */
};
const unsigned kJitModuleFragmentCount =
    sizeof(kJitModuleFragments) / sizeof(kJitModuleFragments[0]);

bool name_matches_any(const char* name, const char* const* table, unsigned count) {
    if (name == nullptr) {
        return false;
    }
    for (unsigned i = 0; i < count; ++i) {
        if (std::strstr(name, table[i]) != nullptr) {
            return true;
        }
    }
    return false;
}

} // namespace

#if defined(HK_PLATFORM_LINUX)
namespace {

/* One parsed /proc/self/maps line range. */
struct MapRange {
    uint64_t start;
    uint64_t end;
    bool     exec;        /* 'x' protection bit set */
    bool     file_backed; /* a non-empty pathname column AND not [anon]/[stack]/[heap] */
};

/* PURE: is `addr` inside any file-backed mapping? If it is inside an executable
 * mapping that is NOT file-backed, it is an "unbacked RX" address. Caller passes
 * the parsed range array; this does no I/O so the classification is testable.
 * Retained (currently unreferenced) as the classifier for the pending eBPF entry-IP
 * path: the clone/sched_process_fork hook supplies a captured entry IP that this
 * function classifies against /proc/self/maps — see count_unbacked_rx_threads. */
[[maybe_unused]] bool addr_in_unbacked_rx(uint64_t addr, const MapRange* ranges,
                                          unsigned count) noexcept {
    if (ranges == nullptr || count == 0u) {
        return false;
    }
    for (unsigned i = 0; i < count; ++i) {
        if (addr < ranges[i].start || addr >= ranges[i].end) {
            continue;
        }
        /* Address resolves into this mapping. Unbacked-RX iff executable and not
         * file-backed. A file-backed executable mapping (a real module) is fine. */
        return ranges[i].exec && !ranges[i].file_backed;
    }
    /* Address resolves into no known mapping — conservatively NOT counted (it may
     * be a transient teardown race; never UB, never a guess). */
    return false;
}

/* Read /proc/self/maps into a bounded range table. Returns the number of ranges
 * parsed (capped). Bounds every field; a malformed line is skipped, never UB. */
unsigned read_self_maps(MapRange* out, unsigned cap, bool* any_jit_path) {
    if (out == nullptr || cap == 0u) {
        return 0u;
    }
    std::FILE* f = std::fopen("/proc/self/maps", "re");
    if (f == nullptr) {
        return 0u;
    }
    unsigned n = 0u;
    char line[512];
    while (n < cap && std::fgets(line, sizeof(line), f) != nullptr) {
        uint64_t start = 0, end = 0;
        char perms[8] = {0};
        char path[256] = {0};
        /* maps format: "start-end perms offset dev inode pathname" */
        int got = std::sscanf(line, "%llx-%llx %7s %*x %*x:%*x %*u %255[^\n]",
                              (unsigned long long*)&start,
                              (unsigned long long*)&end, perms, path);
        if (got < 3 || end <= start) {
            continue;
        }
        MapRange r;
        r.start = start;
        r.end = end;
        r.exec = (std::strchr(perms, 'x') != nullptr);
        /* file-backed iff a real pathname (got==4 means the path field matched) and
         * it is an actual file, not a kernel pseudo-region ([heap], [stack], [vdso],
         * anonymous, etc.). */
        const bool has_path = (got == 4 && path[0] != '\0');
        r.file_backed = has_path && path[0] != '[';
        out[n++] = r;
        if (any_jit_path != nullptr && has_path &&
            name_matches_any(path, kJitModuleFragments, kJitModuleFragmentCount)) {
            *any_jit_path = true;
        }
    }
    std::fclose(f);
    return n;
}

/* HK-UNCERTAIN: the unbacked-RX-thread residency observable is NOT implementable
 * via /proc/self/task/<tid>/stat. The thread entry PC is not in stat at all, and
 * the live instruction pointer (field 30, "kstkeip") is intentionally zeroed by the
 * kernel for every non-exiting task: do_task_stat() in fs/proc/array.c only sets
 *   eip = KSTK_EIP(task); esp = KSTK_ESP(task);
 * when (permitted && (task->flags & (PF_EXITING|PF_DUMPCORE))), with the comment
 * "esp and eip are intentionally zeroed out. There is no non-racy way to read them
 * without freezing the task." proc(5) marks fields 29/30 [PT] for the same reason.
 * A prior version walked field 30 as a "conservative proxy" — it reads 0 for every
 * live thread, so it detected nothing while appearing functional. Returning 0 here
 * honestly until the real mechanism lands (an eBPF clone/sched_process_fork hook
 * capturing the entry IP at thread creation — Horkos has the eBPF layer; needs a
 * Linux target to build/attach/validate CO-RE reads, per ARCHITECTURE build matrix).
 * Refs: fs/proc/array.c do_task_stat; man proc_pid_stat(5) fields 28-30. */
unsigned count_unbacked_rx_threads(const MapRange* ranges, unsigned range_count) {
    (void)ranges;
    (void)range_count;
    return 0u;
}

/* Frida's documented default control port (gadget/agent listen port). The client
 * only checks for a listener on this port owned by this process; the server owns
 * any wider allowlist. 27042 is Frida's documented default. */
const uint32_t kFridaDefaultPort = 27042u;

/* Scan /proc/net/tcp for a LISTEN socket bound to kFridaDefaultPort. Returns 1 on
 * a match, 0 otherwise. Read-only text parse, fully bounded. NOTE: this is a
 * coarse process-tree-agnostic check (the inode→pid attribution that would scope
 * it to our tree is not wired here — see HK-UNCERTAIN below); a match is reported
 * raw and the server scopes/weights it. */
uint32_t scan_control_port_listener() {
    std::FILE* f = std::fopen("/proc/net/tcp", "re");
    if (f == nullptr) {
        return 0u;
    }
    char line[512];
    /* Discard header line. */
    if (std::fgets(line, sizeof(line), f) == nullptr) {
        std::fclose(f);
        return 0u;
    }
    uint32_t found = 0u;
    while (std::fgets(line, sizeof(line), f) != nullptr) {
        /* Columns: sl local_address rem_address st ... local_address is
         * "HEXIP:HEXPORT". st == 0A is TCP_LISTEN. */
        unsigned local_port = 0u, st = 0u;
        /* Skip sl and the IP, capture port and state. */
        if (std::sscanf(line, "%*u %*8[0-9A-Fa-f]:%x %*8[0-9A-Fa-f]:%*x %x",
                        &local_port, &st) == 2) {
            if (st == 0x0Au && local_port == kFridaDefaultPort) {
                found = 1u;
                break;
            }
        }
    }
    std::fclose(f);
    return found;
}

} // namespace
#endif /* HK_PLATFORM_LINUX */

int anti_analysis_sample_instrumentation(aa_instrumentation* out) {
    if (out == nullptr) {
        return HK_AC_NOT_IMPLEMENTED;
    }
    std::memset(out, 0, sizeof(*out));

#if defined(HK_PLATFORM_LINUX)
    /* Observable (a): unbacked-RX thread starts. Parse /proc/self/maps once into a
     * bounded range table, then probe each thread's instruction pointer. */
    enum { kMaxRanges = 1024 };
    static MapRange ranges[kMaxRanges];
    bool jit_path = false;
    const unsigned range_count = read_self_maps(ranges, kMaxRanges, &jit_path);
    out->unbacked_rx_threads = count_unbacked_rx_threads(ranges, range_count);

    /* Observable (b): module export-name scan. We approximate the "exported
     * symbol" scan with the module PATHNAME match from /proc/self/maps (the gadget
     * dylib/so name itself carries the runtime fragment). A full export-table walk
     * needs the shared ELF module-map backend (not present); the path match is the
     * verifiable subset and the server reconciles. */
    {
        uint32_t matches = 0u;
        /* Re-read maps capturing only matching module pathnames to count distinct
         * runtime-export modules (the parsed range table above does not retain the
         * pathname column). Bounded re-read. */
        std::FILE* f = std::fopen("/proc/self/maps", "re");
        if (f != nullptr) {
            char line[512];
            char last_match[256] = {0};
            while (std::fgets(line, sizeof(line), f) != nullptr) {
                char path[256] = {0};
                if (std::sscanf(line, "%*llx-%*llx %*7s %*x %*x:%*x %*u %255[^\n]",
                                path) == 1 && path[0] == '/') {
                    if (name_matches_any(path, kRuntimeExportFragments,
                                         kRuntimeExportFragmentCount) &&
                        std::strcmp(path, last_match) != 0) {
                        ++matches;
                        std::strncpy(last_match, path, sizeof(last_match) - 1);
                    }
                }
            }
            std::fclose(f);
        }
        out->runtime_export_match = matches;
    }

    /* Observable (c, Linux only): control-port listener. */
    out->control_port_listener = scan_control_port_listener();

    out->jit_module_present = jit_path ? 1u : 0u;

    out->confidence_tier = hk::anti_analysis::instrumentation_confidence_tier(
        out->unbacked_rx_threads, out->runtime_export_match,
        out->control_port_listener, out->jit_module_present);
    return HK_AC_OK;

#elif defined(HK_PLATFORM_MACOS)
    /* Observable (b): loaded-module name scan via the dyld image list. This is the
     * verifiable macOS observable — _dyld_get_image_name is documented and
     * read-only. We count modules whose path carries a runtime-export fragment and
     * set jit_module_present from the same list. */
    uint32_t matches = 0u;
    bool jit = false;
    const uint32_t img_count = _dyld_image_count();
    for (uint32_t i = 0; i < img_count; ++i) {
        const char* name = _dyld_get_image_name(i);
        if (name == nullptr) {
            continue;
        }
        if (name_matches_any(name, kRuntimeExportFragments,
                             kRuntimeExportFragmentCount)) {
            ++matches;
        }
        if (name_matches_any(name, kJitModuleFragments, kJitModuleFragmentCount)) {
            jit = true;
        }
    }
    out->runtime_export_match = matches;
    out->jit_module_present = jit ? 1u : 0u;

    /* HK-UNCERTAIN(macos-thread-start): a reliable, ptrace-free read of each
     * thread's START address (vs its current PC) is not available — task_threads +
     * thread_get_state returns the current register state, not the entry point, and
     * mapping that to an "unbacked anon-RX agent thread" under the hardened runtime
     * is not verified here (guardrail #13). Left at 0 (no signal) rather than
     * guessing; the export-name observable still drives the tier. */
    out->unbacked_rx_threads = 0u;

    /* macOS has no /proc/net/tcp; control-port enumeration via the (private) proc
     * socket APIs is not verified here — leave at 0 (no signal), not a guess. */
    out->control_port_listener = 0u;

    out->confidence_tier = hk::anti_analysis::instrumentation_confidence_tier(
        out->unbacked_rx_threads, out->runtime_export_match,
        out->control_port_listener, out->jit_module_present);
    return HK_AC_OK;

#else /* HK_PLATFORM_WINDOWS or other */
    /* HK-UNCERTAIN(win-thread-start): the Windows thread-start-address read is
     * NtQueryInformationThread(ThreadQuerySetWin32StartAddress) — an Nt-prefixed,
     * undocumented information class whose exact semantics and the shared PE
     * module-map / VA-range resolver this sampler would reuse are not present here
     * (guardrails #2/#13). The Windows variant also folds kernel ObRegisterCallbacks
     * handle-open records, which is not wired in this TU. Rather than guess, the
     * Windows sampler returns NOT_IMPLEMENTED with a zeroed result; the aggregator
     * clears the instrumentation sensors_ok bit. The live Windows body lands when
     * the module-map backend + the verified Nt info-class semantics are confirmed. */
    return HK_AC_NOT_IMPLEMENTED;
#endif
}
