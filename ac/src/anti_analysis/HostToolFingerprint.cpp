/*
 * Role: Signal 197 (memory-editor / debugger host fingerprint) sampler,
 *       Windows. Three read-only host enumerations:
 *         (a) EnumWindows + RealGetWindowClassW against a static table of known
 *             debugger / memory-editor top-level window classes;
 *         (b) object-manager namespace probe (NtOpenDirectoryObject +
 *             NtQueryDirectoryObject over \Device and \GLOBAL??) against known
 *             editor device / symlink names;
 *         (c) EnumDeviceDrivers + GetDeviceDriverBaseNameW against known editor
 *             helper driver base names, with byovd_driver_match set when a loaded
 *             driver matches the known-bad helper set mirrored from the kernel
 *             whitelist (kernel/win/src/Whitelist.c).
 *       The raw hit counts/flags are folded through the pure severity-tier core
 *       (host_tools_severity_tier) into the aa_host_tools result. Read-only
 *       enumeration only — no injection, no tampering. Every API call is checked;
 *       a failed/degenerate enumeration yields zero counts, never UB.
 *
 *       opened_handle_to_game is NOT determined here: it is folded from the
 *       kernel ObRegisterCallbacks handle-open records, which arrive via the SDK
 *       IOCTL drain bridge (HK_IOCTL_DRAIN_EVENTS). That drain envelope decode
 *       shares the device-handle path that lands with the schema bump (see
 *       ac/src/timing/timing_kernel_correlate.cpp precedent: the drained record
 *       type is not yet a distinct, server-understood schema type), so this
 *       sampler leaves opened_handle_to_game == 0 and ac.cpp folds the drained
 *       handle-open records in once that plumbing lands. No new IOCTL path is
 *       built here.
 * Target platforms: Windows only. This TU is compiled ONLY when targeting
 *       Windows (gated in ac/CMakeLists.txt under if(WIN32) like the other
 *       win-only sources); the #if HK_PLATFORM_WINDOWS guard below additionally
 *       makes a stray host compile a link-safe no-op rather than a hard error.
 *       Off Windows the C entry's not-implemented path is provided by
 *       anti_analysis_collect.cpp.
 * Interface: implements anti_analysis_sample_host_tools() declared in
 *       horkos/anti_analysis/anti_analysis_signals.h (Windows half); folds via
 *       the pure core in horkos/anti_analysis/host_tools.h. The Nt* directory-
 *       object calls are documented-but-Nt-prefixed and are declared LOCALLY in
 *       this TU (no proprietary SDK header; guardrail #2), each with a comment
 *       naming the documented routine it maps to.
 */

#include "horkos/anti_analysis/anti_analysis_signals.h"
#include "horkos/anti_analysis/host_tools.h"

#include "platform.h"

#if defined(HK_PLATFORM_WINDOWS)

#include <windows.h>
#include <psapi.h>

#include <cstring>
#include <cwchar>

namespace {

/* -------------------------------------------------------------------------
 * Static fingerprint tables. These are case-insensitively matched. They are
 * deliberately small and conservative: generic RE tools have legitimate
 * developer uses (catalog medium-FP), so a bare match only ever produces an
 * INFO/TOOL-PRESENT raw observation — the server applies the allowlist and the
 * final verdict. Presence here is NEVER a local ban.
 * ------------------------------------------------------------------------- */

/* (a) Known debugger / memory-editor top-level window classes. RealGetWindowClassW
 * returns the real (not superclassed) class atom name, defeating trivial class
 * renaming via superclassing. */
static const wchar_t* const kDebuggerWindowClasses[] = {
    L"Qt5QWindowIcon",        /* x64dbg / x32dbg main window (Qt) — see note below */
    L"Qt672QWindowIcon",      /* newer x64dbg Qt builds                            */
    L"OLLYDBG",               /* OllyDbg main window class                         */
    L"ID",                    /* Immunity Debugger (Olly-derived)                  */
    L"WinDbgFrameClass",      /* WinDbg classic frame                              */
    L"IDA Pro",              /* IDA disassembler main frame (heuristic)           */
};
/* HK-UNCERTAIN(window-class): x64dbg is a Qt app, so its top-level class is the
 * generic Qt window class ("Qt5QWindowIcon" / version-suffixed), which is shared
 * by EVERY Qt application on the box — matching it alone is high-FP and is why a
 * window-class hit is only INFO tier and the server allowlists. The exact Qt
 * class-name suffix tracks the Qt version x64dbg is built against and changes
 * across releases; this table is a best-effort superset, NOT an exhaustive or
 * version-pinned list. Treat the count as a coarse raw observation; the server
 * corroborates with the device-object / driver / handle-open signals before any
 * verdict. */

/* (b) Known editor device-object / symlink leaf names under \Device and \GLOBAL??.
 * Matched as a case-insensitive leaf-name compare against NtQueryDirectoryObject
 * entries. */
static const wchar_t* const kEditorDeviceNames[] = {
    L"DBK64",   /* Cheat Engine kernel driver device (DBK64.sys)                 */
    L"DBK32",   /* Cheat Engine 32-bit kernel driver device                      */
    L"dbk",     /* Cheat Engine generic DBK device leaf                          */
};

/* (c) Known editor helper / BYOVD driver BASE names (as reported by
 * GetDeviceDriverBaseNameW). Source of truth for the BYOVD known-bad set is the
 * kernel whitelist (kernel/win/src/Whitelist.c) — which Phase 3 ships EMPTY (it
 * is hash-based and populated from a signed rule bundle later). Userspace cannot
 * link kernel code (guardrail #4), so this base-name table is a STANDALONE mirror
 * of the same editor-helper driver class for the usermode name-based pre-screen;
 * when the kernel whitelist's signed bundle lands, the authoritative
 * byovd_driver_match comes from the kernel Ob/whitelist record and this table
 * becomes the coarse usermode corroboration. Conservative: only well-known
 * memory-editor helper drivers, not general-purpose vulnerable drivers. */
static const wchar_t* const kEditorDriverBaseNames[] = {
    L"DBK64.sys",   /* Cheat Engine kernel driver                                */
    L"DBK32.sys",   /* Cheat Engine 32-bit kernel driver                         */
    L"dbk64.sys",   /* lowercase variant (match is case-insensitive anyway)      */
};

/* The subset of (c) that is treated as a BYOVD known-bad helper (sets
 * byovd_driver_match, which the pure core maps to >= TOOL_PRESENT). Mirrors the
 * editor-helper class the kernel whitelist (kernel/win/src/Whitelist.c) will
 * carry; kept separate so a generic editor helper can be reported without
 * asserting the BYOVD bit. */
static const wchar_t* const kByovdDriverBaseNames[] = {
    L"DBK64.sys",   /* Cheat Engine's signed-but-abusable kernel helper          */
    L"DBK32.sys",
};

static bool iequals_w(const wchar_t* a, const wchar_t* b) noexcept {
    if (a == nullptr || b == nullptr) {
        return false;
    }
    return _wcsicmp(a, b) == 0;
}

/* True if `name` matches any entry in a null-terminated-pointer-array table of
 * `count` entries (case-insensitive). */
static bool matches_any(const wchar_t* name,
                        const wchar_t* const* table,
                        size_t count) noexcept {
    if (name == nullptr) {
        return false;
    }
    for (size_t i = 0; i < count; ++i) {
        if (iequals_w(name, table[i])) {
            return true;
        }
    }
    return false;
}

/* ---- (a) window-class enumeration -------------------------------------- */

struct WindowScanState {
    uint32_t hits;
};

static BOOL CALLBACK window_class_proc(HWND hwnd, LPARAM lparam) {
    WindowScanState* st = reinterpret_cast<WindowScanState*>(lparam);
    if (st == nullptr) {
        return FALSE; /* stop: degenerate state */
    }

    /* RealGetWindowClassW returns the number of chars copied, 0 on failure. */
    wchar_t cls[256];
    cls[0] = L'\0';
    UINT n = RealGetWindowClassW(hwnd, cls, ARRAYSIZE(cls));
    if (n == 0) {
        return TRUE; /* skip this window; keep enumerating */
    }
    if (matches_any(cls, kDebuggerWindowClasses, ARRAYSIZE(kDebuggerWindowClasses))) {
        ++st->hits;
    }
    return TRUE;
}

static uint32_t count_debugger_window_classes() noexcept {
    WindowScanState st;
    st.hits = 0u;
    /* EnumWindows enumerates top-level windows only; returns FALSE if the
     * callback stopped it or on error. Either way `st.hits` holds the count of
     * matches seen so far — a failed enumeration degrades to a partial/zero
     * count, never UB. */
    EnumWindows(&window_class_proc, reinterpret_cast<LPARAM>(&st));
    return st.hits;
}

/* ---- (b) object-manager namespace probe -------------------------------- *
 * NtOpenDirectoryObject / NtQueryDirectoryObject are documented (WDK /
 * ntifs.h-shaped) but NOT in the public usermode SDK headers, so the prototypes
 * and the structs they need are declared LOCALLY here (guardrail #2), each
 * commented with the documented routine / struct it maps to. We resolve them at
 * runtime from ntdll.dll rather than link-importing, so a build/runtime without
 * them degrades to zero counts. */

/* Maps to the documented NTSTATUS type. */
typedef LONG HK_NTSTATUS;

/* Maps to the documented OBJECT_ATTRIBUTES + UNICODE_STRING. We declare minimal
 * local mirrors to avoid pulling winternl.h (whose definitions vary by SDK). */
typedef struct _HK_UNICODE_STRING {
    USHORT  Length;
    USHORT  MaximumLength;
    PWSTR   Buffer;
} HK_UNICODE_STRING;

typedef struct _HK_OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    HK_UNICODE_STRING* ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} HK_OBJECT_ATTRIBUTES;

/* Maps to the documented OBJECT_DIRECTORY_INFORMATION returned by
 * NtQueryDirectoryObject: a name + a type name, both UNICODE_STRING; the array
 * is terminated by an all-zero entry. */
typedef struct _HK_OBJECT_DIRECTORY_INFORMATION {
    HK_UNICODE_STRING Name;
    HK_UNICODE_STRING TypeName;
} HK_OBJECT_DIRECTORY_INFORMATION;

/* OBJ_CASE_INSENSITIVE from the WDK. */
#ifndef HK_OBJ_CASE_INSENSITIVE
#  define HK_OBJ_CASE_INSENSITIVE 0x00000040u
#endif
#ifndef HK_DIRECTORY_QUERY
#  define HK_DIRECTORY_QUERY 0x0001u
#endif
#ifndef HK_STATUS_MORE_ENTRIES
#  define HK_STATUS_MORE_ENTRIES ((HK_NTSTATUS)0x00000105L)
#endif
#ifndef HK_STATUS_NO_MORE_ENTRIES
#  define HK_STATUS_NO_MORE_ENTRIES ((HK_NTSTATUS)0x8000001AL)
#endif

/* Maps to documented NtOpenDirectoryObject. */
typedef HK_NTSTATUS(NTAPI* HK_NtOpenDirectoryObject_t)(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    HK_OBJECT_ATTRIBUTES* ObjectAttributes);

/* Maps to documented NtQueryDirectoryObject. */
typedef HK_NTSTATUS(NTAPI* HK_NtQueryDirectoryObject_t)(
    HANDLE DirectoryHandle,
    PVOID Buffer,
    ULONG Length,
    BOOLEAN ReturnSingleEntry,
    BOOLEAN RestartScan,
    PULONG Context,
    PULONG ReturnLength);

/* Maps to documented RtlInitUnicodeString. */
typedef VOID(NTAPI* HK_RtlInitUnicodeString_t)(
    HK_UNICODE_STRING* DestinationString,
    PCWSTR SourceString);

struct NtDirApi {
    HK_NtOpenDirectoryObject_t  open;
    HK_NtQueryDirectoryObject_t query;
    HK_RtlInitUnicodeString_t   init_unicode;
    bool ok;
};

static NtDirApi resolve_nt_dir_api() noexcept {
    NtDirApi api;
    api.open = nullptr;
    api.query = nullptr;
    api.init_unicode = nullptr;
    api.ok = false;

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
        return api;
    }
    api.open = reinterpret_cast<HK_NtOpenDirectoryObject_t>(
        reinterpret_cast<void*>(GetProcAddress(ntdll, "NtOpenDirectoryObject")));
    api.query = reinterpret_cast<HK_NtQueryDirectoryObject_t>(
        reinterpret_cast<void*>(GetProcAddress(ntdll, "NtQueryDirectoryObject")));
    api.init_unicode = reinterpret_cast<HK_RtlInitUnicodeString_t>(
        reinterpret_cast<void*>(GetProcAddress(ntdll, "RtlInitUnicodeString")));
    api.ok = (api.open != nullptr && api.query != nullptr &&
              api.init_unicode != nullptr);
    return api;
}

/* Enumerate one object directory (e.g. L"\\Device" or L"\\GLOBAL??") and count
 * leaf names matching the editor-device table. Read-only: opens the directory
 * with DIRECTORY_QUERY only. Any failure returns 0 (never UB). */
static uint32_t scan_object_directory(const NtDirApi& api,
                                      const wchar_t* dir_path) noexcept {
    if (!api.ok || dir_path == nullptr) {
        return 0u;
    }

    HK_UNICODE_STRING name;
    name.Length = 0;
    name.MaximumLength = 0;
    name.Buffer = nullptr;
    api.init_unicode(&name, dir_path);

    HK_OBJECT_ATTRIBUTES oa;
    std::memset(&oa, 0, sizeof(oa));
    oa.Length = sizeof(oa);
    oa.RootDirectory = nullptr;
    oa.ObjectName = &name;
    oa.Attributes = HK_OBJ_CASE_INSENSITIVE;
    oa.SecurityDescriptor = nullptr;
    oa.SecurityQualityOfService = nullptr;

    HANDLE dir = nullptr;
    HK_NTSTATUS st = api.open(&dir, HK_DIRECTORY_QUERY, &oa);
    if (st < 0 || dir == nullptr) {
        return 0u; /* access denied / not present — no observation */
    }

    uint32_t hits = 0u;
    /* Buffer holds an array of OBJECT_DIRECTORY_INFORMATION followed by the
     * variable-length name buffers; 8 KiB is ample for one query pass and we
     * iterate via the kernel-maintained Context cookie. */
    ULONG ctx = 0;
    bool restart = true;
    for (;;) {
        BYTE buf[8192];
        ULONG ret_len = 0;
        st = api.query(dir, buf, sizeof(buf),
                       FALSE /* return all entries that fit */,
                       restart ? TRUE : FALSE,
                       &ctx, &ret_len);
        restart = false;

        if (st == HK_STATUS_NO_MORE_ENTRIES) {
            break;
        }
        if (st < 0 && st != HK_STATUS_MORE_ENTRIES) {
            break; /* unexpected error: stop, keep what we counted */
        }

        const HK_OBJECT_DIRECTORY_INFORMATION* entries =
            reinterpret_cast<const HK_OBJECT_DIRECTORY_INFORMATION*>(buf);
        /* The array is terminated by an all-zero entry (Name.Buffer == nullptr).
         * Bound the walk by the entry-array capacity so a malformed buffer can
         * never run off the end. */
        const size_t max_entries = sizeof(buf) / sizeof(entries[0]);
        for (size_t i = 0; i < max_entries; ++i) {
            const HK_UNICODE_STRING& nm = entries[i].Name;
            if (nm.Buffer == nullptr || nm.Length == 0) {
                break; /* terminator */
            }
            /* nm.Buffer is not guaranteed NUL-terminated; copy Length bytes into
             * a bounded, NUL-terminated scratch before comparing. */
            wchar_t leaf[128];
            size_t chars = nm.Length / sizeof(wchar_t);
            if (chars >= ARRAYSIZE(leaf)) {
                chars = ARRAYSIZE(leaf) - 1;
            }
            /* Verify the source span is inside our buffer before reading it. */
            const BYTE* src = reinterpret_cast<const BYTE*>(nm.Buffer);
            if (src < buf || src + (chars * sizeof(wchar_t)) > buf + sizeof(buf)) {
                /* Name buffer points outside our scratch (shouldn't happen for a
                 * single-call query, but never trust the layout) — skip it. */
                continue;
            }
            std::memcpy(leaf, nm.Buffer, chars * sizeof(wchar_t));
            leaf[chars] = L'\0';

            if (matches_any(leaf, kEditorDeviceNames,
                            ARRAYSIZE(kEditorDeviceNames))) {
                ++hits;
            }
        }

        if (st != HK_STATUS_MORE_ENTRIES) {
            break; /* HK_AC_OK-equivalent: all entries returned in this pass */
        }
    }

    CloseHandle(dir);
    return hits;
}

static uint32_t count_known_device_objects(const NtDirApi& api) noexcept {
    uint32_t hits = 0u;
    hits += scan_object_directory(api, L"\\Device");
    hits += scan_object_directory(api, L"\\GLOBAL??");
    return hits;
}

/* ---- (c) loaded-driver enumeration ------------------------------------- */

struct DriverScanResult {
    uint32_t suspicious;
    uint32_t byovd;
};

static DriverScanResult count_suspicious_drivers() noexcept {
    DriverScanResult res;
    res.suspicious = 0u;
    res.byovd = 0u;

    /* First call sizes the array. EnumDeviceDrivers returns FALSE on failure. */
    DWORD needed = 0;
    if (!EnumDeviceDrivers(nullptr, 0, &needed) || needed == 0) {
        return res;
    }
    const DWORD count = needed / sizeof(LPVOID);
    if (count == 0) {
        return res;
    }
    /* Cap to a sane bound so a hostile/garbage `needed` can't drive a huge
     * allocation; the system driver count is small. */
    const DWORD kMaxDrivers = 4096;
    const DWORD use = (count > kMaxDrivers) ? kMaxDrivers : count;

    LPVOID* bases = static_cast<LPVOID*>(
        HeapAlloc(GetProcessHeap(), 0, use * sizeof(LPVOID)));
    if (bases == nullptr) {
        return res;
    }

    DWORD got = 0;
    if (EnumDeviceDrivers(bases, use * sizeof(LPVOID), &got)) {
        const DWORD got_count = got / sizeof(LPVOID);
        const DWORD n = (got_count < use) ? got_count : use;
        for (DWORD i = 0; i < n; ++i) {
            wchar_t base[MAX_PATH];
            base[0] = L'\0';
            DWORD len = GetDeviceDriverBaseNameW(bases[i], base, ARRAYSIZE(base));
            if (len == 0) {
                continue; /* could not name this driver; skip */
            }
            if (matches_any(base, kEditorDriverBaseNames,
                            ARRAYSIZE(kEditorDriverBaseNames))) {
                ++res.suspicious;
            }
            if (matches_any(base, kByovdDriverBaseNames,
                            ARRAYSIZE(kByovdDriverBaseNames))) {
                ++res.byovd;
            }
        }
    }

    HeapFree(GetProcessHeap(), 0, bases);
    return res;
}

} // namespace

extern "C" int anti_analysis_sample_host_tools(aa_host_tools* out) {
    if (out == nullptr) {
        return HK_AC_NOT_IMPLEMENTED;
    }
    std::memset(out, 0, sizeof(*out));

    out->debugger_window_classes = count_debugger_window_classes();

    NtDirApi nt = resolve_nt_dir_api();
    out->known_device_objects = count_known_device_objects(nt);

    DriverScanResult drv = count_suspicious_drivers();
    out->suspicious_drivers = drv.suspicious;
    out->byovd_driver_match = (drv.byovd != 0u) ? 1u : 0u;

    /* opened_handle_to_game is folded from the kernel ObRegisterCallbacks
     * handle-open records by ac.cpp once the IOCTL-drain decode lands (see the
     * module comment). The sampler never opens a foreign handle itself
     * (read-only), so it leaves this 0; the aggregator/ac.cpp may overwrite it
     * before computing the final tier. */
    out->opened_handle_to_game = 0u;

    out->severity_tier = hk::anti_analysis::host_tools_severity_tier(
        out->debugger_window_classes,
        out->known_device_objects,
        out->suspicious_drivers,
        out->byovd_driver_match,
        out->opened_handle_to_game);

    return HK_AC_OK;
}

#endif /* HK_PLATFORM_WINDOWS */
