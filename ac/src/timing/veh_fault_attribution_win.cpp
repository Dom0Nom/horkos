/*
 * ac/src/timing/veh_fault_attribution_win.cpp
 * Role: Signal 154 — VEH-ordering / fault-resolver attribution sensor, plus the SHARED
 *       first-chain VEH install/teardown + self-armed decoy PAGE_GUARD machinery reused
 *       by signals 159 (dispatch latency) and 161 (guard cadence). The first-in-chain
 *       handler observes STATUS_GUARD_PAGE_VIOLATION on the AC's own decoy region, reads
 *       CONTEXT.Dr6/Dr7, and resolves the dispatch-frame return address to an owning
 *       image via RtlPcToFileHeader; it attributes the RESOLVER, flagging only an
 *       unsigned/non-attested resolver WITH a live DR6 step/BP bit (server decides).
 * Target platform: Windows. The entire active body is behind HK_PLATFORM_WINDOWS
 *       (guardrail #1); off-Windows the samplers are not-implemented no-ops.
 * Interface: implements ac/include/horkos/timing/fault_attribution.h. Exposes the
 *       shared decoy state (hk_timing_decoy_*) consumed by the 159/161 TUs.
 *
 * SAFETY (plan §154): the VEH runs in the faulting thread's context — it is
 * allocation-free, re-entrancy-safe, and never calls back into anything that can fault
 * the decoy again. It only snapshots into preallocated atomics and continues.
 *
 * FP (plan): overlays / IME / .NET / GPU drivers register legitimate VEHs and benign
 * guard faults — the client NEVER decides locally; it ships the attribution + DR bits
 * and the server applies the unsigned/non-attested + live-DR gate.
 */

#include "horkos/timing/fault_attribution.h"
#include "horkos/timing/timing_signals.h"
#include "platform.h"

#include <cstring>

namespace hk {
namespace timing {

#if defined(HK_PLATFORM_WINDOWS)

} // namespace timing
} // namespace hk

/* Windows headers outside the namespace. */
#include <windows.h>

namespace hk {
namespace timing {

namespace {

/* Shared decoy + handler state. All fields are written only from init (single-threaded
 * arm) or from the VEH via Interlocked/atomic stores — no allocation in handler context. */
PVOID                 g_veh_handle      = nullptr;   /* AddVectoredExceptionHandler cookie */
void*                 g_decoy_page      = nullptr;   /* AC-owned guarded decoy region */
volatile LONG         g_armed           = 0;

/* Last captured 154 attribution (snapshotted in the VEH, read by the sampler). */
volatile LONG64       g_last_resolver_base = 0;
volatile LONG         g_last_dr6_step      = 0;
volatile LONG         g_last_dr7_lenable   = 0;
volatile LONG         g_last_have_attrib   = 0;

/* 159/161 shared counters the other TUs read through the accessors below. */
volatile LONG64       g_guard_fault_count  = 0;  /* total decoy guard faults seen */
volatile LONG64       g_last_fault_qpc     = 0;  /* QPC of the most recent fault */
volatile LONG         g_last_eflags_tf     = 0;  /* TF set in the most recent guard VEH */

/* Resolve a code address to its owning image base WITHOUT allocating. RtlPcToFileHeader
 * walks the loaded-module list and returns the image base (or NULL if unmapped). */
PVOID resolve_image_base(PVOID pc) {
    PVOID base = nullptr;
    /* RtlPcToFileHeader is documented and safe to call from a VEH (no lock that the
     * faulting context could already hold for our decoy). */
    (void)RtlPcToFileHeader(pc, &base);
    return base;
}

LONG CALLBACK hk_first_chain_veh(PEXCEPTION_POINTERS info) {
    if (info == nullptr || info->ExceptionRecord == nullptr ||
        info->ContextRecord == nullptr) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    const DWORD code = info->ExceptionRecord->ExceptionCode;
    if (code != STATUS_GUARD_PAGE_VIOLATION) {
        return EXCEPTION_CONTINUE_SEARCH; /* not our decoy fault — let the chain run */
    }

    /* Only act on faults against OUR decoy region. ExceptionInformation[1] is the
     * faulting VA for guard-page violations. */
    const ULONG_PTR fault_va = (info->ExceptionRecord->NumberParameters >= 2)
                                   ? info->ExceptionRecord->ExceptionInformation[1]
                                   : 0u;
    const ULONG_PTR base = reinterpret_cast<ULONG_PTR>(g_decoy_page);
    if (g_decoy_page == nullptr || fault_va < base ||
        fault_va >= base + 0x1000u) {
        return EXCEPTION_CONTINUE_SEARCH; /* someone else's guard fault */
    }

#if defined(_M_X64) || defined(_M_IX86)
    const DWORD64 dr6 = info->ContextRecord->Dr6;
    const DWORD64 dr7 = info->ContextRecord->Dr7;
#else
    const DWORD64 dr6 = 0; /* ARM64 has no DR0-7; the step/BP bits are x86-only */
    const DWORD64 dr7 = 0;
#endif
    /* DR6 low 4 bits = B0..B3 (a HW breakpoint hit); BS (bit 14) = single-step. */
    const LONG dr6_step = ((dr6 & 0xFull) != 0 || (dr6 & (1ull << 14)) != 0) ? 1 : 0;
    /* DR7 L0..L3 = bits 0,2,4,6 (local-enable per DR). */
    const LONG dr7_lenable =
        static_cast<LONG>((dr7 & 0x1ull) | ((dr7 >> 1) & 0x2ull) |
                          ((dr7 >> 2) & 0x4ull) | ((dr7 >> 3) & 0x8ull));

    /* Attribute the dispatch-frame return address. The instruction pointer at fault is
     * the access site; its owning image is the resolver to attribute. */
#if defined(_M_X64)
    PVOID pc = reinterpret_cast<PVOID>(info->ContextRecord->Rip);
#elif defined(_M_IX86)
    PVOID pc = reinterpret_cast<PVOID>(info->ContextRecord->Eip);
#else
    PVOID pc = reinterpret_cast<PVOID>(info->ContextRecord->Pc);
#endif
    PVOID resolver_base = resolve_image_base(pc);

    /* EFLAGS.TF (bit 8) read in the same VEH (161 correlation). */
#if defined(_M_X64) || defined(_M_IX86)
    const LONG tf = (info->ContextRecord->EFlags & 0x100u) ? 1 : 0;
#else
    const LONG tf = 0;
#endif

    /* Snapshot atomically; no allocation, no re-fault. */
    InterlockedExchange64(&g_last_resolver_base,
                          reinterpret_cast<LONG64>(resolver_base));
    InterlockedExchange(&g_last_dr6_step, dr6_step);
    InterlockedExchange(&g_last_dr7_lenable, dr7_lenable);
    InterlockedExchange(&g_last_have_attrib, 1);
    InterlockedExchange(&g_last_eflags_tf, tf);
    InterlockedIncrement64(&g_guard_fault_count);

    LARGE_INTEGER qpc;
    QueryPerformanceCounter(&qpc);
    InterlockedExchange64(&g_last_fault_qpc, qpc.QuadPart);

    /* The access auto-cleared PAGE_GUARD; the original instruction is re-executed when
     * we continue execution, now hitting the un-guarded page. The 161 sampler re-arms
     * PAGE_GUARD out-of-band (bounded) to keep observing.
     * HK-UNCERTAIN(veh-guard-continue): returning EXCEPTION_CONTINUE_EXECUTION from a
     * first-chain VEH on STATUS_GUARD_PAGE_VIOLATION re-runs the faulting instruction
     * against the now-unguarded page. This is the intended observe-and-let-through
     * behavior for an AC-owned decoy, but the precise interaction of a first-chain VEH
     * CONTINUE with the kernel's guard-page single-shot semantics should be confirmed
     * on-box before relying on it under a real stepping debugger (the alternative is
     * CONTINUE_SEARCH to let the default dispatch complete the access). Do not ship this
     * as the decoy's behavior without that confirmation. */
    return EXCEPTION_CONTINUE_EXECUTION;
}

} // namespace

/* ---- Accessors the 159/161 TUs use to read the shared decoy state without
 * re-including windows.h structures. ---- */
bool hk_timing_decoy_is_armed() { return InterlockedCompareExchange(&g_armed, 0, 0) != 0; }
void* hk_timing_decoy_page()    { return g_decoy_page; }
long long hk_timing_decoy_fault_count() {
    return InterlockedCompareExchange64(&g_guard_fault_count, 0, 0);
}
long long hk_timing_decoy_last_fault_qpc() {
    return InterlockedCompareExchange64(&g_last_fault_qpc, 0, 0);
}
int hk_timing_decoy_last_tf() {
    return static_cast<int>(InterlockedCompareExchange(&g_last_eflags_tf, 0, 0));
}

/* Re-arm PAGE_GUARD on the decoy page (used by 161 after a read auto-cleared it).
 * Bounded by the caller; returns true if re-armed. */
bool hk_timing_decoy_rearm() {
    if (g_decoy_page == nullptr) {
        return false;
    }
    DWORD old = 0;
    return VirtualProtect(g_decoy_page, 0x1000u, PAGE_READWRITE | PAGE_GUARD, &old) != 0;
}

bool timing_veh_arm() noexcept {
    if (InterlockedCompareExchange(&g_armed, 1, 0) != 0) {
        return true; /* already armed */
    }
    /* Allocate one AC-owned page for the decoy and arm PAGE_GUARD on it. The page is
     * read/written deliberately by the 159/161 samplers; it is NEVER in the GAME hot
     * loop (guardrail #9) — it is private AC memory. */
    g_decoy_page = VirtualAlloc(nullptr, 0x1000u, MEM_COMMIT | MEM_RESERVE,
                                PAGE_READWRITE);
    if (g_decoy_page == nullptr) {
        InterlockedExchange(&g_armed, 0);
        return false;
    }
    DWORD old = 0;
    if (!VirtualProtect(g_decoy_page, 0x1000u, PAGE_READWRITE | PAGE_GUARD, &old)) {
        VirtualFree(g_decoy_page, 0, MEM_RELEASE);
        g_decoy_page = nullptr;
        InterlockedExchange(&g_armed, 0);
        return false;
    }
    /* TRUE => first in the handler chain (plan §154). */
    g_veh_handle = AddVectoredExceptionHandler(TRUE, hk_first_chain_veh);
    if (g_veh_handle == nullptr) {
        VirtualFree(g_decoy_page, 0, MEM_RELEASE);
        g_decoy_page = nullptr;
        InterlockedExchange(&g_armed, 0);
        return false;
    }
    return true;
}

void timing_veh_teardown() noexcept {
    if (InterlockedCompareExchange(&g_armed, 0, 1) == 0) {
        return; /* not armed */
    }
    /* Remove the first-chain VEH BEFORE freeing the decoy so a late fault cannot reach
     * a handler that references freed state. */
    if (g_veh_handle != nullptr) {
        RemoveVectoredExceptionHandler(g_veh_handle);
        g_veh_handle = nullptr;
    }
    if (g_decoy_page != nullptr) {
        VirtualFree(g_decoy_page, 0, MEM_RELEASE);
        g_decoy_page = nullptr;
    }
}

bool timing_sample_veh_attrib(timing_veh_attrib* out) noexcept {
    if (out == nullptr) {
        return false;
    }
    std::memset(out, 0, sizeof(*out));
    if (InterlockedCompareExchange(&g_last_have_attrib, 0, 0) == 0) {
        return false; /* nothing faulted the decoy this pass */
    }

    const LONG64 base = InterlockedCompareExchange64(&g_last_resolver_base, 0, 0);
    out->resolver_image_base = static_cast<uint64_t>(base);
    out->dr6_stepbit     = static_cast<uint32_t>(
        InterlockedCompareExchange(&g_last_dr6_step, 0, 0));
    out->dr7_local_enable = static_cast<uint32_t>(
        InterlockedCompareExchange(&g_last_dr7_lenable, 0, 0));

    /* foreign_resolver / resolver_signed are server-side determinations from the
     * attestation module list — the client ships the resolver base and the DR bits and
     * lets the server decide. We set foreign_resolver=1 only as a coarse "resolver is
     * not our own image" hint when the base differs from our module; resolver_signed is
     * left 0 (unknown) because in-process signature checks are spoofable.
     * HK-TODO(attest-list): cross-reference resolver_image_base against the attestation
     * module list (cross-domain seam) to set these authoritatively; until that seam
     * exists, ship raw base + DR bits and leave the flags as the coarse hint. */
    HMODULE self = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCWSTR>(&hk_first_chain_veh), &self);
    out->foreign_resolver =
        (base != 0 && reinterpret_cast<LONG64>(self) != base) ? 1u : 0u;
    out->resolver_signed = 0u;
    return true;
}

#else /* non-Windows: not-implemented no-ops (HK_TIMING_OK_VEH stays clear). */

bool timing_veh_arm() noexcept { return false; }
void timing_veh_teardown() noexcept {}

bool timing_sample_veh_attrib(timing_veh_attrib* out) noexcept {
    if (out != nullptr) {
        std::memset(out, 0, sizeof(*out));
    }
    return false;
}

#endif /* HK_PLATFORM_WINDOWS */

} // namespace timing
} // namespace hk
