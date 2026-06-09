/*
 * sdk/src/backends/win/ThreadProvenanceWin.h
 * Role: SDK-internal interface for the Windows userspace thread-provenance
 *       enrichment plane (win-kernel-thread-injection, catalog signals
 *       22/23/24/25). Declares threadprov::enrich(tid) and the small,
 *       platform-free result/seam types the host unit tests drive without a live
 *       thread.
 * Target platforms: Windows (userspace). The pure decision logic
 *       (classify_start_mismatch) is platform-free so it is host-testable.
 * Interface: consumed by EtwTiConsumer.cpp and the Windows sdk.cpp path;
 *       implemented in ThreadProvenanceWin.cpp.
 */

#pragma once

#include <cstdint>

namespace hk { namespace sdk { namespace threadprov {

/* Region classification of a thread's entry page (mirrors HK_REGION_* in the
 * kernel-private mirror; kept as a small enum here so the pure classifier needs
 * no kernel header). */
enum class Region : uint32_t {
    Unknown = 0,
    Image   = 1,   /* HK_REGION_IMAGE   */
    Private = 2,   /* HK_REGION_PRIVATE */
    Mapped  = 3,   /* HK_REGION_MAPPED  */
};

/* Inputs to the start-address-mismatch decision (signal 23), captured behind a
 * seam so the host unit test can exercise the decision table with no live
 * thread / no NT query. All addresses are process-virtual. */
struct StartMismatchInput {
    uint64_t kernel_start_address; /* from hk_event_thread_create (0 if absent) */
    uint64_t user_start_address;   /* ZwQueryInformationThread Win32StartAddress */
    Region   kernel_start_region;  /* backing of the kernel start address        */
    Region   user_start_region;    /* backing of the user start address          */
    bool     user_in_known_module; /* user start resolves inside a loaded module  */
    bool     is_ntdll_thread_shim; /* kernel start is the RtlUserThreadStart shim */
};

/* The spoof signature for signal 23: kernel start UNBACKED (not image) while the
 * spoofable user start sits in a known module — i.e. the queryable value was
 * patched to look benign. Returns true => set HK_PROV_START_MISMATCH.
 *
 * Pure function (no platform calls), defined inline so it is unit-tested on the
 * host with no platform TU to link (mirrors minifilter_altitude.h). Deliberately
 * does NOT flag the reverse (user unbacked, kernel in-module) — that is a normal
 * JIT/thunk pattern, not the documented spoof — and never flags the known ntdll
 * RtlUserThreadStart shim delta. */
inline bool classify_start_mismatch(const StartMismatchInput &in)
{
    /* The known ntdll RtlUserThreadStart shim is the legitimate common start for
     * many threads; never treat its delta as a spoof. */
    if (in.is_ntdll_thread_shim) {
        return false;
    }

    /* Need a real kernel start to compare against. If the kernel plane could not
     * supply one (kernel_start_address == 0, e.g. the Ex-notify limitation — see
     * ThreadProvenance.c HK-UNCERTAIN), we cannot make the spoof-resistant call
     * and must NOT guess; report no mismatch (the server still sees the raw user
     * start and the absence of a kernel start). */
    if (in.kernel_start_address == 0) {
        return false;
    }

    /* Equal addresses are never a mismatch. */
    if (in.kernel_start_address == in.user_start_address) {
        return false;
    }

    const bool kernel_unbacked = (in.kernel_start_region != Region::Image);
    const bool user_in_module  = in.user_in_known_module &&
                                 (in.user_start_region == Region::Image);

    /* Spoof signature: addresses disagree, kernel start unbacked, user start
     * dressed up as in-module. */
    return kernel_unbacked && user_in_module;
}

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)
/* On-demand enrichment for a TID the kernel/ETW planes flagged. Performs the
 * ZwQueryInformationThread / ZwQueryVirtualMemory reads, the on-disk RVA byte
 * compare (reusing dma_detect/page_hash.h), and the HideFromDebugger/WOW64
 * checks, then emits an hk_event_thread_provenance record into the SDK report
 * queue. Read-only. Returns 0 on success, -1 if the thread could not be queried.
 *
 * (The _WIN32 fallback in the guard mirrors sdk_backend.h: the SDK has not yet
 * defined HK_PLATFORM_WINDOWS for this TU, but the implementation lives strictly
 * under backends/win/ per guardrail #1.) */
int enrich(uint32_t tid);
#endif

} } } // namespace hk::sdk::threadprov
