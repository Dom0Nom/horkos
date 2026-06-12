/*
 * Role: Windows userspace thread-provenance enrichment (win-kernel-thread-
 *       injection, catalog signals 22/23/24/25). On demand for a flagged TID:
 *       compares the spoofable Win32StartAddress against the kernel-captured
 *       start (signal 23), classifies the entry page MEM_IMAGE/PRIVATE/MAPPED and
 *       byte-compares a MEM_IMAGE entry page to its on-disk RVA for module
 *       stomping (signal 24, reusing dma_detect/page_hash.h), checks the WOW64
 *       64-bit-start rule (signal 22) and ThreadHideFromDebugger (signal 25).
 *       Read-only; emits hk_event_thread_provenance into the SDK report queue.
 * Target platforms: Windows (userspace). Guardrail #1: NT query API confined to
 *       this backends/win/ TU. The decision table (classify_start_mismatch) is
 *       platform-free and host-tested.
 * Interface: implements hk::sdk::threadprov from ThreadProvenanceWin.h.
 */

#include "ThreadProvenanceWin.h"

#include "horkos/page_hash.h"   /* reuse the shared page-hash helper (signal 24) */

namespace hk { namespace sdk { namespace threadprov {

/* classify_start_mismatch (signal 23) is defined inline in ThreadProvenanceWin.h
 * so it is host-unit-testable with no platform TU to link. */

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

/* -------------------------------------------------------------------------
 * HK-UNCERTAIN(versioned-info-classes): the enrichment reads below depend on
 * ZwQueryInformationThread info classes whose exact contract is version-gated
 * (guardrail #13):
 *   - ThreadQuerySetWin32StartAddress: spoofable user start (signal 23 input).
 *   - ThreadHideFromDebugger: readable only Win10 1607+ (signal 25).
 *   - ThreadWow64Context: query semantics are version-sensitive (signal 22).
 * The frozen public Windows SDK does not export these NT info classes; relying
 * on them needs the exact info-class numbers + struct shapes confirmed against
 * the target build. This function is therefore SCAFFOLD ONLY: it lays out the
 * read sequence and the emit shape, but the actual NtQuery calls are left as a
 * documented stub rather than coded against unverified info-class numbers. The
 * pure classifier above (the tested part) is unaffected. Confirm on-box before
 * filling these in.
 * ------------------------------------------------------------------------- */
int enrich(uint32_t tid)
{
    /* Steps the verified implementation performs (NOT coded here — see
     * HK-UNCERTAIN above):
     *   1. OpenThread(THREAD_QUERY_LIMITED_INFORMATION, tid).
     *   2. ZwQueryInformationThread(ThreadQuerySetWin32StartAddress) -> user start.
     *   3. Look up the kernel start from the drained hk_event_thread_create for tid.
     *   4. Resolve both addresses' regions via VirtualQueryEx / NtQueryVirtualMemory
     *      (MemoryBasicInformation: Type/AllocationProtect;
     *      MemoryMappedFilenameInformation: backing section path).
     *   5. classify_start_mismatch(...) -> HK_PROV_START_MISMATCH.
     *   6. For a MEM_IMAGE entry page: read the on-disk file at the same RVA and
     *      hk_page_byte_delta(mapped_page, disk_page) -> entry_page_disk_delta /
     *      HK_PROV_ENTRY_STOMPED. MEM_PRIVATE/MEM_MAPPED RX -> HK_PROV_ENTRY_PRIVATE.
     *   7. backing_module_hash32 = hk_bytes_hash32(backing_path).
     *   8. If the kernel flagged HK_THREAD_FLAG_WOW64_TARGET:
     *      ThreadWow64Context + start>0xFFFFFFFF -> HK_PROV_WOW64_64BIT_START
     *      (allowlisting wow64cpu/ntdll transition stubs by path).
     *   9. ThreadHideFromDebugger -> HK_PROV_HIDE_FROM_DEBUGGER.
     *  10. JIT-host allowlist (CLR/V8/JVM/.NET R2R) -> HK_PROV_JIT_ALLOWLISTED.
     *  11. Emit hk_event_thread_provenance into the SDK report queue. (HK-TODO
     *      (schema): hk_event_thread_provenance is a kernel-private mirror until
     *      the Schema phase appends it to event_schema.h; the userspace report
     *      queue type follows the same gate.)
     */
    (void)tid;
    return -1; /* not enriched: NT info-class reads are an on-box-verified stub */
}

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */

} } } // namespace hk::sdk::threadprov
