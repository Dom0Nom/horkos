/*
 * Role: Windows backend for the hk::platform abstraction layer.
 * Target platforms: Windows only. Selected by CMake if(WIN32).
 * Implements: platform/platform.h
 */

#include "platform.h"
#include <windows.h>
#include <sysinfoapi.h>

namespace hk { namespace platform {

uint32_t page_size() {
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    return static_cast<uint32_t>(si.dwPageSize);
}

process_id_t current_process_id() {
    return static_cast<process_id_t>(GetCurrentProcessId());
}

bool is_debugger_attached() {
    return IsDebuggerPresent() != FALSE;
}

/* -------------------------------------------------------------------------
 * macOS platform-trust reads (signal 124). Not available on Windows; return the
 * header-documented "unavailable" values so any TU that includes platform.h
 * can link regardless of which platform backend is selected by CMake.
 * ------------------------------------------------------------------------- */
bool csr_active_config(uint32_t * /*out_config*/) { return false; }
bool sip_enabled() { return true; }
uint32_t read_boot_args(char * /*out*/, uint32_t /*cap*/) { return 0; }

/* -------------------------------------------------------------------------
 * Client self-integrity reads (memory-integrity-selfcheck, signals 145-153).
 * On Windows the authoritative reads come from the KMDF driver via
 * HK_IOCTL_SELF_READ_VA. The driver must FIRST prove the caller is the
 * legitimate AC and that the requested VA lies inside the caller's own image
 * mapping before it foreign-reads — that secure-binding mechanism is UNSETTLED
 * (see kernel/win/src/selfcheck_read.c §caller-identity). Until it is settled and
 * the large-record reply plane lands, these shims report "unavailable" (return
 * false / 0) so the sensor TUs emit nothing rather than trusting an ungated
 * foreign-read primitive (a foreign-read IOCTL is a privilege boundary;
 * mis-scoping it is worse than shipping fewer signals).
 * ------------------------------------------------------------------------- */
bool page_share_state(uint64_t /*va_base*/, uint64_t /*va_len*/,
                      uint32_t* /*out_private*/, uint32_t* /*out_dirty*/) {
    /* HK-UNCERTAIN(selfcheck-ioctl): the HK_IOCTL_SELF_READ_VA caller-identity
     * gate is unsettled; do not issue the foreign-read IOCTL yet. QueryWorkingSetEx
     * gives a spoofable usermode page-share view, but the trustworthy half is the
     * kernel PFN/MMPTE read, which this seam must carry — left unavailable. */
    return false;
}

uint32_t module_image_file_name(uint64_t /*addr*/, char* /*out*/, uint32_t /*cap*/) {
    /* HK-UNCERTAIN(selfcheck-ioctl): the kernel section-object FILE name for our VA
     * (HK_SELF_READ_IMAGE_FILE) rides the same ungated IOCTL — unavailable until the
     * caller-identity gate lands. */
    return 0;
}

uint32_t selfcheck_kernel_read(uint32_t /*req_kind*/, uint64_t /*va_base*/,
                               uint64_t /*va_len*/, void* /*out*/, uint32_t /*cap*/) {
    /* HK-UNCERTAIN(selfcheck-ioctl): same gate. The intended body opens
     * \\.\Horkos, fills hk_self_read_request, and DeviceIoControl(HK_IOCTL_SELF_
     * READ_VA) into the large-record reply; not issued until the secure caller
     * binding + the large-record drain plane are settled. */
    return 0;
}

/* -------------------------------------------------------------------------
 * Timing clock seam (timing-side-channels signal 156 + fenced timing for
 * 159/161/162). x86-only intrinsic; ARM64 Windows falls back to QPC and aux=0.
 * ------------------------------------------------------------------------- */
uint64_t rdtscp_aux(uint32_t* out_aux) {
#if defined(_M_X64) || defined(_M_IX86)
    /* __rdtscp is ordering-serializing for prior loads; the caller adds _mm_lfence
     * fences where it needs full serialization (159/162). aux is IA32_TSC_AUX,
     * which Windows programs with the logical processor id on each core. */
    unsigned int aux = 0u;
    const unsigned long long tsc = __rdtscp(&aux);
    if (out_aux) {
        *out_aux = static_cast<uint32_t>(aux);
    }
    return static_cast<uint64_t>(tsc);
#else
    /* ARM64: no TSC_AUX. Use QPC as the monotonic fallback; aux unknown (0). */
    if (out_aux) {
        *out_aux = 0u;
    }
    LARGE_INTEGER c;
    QueryPerformanceCounter(&c);
    return static_cast<uint64_t>(c.QuadPart);
#endif
}

bool pin_thread_to_core(uint32_t core_index) {
    /* SetThreadAffinityMask gives a hard pin on a single logical processor (within
     * the calling thread's processor group). Group-aware pinning across >64 CPUs
     * would need SetThreadGroupAffinity; the watchdog only needs a stable single
     * core, so the simple mask is sufficient and group 0 is assumed.
     * HK-UNCERTAIN(affinity-group): on >64-CPU multi-group hosts core_index>=64
     * must route through SetThreadGroupAffinity — confirm before relying on a flat
     * index there. */
    if (core_index >= 64u) {
        return false;
    }
    const DWORD_PTR mask = (static_cast<DWORD_PTR>(1) << core_index);
    return SetThreadAffinityMask(GetCurrentThread(), mask) != 0;
}

void unpin_thread() {
    /* Restore to all processors in the current group. */
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const DWORD_PTR all = (si.dwActiveProcessorMask != 0)
                              ? si.dwActiveProcessorMask
                              : ~static_cast<DWORD_PTR>(0);
    SetThreadAffinityMask(GetCurrentThread(), all);
}

} } // namespace hk::platform
