/*
 * platform/platform_linux.cpp
 * Role: Linux backend for the hk::platform abstraction layer.
 * Target platforms: Linux only. Selected by CMake if(UNIX AND NOT APPLE).
 * Implements: platform/platform.h
 */

#include "platform.h"
#ifndef _GNU_SOURCE
#  define _GNU_SOURCE 1   /* cpu_set_t / CPU_* / pthread_setaffinity_np */
#endif
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <pthread.h>   /* pthread_setaffinity_np, pthread_self */
#include <sched.h>     /* cpu_set_t, CPU_ZERO/CPU_SET */
#include <time.h>      /* clock_gettime (non-x86 fallback) */
#include <cstdio>
#include <cstring>

namespace hk { namespace platform {

uint32_t page_size() {
    const long ps = sysconf(_SC_PAGESIZE);
    return static_cast<uint32_t>(ps > 0 ? ps : 4096);
}

process_id_t current_process_id() {
    return static_cast<process_id_t>(getpid());
}

bool is_debugger_attached() {
    /* Read TracerPid from /proc/self/status. A non-zero value means a
       debugger is attached. Phase 1 uses this simple heuristic only;
       hardened detection lands in a later phase. */
    FILE* f = fopen("/proc/self/status", "r");
    if (!f) return false;

    char line[256];
    bool result = false;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            long tracer_pid = 0;
            if (sscanf(line + 10, "%ld", &tracer_pid) == 1) {
                result = tracer_pid != 0;
            }
            break;
        }
    }
    fclose(f);
    return result;
}

/* -------------------------------------------------------------------------
 * macOS platform-trust reads (signal 124). Not available on Linux; return the
 * header-documented "unavailable" values so any TU that includes platform.h
 * can link regardless of which platform backend is selected by CMake.
 * ------------------------------------------------------------------------- */
bool csr_active_config(uint32_t * /*out_config*/) { return false; }
bool sip_enabled() { return true; }
uint32_t read_boot_args(char * /*out*/, uint32_t /*cap*/) { return 0; }

/* -------------------------------------------------------------------------
 * Client self-integrity reads (memory-integrity-selfcheck, signals 145-153).
 * On Linux the foreign read of the AC task's own memory comes from the eBPF
 * self-read program (bpf_probe_read_user over the AC task) on Deck/Game-Mode, or
 * the LKM self-read path on self-hosted/non-Deck (locked decision 3). Both are
 * default-OFF and their reachability for the AC task from an unrelated probe
 * context is UNCERTAIN (bpf_probe_read_user reads the CURRENT task; reading the
 * AC task from another context, and soft-dirty/file_mprotect LSM availability,
 * depend on kernel config). Until that is confirmed these report "unavailable".
 * The spoofable usermode half (/proc/self/smaps, /proc/self/pagemap soft-dirty,
 * /proc/self/maps prot) is intentionally NOT used as the trustworthy source here
 * — the sensor TU pairs it against the kernel read this seam must carry.
 * ------------------------------------------------------------------------- */
bool page_share_state(uint64_t /*va_base*/, uint64_t /*va_len*/,
                      uint32_t* /*out_private*/, uint32_t* /*out_dirty*/) {
    /* HK-UNCERTAIN(ebpf-self-read): cross-context bpf_probe_read_user of the AC
     * task + pagemap CAP_SYS_ADMIN requirement (see text_sample.bpf.c pagemap
     * caveat). Unavailable until confirmed on target kernels. */
    return false;
}

uint32_t module_image_file_name(uint64_t /*addr*/, char* /*out*/, uint32_t /*cap*/) {
    /* The loader's authoritative backing path for our VA (link_map vs file).
     * HK-TODO(151): /proc/self/maps gives the path but is the spoofable view; the
     * trustworthy cross-check is the eBPF/LKM read — unavailable until that lands. */
    return 0;
}

uint32_t selfcheck_kernel_read(uint32_t /*req_kind*/, uint64_t /*va_base*/,
                               uint64_t /*va_len*/, void* /*out*/, uint32_t /*cap*/) {
    /* HK-UNCERTAIN(ebpf-self-read): same gate as page_share_state. */
    return 0;
}

/* -------------------------------------------------------------------------
 * Timing clock seam (timing-side-channels signal 156 + fenced timing for
 * 159/161/162). x86-only intrinsic; non-x86 falls back to CLOCK_MONOTONIC_RAW
 * and aux=0. pthread_setaffinity_np gives a hard pin on Linux.
 * ------------------------------------------------------------------------- */
uint64_t rdtscp_aux(uint32_t* out_aux) {
#if defined(__x86_64__) || defined(__i386__)
    /* __rdtscp serializes prior loads; writes IA32_TSC_AUX into *aux. The Linux
     * kernel programs TSC_AUX with (numa_node << 12 | cpu); we expose the raw
     * value and the watchdog compares it for "same slot" rather than decoding it. */
    unsigned int aux = 0u;
    const unsigned long long tsc = __builtin_ia32_rdtscp(&aux);
    if (out_aux) {
        *out_aux = static_cast<uint32_t>(aux);
    }
    return static_cast<uint64_t>(tsc);
#else
    if (out_aux) {
        *out_aux = 0u;
    }
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ull +
           static_cast<uint64_t>(ts.tv_nsec);
#endif
}

bool pin_thread_to_core(uint32_t core_index) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(static_cast<int>(core_index), &set);
    /* Hard pin of the calling thread. Returns 0 on success. */
    return pthread_setaffinity_np(pthread_self(), sizeof(set), &set) == 0;
}

void unpin_thread() {
    /* Restore affinity to every online CPU. */
    cpu_set_t set;
    CPU_ZERO(&set);
    const long n = sysconf(_SC_NPROCESSORS_ONLN);
    const int count = (n > 0 && n < CPU_SETSIZE) ? static_cast<int>(n) : CPU_SETSIZE;
    for (int i = 0; i < count; ++i) {
        CPU_SET(i, &set);
    }
    (void)pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
}

} } // namespace hk::platform
