/*
 * Role: macOS backend for the hk::platform abstraction layer.
 * Target platforms: macOS only. Selected by CMake if(APPLE).
 * Implements: platform/platform.h
 */

#include "platform.h"
#include <unistd.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <mach/mach_time.h>   /* mach_continuous_time (arm64 timing fallback) */
#include <cstring>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>

namespace hk { namespace platform {

uint32_t page_size() {
    return static_cast<uint32_t>(getpagesize());
}

process_id_t current_process_id() {
    return static_cast<process_id_t>(getpid());
}

bool is_debugger_attached() {
    /* Check the P_TRACED flag via sysctl(KERN_PROC_PID). Phase 1 only;
       hardened detection lands in a later phase. */
    struct kinfo_proc info;
    memset(&info, 0, sizeof(info));

    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    size_t size = sizeof(info);

    if (sysctl(mib, 4, &info, &size, nullptr, 0) != 0) {
        return false;
    }
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

/* -------------------------------------------------------------------------
 * Signal-124 platform-trust reads. The IORegistry boot-args read is a public,
 * stable IOKit path. The csr_* reads are PRIVATE SPI (see HK-UNCERTAIN), so
 * csr_active_config degrades to "unavailable" rather than guessing the bit
 * layout, and sip_enabled fails SAFE (returns true when it cannot tell).
 * ------------------------------------------------------------------------- */

bool csr_active_config(uint32_t *out_config) {
    /* HK-UNCERTAIN(csr-active-config): csr_get_active_config() (and csr_check())
     * are PRIVATE SPI (plan Risk 2). Their availability, exact signature, and the
     * CSR flag bit layout are not in a public header and have changed across
     * macOS versions (notably on Apple Silicon, where SIP is expressed
     * differently). Per guardrail #12 we do NOT declare the SPI symbol and call it
     * on a guessed signature, and we do NOT hardcode a guessed CSR bit layout.
     * This returns "unavailable" until the SPI contract is confirmed against the
     * target SDK on each OS version; signal 124 therefore ships report-only and
     * degraded (the plan's "default-ON-but-degraded" decision). When confirmed,
     * call csr_get_active_config(out_config) here and return its success. */
    (void)out_config;
    return false;
}

bool sip_enabled() {
    uint32_t config = 0;
    if (!csr_active_config(&config)) {
        /* Cannot determine — fail SAFE: do not assume a weakened/dev box. A
         * consumer (e.g. AmfidWatch) treats "unknown" as SIP-on so it does not
         * silently downgrade a real finding. */
        return true;
    }
    /* HK-UNCERTAIN(csr-bit-layout): interpreting `config` requires the confirmed
     * CSR bit layout (Risk 2). Until csr_active_config returns a real value this
     * branch is unreachable; do not guess the bits here. */
    return config == 0;  /* config == 0 conventionally means "SIP fully enabled" */
}

uint32_t read_boot_args(char *out, uint32_t cap) {
    if (out == nullptr || cap == 0) {
        return 0;
    }
    out[0] = '\0';

    /* IOPlatformExpertDevice carries the "boot-args" property. This is a public,
     * stable IOKit path (unlike the csr_* SPI). IOServiceGetMatchingService
     * consumes the matching dict; the returned service must be released. */
    io_registry_entry_t entry = IOServiceGetMatchingService(
        kIOMasterPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
    if (entry == MACH_PORT_NULL) {
        return 0;
    }

    CFTypeRef prop = IORegistryEntryCreateCFProperty(
        entry, CFSTR("boot-args"), kCFAllocatorDefault, 0);
    IOObjectRelease(entry);

    if (prop == nullptr) {
        return 0;   /* property absent (no boot-args set) */
    }

    uint32_t written = 0;
    if (CFGetTypeID(prop) == CFStringGetTypeID()) {
        if (CFStringGetCString(static_cast<CFStringRef>(prop), out, cap,
                               kCFStringEncodingUTF8)) {
            written = static_cast<uint32_t>(strnlen(out, cap));
        }
    }
    CFRelease(prop);
    return written;
}

/* -------------------------------------------------------------------------
 * Client self-integrity reads (memory-integrity-selfcheck, signals 145-153).
 * On macOS the self-read backend is the horkosd daemon (daemon/macos/
 * SelfCheckRead.mm), which mach_vm_read_overwrite / mach_vm_region_recurse /
 * thread_get_state over the AC's OWN task port. Whether the daemon can introspect
 * the AC task's own port WITHOUT an EndpointSecurity entitlement or task_for_pid
 * privilege is UNCERTAIN (bring-up path; SysExt swap is a separate locked
 * decision). Until confirmed on Apple Silicon AND Intel these report
 * "unavailable". This is NOT an ES auth-event path, so guardrail #7's reply
 * deadline does not apply.
 * ------------------------------------------------------------------------- */
bool page_share_state(uint64_t /*va_base*/, uint64_t /*va_len*/,
                      uint32_t* /*out_private*/, uint32_t* /*out_dirty*/) {
    /* HK-UNCERTAIN(macos-self-task): self-task mach_vm_region_recurse share_mode
     * (SM_COW/SM_PRIVATE) over our own task port — confirm no entitlement needed. */
    return false;
}

uint32_t module_image_file_name(uint64_t /*addr*/, char* /*out*/, uint32_t /*cap*/) {
    /* dyld backing path for our VA; HK-TODO(151): _dyld_image_path_containing_address
     * gives the in-process (spoofable) view, the daemon mach read is the cross-check —
     * unavailable until the daemon path is confirmed. */
    return 0;
}

uint32_t selfcheck_kernel_read(uint32_t /*req_kind*/, uint64_t /*va_base*/,
                               uint64_t /*va_len*/, void* /*out*/, uint32_t /*cap*/) {
    /* HK-UNCERTAIN(macos-self-task): same gate. */
    return 0;
}

/* -------------------------------------------------------------------------
 * Timing clock seam (timing-side-channels signal 156). macOS gives NO hard
 * thread-to-core pinning — thread_policy_set(THREAD_AFFINITY_POLICY) is only an
 * affinity HINT and is a no-op on Apple Silicon. So pin_thread_to_core always
 * returns false here and signal 156 must be weighted lower server-side (plan
 * FLAG signal-156 macOS). On Apple Silicon there is no userspace TSC/TSC_AUX, so
 * rdtscp_aux falls back to mach_continuous_time and aux=0 (core unknown).
 * ------------------------------------------------------------------------- */
uint64_t rdtscp_aux(uint32_t* out_aux) {
#if defined(__x86_64__) || defined(__i386__)
    unsigned int aux = 0u;
    const unsigned long long tsc = __builtin_ia32_rdtscp(&aux);
    if (out_aux) {
        *out_aux = static_cast<uint32_t>(aux);
    }
    return static_cast<uint64_t>(tsc);
#else
    /* Apple Silicon: no rdtscp. mach_continuous_time is the monotonic fallback;
     * the caller must not treat this as a cycle counter (it is timebase ticks). */
    if (out_aux) {
        *out_aux = 0u;
    }
    return static_cast<uint64_t>(mach_continuous_time());
#endif
}

bool pin_thread_to_core(uint32_t /*core_index*/) {
    /* No hard pin on macOS. THREAD_AFFINITY_POLICY is a hint and unavailable on
     * arm64; returning false tells the watchdog to down-weight migration discards.
     * HK-UNCERTAIN(macos-affinity): even the x86 affinity-tag hint does not
     * guarantee a stable core; do not rely on it for the 156 core-migration gate. */
    return false;
}

void unpin_thread() {
    /* Nothing to restore — we never applied a hard pin. */
}

} } // namespace hk::platform
