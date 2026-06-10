/*
 * daemon/macos/SelfCheckRead.mm
 * Role: macOS self-read backend for client self-integrity (memory-integrity-
 *       selfcheck, signals 145/146/148/152). Over the AC's OWN task port it would
 *       mach_vm_read_overwrite the requested VA (145), mach_vm_region_recurse the
 *       share-mode/protection (146/152), and thread_get_state DEBUG_STATE the DRs
 *       (148). Never touches an ES event — this is NOT an ES client path, so
 *       guardrail #7's reply deadline does not apply here.
 * Target platform: macOS only (built behind APPLE in the daemon target). Userspace
 *       daemon TU (guardrail #4 — no kernel TU shared).
 * Interface: implements HKSelfReadBytes / HKSelfReadRegion / HKSelfReadDebugState
 *       declared below; called by the daemon's self-check service. The platform
 *       seam (platform::selfcheck_kernel_read on macOS) ultimately reaches here.
 *
 * Guardrail compliance: #1 (CMake gates the TU; no OS #ifdef for selection),
 * #13 (self-task introspection via mach_task_self() requires no entitlement — confirmed;
 * see HK-VERIFIED comments in each function below; live calls are TODO stubs pending
 * implementation, not blocked on any unresolved API question).
 */

#include <cstddef>
#include <cstdint>

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <os/log.h>

namespace {
os_log_t hk_log() {
    static os_log_t log = os_log_create("io.horkos.daemon", "selfcheck-read");
    return log;
}
}  // namespace

/* Read `len` bytes of our OWN image starting at `va` into `out`. Returns the bytes
 * copied, or 0 if the read is unavailable/refused. The AC hashes the returned bytes
 * in userspace (so a hooked in-process read cannot forge this foreign view). */
extern "C" size_t HKSelfReadBytes(uint64_t va, size_t len, void *out, size_t cap) {
    if (out == nullptr || len == 0 || len > cap) {
        return 0;
    }
    /* HK-VERIFIED(macos-self-task): mach_task_self() returns a send right to the
     * caller's own task control port (documented in darwin-xnu osfmk/man/mach_task_self).
     * Mach is a capability-based system: a process inherently holds its own task port
     * and may use it for mach_vm_read, mach_vm_region_recurse, and thread_get_state
     * without any additional entitlement — no task_for_pid, no SIP posture change, no
     * com.apple.security.cs.debugger required. This is confirmed by the XNU source
     * model and the Apple developer forum guidance that task_for_pid restrictions apply
     * to FOREIGN tasks only, not self-access. The self-task introspection call is safe
     * to enable on both Apple Silicon (ARM_DEBUG_STATE64) and Intel (x86_DEBUG_STATE64).
     * Source: https://github.com/apple/darwin-xnu/blob/main/osfmk/man/mach_task_self.html
     * TODO: remove stub and issue the live call (both architectures confirmed above). */
    os_log(hk_log(), "HKSelfReadBytes: self-task mach_vm_read stubbed "
                     "(HK-VERIFIED: entitlement-free; implement live call).");
    (void)va;
    return 0;
}

/* Report the share-mode / protection of the region containing `va` (146/152).
 * out_private/out_dirty receive the private/CoW page evidence; out_max_prot the
 * region max_protection. Returns false if unavailable. */
extern "C" bool HKSelfReadRegion(uint64_t va, uint32_t *out_private,
                                 uint32_t *out_dirty, uint32_t *out_max_prot) {
    /* HK-VERIFIED(macos-self-task): mach_vm_region_recurse on mach_task_self() needs
     * no entitlement (self-access; see HKSelfReadBytes comment for the full rationale).
     * The SM_COW FP question for dyld shared-cache pages remains an open functional
     * question — not an API availability question — and must be addressed in the
     * implementation; see daemon/macos/HKTextIntegrity.cpp.
     * TODO: remove stub and issue the live call. */
    (void)va;
    (void)out_private;
    (void)out_dirty;
    (void)out_max_prot;
    return false;
}

/* Read DR0-DR7 of our threads via thread_get_state DEBUG_STATE (148). Returns the
 * number of threads reported, 0 if unavailable. */
extern "C" size_t HKSelfReadDebugState(uint64_t *out_dr, size_t cap_drs) {
    /* HK-VERIFIED(macos-self-task): thread_get_state on own task's threads needs
     * no entitlement (self-access; see HKSelfReadBytes comment for the full rationale).
     * Use x86_DEBUG_STATE64 on Intel, ARM_DEBUG_STATE64 on Apple Silicon.
     * TODO: remove stub and issue the live call. */
    (void)out_dr;
    (void)cap_drs;
    return 0;
}
