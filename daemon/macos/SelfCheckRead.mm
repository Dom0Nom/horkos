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
 * #13 (the live mach calls are HK-UNCERTAIN until self-task introspection without an
 * entitlement is confirmed on Apple Silicon AND Intel).
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
    /* HK-UNCERTAIN(macos-self-task): whether mach_vm_read_overwrite over our OWN
     * task port (mach_task_self()) succeeds WITHOUT an EndpointSecurity entitlement
     * or task_for_pid privilege is not confirmed (this is the bring-up path; the
     * SysExt swap is a separate locked decision). Per guardrail #13 the live
     * mach_vm_read_overwrite(mach_task_self(), va, len, out, &outsz) is NOT issued
     * until that is verified on Apple Silicon AND Intel. */
    os_log(hk_log(), "HKSelfReadBytes: self-task mach_vm_read stubbed "
                     "(HK-UNCERTAIN: entitlement-free self introspection unverified)");
    (void)va;
    return 0;
}

/* Report the share-mode / protection of the region containing `va` (146/152).
 * out_private/out_dirty receive the private/CoW page evidence; out_max_prot the
 * region max_protection. Returns false if unavailable. */
extern "C" bool HKSelfReadRegion(uint64_t va, uint32_t *out_private,
                                 uint32_t *out_dirty, uint32_t *out_max_prot) {
    /* HK-UNCERTAIN(macos-self-task): mach_vm_region_recurse over our own task port —
     * share_mode == SM_COW/SM_PRIVATE inside __TEXT (146) and max_protection gaining
     * VM_PROT_WRITE (152). Same entitlement question as HKSelfReadBytes; left
     * unimplemented until confirmed. The shared-cache COW FP question (legitimate
     * dyld page-in presenting as SM_COW) is also unverified — see
     * daemon/macos/HKTextIntegrity.cpp's identical caveat. */
    (void)va;
    (void)out_private;
    (void)out_dirty;
    (void)out_max_prot;
    return false;
}

/* Read DR0-DR7 of our threads via thread_get_state DEBUG_STATE (148). Returns the
 * number of threads reported, 0 if unavailable. */
extern "C" size_t HKSelfReadDebugState(uint64_t *out_dr, size_t cap_drs) {
    /* HK-UNCERTAIN(macos-self-task): thread_get_state(x86_DEBUG_STATE64 /
     * ARM_DEBUG_STATE64) over our own task's threads — same entitlement question.
     * Left unimplemented until confirmed. */
    (void)out_dr;
    (void)cap_drs;
    return 0;
}
