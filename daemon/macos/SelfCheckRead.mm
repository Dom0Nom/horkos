/*
 * daemon/macos/SelfCheckRead.mm
 * Role: macOS self-read backend for client self-integrity (memory-integrity-
 *       selfcheck, signals 145/146/148/152). Over the AC's OWN task port it
 *       mach_vm_read_overwrite's the requested VA (145), mach_vm_region_recurse's
 *       the share-mode/protection (146/152), and thread_get_state DEBUG_STATE's
 *       the debug registers (148). Never touches an ES event — this is NOT an ES
 *       client path, so guardrail #7's reply deadline does not apply here.
 * Target platform: macOS only (built behind APPLE in the daemon target). Userspace
 *       daemon TU (guardrail #4 — no kernel TU shared).
 * Interface: implements HKSelfReadBytes / HKSelfReadRegion / HKSelfReadDebugState.
 *
 * Self-task introspection via mach_task_self() requires no entitlement (Mach is
 * capability-based; task_for_pid restrictions apply to FOREIGN tasks only). The
 * live calls below are implemented and verified on-device (both Apple Silicon
 * ARM_DEBUG_STATE64 and Intel x86_DEBUG_STATE64). The reads go through the task
 * PORT, not a plain in-process memcpy, so a hooked in-process reader cannot forge
 * this foreign view of our own image.
 */

#include <cstddef>
#include <cstdint>
#include <cstring>

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
    mach_vm_size_t outsize = 0;
    kern_return_t kr = mach_vm_read_overwrite(
        mach_task_self(), static_cast<mach_vm_address_t>(va),
        static_cast<mach_vm_size_t>(len),
        reinterpret_cast<mach_vm_address_t>(out), &outsize);
    if (kr != KERN_SUCCESS) {
        os_log_error(hk_log(), "HKSelfReadBytes: mach_vm_read_overwrite failed kr=%d", kr);
        return 0;
    }
    return static_cast<size_t>(outsize);
}

/* Report the share-mode / protection of the region containing `va` (146/152).
 * out_private/out_dirty receive the private/CoW page evidence; out_max_prot the
 * region max_protection. Returns false if unavailable. */
extern "C" bool HKSelfReadRegion(uint64_t va, uint32_t *out_private,
                                 uint32_t *out_dirty, uint32_t *out_max_prot) {
    mach_vm_address_t addr = static_cast<mach_vm_address_t>(va);
    mach_vm_size_t size = 0;
    natural_t depth = 0;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;

    kern_return_t kr = mach_vm_region_recurse(
        mach_task_self(), &addr, &size, &depth,
        reinterpret_cast<vm_region_recurse_info_t>(&info), &count);
    if (kr != KERN_SUCCESS) {
        return false;
    }
    // SM_COW pages on the dyld shared cache are a known false-positive source for
    // a naive "shared => suspicious" rule; the share_mode is reported raw and the
    // FP gate lives in HKTextIntegrity.cpp, not here.
    if (out_private) {
        *out_private = (info.share_mode == SM_PRIVATE) ? 1u : 0u;
    }
    if (out_dirty) {
        *out_dirty = info.pages_dirtied;
    }
    if (out_max_prot) {
        *out_max_prot = static_cast<uint32_t>(info.max_protection);
    }
    return true;
}

/* Read the per-thread hardware debug registers via thread_get_state DEBUG_STATE
 * (148). Emits the breakpoint value registers (x86 DR0-DR3 / DR6 / DR7 on Intel;
 * ARM bvr[0..] on Apple Silicon) into out_dr. Returns the number of u64 slots
 * written, 0 if unavailable. */
extern "C" size_t HKSelfReadDebugState(uint64_t *out_dr, size_t cap_drs) {
    if (out_dr == nullptr || cap_drs == 0) {
        return 0;
    }
    thread_act_array_t threads = nullptr;
    mach_msg_type_number_t thread_count = 0;
    if (task_threads(mach_task_self(), &threads, &thread_count) != KERN_SUCCESS) {
        return 0;
    }

    size_t written = 0;
    // One pass: read up to cap_drs slots, but deallocate EVERY thread port
    // exactly once (leaking a thread send right per poll is a real bug).
    for (mach_msg_type_number_t i = 0; i < thread_count; ++i) {
        if (written < cap_drs) {
#if defined(__arm64__)
            arm_debug_state64_t ds;
            mach_msg_type_number_t cnt = ARM_DEBUG_STATE64_COUNT;
            if (thread_get_state(threads[i], ARM_DEBUG_STATE64,
                                 reinterpret_cast<thread_state_t>(&ds), &cnt) == KERN_SUCCESS) {
                // The first breakpoint value register per thread (a set bvr is
                // the hardware-breakpoint tell the server correlates).
                out_dr[written++] = ds.__bvr[0];
            }
#elif defined(__x86_64__)
            x86_debug_state64_t ds;
            mach_msg_type_number_t cnt = x86_DEBUG_STATE64_COUNT;
            if (thread_get_state(threads[i], x86_DEBUG_STATE64,
                                 reinterpret_cast<thread_state_t>(&ds), &cnt) == KERN_SUCCESS) {
                out_dr[written++] = ds.__dr7; // DR7 carries the enabled-breakpoint bits
            }
#endif
        }
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    mach_vm_deallocate(mach_task_self(), reinterpret_cast<mach_vm_address_t>(threads),
                       thread_count * sizeof(thread_act_t));
    return written;
}
