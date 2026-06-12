/*
 * Role: task_threads + thread_get_state enumeration of the game task, resolve
 *       each thread's entry PC against the dyld image map, flag foreign/anon
 *       entries (signal 114). Intersects with the signal-111 mmap baseline so a
 *       foreign entry inside a sanctioned JIT region is not high-signal.
 * Target platform: macOS only (arm64 + x86_64; built behind `if(APPLE)`).
 * Interface: implements HKResolveEntryRegion() (pure) and HKThreadScan() from
 *            HKThreadIntegrity.h. Userspace daemon TU (guardrail #4).
 *
 * Guardrail compliance:
 *   #1  No raw __APPLE__ / __arm64__ host guard for platform selection — CMake
 *       gates the TU. The arm64-vs-x86_64 thread-state read below uses the
 *       compiler's target arch macros ONLY to pick the correct register struct,
 *       which is an arch (not OS) distinction inside an already-macOS TU; there
 *       is no cross-OS conditional here.
 *   #13 The entry-PC read is HK-UNCERTAIN for Rosetta-translated (x86 under
 *       arm64) game tasks and depends on the stubbed CONTROL-level task handle,
 *       so the live enumeration no-ops until both are verified. The PURE region
 *       resolver (HKResolveEntryRegion) is fully implemented and unit-tested.
 */

#include "HKThreadIntegrity.h"

#include <mach/mach.h>
#include <mach/task.h>
#include <mach/thread_act.h>
#include <mach/thread_status.h>
#include <mach/vm_map.h>     /* vm_deallocate */
#include <string.h>
#include <os/log.h>

namespace {
os_log_t hk_log() {
    static os_log_t log = os_log_create("io.horkos.daemon", "thread-integrity");
    return log;
}

inline bool pc_in_range(uint64_t pc, uint64_t base, uint64_t size) {
    /* Guard against base+size overflow on a malformed region. */
    if (size == 0) {
        return false;
    }
    uint64_t end = base + size;
    if (end < base) {  /* wrapped */
        return pc >= base;  /* treat the wrapped tail as in-range */
    }
    return pc >= base && pc < end;
}
}  // namespace

extern "C" uint32_t HKResolveEntryRegion(uint64_t             entry_pc,
                                         const HKImageRegion *images,
                                         size_t               image_count,
                                         const HKJitRegion   *jit,
                                         size_t               jit_count) {
    /* Image membership wins: a PC inside a real mach-o image is IMAGE even if it
     * also overlaps a JIT region the title declared. */
    if (images != nullptr) {
        for (size_t i = 0; i < image_count; ++i) {
            if (pc_in_range(entry_pc, images[i].base, images[i].size)) {
                return HK_REGION_IMAGE;
            }
        }
    }
    if (jit != nullptr) {
        for (size_t i = 0; i < jit_count; ++i) {
            if (pc_in_range(entry_pc, jit[i].base, jit[i].size)) {
                return HK_REGION_JIT_SANCTIONED;
            }
        }
    }
    return HK_REGION_ANON;
}

extern "C" size_t HKThreadScan(const HKGameTaskHandle *game,
                               const HKImageRegion    *images, size_t image_count,
                               const HKJitRegion      *jit,    size_t jit_count,
                               HKThreadOriginEmit      emit,   void  *ctx) {
    if (game == nullptr || emit == nullptr) {
        return 0;
    }
    if (!game->valid || game->task == MACH_PORT_NULL) {
        /* HK-UNCERTAIN(thread-scan): needs a CONTROL-level task port
         * (HKGameTaskHandle stubbed) AND a verified per-arch entry-PC read,
         * including the Rosetta (x86 under arm64) case where the thread-state
         * flavor differs. No-op until both are verified on hardware. */
        return 0;
    }

    thread_act_array_t threads = nullptr;
    mach_msg_type_number_t thread_count = 0;
    kern_return_t kr = task_threads(game->task, &threads, &thread_count);
    if (kr != KERN_SUCCESS || threads == nullptr) {
        os_log_error(hk_log(), "HKThreadScan: task_threads failed: %d", kr);
        return 0;
    }

    size_t emitted = 0;
    for (mach_msg_type_number_t i = 0; i < thread_count; ++i) {
        uint64_t entry_pc = 0;
        bool got_pc = false;

#if defined(__arm64__) || defined(__aarch64__)
        arm_thread_state64_t st;
        mach_msg_type_number_t cnt = ARM_THREAD_STATE64_COUNT;
        kr = thread_get_state(threads[i], ARM_THREAD_STATE64,
                              reinterpret_cast<thread_state_t>(&st), &cnt);
        if (kr == KERN_SUCCESS) {
            entry_pc = arm_thread_state64_get_pc(st);
            got_pc = true;
        }
#elif defined(__x86_64__)
        x86_thread_state64_t st;
        mach_msg_type_number_t cnt = x86_THREAD_STATE64_COUNT;
        kr = thread_get_state(threads[i], x86_THREAD_STATE64,
                              reinterpret_cast<thread_state_t>(&st), &cnt);
        if (kr == KERN_SUCCESS) {
            entry_pc = st.__rip;
            got_pc = true;
        }
#else
#  error "HKThreadIntegrity: unsupported macOS architecture"
#endif
        /* The CURRENT pc is not the thread's ENTRY pc; recovering the true entry
         * address requires unwinding to the thread's start routine. HK-UNCERTAIN
         * (thread-entry): the running pc is used as a coarse proxy here; a
         * precise entry-pc recovery (thread start routine via the thread's
         * initial frame) is unverified and must be validated on hardware before
         * 114 is relied upon. Anon current-pc is still a useful coarse signal. */
        uint32_t kind = HK_REGION_ANON;
        if (got_pc) {
            kind = HKResolveEntryRegion(entry_pc, images, image_count,
                                        jit, jit_count);
        }

        /* task_threads() returns a send right per thread_act_t; we must
         * deallocate each port after use on ALL exit paths (including the
         * early continue below). */
        mach_port_deallocate(mach_task_self(), threads[i]);

        if (!got_pc || kind == HK_REGION_IMAGE) {
            continue;
        }

        hk_es_thread_origin ev;
        memset(&ev, 0, sizeof(ev));
        ev.game_pid    = static_cast<uint32_t>(game->pid);
        ev.thread_id   = static_cast<uint32_t>(i);  /* index proxy; mach tid below */
        ev.entry_pc    = entry_pc;
        ev.region_kind = kind;
        emit(&ev, ctx);
        ++emitted;
    }

    /* Deallocate the kernel-allocated thread port array. Individual port send
     * rights were already released in the loop above. */
    vm_deallocate(mach_task_self(),
                  reinterpret_cast<vm_address_t>(threads),
                  thread_count * sizeof(*threads));
    return emitted;
}
