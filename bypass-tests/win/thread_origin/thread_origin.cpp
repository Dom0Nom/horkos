/*
 * Role: Merge-gate bypass test (guardrail #12) for the win-kernel-thread-injection
 *       security folder. One sub-case per catalog evasion the plan names
 *       (signals 19-27): manual-map thread, setcontext/resume chain, remote APC,
 *       Heaven's-Gate WOW64 start, start-address spoof, module stomp,
 *       hide-from-debugger co-signal, cross-session injector, and worker burst.
 *       Each sub-case asserts BOTH (a) the sensor emits the expected record and
 *       (b) the named evasion is NOT silently accepted (it either flags or is
 *       faithfully reported with its FP-gate flag for server adjudication).
 *
 *       Phase ships DISABLED (HK_THREAD_ORIGIN_TEST_ENABLED undefined): a compiled
 *       no-op that reports "DISABLED" and returns 0, exactly like the sibling
 *       byovd_load.cpp / callback_unhook.cpp gates. It activates when the live
 *       fixtures exist:
 *         - the kernel notify plane emits hk_event_thread_create over a grown
 *           HK_EVENT_PAYLOAD_MAX (Schema phase), and
 *         - the ETW-TI consumer can be driven by REPLAYED traces (the sanctioned
 *           bring-up path, since the live provider needs a PPL/ELAM host — see
 *           EtwTiConsumer.cpp HK-UNCERTAIN(etw-ti)).
 *       The repo never commits a working injector or an unhooking driver; the
 *       synthetic injectors are built behind the enable flag against a test-only
 *       fixture that is not in this tree.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/ioctl.h (drain envelope) and the
 *       thread-origin event surface (HK_EVENT_THREAD_*, HK_PROV_*, HK_INJECT_*).
 *       HK-TODO(schema): those wire types are kernel-private mirrors in
 *       kernel/win/include/horkos_kernel.h until the Schema phase appends them to
 *       event_schema.h; the activated body references them through that header.
 */

#include <cstdio>

#ifndef HK_THREAD_ORIGIN_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: thread_origin bypass test activates when the kernel "
                "thread-create plane + the grown event schema land and the "
                "ETW-TI consumer can replay recorded traces (the live provider "
                "needs a PPL/ELAM host). See the plan's Risks section.\n");
    return 0; /* Disabled tests pass so the gate stays green pre-enforcement. */
}

#else

#include <windows.h>
#include <vector>

#include "horkos/ioctl.h"
#include "horkos_kernel.h" /* kernel-private mirrors: HK_EVENT_THREAD_*, flags */

/*
 * Drain the kernel ring and count records of `type`. For provenance/inject
 * records the caller additionally checks a flag mask via the returned payload.
 * Shared helper once the fixtures are wired.
 */
static int drain_count(uint32_t type)
{
    /* Phase-later: open \\.\Horkos, issue HK_IOCTL_DRAIN_EVENTS, scan records for
     * header.type == type. The ETW-TI sub-cases instead feed a recorded trace
     * into hk::sdk::etwti::InjectCorrelator and assert on the emitted chain. */
    (void)type;
    return 0;
}

/* ---- one sub-case per catalog evasion (signals 19-27) -------------------- */

/* 19/24: manual-mapped injector creates a thread from unbacked private RX.
 * Assert HK_EVENT_THREAD_CREATE + HK_PROV_ENTRY_PRIVATE; assert a signed-JIT host
 * doing the same is HK_PROV_JIT_ALLOWLISTED (no false ban signal). */
static int case_manual_map_thread(void)     { return 1; /* TODO: fixture + assert */ }

/* 20: CreateRemoteThread-suspended / SetThreadContext / ResumeThread and
 * Early-Bird APC. Assert the ALLOCVM->SETCONTEXT->RESUME chain correlates into one
 * hk_event_thread_inject; assert a debugger-sourced set-context sets
 * HK_INJECT_FLAG_SOURCE_DEBUGGER (reported, not silently dropped). */
static int case_setcontext_resume(void)     { return 1; /* TODO: replay + assert */ }

/* 21: NtQueueApcThreadEx special-user-APC into the target. Assert
 * hk_event_apc_inject with apc_routine resolved to a non-image region; assert
 * same-process I/O-completion APCs produce no record. */
static int case_remote_apc(void)            { return 1; /* TODO: replay + assert */ }

/* 22: 64-bit shellcode thread in a WOW64 game. Assert HK_PROV_WOW64_64BIT_START;
 * assert legitimate wow64 transition stubs do not flag. */
static int case_heavens_gate_wow64(void)    { return 1; /* TODO: fixture + assert */ }

/* 23: patch the queryable Win32StartAddress to a benign in-module value while the
 * real start is shellcode. Assert HK_PROV_START_MISMATCH fires from the
 * kernel-vs-user comparison (the userspace-only check would have been fooled). */
static int case_start_address_spoof(void)   { return 1; /* TODO: fixture + assert */ }

/* 24: overwrite a system-DLL page and start a thread there. Assert
 * HK_PROV_ENTRY_STOMPED with non-zero entry_page_disk_delta; assert a declared-
 * packed game section does not flag. */
static int case_module_stomp(void)          { return 1; /* TODO: fixture + assert */ }

/* 25: thread sets ThreadHideFromDebugger. Assert HK_PROV_HIDE_FROM_DEBUGGER only
 * co-fires with a non-image start (a lone benign DRM thread with the flag does
 * not produce an adversarial co-signal). */
static int case_hide_from_debugger(void)    { return 1; /* TODO: fixture + assert */ }

/* 26: Session-0 service creates a thread into the interactive game. Assert
 * HK_THREAD_FLAG_CROSS_SESSION; assert an allowlisted signed Session-0 publisher
 * is distinguishable server-side. */
static int case_cross_session_injector(void){ return 1; /* TODO: fixture + assert */ }

/* 27: periodic tick-worker recreation from an unbacked stack. Assert raw events
 * reported with creator-stack-unbacked set and NO client-side threshold (the
 * client emits per-event, leaving rate scoring to the server). */
static int case_worker_burst(void)          { return 1; /* TODO: replay + assert */ }

int main(void)
{
    int failures = 0;
    failures += case_manual_map_thread();
    failures += case_setcontext_resume();
    failures += case_remote_apc();
    failures += case_heavens_gate_wow64();
    failures += case_start_address_spoof();
    failures += case_module_stomp();
    failures += case_hide_from_debugger();
    failures += case_cross_session_injector();
    failures += case_worker_burst();

    (void)drain_count;

    if (failures != 0) {
        std::printf("thread_origin: %d sub-case(s) not yet implemented.\n",
                    failures);
        return 1;
    }
    std::printf("thread_origin: all sub-cases passed.\n");
    return 0;
}

#endif /* HK_THREAD_ORIGIN_TEST_ENABLED */
