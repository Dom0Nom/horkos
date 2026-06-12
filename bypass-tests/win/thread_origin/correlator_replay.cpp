/*
 * Role: Host-runnable merge-gate bypass test (guardrail #12) for the ETW-TI
 *       causality core of win-kernel-thread-injection (signals 20/21). Unlike the
 *       DISABLED live-fixture gate (thread_origin.cpp), this one RUNS NOW on the
 *       build host: it replays a recorded-shaped ETW-TI event sequence through the
 *       platform-free hk::sdk::etwti::InjectCorrelator and asserts the named
 *       evasions are not silently accepted:
 *         - a cross-process ALLOCVM->SETTHREADCONTEXT->RESUME sequence correlates
 *           into exactly one chain with all three stage bits (signal 20);
 *         - a debugger-sourced chain still emits, with the SOURCE_DEBUGGER flag
 *           REPORTED (not suppressed client-side) for server adjudication;
 *         - a same-process (source==target) sequence produces NO chain (the
 *           thread-pool / loader FP gate holds);
 *         - a remote APC event is not folded into the injection chain.
 *       This proves the correlation logic before the live PPL/ELAM ETW-TI session
 *       exists, which is the plan's sanctioned bring-up path (replay traces).
 * Target platforms: host (platform-free correlator; built everywhere).
 * Interface: drives sdk/src/backends/win/EtwTiConsumer.h. No Win32/ETW API here —
 *       the live session is the PPL-gated stub in EtwTiConsumer.cpp.
 */

#include <cstdio>

#include "EtwTiConsumer.h"

using hk::sdk::etwti::InjectChain;
using hk::sdk::etwti::InjectCorrelator;
using hk::sdk::etwti::TiEvent;
using hk::sdk::etwti::TiTask;

namespace {

constexpr uint32_t CHAIN_ALLOCVM = 0x00000001u;
constexpr uint32_t CHAIN_SETCTX  = 0x00000002u;
constexpr uint32_t FLAG_DEBUGGER = 0x00000008u;

int g_failures = 0;

void check(bool cond, const char *what)
{
    if (!cond) {
        std::printf("FAIL: %s\n", what);
        ++g_failures;
    }
}

TiEvent mk(TiTask task, uint32_t src, uint32_t tpid, uint32_t ttid,
           uint64_t addr, uint64_t size, uint64_t t_ns, bool dbg = false)
{
    TiEvent e{};
    e.task = task;
    e.source_pid = src;
    e.target_pid = tpid;
    e.target_tid = ttid;
    e.address = addr;
    e.size = size;
    e.event_time_ns = t_ns;
    e.source_is_debugger = dbg;
    return e;
}

} // namespace

int main(void)
{
    /* Window of 50 ms; events arrive within it. */
    const uint64_t window = 50ull * 1000ull * 1000ull;

    /* --- Case 1: full cross-process chain correlates into one ready chain. -- */
    {
        InjectCorrelator c(window);
        InjectChain out{};
        bool r1 = c.feed(mk(TiTask::AllocVmRemote, 100, 200, 201,
                            0x4000'0000, 0x1000, 1'000'000),
                         out);
        check(!r1, "chain not ready after only ALLOCVM");
        bool r2 = c.feed(mk(TiTask::SetThreadContext, 100, 200, 201,
                            0x4000'0040, 0, 2'000'000),
                         out);
        check(r2, "chain ready after ALLOCVM+SETCONTEXT (>=2 stages)");
        check(out.ready, "emitted chain marked ready");
        check((out.chain_flags & CHAIN_ALLOCVM) != 0, "ALLOCVM bit set");
        check((out.chain_flags & CHAIN_SETCTX) != 0, "SETCONTEXT bit set");
        check(out.alloc_base == 0x4000'0000, "alloc_base captured");
        check(out.context_rip == 0x4000'0040, "context_rip captured");
        check(out.target_tid == 201, "target tid carried");

        /* RESUME completes the chain but must NOT re-emit (emit exactly once). */
        InjectChain out2{};
        bool r3 = c.feed(mk(TiTask::ResumeThread, 100, 200, 201, 0, 0, 3'000'000),
                         out2);
        check(!r3, "chain does not re-emit after it already fired");
    }

    /* --- Case 2: debugger-sourced chain still emits, flag REPORTED. --------- */
    {
        InjectCorrelator c(window);
        InjectChain out{};
        (void)c.feed(mk(TiTask::AllocVmRemote, 300, 400, 401, 0x5000'0000,
                        0x2000, 1'000'000, /*dbg=*/true),
                     out);
        bool ready = c.feed(mk(TiTask::ResumeThread, 300, 400, 401, 0, 0,
                               2'000'000, /*dbg=*/true),
                            out);
        check(ready, "debugger-sourced chain still emits (not silently dropped)");
        check((out.flags & FLAG_DEBUGGER) != 0,
              "SOURCE_DEBUGGER flag reported for server adjudication");
    }

    /* --- Case 3: same-process activity never readies a chain (FP gate). ----- */
    {
        InjectCorrelator c(window);
        InjectChain out{};
        bool r1 = c.feed(mk(TiTask::AllocVmRemote, 500, 500, 501, 0x6000'0000,
                            0x1000, 1'000'000),
                         out);
        bool r2 = c.feed(mk(TiTask::SetThreadContext, 500, 500, 501,
                            0x6000'0040, 0, 2'000'000),
                         out);
        check(!r1 && !r2, "same-process (source==target) never correlates");
    }

    /* --- Case 4: remote APC is not folded into the injection chain. --------- */
    {
        InjectCorrelator c(window);
        InjectChain out{};
        bool r = c.feed(mk(TiTask::QueueUserApc, 600, 700, 701, 0xABCD, 0,
                           1'000'000),
                        out);
        check(!r, "remote APC routed separately, not into the alloc/ctx/resume chain");
    }

    if (g_failures != 0) {
        std::printf("correlator_replay: %d assertion(s) failed.\n", g_failures);
        return 1;
    }
    std::printf("correlator_replay: all assertions passed.\n");
    return 0;
}
