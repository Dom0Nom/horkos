/*
 * sdk/src/backends/win/EtwTiConsumer.cpp
 * Role: Windows userspace ETW Threat-Intelligence consumer + cross-process
 *       causality correlation (win-kernel-thread-injection, catalog signals
 *       20/21/27). Correlates ALLOCVM_REMOTE -> SETTHREADCONTEXT -> RESUMETHREAD
 *       into one hk_event_thread_inject, resolves QUEUEUSERAPC_REMOTE into
 *       hk_event_apc_inject, and reports raw create-event stack bursts (no client
 *       thresholding). Capture-only; the server scores rate / unbacked stack.
 * Target platforms: Windows (userspace). Guardrail #1: ALL ETW Win32 API
 *       (StartTrace/OpenTrace/ProcessTrace/EVENT_RECORD) is confined to this
 *       backends/win/ TU; the platform-free correlator (EtwTiConsumer.h) is the
 *       part the host tests exercise. Guardrail #4: userspace TU, no kernel
 *       headers.
 * Interface: implements hk::sdk::etwti::start/stop and InjectCorrelator::feed
 *       from EtwTiConsumer.h. Built only under HK_WIN_ETWTI (default OFF).
 *
 * ============================================================================
 * HK-UNCERTAIN(etw-ti): Microsoft-Windows-Threat-Intelligence is a PROTECTED
 * provider. It does NOT deliver to an ordinary process. Only a Protected-Process
 * -Light anti-malware process (PsProtectedSignerAntimalware, i.e. an ELAM-signed
 * binary holding an anti-malware cert) may open a real-time session on it; the
 * kernel emits to it via EtwRegister. Horkos does NOT currently hold an
 * anti-malware/ELAM certificate. Therefore the LIVE consumer surface below is a
 * STUB: start() reports the session cannot be opened without PPL/ELAM, and the
 * real StartTrace/OpenTrace/ProcessTrace plumbing is intentionally NOT written
 * here. This is exactly the signing/EKU requirement CLAUDE.md says not to guess
 * on. The correlation core IS implemented and testable via replayed traces (the
 * bypass tests under bypass-tests/win/thread_origin/), which is the sanctioned
 * bring-up path until the cert + PPL host land.
 *   ref: ETW for Windows / protected providers (fetched in the task log).
 * ============================================================================
 */

#include "EtwTiConsumer.h"

namespace hk { namespace sdk { namespace etwti {

InjectCorrelator::Entry *
InjectCorrelator::find_or_insert(uint32_t pid, uint32_t tid, uint64_t now_ns)
{
    Entry *freeSlot = nullptr;
    Entry *oldest = nullptr;

    for (auto &e : table_) {
        if (e.used && e.target_pid == pid && e.target_tid == tid) {
            /* Expire a stale chain (outside the window) and reuse the slot. */
            if (now_ns - e.first_ns > window_ns_) {
                e = Entry{};
            } else {
                return &e;
            }
        }
        if (!e.used && freeSlot == nullptr) {
            freeSlot = &e;
        }
        if (e.used && (oldest == nullptr || e.first_ns < oldest->first_ns)) {
            oldest = &e;
        }
    }

    Entry *slot = (freeSlot != nullptr) ? freeSlot : oldest;
    if (slot == nullptr) {
        return nullptr;
    }
    *slot = Entry{};
    slot->used = true;
    slot->target_pid = pid;
    slot->target_tid = tid;
    slot->first_ns = now_ns;
    slot->last_ns = now_ns;
    return slot;
}

bool InjectCorrelator::feed(const TiEvent &ev, InjectChain &out)
{
    /* Remote-APC is its own event type, not part of the alloc/ctx/resume chain;
     * the .cpp routes it straight to hk_event_apc_inject. The correlator only
     * assembles the three-stage injection chain. */
    if (ev.task == TiTask::QueueUserApc) {
        return false;
    }

    /* Same-process activity is Windows' own thread-pool / loader work and never
     * a cross-process injection chain (signal 20 FP gate). */
    if (ev.source_pid == ev.target_pid) {
        return false;
    }

    Entry *e = find_or_insert(ev.target_pid, ev.target_tid, ev.event_time_ns);
    if (e == nullptr) {
        return false;
    }

    e->source_pid = ev.source_pid;
    e->last_ns = ev.event_time_ns;

    /* Bit per chain stage seen. HK_INJECT_CHAIN_* values are duplicated here as
     * locals so this platform-free core needs no kernel/wire header; the .cpp
     * maps them onto the C wire constants when it stamps hk_event_thread_inject. */
    constexpr uint32_t CHAIN_ALLOCVM   = 0x00000001u;
    constexpr uint32_t CHAIN_SETCTX    = 0x00000002u;
    constexpr uint32_t CHAIN_RESUME    = 0x00000004u;
    constexpr uint32_t FLAG_DEBUGGER   = 0x00000008u;
    constexpr uint32_t FLAG_OVERLAY    = 0x00000010u;

    switch (ev.task) {
    case TiTask::AllocVmRemote:
        e->chain_flags |= CHAIN_ALLOCVM;
        e->alloc_base = ev.address;
        e->alloc_size = ev.size;
        break;
    case TiTask::SetThreadContext:
        e->chain_flags |= CHAIN_SETCTX;
        e->context_rip = ev.address;
        break;
    case TiTask::ResumeThread:
        e->chain_flags |= CHAIN_RESUME;
        break;
    default:
        break;
    }

    /* FP gates are REPORTED, never used to suppress client-side (server decides). */
    if (ev.source_is_debugger) {
        e->flags |= FLAG_DEBUGGER;
    }
    if (ev.source_is_overlay) {
        e->flags |= FLAG_OVERLAY;
    }

    /* "Ready" once >=2 distinct stages fired for this TID (per the plan's
     * threshold). Popcount of the three chain bits. Emit exactly once. */
    uint32_t stageBits = e->chain_flags & (CHAIN_ALLOCVM | CHAIN_SETCTX | CHAIN_RESUME);
    int stages = 0;
    for (uint32_t b = stageBits; b != 0; b &= (b - 1)) {
        ++stages;
    }

    if (stages >= 2 && !e->emitted) {
        e->emitted = true;
        out = InjectChain{};
        out.source_pid = e->source_pid;
        out.target_pid = e->target_pid;
        out.target_tid = e->target_tid;
        out.chain_flags = e->chain_flags;
        out.alloc_base = e->alloc_base;
        out.alloc_size = e->alloc_size;
        out.context_rip = e->context_rip;
        out.window_ns = e->last_ns - e->first_ns;
        out.flags = e->flags;
        out.ready = true;
        return true;
    }

    return false;
}

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

int start()
{
    /* HK-UNCERTAIN(etw-ti): the live Microsoft-Windows-Threat-Intelligence
     * real-time session requires a PPL anti-malware (ELAM-signed) host. Without
     * the cert + PPL launch, StartTrace/OpenTrace on this provider fails. The
     * production plumbing is intentionally not written here (guardrail #13);
     * dev/test brings the correlator up via replayed traces in the bypass tests.
     * Returning -1 keeps the SDK in the documented "ETW-TI unavailable" mode
     * rather than pretending a session opened. */
    return -1;
}

void stop()
{
    /* No live session to tear down while start() is the PPL-gated stub. The real
     * stop() will CloseTrace the OpenTrace handle and stop the StartTrace
     * session, on the same thread that opened them, once the PPL path lands. */
}

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */

} } } // namespace hk::sdk::etwti
