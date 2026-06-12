/*
 * Role: SDK-internal lifecycle interface for the protected ETW Threat-Intelligence
 *       consumer (win-kernel-thread-injection, catalog signals 20/21/27). Declares
 *       start/stop plus the platform-free causality-correlation core that the host
 *       unit tests and replay-based bypass tests drive without a live PPL session.
 * Target platforms: Windows (userspace). The correlation state machine
 *       (InjectCorrelator) is platform-free so it is host-testable from replayed
 *       traces.
 * Interface: consumed by the Windows sdk.cpp path; implemented in
 *       EtwTiConsumer.cpp. Built only under the HK_WIN_ETWTI option (default OFF —
 *       the live provider needs a PPL/ELAM-signed host).
 */

#pragma once

#include <cstdint>

namespace hk { namespace sdk { namespace etwti {

/* The three ETW-TI tasks the causality window correlates (signal 20), plus the
 * remote-APC task (signal 21). Values are LOCAL ids for the platform-free
 * correlator — NOT the provider's wire task ids (those are resolved in the .cpp
 * from the real EVENT_RECORD and mapped to these). */
enum class TiTask : uint32_t {
    AllocVmRemote    = 1,  /* KERNEL_THREATINT_TASK_ALLOCVM_REMOTE     */
    SetThreadContext = 2,  /* KERNEL_THREATINT_TASK_SETTHREADCONTEXT   */
    ResumeThread     = 3,  /* KERNEL_THREATINT_TASK_RESUMETHREAD       */
    QueueUserApc     = 4,  /* KERNEL_THREATINT_TASK_QUEUEUSERAPC_REMOTE */
};

/* One normalized ETW-TI event fed to the correlator. Platform-free: the .cpp
 * builds these from EVENT_RECORD payloads. */
struct TiEvent {
    TiTask   task;
    uint32_t source_pid;
    uint32_t target_pid;
    uint32_t target_tid;
    uint64_t address;        /* alloc base / new RIP / ApcRoutine, per task */
    uint64_t size;           /* alloc size; 0 otherwise                     */
    uint64_t event_time_ns;  /* QPC-derived ns                              */
    bool     source_is_debugger; /* registered-debugger source (FP gate)    */
    bool     source_is_overlay;  /* signed-overlay allowlist (FP gate)      */
    bool     apc_is_special;     /* special-user-APC bit (signal 21)        */
};

/* Emitted chain record (mirrors hk_event_thread_inject fields). Returned by the
 * correlator so the .cpp and tests can assert on it without the C wire struct. */
struct InjectChain {
    uint32_t source_pid;
    uint32_t target_pid;
    uint32_t target_tid;
    uint32_t chain_flags;   /* HK_INJECT_CHAIN_* bits seen                  */
    uint64_t alloc_base;
    uint64_t alloc_size;
    uint64_t window_ns;     /* first->last span                            */
    uint64_t context_rip;
    uint32_t flags;         /* HK_INJECT_FLAG_SOURCE_* gates (reported)     */
    bool     ready;         /* true once >=2 distinct chain stages fired    */
};

/* Platform-free causality correlator (signal 20). Keyed on (target_pid,
 * target_tid); slides a bounded time window. NO client-side thresholding of
 * RATE — it only assembles the chain; the server scores. Host unit tests and the
 * trace-replay bypass test drive this directly. */
class InjectCorrelator {
public:
    explicit InjectCorrelator(uint64_t window_ns) : window_ns_(window_ns) {}

    /* Feed one event. If feeding it makes a target's chain "ready"
     * (>=2 distinct stages, cross-process), writes the chain to *out and returns
     * true (emit once). source==target same-process activity never readies a
     * chain (Windows' own thread-pool / loader work). */
    bool feed(const TiEvent &ev, InjectChain &out);

private:
    struct Entry {
        bool     used;
        uint32_t target_pid;
        uint32_t target_tid;
        uint32_t source_pid;
        uint32_t chain_flags;
        uint32_t flags;
        uint64_t alloc_base;
        uint64_t alloc_size;
        uint64_t context_rip;
        uint64_t first_ns;
        uint64_t last_ns;
        bool     emitted;
    };

    static constexpr int kMaxTracked = 256;
    Entry    table_[kMaxTracked] = {};
    uint64_t window_ns_;

    Entry *find_or_insert(uint32_t pid, uint32_t tid, uint64_t now_ns);
};

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)
/* Start/stop the live PPL ETW-TI real-time session. Returns 0 on success, -1 if
 * the session could not be opened (the common case in dev: not PPL/ELAM-signed).
 * HK-VERIFIED(etw-ti): see EtwTiConsumer.cpp — PPL/ELAM cert requirement
 * documented; live path is a stub pending cert acquisition. */
int start();
void stop();
#endif

} } } // namespace hk::sdk::etwti
