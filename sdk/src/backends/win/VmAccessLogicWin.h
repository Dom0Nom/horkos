/*
 * sdk/src/backends/win/VmAccessLogicWin.h
 * Role: PLATFORM-FREE decision cores shared by the win-handle-memory-access
 *       sensors (catalog signals 64-72). Two pure pieces the host unit tests drive
 *       with no driver / no Win32:
 *         (1) classify_target_section — resolve a target VA against a cached set of
 *             per-module section ranges and return the IMAGE_SCN_* characteristics
 *             of the containing section (signal 64/71 input), or 0 if the VA is not
 *             inside a tracked module section.
 *         (2) StagingAssembler — fold an ordered (alloc -> protect -> write) tuple
 *             keyed by source PID inside a short tumbling window and report exactly
 *             one staging verdict when the full ordered triad is seen (signal 72).
 *       Both are written here, header-only and platform-free, so guardrail #1 keeps
 *       every Win32/NT call inside the *Win.cpp siblings and guardrail #4 keeps the
 *       kernel TUs out of this header entirely (no kernel TU includes it).
 * Target platforms: Windows (userspace) for the callers; the logic itself is
 *       platform-free and host-testable (mirrors RenderSensorWin.h / InputSensorWin.h).
 * Interface: consumed by PageProtectAuditWin.cpp and the kernel-side staging notes;
 *       the pure cores are exercised by tests/unit/test_vm_access_logic.cpp.
 *
 * NOTE on the wire types: hk_event_vm_access / hk_event_protect_drift etc. are NOT
 * referenced here. This header is pure logic over plain integers, so it carries no
 * dependency on the (schema-frozen, payload-too-large) wire structs — see the
 * HK-TODO(schema) note in VmWatchWin.h / the kernel mirrors.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace hk { namespace sdk { namespace vmaccess {

/* IMAGE_SCN_* subset we care about for classification. Mirrored here (not pulled
 * from <winnt.h>) so the pure core stays platform-free and host-testable. Values
 * match the public PE/COFF spec. */
constexpr uint32_t kScnMemExecute = 0x20000000u; /* IMAGE_SCN_MEM_EXECUTE */
constexpr uint32_t kScnMemRead    = 0x40000000u; /* IMAGE_SCN_MEM_READ    */
constexpr uint32_t kScnMemWrite   = 0x80000000u; /* IMAGE_SCN_MEM_WRITE   */

/* One resolved section range of a loaded module. Populated at PsSetLoadImage time
 * (kernel) or by a userspace PE walk; the classifier only does range math. */
struct SectionRange {
    uint64_t base;             /* runtime VA of the section start  */
    uint64_t size;             /* section virtual size (bytes)     */
    uint32_t characteristics;  /* IMAGE_SCN_* of this section      */
};

/* Resolve a target VA to the IMAGE_SCN_* characteristics of the section that
 * contains it, or 0 if no tracked section contains it (VA not in a module, or the
 * cache is empty/stale). Pure linear scan — the caches are small and per-process.
 * Returns the FIRST containing section: PE sections do not overlap, so first-match
 * is unambiguous. A zero-size range never matches (defensive against a malformed
 * cache entry). */
inline uint32_t classify_target_section(const std::vector<SectionRange> &cache,
                                        uint64_t target_va)
{
    for (const SectionRange &s : cache) {
        if (s.size == 0) {
            continue;
        }
        /* [base, base+size). Guard the add against wrap on a corrupt size. */
        if (target_va >= s.base && (target_va - s.base) < s.size) {
            return s.characteristics;
        }
    }
    return 0u;
}

/* Convenience predicate: is the resolved target inside an EXECUTABLE shipped
 * section? This is the gate for "external write into a +X code section" (signal 64)
 * and "shipped-code page-protect drift" (signal 71). 0 (not in a module) is false. */
inline bool target_is_executable(uint32_t section_flags)
{
    return (section_flags & kScnMemExecute) != 0u;
}

/* -------------------------------------------------------------------------
 * Staging-sequence assembler (signal 72). External tooling that stages a code
 * patch typically does AllocVm(remote) -> ProtectVm(make +X) -> WriteVm(remote) in
 * that order, from one source PID, inside a short window. We fold those three
 * ordered stages per source PID and emit ONE staging verdict only when the full
 * ordered triad is observed within the window. Out-of-order, partial, or
 * window-expired sequences never emit (they are normal allocator/JIT churn).
 *
 * Pure state machine over abstract "stage" inputs + a monotonic timestamp; the
 * platform sensor feeds it decoded ETW-TI/Ob events. Host-testable with no driver.
 * ------------------------------------------------------------------------- */

enum class VmStage : uint32_t {
    Alloc   = 0, /* ALLOCVM_REMOTE   */
    Protect = 1, /* PROTECTVM (->+X) */
    Write   = 2, /* WRITEVM_REMOTE   */
};

/* The ordered progress for one source PID within the current window. `seen` is the
 * highest IN-ORDER stage reached: Alloc advances to expecting Protect, Protect (only
 * after Alloc) advances to expecting Write, Write (only after Protect) completes. */
struct StagingProgress {
    uint32_t source_pid;
    uint64_t window_start_ns; /* timestamp of the Alloc that opened this window */
    uint32_t reached;         /* count of in-order stages reached (0..3)         */
};

class StagingAssembler {
public:
    /* window_ns: the tumbling-window span. A stage arriving past
     * window_start_ns + window_ns resets the per-PID progress (and, if it is an
     * Alloc, opens a fresh window). Default 250ms per the plan's "short tumbling
     * window"; the exact value is tuned with real captures. */
    explicit StagingAssembler(uint64_t window_ns = 250ull * 1000ull * 1000ull)
        : window_ns_(window_ns) {}

    /* Feed one decoded stage for `source_pid` at monotonic `ts_ns`. Returns true
     * exactly once — on the Write that completes a full ordered Alloc->Protect->
     * Write triad inside the window. All other inputs return false. On a completing
     * Write the per-PID progress is cleared so the same triad cannot double-emit. */
    bool feed(uint32_t source_pid, VmStage stage, uint64_t ts_ns)
    {
        StagingProgress *p = find(source_pid);

        if (stage == VmStage::Alloc) {
            /* Alloc (re)opens the window for this PID regardless of prior state. */
            if (p == nullptr) {
                progress_.push_back(StagingProgress{source_pid, ts_ns, 1});
            } else {
                p->window_start_ns = ts_ns;
                p->reached = 1;
            }
            return false;
        }

        if (p == nullptr) {
            /* Protect/Write with no open Alloc window: not a staging sequence. */
            return false;
        }

        /* Window expiry: a stage past the window invalidates the in-progress triad.
         * Treat as no-signal and drop the stale progress. */
        if (ts_ns < p->window_start_ns || (ts_ns - p->window_start_ns) > window_ns_) {
            erase(source_pid);
            return false;
        }

        if (stage == VmStage::Protect) {
            /* Only advances if Alloc came first (reached == 1). Out-of-order Protect
             * (e.g. Protect before Alloc, or a second Protect) does not advance. */
            if (p->reached == 1) {
                p->reached = 2;
            }
            return false;
        }

        /* stage == Write */
        if (p->reached == 2) {
            /* Full ordered triad inside the window — emit once and clear. */
            erase(source_pid);
            return true;
        }
        return false;
    }

private:
    StagingProgress *find(uint32_t pid)
    {
        for (StagingProgress &p : progress_) {
            if (p.source_pid == pid) {
                return &p;
            }
        }
        return nullptr;
    }

    void erase(uint32_t pid)
    {
        for (size_t i = 0; i < progress_.size(); ++i) {
            if (progress_[i].source_pid == pid) {
                progress_[i] = progress_.back();
                progress_.pop_back();
                return;
            }
        }
    }

    uint64_t window_ns_;
    std::vector<StagingProgress> progress_;
};

} } } // namespace hk::sdk::vmaccess
