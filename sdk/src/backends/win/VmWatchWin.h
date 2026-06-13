/*
 * Role: SDK-internal façade for the Windows userspace external-memory-access
 *       samplers (win-handle-memory-access, catalog signals 65/70/71). Declares the
 *       three sampler entry points and the small PLATFORM-FREE decision cores the
 *       host unit tests drive with no live process / no NT query:
 *         - residency_burst_is_foreign (signal 65): a working-set page-in burst with
 *           no owning-thread CPU delta is foreign-initiated, not the game's own code.
 *         - holder_is_dangerous (signal 70): a foreign process handle granting
 *           VM_READ/WRITE/OPERATION to the game, weighted up if the owner is unsigned.
 *         - protect_is_drift (signal 71): live page protection that disagrees with the
 *           cached PE section characteristics (e.g. RWX on a shipped +X section).
 *       The Win32/NT-touching sampler bodies live in the *Win.cpp siblings; the cores
 *       are header-only so guardrail #4 keeps kernel TUs out (no kernel TU includes
 *       this) and the host test links the logic with no platform TU.
 * Target platforms: Windows (userspace). Pure cores are platform-free (mirrors
 *       ThreadProvenanceWin.h / InputSensorWin.h).
 * Interface: implemented by WorkingSetWatchWin.cpp / SelfHandleAuditWin.cpp /
 *       PageProtectAuditWin.cpp; the cores are platform-free host logic.
 *
 * HK-TODO(schema): the userspace findings (hk_event_foreign_holder #70,
 * hk_event_protect_drift #71, the HK_VM_ETWTI_SILENT correlation #69) flow on the
 * SDK report queue whose wire types are the kernel-private mirrors in
 * kernel/win/include/horkos_kernel.h until the Schema phase appends them — the
 * samplers below are gated the same way and ship dark (HK_WIN_VMWATCH default OFF).
 */

#pragma once

#include <cstdint>

#include "VmAccessLogicWin.h"  /* SectionRange / classify_target_section reuse (#71) */

namespace hk { namespace sdk { namespace vmaccess {

/* -------------------------------------------------------------------------
 * Signal 65 — working-set residency-burst correlation (pure core).
 * QueryWorkingSetEx reports which of the game's pages became resident; a burst of
 * newly-resident pages that is NOT accompanied by the game's own owning-thread CPU
 * advancing is evidence of a FOREIGN reader faulting those pages in. The game
 * paging in its own code while running advances thread CPU; a foreign ReadProcessMemory
 * does not. Conservative: with no CPU sample (cpu_delta_valid == false) we do NOT
 * call it foreign (return false) — the kernel/ETW plane corroborates instead.
 * ------------------------------------------------------------------------- */
struct ResidencyBurstInput {
    uint32_t newly_resident_pages; /* pages that flipped to resident this sample */
    uint64_t owning_cpu_delta_ns;  /* game owning-thread CPU time advanced this sample */
    bool     cpu_delta_valid;      /* a GetProcessTimes pair was captured */
    uint32_t burst_threshold;      /* min pages to consider a "burst" (tunable) */
};

inline bool residency_burst_is_foreign(const ResidencyBurstInput &in)
{
    if (!in.cpu_delta_valid) {
        return false; /* no CPU baseline -> cannot attribute; defer to kernel plane */
    }
    if (in.newly_resident_pages < in.burst_threshold) {
        return false; /* not a burst */
    }
    /* A burst with ~no owning-thread CPU advance is the foreign-read signature. */
    return in.owning_cpu_delta_ns == 0;
}

/* -------------------------------------------------------------------------
 * Signal 70 — foreign process-handle holder classification (pure core).
 * NtQuerySystemInformation(SystemExtendedHandleInformation) lists every Process-type
 * handle to the game and its GrantedAccess + owner. A handle granting VM_READ/WRITE/
 * OPERATION held by a process OTHER than the game is the signal; an unsigned owner
 * weights it up. Conservative: the game's own handle to itself and signed
 * allowlisted owners are not dangerous.
 * ------------------------------------------------------------------------- */
/* Mirrored PROCESS_* access bits (not from <winnt.h>) so the core stays platform-free. */
constexpr uint32_t kProcVmRead      = 0x0010u; /* PROCESS_VM_READ      */
constexpr uint32_t kProcVmWrite     = 0x0020u; /* PROCESS_VM_WRITE     */
constexpr uint32_t kProcVmOperation = 0x0008u; /* PROCESS_VM_OPERATION */
constexpr uint32_t kProcDangerousMask = kProcVmRead | kProcVmWrite | kProcVmOperation;

struct ForeignHolderInput {
    uint32_t owner_pid;
    uint32_t game_pid;
    uint32_t granted_access;
    bool     owner_signed;       /* owner image Authenticode chain valid */
    bool     owner_allowlisted;  /* server allow-list hit for the owner signer */
};

/* Returns true if this holder is a foreign dangerous-rights holder worth reporting.
 * out_flags receives HK_HND_DANGEROUS_RIGHTS / HK_HND_UNSIGNED_OWNER bits (mirrored
 * locally to avoid a kernel-header dependency in this pure core). */
constexpr uint32_t kHndDangerousRights = 0x00000001u; /* == HK_HND_DANGEROUS_RIGHTS */
constexpr uint32_t kHndUnsignedOwner   = 0x00000002u; /* == HK_HND_UNSIGNED_OWNER   */

inline bool holder_is_dangerous(const ForeignHolderInput &in, uint32_t *out_flags)
{
    uint32_t flags = 0;
    if (out_flags != nullptr) {
        *out_flags = 0;
    }
    /* The game's own handle to itself is never foreign. */
    if (in.owner_pid == in.game_pid) {
        return false;
    }
    if ((in.granted_access & kProcDangerousMask) == 0) {
        return false; /* no VM read/write/operation rights -> not the signal */
    }
    /* A signed, server-allowlisted owner (e.g. an approved overlay/AV) is exempt. */
    if (in.owner_signed && in.owner_allowlisted) {
        return false;
    }
    flags |= kHndDangerousRights;
    if (!in.owner_signed) {
        flags |= kHndUnsignedOwner;
    }
    if (out_flags != nullptr) {
        *out_flags = flags;
    }
    return true;
}

/* -------------------------------------------------------------------------
 * Signal 71 — page-protection drift on shipped code (pure core).
 * VirtualQueryEx gives MEMORY_BASIC_INFORMATION.Protect for a region; comparing it
 * to the section characteristics cached for that VA flags an unexpected protection,
 * the classic being RWX on a section shipped as RX (write-was-added). Mirrored
 * PAGE_* constants keep the core platform-free.
 * ------------------------------------------------------------------------- */
constexpr uint32_t kPageExecuteReadWrite = 0x40u; /* PAGE_EXECUTE_READWRITE */
constexpr uint32_t kPageExecuteWriteCopy = 0x80u; /* PAGE_EXECUTE_WRITECOPY */

constexpr uint32_t kProtWxOnShipped = 0x00000001u; /* == HK_PROT_WX_ON_SHIPPED */

struct ProtectDriftInput {
    uint32_t live_protect;       /* MEMORY_BASIC_INFORMATION.Protect */
    uint32_t section_flags;      /* IMAGE_SCN_* of the region's PE section (0 if none) */
};

/* Returns true if the live protection drifts from the shipped expectation. Today the
 * one high-confidence case: an executable shipped section (IMAGE_SCN_MEM_EXECUTE set,
 * write NOT shipped) now mapped writable+executable. out_flags receives kProtWxOnShipped.
 * A region not inside a tracked +X section (section_flags == 0 or non-exec) never drifts. */
inline bool protect_is_drift(const ProtectDriftInput &in, uint32_t *out_flags)
{
    if (out_flags != nullptr) {
        *out_flags = 0;
    }
    const bool shipped_exec = (in.section_flags & kScnMemExecute) != 0;
    const bool shipped_writable = (in.section_flags & kScnMemWrite) != 0;
    if (!shipped_exec || shipped_writable) {
        return false; /* not a shipped read-only-exec section -> no W^X expectation */
    }
    const bool live_wx = (in.live_protect == kPageExecuteReadWrite) ||
                         (in.live_protect == kPageExecuteWriteCopy);
    if (live_wx) {
        if (out_flags != nullptr) {
            *out_flags = kProtWxOnShipped;
        }
        return true;
    }
    return false;
}

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)
/* Sampler entry points (one tick of each). Read-only. Each returns the number of
 * findings produced (>= 0), or -1 if the underlying NT/Win32 query failed (the
 * caller degrades to no-signal rather than guessing). Implemented in the *Win.cpp
 * siblings; ship dark behind HK_WIN_VMWATCH. */
int sample_working_set(uint32_t game_pid);   /* signal 65 */
int sample_self_handles(uint32_t game_pid);  /* signal 70 */
int sample_page_protect(uint32_t game_pid);  /* signal 71 */
#endif

} } } // namespace hk::sdk::vmaccess
