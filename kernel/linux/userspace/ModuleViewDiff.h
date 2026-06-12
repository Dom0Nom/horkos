/*
 * Role: Signal 92 — module-enumeration cross-view diff. Diffs the module set
 *       seen via /proc/modules, the /sys/module tree, and (when present) the LKM
 *       debugfs module-CRC view / bpf-iter view. A module visible in one source
 *       but absent from another — after a debounce that absorbs insmod/rmmod
 *       races and MODULE_STATE_COMING/GOING — is the classic list_del self-unlink
 *       tell. Emits HK_EVENT_MODULE_VIEW_DIFF.
 * Target platform: Linux userspace (guardrail #4).
 * Interface: pure parsers + a stateful Differ (holds the previous snapshot for
 *            the 500 ms debounce); live entry hk_sensor_module_view().
 *            Audit-only / read-only.
 *
 * §7-C decision: ships with the two userspace views + the LKM view (when the LKM
 * is built); the BPF module-iterator third view is a later upgrade (no confirmed
 * stable bpf_iter over the module list). The two-view diff already catches the
 * classic list_del self-unlink because the sysfs kobject survives the unlink.
 */

#pragma once

#include <cstdint>
#include <set>
#include <string>
#include <unordered_map>

#include "HostIntegritySensors.h"
#include "SymbolMap.h"

namespace horkos::modint {

/* Parse module NAMES from /proc/modules content (first whitespace token of each
 * non-empty line). */
std::set<std::string> ParseProcModules(const std::string& content);

/* The three views, any of which may be empty (unread). */
struct ModuleViews {
    std::set<std::string> proc_modules;   /* /proc/modules */
    std::set<std::string> sysfs_modules;  /* /sys/module dir entry names */
    std::set<std::string> lkm_or_bpf;     /* LKM debugfs / bpf-iter, may be empty */
    bool lkm_view_present = false;        /* false → third view not consulted */
};

/* A per-module present-mask snapshot (which views saw it). */
using PresenceSnapshot = std::unordered_map<std::string, uint32_t>;

/* Build the present-mask snapshot from the three views. */
PresenceSnapshot BuildPresence(const ModuleViews& views);

/* Stateful differ enforcing the 500 ms / two-consecutive-snapshot debounce. A
 * single-source discrepancy is only emitted when it persists across two
 * consecutive Observe() calls (so a transient COMING/GOING is absorbed). */
class ModuleViewDiffer {
public:
    /* Observe one freshly-built snapshot. Emits HK_EVENT_MODULE_VIEW_DIFF for
     * every module whose present_mask shows a single-source discrepancy AND whose
     * SAME discrepancy was present in the immediately prior snapshot. Returns the
     * number of events emitted. `had_proc`/`had_sysfs` say whether those sources
     * were readable this cycle (an unread source suppresses its half of the diff,
     * avoiding a false "absent" — and emits SENSOR_UNAVAILABLE(92) when BOTH core
     * userspace views are unreadable). */
    int Observe(const ModuleViews& views, HkEventSink sink,
                bool had_proc, bool had_sysfs);

private:
    PresenceSnapshot prev_;
    bool have_prev_ = false;
};

/* Whether a present_mask indicates a single-source discrepancy worth flagging.
 * A module present in /proc but not /sys (or vice versa), or present in the LKM
 * view but neither userspace view, is a discrepancy. Full agreement is not. */
bool IsSingleSourceDiscrepancy(uint32_t present_mask, bool lkm_present);

/* Live sensor entry (HkHostSensorFn). Uses a function-local ModuleViewDiffer so
 * the debounce state persists across cycles. */
int hk_sensor_module_view(const HkSymbolMap* map, HkEventSink sink);

}  // namespace horkos::modint
