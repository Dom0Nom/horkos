/*
 * Role: Signal 94 — kprobe/kretprobe placement on credential/exec/sig-verify
 *       symbols. Parses /sys/kernel/debug/kprobes/list (+ tracing/kprobe_events),
 *       resolves each probe address to a symbol, matches against the sensitive
 *       set, and flags module-less / unsigned-module probes. Emits
 *       HK_EVENT_KPROBE_SENSITIVE (a weight; signed-EDR probes are allowlisted
 *       server-side).
 * Target platform: Linux userspace (guardrail #4).
 * Interface: pure parser ParseKprobeList(content) + decision core
 *            AnalyzeKprobes(...) over a fixture; live entry hk_sensor_kprobe().
 *            Audit-only / read-only.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "HostIntegritySensors.h"
#include "SymbolMap.h"

namespace horkos::modint {

/* One parsed kprobes/list row. Format (column count VARIES across versions —
 * §3, parse tolerantly):
 *   <addr>  <type>  <symbol>+<offset>    <flags...>  [MODULE]
 * e.g. "ffffffff8128a0b0  k  commit_creds+0x0    [OPTIMIZED]"
 *      "ffffffffc0a12000  r  do_exit+0x10  [DISABLED][FTRACE]  [evil_mod]" */
struct KprobeRow {
    uint64_t probe_addr = 0;
    std::string symbol;          /* resolved symbol (offset stripped) */
    std::string owner_module;    /* trailing [module], empty if module-less */
    bool optimized = false;
    bool disabled = false;
};

/* Parse kprobes/list content into rows. Tolerant of flag column count and of the
 * "symbol+offset" form. */
std::vector<KprobeRow> ParseKprobeList(const std::string& content);

/* Decide whether a module owner counts as "signed/known" for the client-side
 * floor. The authoritative EDR allowlist is server-side; this only treats a
 * named, non-empty owner module as a weaker anomaly than a module-less probe. */
bool IsKnownSignedKprobeOwner(const std::string& owner_module);

/* Pure decision core. Emits HK_EVENT_KPROBE_SENSITIVE for each probe on a
 * sensitive symbol, flagging MODULELESS when no owner module is named. An
 * unreadable source emits a single SENSOR_UNAVAILABLE(94). Returns event count. */
int AnalyzeKprobes(const std::string& kprobe_list_content,
                   const HkSymbolMap& map, HkEventSink sink, bool source_readable);

/* Live sensor entry (HkHostSensorFn). */
int hk_sensor_kprobe(const HkSymbolMap* map, HkEventSink sink);

}  // namespace horkos::modint
