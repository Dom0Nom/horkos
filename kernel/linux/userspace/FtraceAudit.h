/*
 * kernel/linux/userspace/FtraceAudit.h
 * Role: Signal 93 — ftrace handler-ownership audit on the sensitive kernel
 *       function set. Parses /sys/kernel/tracing/enabled_functions (and, on
 *       >=5.18, touched_functions), attributes each function's ftrace_ops
 *       callback owner address against the loaded-module text map, and flags
 *       callbacks on credential/exec/sig-verify symbols whose owner is
 *       unattributable to a known signed module. Emits HK_EVENT_FTRACE_HOOK.
 * Target platform: Linux userspace (guardrail #4).
 * Interface: pure parser ParseEnabledFunctions(content) + decision core
 *            AnalyzeFtrace(...) over a fixture; live entry hk_sensor_ftrace().
 *            Audit-only / read-only.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "HostIntegritySensors.h"
#include "SymbolMap.h"

namespace horkos::modint {

/* One parsed enabled_functions row. The file format is:
 *   <symbol> (<count>)\n
 *      tramp: <hex>  ...        (indented continuation lines, kernel >= 5.x)
 *      ops: <hex>
 * We capture the function name, its resolved address (from the map), and the
 * ops/tramp owner address when the row exposes one. */
struct FtraceRow {
    std::string func_name;
    uint64_t func_addr = 0;       /* filled from the symbol map / inline addr */
    uint64_t ops_owner_addr = 0;  /* tramp:/ops: hex, 0 if not present */
    uint32_t callback_count = 0;
};

/* Parse enabled_functions content into rows. Tolerant of the count column and of
 * the indented tramp:/ops: continuation lines (format varies across versions —
 * §3). A row with no resolvable owner address keeps ops_owner_addr == 0. */
std::vector<FtraceRow> ParseEnabledFunctions(const std::string& content);

/* Pure decision core. For each row whose function is in the sensitive set, emit
 * HK_EVENT_FTRACE_HOOK when the ops owner address is not attributable to a known
 * module text range (owner_attributed=0). An empty/unreadable content emits a
 * single SENSOR_UNAVAILABLE(93). Returns the number of hook events emitted. */
int AnalyzeFtrace(const std::string& enabled_functions_content,
                  const HkSymbolMap& map, HkEventSink sink, bool source_readable);

/* Live sensor entry (HkHostSensorFn). */
int hk_sensor_ftrace(const HkSymbolMap* map, HkEventSink sink);

}  // namespace horkos::modint
