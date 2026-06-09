/*
 * kernel/linux/userspace/KallsymsAudit.h
 * Role: Signal 91 — kallsyms text-address drift. Cross-checks each sensitive
 *       kernel symbol's resolved address against the kernel core .text bounds
 *       (_stext.._etext) and the per-module .text ranges from the shared
 *       HkSymbolMap, detecting out-of-bounds resolution, address collisions, and
 *       core-symbol-shadowed-into-a-module relocations. Emits HK_EVENT_KSYM_DRIFT
 *       (a trust weight; livepatch prefixes are allowlisted server-side).
 * Target platform: Linux userspace (guardrail #4 — no kernel/BPF headers).
 * Interface: pure decision core AnalyzeKsym(map, sink) testable on a fixture
 *            HkSymbolMap; the live entry hk_sensor_kallsyms() builds the map and
 *            calls it. Audit-only / read-only.
 */

#pragma once

#include "HostIntegritySensors.h"
#include "SymbolMap.h"

namespace horkos::modint {

/* Allowlist prefixes for livepatch/kpatch relocations: a sensitive symbol that
 * resolves into a module whose name starts with one of these is a legitimate
 * live-patched function, NOT drift. (Catalog FP gate for 91; the server holds
 * the authoritative list — this is a conservative client-side floor only.) */
bool IsLivepatchModule(const std::string& module_name);

/* Pure decision core: given a built map, emit ksym-drift events for sensitive
 * symbols that resolve out-of-bounds or into a (non-livepatch) module. If the
 * map's addresses are not visible (kptr_restrict) or the core range is invalid,
 * emits a single SENSOR_UNAVAILABLE(91) instead of any drift. Returns the number
 * of drift events emitted (0 when unavailable). */
int AnalyzeKsym(const HkSymbolMap& map, HkEventSink sink);

/* Live sensor entry (HkHostSensorFn). */
int hk_sensor_kallsyms(const HkSymbolMap* map, HkEventSink sink);

}  // namespace horkos::modint
