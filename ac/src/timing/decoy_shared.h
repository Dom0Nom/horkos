/*
 * Role: TU-local accessors over the SHARED first-chain VEH + decoy PAGE_GUARD state
 *       owned by veh_fault_attribution_win.cpp (signal 154). The 159 (dispatch latency)
 *       and 161 (guard cadence) samplers read fault counts / QPC / TF and re-arm the
 *       decoy through these, so the three signals share ONE first-chain VEH + one decoy
 *       page rather than each installing its own (plan §sequencing step 4).
 * Target platform: Windows (the accessors are only defined in the Windows build of
 *       veh_fault_attribution_win.cpp; this header is included only by the *_win.cpp
 *       timing TUs, never cross-platform).
 * Interface: declarations only; definitions live in veh_fault_attribution_win.cpp.
 */

#pragma once

namespace hk {
namespace timing {

bool       hk_timing_decoy_is_armed();
void*      hk_timing_decoy_page();
long long  hk_timing_decoy_fault_count();
long long  hk_timing_decoy_last_fault_qpc();
int        hk_timing_decoy_last_tf();
bool       hk_timing_decoy_rearm();

} // namespace timing
} // namespace hk
