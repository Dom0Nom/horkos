/*
 * sdk/src/backends/win/PresentVtableProvenanceWin.cpp
 * Role: Signal 46 (win-usermode-overlay). COM vtable-slot provenance sensor for
 *       the swapchain / command-queue present path: reads the Present, Present1,
 *       ResizeBuffers and ID3D12CommandQueue::ExecuteCommandLists vtable slots,
 *       resolves each slot's target VA against the shared signed-module map, and
 *       emits a per-slot hk_provenance_verdict. Read-only: it dereferences vtable
 *       pointers and VirtualQueryEx's the targets in the OWN process; it never
 *       writes a slot, unhooks, or patches. Presence of a hook is reported, never
 *       acted on — the server alone decides (catalog).
 * Target platforms: Windows userspace. Guardrail #1: DXGI/D3D/VirtualQuery use is
 *       confined here. The verdict logic is the pure classify_provenance in
 *       RenderSensorWin.h (host-tested).
 * Interface: implements hk::sdk::render::sense_present_vtable.
 */

#include "RenderSensorWin.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <windows.h>

namespace hk { namespace sdk { namespace render {

namespace {

/* Resolve a target VA against the sorted module map; fills the ProvenanceInput's
 * in_known_module / module_signed / module_allowlisted. backing must be set by the
 * caller from VirtualQueryEx. */
void ResolveAgainstMap(const ModuleMap& map, uint64_t target, ProvenanceInput& pin)
{
    pin.in_known_module = false;
    pin.module_signed = false;
    pin.module_allowlisted = false;
    for (const auto& e : map.entries) {
        if (target >= e.base && target < e.base + e.size) {
            pin.in_known_module = true;
            pin.module_signed = e.signed_ok;
            pin.module_allowlisted = e.allowlisted;
            return;
        }
    }
}

/* Classify a target VA's backing via VirtualQueryEx on the own process. Returns
 * Unresolved on query failure so the sensor never fabricates a verdict. */
TargetBacking QueryBacking(uint64_t target)
{
    if (target == 0) return TargetBacking::Unresolved;
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(target), &mbi, sizeof(mbi)) == 0) {
        return TargetBacking::Unresolved;
    }
    if (mbi.State != MEM_COMMIT) return TargetBacking::Unresolved;
    switch (mbi.Type) {
        case MEM_IMAGE:   return TargetBacking::Image;
        case MEM_MAPPED:  return TargetBacking::Mapped;
        case MEM_PRIVATE: return TargetBacking::Private;
        default:          return TargetBacking::Unresolved;
    }
}

} // namespace

int sense_present_vtable(const ModuleMap& module_map,
                         std::vector<hk_render_finding>& out)
{
    /* HK-UNCERTAIN(live-swapchain-acquisition): obtaining a callable
     * IDXGISwapChain* / ID3D12CommandQueue* for the object the GAME already
     * created — from the same process but outside the game's render code — is the
     * unresolved integration question (plan R2). DXGIGetDebugInterface1 +
     * IDXGIDebug::ReportLiveObjects enumerates COM objects but does NOT, per a
     * documented contract, hand back an addressable vtable for an arbitrary live
     * swapchain. The clean path is the GAME handing the sensor its device/swapchain
     * pointer through the SDK at device-creation time. DO NOT guess the COM
     * enumeration semantics. This sensor therefore lays out the read+classify
     * sequence below but leaves the swapchain-pointer acquisition as a documented
     * stub: with no SDK-provided pointer it emits nothing this tick.
     *
     * Verified sequence once a swapchain/queue pointer `p` is supplied:
     *   1. vtbl = *(void***)p;  guard p and vtbl against null before deref.
     *   2. For each tracked slot index s (Present / Present1 / ResizeBuffers /
     *      ExecuteCommandLists), read target = vtbl[s] under a structured guard so
     *      a garbage pointer cannot crash the tick.
     *   3. backing = QueryBacking(target); ResolveAgainstMap(module_map, target,..).
     *   4. verdict = classify_provenance(pin); emit a finding carrying slot_index,
     *      target_addr, verdict, and the resolved module path/signer in the JSON
     *      side-channel.
     *   5. A null/garbage slot yields HK_PROV_UNRESOLVED, never a deref-crash.
     */
    (void)module_map;
    (void)out;
    (void)&ResolveAgainstMap;
    (void)&QueryBacking;
    return 0; /* no SDK-provided swapchain pointer: nothing observed this tick */
}

} } } // namespace hk::sdk::render

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
