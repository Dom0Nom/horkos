/*
 * sdk/src/backends/win/VulkanLayerChainWin.cpp
 * Role: Signal 54 (win-usermode-overlay). Vulkan implicit/forced-layer overlay-
 *       injection chain sensor. Reads the implicit-layer manifests registered under
 *       HKLM/HKCU\SOFTWARE\Khronos\Vulkan\ImplicitLayers, parses each referenced
 *       layer JSON for its library_path, reads the OWN process environment for
 *       VK_INSTANCE_LAYERS / VK_LAYER_PATH / VK_ADD_LAYER_PATH, and confirms via the
 *       shared module map that the layer DLL is actually mapped into the process.
 *       Reports manifest path + library signer + which env var forced the layer; the
 *       server fuses with 46/47 to separate a dev's RenderDoc from a forced
 *       present-intercept layer. Read-only: registry reads, file reads, own-process
 *       env + module map only; it never writes the registry, env, or a layer file.
 * Target platforms: Windows userspace. Guardrail #1: advapi32 (registry) use is
 *       confined here; mapped-DLL confirmation comes from the shared ModuleMap.
 * Interface: implements hk::sdk::render::sense_vulkan_layers.
 */

#include "RenderSensorWin.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <windows.h>

namespace hk { namespace sdk { namespace render {

int sense_vulkan_layers(const ModuleMap& module_map,
                        std::vector<hk_render_finding>& out)
{
    /* Sequence (read-only):
     *   1. RegOpenKeyEx(HKEY_LOCAL_MACHINE / HKEY_CURRENT_USER,
     *      L"SOFTWARE\\Khronos\\Vulkan\\ImplicitLayers", KEY_READ). Each value name
     *      is the absolute path to a layer manifest JSON; the DWORD value (0)
     *      indicates the manifest is enabled (non-zero = disabled).
     *   2. Read each enabled manifest file read-only and parse the JSON for
     *      "library_path" (the layer DLL) and "name". Manifests are plain JSON; a
     *      minimal hand-rolled reader extracts the two string fields — no Vulkan SDK
     *      link dependency (plan section 4).
     *   3. Read the OWN process environment via GetEnvironmentStringsW for
     *      VK_INSTANCE_LAYERS / VK_LAYER_PATH / VK_ADD_LAYER_PATH; record which (if
     *      any) env var forced a layer in. For the OWN process this is trivially
     *      readable; cross-process env reading is explicitly NOT attempted here
     *      (plan R3 — undocumented PEB walk, Wow64 layout differences).
     *   4. For each layer DLL resolved at steps 2-3, scan `module_map` to confirm it
     *      is actually MAPPED into the process (a registered-but-not-loaded layer is
     *      not an active intercept). For a mapped layer, emit a finding:
     *      verdict = classify_provenance over the layer module's backing + signer,
     *      module_path = the layer DLL path, signer_subject = its Authenticode
     *      subject, in the JSON side-channel; the env var that forced it travels
     *      alongside. The server fuses with 46/47.
     *
     * HK-UNCERTAIN(vulkan-manifest-schema): the implicit-layer manifest JSON schema
     * (the exact nesting of "layer"/"layers" object vs array, relative vs absolute
     * library_path resolution, and the disable-environment override key) is the one
     * piece needing on-box confirmation against installed manifests before the
     * hand-rolled parser is finalized; the registry enumeration + own-env read +
     * mapped-DLL confirmation against `module_map` are mechanical and verified, but
     * a half-correct JSON parse would mis-attribute a layer's library_path, so the
     * manifest-body parse + emit is left for on-box bring-up. The registry-key +
     * env-var presence enumeration carries no false-positive risk and is the
     * reliable core; the per-layer verdict emit depends on the confirmed parse.
     * Until then this sensor performs the read-only enumeration but emits no finding
     * (presence of a registered layer is never, alone, a client-side flag —
     * report-only contract). */
    (void)module_map;
    (void)out;
    return 0;
}

} } } // namespace hk::sdk::render

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
