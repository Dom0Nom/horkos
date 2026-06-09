/*
 * sdk/src/backends/win/PresentPrologueReconcileWin.cpp
 * Role: Signal 47 (win-usermode-overlay). Present/ExecuteCommandLists export-
 *       prologue reconciliation: maps the implicated DLL read-only from disk,
 *       resolves the export RVA, applies the live load base's relocation delta via
 *       the header-only PeRelocate.h math, then ReadProcessMemory's the live
 *       prologue and compares. A divergence is reported as a region_hash of the
 *       differing bytes (NEVER the bytes), with the target VA and a provenance
 *       verdict. Read-only: maps the file read-only, reads own-process memory; it
 *       never writes the prologue or unhooks.
 * Target platforms: Windows userspace. Guardrail #1: file-mapping / RPM use is
 *       confined here. The PE math (PeRelocate.h) is pure + host-tested; sharing it
 *       with the kernel image-load path is header-only, compiled separately in each
 *       TU, so guardrail #4 (no shared kernel/userspace TU) holds.
 * Interface: implements hk::sdk::render::sense_present_prologue.
 */

#include "RenderSensorWin.h"
#include "PeRelocate.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <windows.h>

namespace hk { namespace sdk { namespace render {

int sense_present_prologue(const ModuleMap& module_map,
                           std::vector<hk_render_finding>& out)
{
    /* The reconciliation sequence (read-only). The PE math used at steps 3-5 is
     * the pure, host-tested PeRelocate.h — the one piece shared with the kernel
     * image-load path, kept header-only so the two compile in separate TUs.
     *
     *   1. For each present-path export of interest (Present/Present1/
     *      ResizeBuffers in dxgi.dll, ExecuteCommandLists in d3d12.dll), find the
     *      module's live base + on-disk path from `module_map`.
     *   2. CreateFileMappingW(.., PAGE_READONLY) + MapViewOfFile the DLL read-only
     *      from disk (raw bytes; parsed manually by PeRelocate.h, NOT SEC_IMAGE, so
     *      no loader side effects).
     *   3. pe::parse_headers(); pe::resolve_export_rva(name) -> export RVA.
     *   4. Copy the on-disk prologue window at that RVA's file offset
     *      (pe::rva_to_file_offset) into a scratch buffer.
     *   5. pe::relocate_window(live_base, ...) — rewrite ASLR-relocated absolute
     *      branches so a RELOCATION is not misread as a patch (the catalog FP). CFG
     *      guard-check thunks and retpolines that are PRESENT on disk reconcile
     *      naturally; only a genuine prologue overwrite diverges.
     *   6. ReadProcessMemory(GetCurrentProcess(), live_base+export_rva, ...) the
     *      live prologue; compare to the relocated on-disk window.
     *   7. On divergence: emit a finding with target_addr = live VA, slot_index =
     *      export ordinal, region_hash = pe::region_hash(divergent bytes),
     *      verdict = classify_provenance(...) for the live target's backing.
     *      Report the HASH only, never the bytes.
     *
     * HK-UNCERTAIN(prologue-window-length): the exact prologue byte-window length
     * that is stable across compiler/CET-shadow-stack/CFG variants for these
     * specific exports needs on-box calibration against the shipped dxgi/d3d12
     * builds (too short misses a trampoline; too long ingests unrelated relocated
     * code). The relocation + hashing math is verified and host-tested; only the
     * window length is a tuning constant left for on-box bring-up. Until then this
     * sensor performs no live compare. */
    (void)module_map;
    (void)out;
    /* Touch the PE entry points so the dependency stays wired and any PeRelocate.h
     * API drift surfaces as a build error in this TU. */
    (void)&pe::parse_headers;
    (void)&pe::resolve_export_rva;
    (void)&pe::relocate_window;
    (void)&pe::region_hash;
    return 0;
}

} } } // namespace hk::sdk::render

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
