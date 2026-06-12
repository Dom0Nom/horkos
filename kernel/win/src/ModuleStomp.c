/*
 * Role: Module-stomp scanner (signal 12) + evidence staging for the unsigned-
 *       image signal (18). For each signed module it maps the on-disk backing
 *       file read-only, normalizes relocations + zeroes IAT thunks, and diffs the
 *       code sections against the live mapping captured while attached; the first
 *       unexplained byte is emitted as first_diff_rva via the host-tested pure
 *       core hk_mem_first_diff_rva (mem_logic_stomp.h). Emits RAW first-diff RVA
 *       + both section hashes — NEVER a verdict (FP risk is high: hotpatch,
 *       Detours, overlays). Runs DETACHED (the KeStackAttachProcess caution bars
 *       file mapping in the attached window); the live bytes are captured into
 *       the scan ctx during the attached VAD pass.
 *       READ-ONLY: maps the on-disk file PAGE_READONLY; never patches.
 *
 *       HK-UNCERTAIN (plan UNCERTAINTY FLAG): ZwCreateSection/ZwMapViewOfSection
 *       handle lifetime + the guarantee that mapping a game-owned file from the
 *       worker context raises no sharing violation / self-DoS must be confirmed
 *       on the Windows box before this is enabled. Until the on-disk map + the
 *       attached-window live-byte capture are wired, this stages nothing and
 *       emits nothing.
 * Target platforms: Windows kernel (KMDF). Builds only with the WDK.
 * Interface: implements HkModuleStomp from mem_scan.h, over mem_logic_stomp.h.
 */

#include "mem_scan.h"
#include "mem_logic_stomp.h"

void HkModuleStomp(PHK_MEM_SCAN_CTX Ctx)
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    if (Ctx == NULL || Ctx->Layout == NULL) {
        return; /* fail closed. */
    }

    /* HK-UNCERTAIN (confirm on the box): for each image VAD captured in
     * Ctx->Nodes, (1) capture the live code-section bytes during the attached VAD
     * pass into a bounded buffer, (2) here (detached) ZwCreateSection +
     * ZwMapViewOfSection the backing file PAGE_READONLY, (3) parse PE headers,
     * apply IMAGE_BASE_RELOCATION fix-ups to the disk copy, gather the IAT thunk
     * ranges, (4) call hk_mem_first_diff_rva(disk, live, len, relocs, iats) and
     * emit hk_event_mem_module_stomp with first_diff_rva + both SHA-256 hashes
     * when it is >= 0, (5) stage {path, file_sha256} for the signal-18 userspace
     * WinVerifyTrust verdict (ImageSigningWin.cpp). The diff/normalize math is
     * host-tested (mem_logic_stomp.h) and ready; the file-map + live-capture
     * plumbing lands on the box. Emit nothing until then — never a guessed diff. */
    (void)hk_mem_first_diff_rva;
}
