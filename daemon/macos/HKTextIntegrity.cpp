/*
 * Role: __TEXT W^X scanner + code-signature status check (signal 117). Resolves
 *       the game's __TEXT range from on-disk mach-o load commands, walks the slid
 *       range via mach_vm_region_recurse, and flags any writable / COW-broken
 *       page inside signed __TEXT, cross-checked against csops.
 * Target platform: macOS only (built behind `if(APPLE)`).
 * Interface: implements HKParseTextRange() (pure) and HKTextScan() from
 *            HKTextIntegrity.h. Userspace daemon TU (guardrail #4).
 *
 * Guardrail compliance:
 *   #1  No platform #ifdef for OS selection — CMake gates the TU.
 *   #13 The live mach_vm_region_recurse walk + ASLR-slide adjustment + the
 *       SM_COW-vs-shared-cache FP question (plan uncertainty #4) are HK-UNCERTAIN
 *       and depend on the stubbed CONTROL-level task handle; the live scan
 *       no-ops until verified on Apple Silicon AND Intel. The PURE mach-o
 *       __TEXT-range parser is implemented and unit-tested.
 */

#include "HKTextIntegrity.h"

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/loader.h>   /* mach_header_64, segment_command_64, LC_SEGMENT_64 */
#include <string.h>
#include <os/log.h>

namespace {
os_log_t hk_log() {
    static os_log_t log = os_log_create("io.horkos.daemon", "text-integrity");
    return log;
}
}  // namespace

extern "C" bool HKParseTextRange(const void *image, size_t len, HKTextRange *out) {
    if (out == nullptr) {
        return false;
    }
    out->found  = false;
    out->vmaddr = 0;
    out->vmsize = 0;

    if (image == nullptr || len < sizeof(struct mach_header_64)) {
        return false;
    }

    const struct mach_header_64 *mh =
        static_cast<const struct mach_header_64 *>(image);
    if (mh->magic != MH_MAGIC_64) {
        return false;  /* 64-bit mach-o only (see header note) */
    }

    /* Bound the load-command region against `len` so a truncated/forged image
     * cannot walk past the buffer. */
    const uint8_t *base = static_cast<const uint8_t *>(image);
    size_t off = sizeof(struct mach_header_64);
    uint32_t ncmds = mh->ncmds;

    for (uint32_t i = 0; i < ncmds; ++i) {
        if (off + sizeof(struct load_command) > len) {
            break;  /* truncated load-command stream */
        }
        const struct load_command *lc =
            reinterpret_cast<const struct load_command *>(base + off);
        uint32_t cmdsize = lc->cmdsize;
        if (cmdsize < sizeof(struct load_command) || off + cmdsize > len) {
            break;  /* malformed cmdsize — stop rather than over-read */
        }

        if (lc->cmd == LC_SEGMENT_64 &&
            cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg =
                reinterpret_cast<const struct segment_command_64 *>(base + off);
            if (strncmp(seg->segname, "__TEXT", sizeof(seg->segname)) == 0) {
                out->found  = true;
                out->vmaddr = seg->vmaddr;
                out->vmsize = seg->vmsize;
                return true;
            }
        }
        off += cmdsize;
    }
    return false;
}

extern "C" size_t HKTextScan(const HKGameTaskHandle *game,
                             const HKTextRange      *on_disk_text,
                             uint64_t                aslr_slide,
                             HKTextWxEmit            emit,
                             void                   *ctx) {
    (void)aslr_slide;
    (void)ctx;  /* used once the live walk below is un-stubbed (HK-UNCERTAIN) */
    if (game == nullptr || on_disk_text == nullptr || emit == nullptr) {
        return 0;
    }
    if (!game->valid || game->task == MACH_PORT_NULL || !on_disk_text->found) {
        return 0;
    }

    /* HK-UNCERTAIN(text-wx-scan): the live walk is left unimplemented pending
     * hardware verification of:
     *   1. correct ASLR-slide adjustment of on_disk_text->vmaddr to the running
     *      image (slid = vmaddr + aslr_slide),
     *   2. whether legitimate dyld page-in / shared-cache COW presents as SM_COW
     *      inside __TEXT and produces false positives (plan uncertainty #4),
     *   3. mach_vm_region_recurse's exact info struct / depth semantics for a
     *      foreign task.
     * Per guardrail #12 the mach_vm_region_recurse loop and the csops(CS_OPS_
     * STATUS) cross-check are NOT guessed. When un-stubbed, walk
     * [slid, slid+vmsize), and for any page with (info.protection & VM_PROT_WRITE)
     * or share_mode == SM_COW, emit hk_es_text_wx with the csops_valid result. */
    os_log(hk_log(),
        "HKTextScan: live __TEXT W^X walk stubbed (HK-UNCERTAIN: ASLR slide + "
        "SM_COW FP semantics unverified) for game pid %d", game->pid);
    return 0;
}
