/*
 * Role: Interface for the __TEXT W^X integrity scanner (signal 117). Declares
 *       HKTextScan() and the pure __TEXT-range resolver that parses a mach-o's
 *       on-disk load commands to find the signed __TEXT segment.
 * Target platform: macOS only (CMake `if(APPLE)` gates the implementing TU).
 * Interface: daemon-only. The mach-o range parser is pure and host-runnable.
 */

#pragma once

#include "HKGameTaskHandle.h"
#include "horkos/event_schema_macos.h"  /* hk_es_text_wx */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* On-disk (un-slid) __TEXT segment range parsed from the mach-o load commands. */
typedef struct HKTextRange {
    bool     found;
    uint64_t vmaddr;   /* un-slid __TEXT vmaddr from the LC_SEGMENT_64 */
    uint64_t vmsize;
} HKTextRange;

/*
 * HKParseTextRange — parse the __TEXT segment range from a mach-o image (PURE;
 * host-runnable). `image` points at a mapped/loaded mach-o header (at least
 * `len` bytes readable). Supports 64-bit mach-o (MH_MAGIC_64) only — the game
 * binaries Horkos targets are 64-bit. On success sets out->found=true with the
 * un-slid vmaddr/vmsize; otherwise out->found=false.
 *
 * Returns true iff __TEXT was located. The ASLR slide is applied by the CALLER
 * (it needs the running image's slide), not here.
 */
bool HKParseTextRange(const void *image, size_t len, HKTextRange *out);

/*
 * HKTextScan — walk the running game's slid __TEXT via mach_vm_region_recurse,
 * flag writable / COW-broken pages, cross-check csops. Emits a hk_es_text_wx per
 * offending page. No-op on an invalid game-task handle. Returns events emitted.
 */
typedef void (*HKTextWxEmit)(const hk_es_text_wx *event, void *ctx);

size_t HKTextScan(const HKGameTaskHandle *game,
                  const HKTextRange      *on_disk_text,
                  uint64_t                aslr_slide,
                  HKTextWxEmit            emit,
                  void                   *ctx);

#ifdef __cplusplus
}  /* extern "C" */
#endif
