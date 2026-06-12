/*
 * Role: Host-safe normalized POD types shared by the memory-scan pure-logic
 *       decision cores (mem_logic_vad.h / mem_logic_image.h / mem_logic_stomp.h)
 *       and the kernel scan TUs. The kernel sampler reduces build-specific
 *       MMVAD / PTE / loader state into these stable, layout-free structs BEFORE
 *       any classification runs, so the pure cores — and their host unit tests —
 *       never touch a kernel header. Plain C99, includes only <stdint.h> and the
 *       wire constants from event_schema.h; includable from a kernel C TU and a
 *       host C++ test alike (never the same TU — guardrail #4).
 *       READ-ONLY: describes observed state; nothing here mutates anything.
 * Target platforms: all (pure data; the sampling that fills these is Win-kernel).
 * Interface: HK_VAD_NODE consumed by mem_logic_vad.h + MemScanVad.c / VadWalk.c.
 */

#pragma once

#include <stdint.h>

#include "horkos/event_schema.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * One normalized VAD leaf, produced by the read-only VAD walk (VadWalk.c) after
 * it resolves the build-specific MMVAD fields through vad_layout.h. All fields
 * are already normalized to the wire constants (HK_MEM_VAD_* / HK_MEM_PROT_*),
 * so the classifiers in mem_logic_vad.h are pure arithmetic over this struct.
 */
typedef struct hk_vad_node {
    uint64_t region_base;     /* StartingVpn << PAGE_SHIFT. */
    uint64_t region_size;     /* (EndingVpn - StartingVpn + 1) << PAGE_SHIFT. */
    uint32_t vad_type;        /* HK_MEM_VAD_*. */
    uint32_t protection;      /* HK_MEM_PROT_* mask. */
    uint32_t has_control_area;/* 1 if the leaf has a ControlArea/FilePointer
                                 (i.e. it is section/file-backed); 0 = private. */
    uint32_t large_page;      /* 1 if the large-page flag is set on the leaf. */
    uint32_t has_jit_owner;   /* 1 if the region falls inside a known-JIT module
                                 range (CLR/V8/Chakra/JVM). Annotation only — the
                                 server decides; the kernel never hard-flags it. */
    uint32_t reserved;        /* must be zero. */
} HK_VAD_NODE;

#ifdef __cplusplus
} /* extern "C" */
#endif
