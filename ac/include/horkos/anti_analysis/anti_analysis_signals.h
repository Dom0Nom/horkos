/*
 * ac/include/horkos/anti_analysis/anti_analysis_signals.h
 * Role: Usermode analysis-tooling-presence sensor surface for catalog signals
 *       194 (dynamic-instrumentation / DBI residency fingerprint) and 197
 *       (memory-editor / debugger host fingerprint). Declares the two fixed POD
 *       result structs, the slim `anti_analysis_report` envelope that carries
 *       just those two plus a `sensors_ok` bitmask, and the per-signal samplers
 *       + the `anti_analysis_collect_all()` aggregator. Each sampler reports raw
 *       observations only; ALL classification (allowlist matching, severity /
 *       confidence tiering) is server-side (the client never decides a ban).
 *
 *       NOTE: this report covers signals 194 + 197 ONLY. The other anti-analysis
 *       catalog signals live elsewhere and are NOT re-declared here: 190 (HW
 *       debug registers) and 192/193/148 ride the selfcheck domain (selfcheck/);
 *       198 / 154-162 timing-variance ride the timing domain (timing/); 191
 *       (kernel-debugger flag) rides the Windows KMDF kernel ring; 195 (ptrace
 *       tripwire) rides the Linux eBPF plane; 196 (Mach exception-port) rides the
 *       macOS daemon. This header is the surface for the two cross/Windows
 *       usermode samplers only.
 * Target platforms: Windows + Linux + macOS. The cross core compiles everywhere;
 *       the platform-specific sampler bodies are HK_PLATFORM_*-gated inside their
 *       .cpp (guardrail #1). Signal 197's host-tool fingerprint is Windows-only;
 *       on other platforms its sampler returns HK_AC_NOT_IMPLEMENTED and clears
 *       its `sensors_ok` bit.
 * Interface: this header IS the 194+197 sensor surface; the
 *       the ac/src/anti_analysis .cpp TUs implement it; consumed by ac/src/ac.cpp.
 *       Status codes reuse the HK_AC_* codes from horkos/ac.h. No platform API in
 *       this header (guardrail #1).
 */

#pragma once

#include <stdint.h>

#include "horkos/ac.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * `sensors_ok` bitmask. A SET bit means that sampler ran on this platform and
 * its sub-struct carries real observations; a CLEAR bit means the sampler was
 * unavailable (returned HK_AC_NOT_IMPLEMENTED) and the server must read the
 * zeroed sub-struct as "not collected", never as "clean".
 * ------------------------------------------------------------------------- */
#define HK_AA_OK_INSTRUMENTATION 0x00000001u /* signal 194 sampler ran */
#define HK_AA_OK_HOST_TOOLS      0x00000002u /* signal 197 sampler ran */

/* -------------------------------------------------------------------------
 * Signal 194 — dynamic-instrumentation (Frida/DBI) residency fingerprint.
 * Three combined observables; single observable is informational only. The
 * server tiers the combination; the client only ships the raw counts/flags and
 * the locally-derived `confidence_tier` (a pure combiner, server-overridable).
 * `jit_module_present` is FP CONTEXT (Java/V8/.NET/LuaJIT also create anon-RX
 * threads) and never raises the tier on its own.
 * ------------------------------------------------------------------------- */
typedef struct aa_instrumentation {        /* signal 194 */
    uint32_t unbacked_rx_threads;   /* thread starts in anon-RX, not module-backed */
    uint32_t runtime_export_match;  /* modules exporting framework symbols */
    uint32_t control_port_listener; /* 1 if framework default port listening in tree */
    uint32_t jit_module_present;    /* 1 if a known-JIT module is loaded (FP context) */
    uint32_t confidence_tier;       /* 0=none,1=info(single),2=high(combined) */
    uint32_t reserved;
} aa_instrumentation;

/* -------------------------------------------------------------------------
 * Signal 197 — memory-editor / debugger host fingerprint (Windows).
 * Read-only enumeration of debugger window classes, object-manager device /
 * symlink names, and loaded drivers, cross-checked against the kernel driver
 * whitelist + the kernel ObRegisterCallbacks handle-open records. The server
 * tiers severity; the client ships the raw hit counts/flags and the locally-
 * derived `severity_tier` (a pure function, server-overridable).
 * ------------------------------------------------------------------------- */
typedef struct aa_host_tools {             /* signal 197 */
    uint32_t debugger_window_classes; /* known x64dbg/Olly/etc. window classes */
    uint32_t known_device_objects;    /* CE/ReClass device/symlink names present */
    uint32_t suspicious_drivers;      /* editor helper drivers loaded (e.g. DBK64) */
    uint32_t byovd_driver_match;      /* matched the kernel whitelist known-bad set */
    uint32_t opened_handle_to_game;   /* from kernel Ob records: editor opened a handle */
    uint32_t severity_tier;           /* 0=none,1=info,2=tool-present,3=handle-open */
} aa_host_tools;

/* -------------------------------------------------------------------------
 * The 194+197 report envelope. Slim by design — it carries ONLY these two
 * sub-payloads plus the `sensors_ok` bitmask. The other anti-analysis catalog
 * signals ride their own domains' planes (see the module comment above); this
 * is NOT the full anti-analysis report.
 * ------------------------------------------------------------------------- */
typedef struct anti_analysis_report {
    aa_instrumentation instr;       /* 194 */
    aa_host_tools      host;        /* 197 */
    uint32_t           sensors_ok;  /* HK_AA_OK_* : which samplers ran on this platform */
} anti_analysis_report;

/* -------------------------------------------------------------------------
 * Samplers. Each fills its result by out-param and returns an HK_AC_* status:
 * HK_AC_OK when the sampler ran, HK_AC_NOT_IMPLEMENTED on an unsupported
 * platform (the aggregator then clears the matching `sensors_ok` bit and leaves
 * the sub-struct zeroed). A null out-param is HK_AC_NOT_IMPLEMENTED (defensive,
 * not a crash). No logic in this scaffolding pass — the bodies land under /tdd.
 * ------------------------------------------------------------------------- */

/* Signal 194: dynamic-instrumentation residency. Cross-platform (anon-RX thread
 * scan + export-symbol scan + control-port listener check). */
int anti_analysis_sample_instrumentation(aa_instrumentation* out);

/* Signal 197: host-tool fingerprint. Windows-only; HK_AC_NOT_IMPLEMENTED
 * elsewhere. */
int anti_analysis_sample_host_tools(aa_host_tools* out);

/* Aggregator: runs every available sampler, zeroes unavailable sub-structs and
 * clears their `sensors_ok` bit, builds the report. Returns HK_AC_OK if the
 * report was assembled (even if some samplers were unavailable on this
 * platform), HK_AC_NOT_IMPLEMENTED only on a null out-param. */
int anti_analysis_collect_all(anti_analysis_report* out);

#ifdef __cplusplus
} /* extern "C" */
#endif
