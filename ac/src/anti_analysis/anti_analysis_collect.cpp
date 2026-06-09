/*
 * ac/src/anti_analysis/anti_analysis_collect.cpp
 * Role: Aggregator for the 194+197 anti-analysis report. Runs each available
 *       sampler, zeroes any sub-struct whose sampler is unavailable on this
 *       platform and clears its `sensors_ok` bit, and assembles the slim
 *       `anti_analysis_report`. On non-Windows hosts it also supplies the
 *       not-implemented fallback for the Windows-only signal-197 host-tool
 *       sampler (HostToolFingerprint.cpp is compiled only on Windows), so
 *       `anti_analysis_sample_host_tools()` resolves on every target. SCAFFOLD:
 *       no live correlation logic (kernel handle-open / whitelist folding) yet —
 *       that lands under /tdd (guardrail #14).
 * Target platforms: cross. The Windows-only host-tool fallback is HK_PLATFORM_*-
 *       gated (guardrail #1).
 * Interface: implements anti_analysis_collect_all() declared in
 *       horkos/anti_analysis/anti_analysis_signals.h; on non-Windows also defines
 *       the not-implemented anti_analysis_sample_host_tools().
 */

#include "horkos/anti_analysis/anti_analysis_signals.h"

#include "platform.h"

#include <cstring>

#if !defined(HK_PLATFORM_WINDOWS)
/* HostToolFingerprint.cpp (the live Windows sampler) is not compiled off
 * Windows, so provide the not-implemented entry here. Returns a zeroed result
 * and HK_AC_NOT_IMPLEMENTED; the aggregator clears the host-tools `sensors_ok`
 * bit. */
extern "C" int anti_analysis_sample_host_tools(aa_host_tools* out) {
    if (out == nullptr) {
        return HK_AC_NOT_IMPLEMENTED;
    }
    std::memset(out, 0, sizeof(*out));
    return HK_AC_NOT_IMPLEMENTED;
}
#endif

int anti_analysis_collect_all(anti_analysis_report* out) {
    if (out == nullptr) {
        return HK_AC_NOT_IMPLEMENTED;
    }
    std::memset(out, 0, sizeof(*out));

    if (anti_analysis_sample_instrumentation(&out->instr) == HK_AC_OK) {
        out->sensors_ok |= HK_AA_OK_INSTRUMENTATION;
    } else {
        std::memset(&out->instr, 0, sizeof(out->instr));
    }

    if (anti_analysis_sample_host_tools(&out->host) == HK_AC_OK) {
        out->sensors_ok |= HK_AA_OK_HOST_TOOLS;
    } else {
        std::memset(&out->host, 0, sizeof(out->host));
    }

    return HK_AC_OK;
}
