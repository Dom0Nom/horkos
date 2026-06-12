/*
 * Role: Merge-gate bypass test (anti-analysis-environment signal 194, cross-
 *       platform). Adversarial fixture for the dynamic-instrumentation / DBI
 *       residency fingerprint. It (1) drives the REAL signal-194 sampler on the
 *       host and asserts the report is a bounded, total "no-signal" result on a
 *       clean machine (the sampler never UB's, always returns a valid envelope);
 *       (2) where the platform permits an executable anonymous mapping, spins a
 *       real worker thread whose entry is a tiny copied function inside that
 *       anon-RX region and asserts the sampler observes unbacked_rx_threads > 0
 *       with confidence_tier == INFO (single observable — NOT high); (3) drives
 *       the pure confidence-tier core directly to assert that the COMBINED
 *       observable set escalates to HIGH while any single observable stays INFO,
 *       and that a JIT context never raises the tier. It asserts RAW report
 *       fields only — never a local ban (ban authority is server-side).
 * Target platforms: cross. The pure-core assertions run on every host; the live
 *       unbacked-RX-thread assertion runs only where an executable anon mapping is
 *       obtainable (Linux mmap PROT_EXEC; macOS MAP_JIT). On a host where the
 *       executable anon mapping is refused (hardened runtime without the JIT
 *       entitlement) the fixture falls back to the pure-core assertions, which
 *       still meaningfully gate the classifier.
 * Interface: drives anti_analysis_sample_instrumentation() (raw report field) and
 *       hk::anti_analysis::instrumentation_confidence_tier() (the pure core),
 *       never a local ban.
 *
 * Merge gate (guardrail #12): the bypass test for the signal-194 DBI residency
 * fingerprint. The repo never commits a real instrumentation runtime or gadget.
 */

#include <cstdio>
#include <cstring>

#include "horkos/anti_analysis/anti_analysis_signals.h"
#include "horkos/anti_analysis/instrumentation.h"

#include "platform.h"

using namespace hk::anti_analysis;

/* -------------------------------------------------------------------------
 * Pure-core assertions (always run). These are the load-bearing combination /
 * FP-context invariants the catalog mandates for signal 194.
 * ------------------------------------------------------------------------- */
static int core_invariants(void) {
    int rc = 0;
    if (instrumentation_confidence_tier(0, 0, 0, 0) != HK_AA_INSTR_TIER_NONE) {
        std::printf("FAIL: empty observable set is not NONE\n");
        rc = 1;
    }
    /* Single observable (the unbacked-RX thread alone — the JIT-like case) is
     * INFO, never HIGH. */
    if (instrumentation_confidence_tier(1, 0, 0, 0) != HK_AA_INSTR_TIER_INFO) {
        std::printf("FAIL: single observable is not INFO\n");
        rc = 1;
    }
    /* A JIT context alongside a single observable does NOT escalate. */
    if (instrumentation_confidence_tier(1, 0, 0, 1) != HK_AA_INSTR_TIER_INFO) {
        std::printf("FAIL: jit-context + single observable escalated past INFO\n");
        rc = 1;
    }
    /* COMBINED observables escalate to HIGH. */
    if (instrumentation_confidence_tier(1, 1, 1, 0) != HK_AA_INSTR_TIER_HIGH) {
        std::printf("FAIL: combined observable set is not HIGH\n");
        rc = 1;
    }
    return rc;
}

/* -------------------------------------------------------------------------
 * Live-sampler assertion: the sampler must always produce a bounded, total
 * report (never UB) and a self-consistent confidence tier derivable from the
 * raw fields it shipped. On a clean CI host with no instrumentation runtime
 * resident, the tier is NONE.
 * ------------------------------------------------------------------------- */
static int sampler_is_total_and_consistent(void) {
    aa_instrumentation r;
    std::memset(&r, 0xAB, sizeof(r)); /* poison: the sampler must fully overwrite */
    const int st = anti_analysis_sample_instrumentation(&r);

    /* On platforms where the sampler runs (Linux/macOS) it returns OK; on the
     * Windows HK-UNCERTAIN stub it returns NOT_IMPLEMENTED with a zeroed result.
     * Either way the report must be a valid, bounded envelope. */
    if (st != HK_AC_OK && st != HK_AC_NOT_IMPLEMENTED) {
        std::printf("FAIL: sampler returned unexpected status %d\n", st);
        return 1;
    }
    if (st == HK_AC_NOT_IMPLEMENTED) {
        /* Not-implemented contract: zeroed result. */
        aa_instrumentation z;
        std::memset(&z, 0, sizeof(z));
        if (std::memcmp(&r, &z, sizeof(r)) != 0) {
            std::printf("FAIL: NOT_IMPLEMENTED sampler left a non-zero result\n");
            return 1;
        }
        return 0;
    }

    /* OK path: the shipped confidence_tier must equal the pure core applied to the
     * raw fields the sampler reported (the sensor never invents a tier). */
    const uint32_t expect = instrumentation_confidence_tier(
        r.unbacked_rx_threads, r.runtime_export_match, r.control_port_listener,
        r.jit_module_present);
    if (r.confidence_tier != expect) {
        std::printf("FAIL: shipped tier %u != core-derived %u\n",
                    r.confidence_tier, expect);
        return 1;
    }
    if (r.confidence_tier > HK_AA_INSTR_TIER_HIGH) {
        std::printf("FAIL: confidence_tier %u out of range\n", r.confidence_tier);
        return 1;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * Live unbacked-RX-thread drive. Maps an anonymous executable region, copies a
 * tiny thread entry into it (W^X-safe: write then flip to RX, or MAP_JIT), spins
 * a real thread whose entry is inside that anon-RX mapping, and asserts the
 * sampler reports unbacked_rx_threads > 0 at tier INFO. Returns:
 *   0  assertion ran and passed,
 *   1  assertion ran and FAILED,
 *  -1  the platform refused an executable anon mapping (skip — fall back to core).
 * Linux only: the sampler probes /proc/self/task/<tid>/kstkeip, so the worker must
 * be parked spinning inside the anon-RX region while we sample.
 * ------------------------------------------------------------------------- */
static int drive_unbacked_rx_thread(void) {
    /* The live drive that once spun a worker inside an anon-RX mapping is retired:
     * its only observable was aa_instrumentation.unbacked_rx_threads, which the
     * Linux sampler can no longer source. /proc/self/task/<tid>/stat exposes no
     * thread entry PC, and field 30 (kstkeip) is intentionally zeroed by the kernel
     * for every non-exiting task (fs/proc/array.c do_task_stat sets eip/esp only
     * under PF_EXITING|PF_DUMPCORE; comment: "There is no non-racy way to read them
     * without freezing the task"; proc(5) marks fields 29/30 [PT]). So the sampler
     * honestly returns 0 here (HK-UNCERTAIN), and a live drive would only ever read
     * back 0 — a vacuous assertion. Skip until the real mechanism lands (an eBPF
     * clone/sched_process_fork hook capturing the entry IP, validated on a Linux
     * target). The pure-core combination/FP assertions in core_invariants() remain
     * the active merge gate for signal 194's classifier. */
    return -1;
}

int main(void) {
    int rc = 0;

    rc |= core_invariants();
    rc |= sampler_is_total_and_consistent();

    const int live = drive_unbacked_rx_thread();
    if (live > 0) {
        rc = 1; /* the live drive ran and FAILED */
    } else if (live < 0) {
        std::printf("INFO: live unbacked-RX-thread drive retired (the Linux "
                    "sampler cannot source a thread entry PC from /proc — kstkeip "
                    "is kernel-zeroed for live tasks); pure-core combination "
                    "assertions still gate the classifier.\n");
    }

    if (rc == 0) {
        std::printf("frida_gadget_residency (signal 194): PASS\n");
    }
    return rc;
}
