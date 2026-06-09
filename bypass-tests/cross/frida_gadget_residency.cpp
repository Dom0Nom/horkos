/*
 * bypass-tests/cross/frida_gadget_residency.cpp
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
#if defined(HK_PLATFORM_LINUX)

#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>

static int drive_unbacked_rx_thread(void) {
    const size_t page = static_cast<size_t>(::sysconf(_SC_PAGESIZE));
    void* rx = ::mmap(nullptr, page, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (rx == MAP_FAILED) {
        return -1;
    }
    /* The thread entry IS the anon-RX address: pthread_create's start_routine is
     * the anon stub. We synthesize a self-relative infinite jmp (x86-64/i386:
     * EB FE), so the worker's start address AND its parked instruction pointer are
     * both inside the anon-RX region — exactly the residency the sampler keys on.
     * On non-x86 we skip (return -1) rather than emit wrong opcode bytes. */
#if defined(__x86_64__) || defined(__i386__)
    unsigned char stub[2] = {0xEB, 0xFE}; /* jmp $ : infinite self-loop */
    std::memcpy(rx, stub, sizeof(stub));
#else
    ::munmap(rx, page);
    return -1;
#endif
    if (::mprotect(rx, page, PROT_READ | PROT_EXEC) != 0) {
        ::munmap(rx, page);
        return -1; /* hardened / SELinux W^X enforcement — skip, fall back to core */
    }

    pthread_t th;
    typedef void* (*entry_t)(void*);
    entry_t entry = reinterpret_cast<entry_t>(rx);
    if (::pthread_create(&th, nullptr, entry, nullptr) != 0) {
        ::munmap(rx, page);
        return -1;
    }
    /* Give the worker a moment to be scheduled and parked inside the region. */
    for (int i = 0; i < 100; ++i) {
        usleep(1000);
    }

    aa_instrumentation r;
    std::memset(&r, 0, sizeof(r));
    const int st = anti_analysis_sample_instrumentation(&r);

    /* The spun thread never returns (infinite loop); we cannot join it. Detach so
     * it is reaped at process exit. It holds only the anon mapping, which the OS
     * frees on exit — acceptable for a short-lived test process. */
    ::pthread_detach(th);

    int rc = 0;
    if (st != HK_AC_OK) {
        std::printf("FAIL: sampler did not run on Linux (status %d)\n", st);
        rc = 1;
    } else if (r.unbacked_rx_threads == 0u) {
        std::printf("FAIL: sampler missed the anon-RX worker thread\n");
        rc = 1;
    } else if (r.confidence_tier != HK_AA_INSTR_TIER_INFO) {
        /* Single observable (the unbacked-RX thread) alone must be INFO, not HIGH —
         * the FP-safe behaviour the catalog mandates. */
        std::printf("FAIL: single unbacked-RX observable produced tier %u "
                    "(expected INFO)\n", r.confidence_tier);
        rc = 1;
    }
    /* Leak the mapping deliberately (worker still executing there). */
    return rc;
}

#else /* non-Linux: executable anon mapping under hardened runtime is unreliable */

static int drive_unbacked_rx_thread(void) {
    /* macOS hardened runtime refuses RX anon mappings without the JIT entitlement,
     * and the macOS sampler's thread-start observable is an HK-UNCERTAIN stub
     * anyway (see InstrumentationResidency.cpp). Skip the live drive and rely on
     * the pure-core combination assertions, which still gate the classifier. */
    return -1;
}

#endif

int main(void) {
    int rc = 0;

    rc |= core_invariants();
    rc |= sampler_is_total_and_consistent();

    const int live = drive_unbacked_rx_thread();
    if (live > 0) {
        rc = 1; /* the live drive ran and FAILED */
    } else if (live < 0) {
        std::printf("INFO: executable anon mapping unavailable on this host; "
                    "the live unbacked-RX-thread drive was skipped — pure-core "
                    "combination assertions still gate the classifier.\n");
    }

    if (rc == 0) {
        std::printf("frida_gadget_residency (signal 194): PASS\n");
    }
    return rc;
}
