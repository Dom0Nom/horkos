# ac/CMakeLists.txt
# Builds hk_ac static library. Depends only on hk_platform.

# -------------------------------------------------------------------------
# Client self-integrity (memory-integrity-selfcheck, catalog signals 145-153).
# Default ON on all platforms — the self-check is core AC functionality, not an
# optional cross-process scan (plan §Build wiring). When ON, HK_SELFCHECK is
# defined on the target and the selfcheck TUs compile their live bodies; when OFF
# they compile to link-safe no-ops so hk_ac still links. The Windows-format TUs
# (iat_target_audit, veh_unwind_audit) and the POSIX analogs (got_target_audit,
# sig_handler_audit) compile everywhere (pure struct walks) but their live bodies
# are HK_PLATFORM_*-guarded inside the TU (guardrail #1). Signal 147's obfuscation
# is opt-in per symbol via the hk_obfuscate annotation, consumed by the LLVM-19
# pass only when the obfuscator toolchain build is selected (guardrail #9).
# -------------------------------------------------------------------------
option(HK_ENABLE_SELFCHECK
       "Build the client self-integrity sensors (memory-integrity-selfcheck, 145-153)"
       ON)

set(hk_ac_src src/ac.cpp)

if(HK_ENABLE_SELFCHECK)
    list(APPEND hk_ac_src
        src/selfcheck/selfcheck.cpp        # orchestrator + guard_entry
        src/selfcheck/self_logic.cpp       # pure decision cores (host-tested)
        src/selfcheck/pe_parse.cpp         # pure PE parser (host-tested)
        src/selfcheck/image_baseline.cpp   # on-disk baseline (format dispatch)
        src/selfcheck/text_crossview.cpp   # 145
        src/selfcheck/page_cow_audit.cpp   # 146
        src/selfcheck/retaddr_provenance.cpp # 147
        src/selfcheck/dr_audit.cpp         # 148
        src/selfcheck/iat_target_audit.cpp # 149 (Windows-format body)
        src/selfcheck/got_target_audit.cpp # 149 (POSIX body)
        src/selfcheck/veh_unwind_audit.cpp # 150 (Windows-format body)
        src/selfcheck/sig_handler_audit.cpp# 150 (POSIX body)
        src/selfcheck/loader_consistency.cpp # 151
        src/selfcheck/wx_pte_audit.cpp     # 152
        src/selfcheck/tls_init_audit.cpp)  # 153
endif()

# -------------------------------------------------------------------------
# Timing & execution-trace side-channels (timing-side-channels, catalog signals
# 154/156/157/159/161/162; 155 is kernel-assisted and folded in). Default ON —
# these are core PC sensors (plan §Build wiring). The cross-platform clock-core
# TUs (timing_logic / timing_collect / sibling_watchdog / cpuid_leaf_fan /
# timing_kernel_correlate) compile on every host with the platform intrinsics
# behind platform/ (guardrail #1); the Windows-only VEH/guard-page/shared-page TUs
# (*_win.cpp) compile only when targeting Windows. The hot-sampling loops are NOT
# obfuscated (guardrail #9); obfuscation stays opt-in per init/integrity symbol.
# -------------------------------------------------------------------------
option(HORKOS_TIMING_SENSORS
       "Build the timing/execution-trace side-channel sensors (154-162)"
       ON)

if(HORKOS_TIMING_SENSORS)
    list(APPEND hk_ac_src
        src/timing/timing_logic.cpp            # pure cores (host-tested)
        src/timing/timing_collect.cpp          # aggregator
        src/timing/sibling_watchdog.cpp        # 156 (cross-platform)
        src/timing/cpuid_leaf_fan_win.cpp      # 162 (cross core, x86-gated)
        src/timing/timing_kernel_correlate.cpp # 155 fold (Win body; no-op elsewhere)
        src/timing/veh_fault_attribution_win.cpp # 154 + shared first-chain VEH/decoy
        src/timing/shared_data_clock_win.cpp   # 157
        src/timing/exception_latency_win.cpp   # 159
        src/timing/guard_fault_cadence_win.cpp)# 161
    # The *_win.cpp TUs are guarded internally by HK_PLATFORM_WINDOWS, so they
    # compile to link-safe no-ops off Windows (no Win32 calls reachable) — they stay
    # in the source list on every host so the AC links identically across platforms.
endif()

# -------------------------------------------------------------------------
# Anti-analysis environment sensors — usermode analysis-tooling presence,
# catalog signals 194 (dynamic-instrumentation/DBI residency) and 197 (memory-
# editor/debugger host fingerprint) ONLY. The other anti-analysis catalog signals
# (190-193/195/196/198) live in the selfcheck/timing/eBPF/daemon domains and are
# NOT built here. Default ON — these are core PC sensors (plan §Build wiring). The
# cross-platform core TUs (InstrumentationResidency / anti_analysis_logic /
# anti_analysis_collect) compile on every host with the platform-specific bodies
# behind platform.h (guardrail #1); the Windows-only HostToolFingerprint.cpp (197)
# compiles only when targeting Windows, exactly like the selfcheck/timing win-only
# sources. The pure tier cores in anti_analysis_logic.cpp are host-unit-tested
# (tests/unit/test_anti_analysis_logic.cpp). No obfuscation of these sampling
# loops (guardrail #9).
# -------------------------------------------------------------------------
option(HORKOS_ANTI_ANALYSIS_SENSORS
       "Build the anti-analysis-environment usermode sensors (194 + 197)"
       ON)

if(HORKOS_ANTI_ANALYSIS_SENSORS)
    list(APPEND hk_ac_src
        src/anti_analysis/InstrumentationResidency.cpp # 194 (cross sampler)
        src/anti_analysis/anti_analysis_logic.cpp      # pure tier cores (host-tested)
        src/anti_analysis/anti_analysis_collect.cpp)   # aggregator (+ non-Win 197 stub)
    if(WIN32)
        list(APPEND hk_ac_src
            src/anti_analysis/HostToolFingerprint.cpp) # 197 (Windows-only sampler)
    endif()
endif()

add_library(hk_ac STATIC ${hk_ac_src})
target_include_directories(hk_ac PUBLIC include)
# The selfcheck TUs route platform reads through platform.h (guardrail #1) and
# include their TU-local pe_parse.h / self_wire.h from src/selfcheck.
target_include_directories(hk_ac PRIVATE
    ${CMAKE_SOURCE_DIR}/platform
    ${CMAKE_CURRENT_SOURCE_DIR}/src/selfcheck
    # timing-side-channels: the *_win.cpp TUs include the TU-local decoy_shared.h
    # (shared first-chain VEH/decoy accessors) from src/timing.
    ${CMAKE_CURRENT_SOURCE_DIR}/src/timing)
target_link_libraries(hk_ac PUBLIC hk_platform)

# timing-side-channels signal 156 spawns a sibling-core watchdog std::thread; link the
# host threading library (pthreads on POSIX) so hk_ac and its consumers resolve it.
if(HORKOS_TIMING_SENSORS)
    find_package(Threads REQUIRED)
    target_link_libraries(hk_ac PUBLIC Threads::Threads)
endif()

if(HK_ENABLE_SELFCHECK)
    target_compile_definitions(hk_ac PRIVATE HK_SELFCHECK=1)
endif()
