# tests/unit/CMakeLists.txt
# Unit test executable linking all Horkos libraries.

include(GoogleTest)

add_executable(hk_unit_tests
    test_sentinel.cpp
    test_attestation_create.cpp
    test_event_schema_sizes.cpp
    test_ioctl_sizes.cpp
    test_selfcheck_fpgate.cpp
    # memory-integrity-selfcheck pure decision cores + PE parser (signals 145-153).
    # The cores live in hk_ac (self_logic.cpp / pe_parse.cpp); this test links hk_ac
    # and exercises them with synthetic fixtures — no kernel, no live image, no OS API.
    test_selfcheck_logic.cpp
    # timing-side-channels pure decision cores (signals 154-162). The cores live in
    # hk_ac (timing_logic.cpp); this test exercises them with synthetic vectors — no
    # debugger, no VM, no OS hook.
    test_timing_logic.cpp
    # anti-analysis-environment pure decision cores (signals 194 + 197). The cores
    # live in hk_ac (anti_analysis_logic.cpp); this test exercises them with synthetic
    # observable sets — no live tooling, no kernel, no OS API.
    test_anti_analysis_logic.cpp
    test_minifilter_altitude.cpp
    test_thread_start_mismatch.cpp
    # win-kernel-driver-integrity pure-logic tests (no WDK; headers are plain C99).
    test_module_map_resolve.cpp
    test_ssdt_decode.cpp
    # win-kernel-memory-injection pure decision cores (signals 10-18). The cores are
    # header-only inline functions under kernel/win/include (mem_logic_vad.h /
    # mem_logic_image.h / mem_logic_stomp.h, plain C99 over normalized mem_types.h);
    # these tests exercise them with synthetic VAD nodes / loader lists / section
    # bytes — no WDK, no live process, no VAD tree, no OS API. The kernel samplers
    # that fill these inputs are Windows-driver-only and not built here.
    test_mem_vad_logic.cpp
    test_mem_image_logic.cpp
    test_mem_stomp_logic.cpp
    # win-hypervisor-detection pure structural-consistency cores (signals
    # 37/40/42/44/45). The cores are header-only inline functions in
    # ac/include/horkos/hv_logic.h over the hv_signals.h POD surface; these tests
    # exercise them with synthetic leaf vectors / MSR flags / TSC samples — no
    # CPUID, no MSR, no Windows runner. The ac/src/hv/*.cpp samplers + kernel HV
    # sensors that fill these inputs are Windows-only and not built here.
    test_hv_logic.cpp
    test_integrity_finding_size.cpp
    # macos-codesign-integrity schema pin + pure FP-gate cores (signals 118-126).
    # The probe TUs split a PURE decision core from the impure csops()/Sec*/ES
    # read; compiled with HK_CS_PROBE_PURE_ONLY the cores link host-side with no
    # macOS headers (the impure bodies #ifdef out). Host-runnable on every CI host.
    test_cs_finding_size.cpp
    test_macos_codesign_logic.cpp
    ${CMAKE_SOURCE_DIR}/daemon/macos/csops/CsFlagsProbe.cpp
    ${CMAKE_SOURCE_DIR}/daemon/macos/csops/CdHashProbe.cpp
    ${CMAKE_SOURCE_DIR}/daemon/macos/csops/EntitlementDiffProbe.cpp
    ${CMAKE_SOURCE_DIR}/daemon/macos/csops/CsInvalidationCorrelator.cpp
    ${CMAKE_SOURCE_DIR}/daemon/macos/seccode/DynamicValidityProbe.cpp
    ${CMAKE_SOURCE_DIR}/daemon/macos/seccode/DylibTeamIdProbe.cpp
    # win-kernel-syscall-etw-integrity pure-logic tests (no WDK; plain C99 header).
    test_syscall_etw_logic.cpp
    # win-usermode-overlay pure-logic tests (no Win32; the render-sensor decision
    # cores + PE relocation math are host-runnable above the platform guard).
    test_render_hook_logic.cpp
    # win-input-automation pure-logic tests (no Win32; the input-sensor decision
    # cores — provenance/ratio/flag folding, timing-feature math, poll-rate
    # derivation — are host-runnable above the platform guard).
    test_input_prov_logic.cpp
    # behavioral-aim platform-free per-tick fold (signals 163/165/171). The fold
    # (AimAccumulator.cpp) takes only the platform-free hk_hid_sample struct — no
    # platform header — so it compiles into this host target directly (guardrail
    # #4: no kernel/platform TU). The OS reads live in the per-platform backends
    # (not built here); the kinematic segmenters (166-169) are server-side Rust.
    test_aim_accumulator.cpp
    ${CMAKE_SOURCE_DIR}/sdk/src/input/AimAccumulator.cpp
    # network-anomaly cross-platform cores (signals 182/184/187 + the aggregator).
    # The cores (ClockDomainProbe/SendBacklogProbe/ProbeChannel/NetCollect) carry no
    # platform header — they dispatch OS reads through the net_backend.h / net_probes.h
    # seams, which this test fakes in-TU — so they compile into this host target
    # directly (guardrail #4: no kernel/platform TU). The per-platform OS-read
    # backends (NetBackend*/NetTiming/TcpInfo/InputFrame/RouteWatch/SocketTable) are
    # NOT built here; their probe symbols are supplied by the test fixture.
    test_net_collect.cpp
    ${CMAKE_SOURCE_DIR}/sdk/src/ClockDomainProbe.cpp
    ${CMAKE_SOURCE_DIR}/sdk/src/SendBacklogProbe.cpp
    ${CMAKE_SOURCE_DIR}/sdk/src/ProbeChannel.cpp
    ${CMAKE_SOURCE_DIR}/sdk/src/NetCollect.cpp
    # win-handle-memory-access pure-logic + schema-pin tests (no WDK/Win32; the
    # section classifier, staging assembler, and residency/holder/protect cores are
    # host-runnable above the platform guard; the size pins replicate the
    # kernel-private wire mirrors).
    test_vm_access_logic.cpp
    test_vm_access_sizes.cpp
    # linux-ebpf-injection pure-logic tests (signals 82-90). The correlator
    # decision cores + ElfModel /proc parsing + OverlayAllowlist verify/lookup are
    # plain C++17 (no libbpf, no Linux-only syscalls in the tested paths) so they
    # are host-runnable above the platform guard via an injected fixture
    # ProcReader. The correlator sources are compiled here directly (they are NOT
    # part of the Linux-only hk_bpf_loader target on a non-Linux host).
    test_linux_injection_logic.cpp
    ${CMAKE_SOURCE_DIR}/kernel/linux/userspace/ElfModel.cpp
    ${CMAKE_SOURCE_DIR}/kernel/linux/userspace/OverlayAllowlist.cpp
    ${CMAKE_SOURCE_DIR}/kernel/linux/userspace/DsoProvenance.cpp
    ${CMAKE_SOURCE_DIR}/kernel/linux/userspace/LinkMapOrder.cpp
    ${CMAKE_SOURCE_DIR}/kernel/linux/userspace/DlopenBacking.cpp
    ${CMAKE_SOURCE_DIR}/kernel/linux/userspace/PreloadWatch.cpp
    ${CMAKE_SOURCE_DIR}/kernel/linux/userspace/InterpCheck.cpp
    ${CMAKE_SOURCE_DIR}/kernel/linux/userspace/GotPltMap.cpp
    ${CMAKE_SOURCE_DIR}/kernel/linux/userspace/RDebugCheck.cpp
    ${CMAKE_SOURCE_DIR}/kernel/linux/userspace/TextPageBacking.cpp
    # linux-module-integrity pure-logic tests (signals 91-99). The proc/sysfs/
    # debugfs parsers + decision cores are plain C++17 (no libbpf — BpfEnumerate's
    # live path is behind HK_HOSTINT_LIBBPF, which is NOT defined here so the
    # degrade-to-unavailable stub compiles). Host-runnable above the platform
    # guard via captured text fixtures and a capturing sink.
    test_linux_module_integrity_logic.cpp
    ${CMAKE_SOURCE_DIR}/kernel/linux/userspace/SymbolMap.cpp
    ${CMAKE_SOURCE_DIR}/kernel/linux/userspace/KallsymsAudit.cpp
    ${CMAKE_SOURCE_DIR}/kernel/linux/userspace/FtraceAudit.cpp
    ${CMAKE_SOURCE_DIR}/kernel/linux/userspace/KprobeAudit.cpp
    ${CMAKE_SOURCE_DIR}/kernel/linux/userspace/LockdownPosture.cpp
    ${CMAKE_SOURCE_DIR}/kernel/linux/userspace/ModuleViewDiff.cpp
    ${CMAKE_SOURCE_DIR}/kernel/linux/userspace/ModuleDiskDrift.cpp
    ${CMAKE_SOURCE_DIR}/kernel/linux/userspace/BpfEnumerate.cpp
    ${CMAKE_SOURCE_DIR}/kernel/linux/userspace/MsrPathResolver.cpp
    ${CMAKE_SOURCE_DIR}/kernel/linux/userspace/HostIntegritySensors.cpp
)

target_include_directories(hk_unit_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/attestation
    ${CMAKE_SOURCE_DIR}/sdk/include
    # selfcheck_fpgate.h: pure FP-gate logic shared with the Win kernel TUs.
    ${CMAKE_SOURCE_DIR}/kernel/win/include
    # minifilter_altitude.h lives under sdk/src/backends/win; include sdk/src so
    # the test includes it as "backends/win/minifilter_altitude.h".
    ${CMAKE_SOURCE_DIR}/sdk/src
    # linux-ebpf-injection correlator headers (host-compiled for the pure-logic
    # tests; the .cpp sources are added to the test target above).
    ${CMAKE_SOURCE_DIR}/kernel/linux/userspace
    # macos-codesign-integrity probe headers (CsScan.h / CsIntegrityProbe.h);
    # the *Probe.cpp pure cores are compiled into this target above.
    ${CMAKE_SOURCE_DIR}/daemon/macos/csops
    # memory-integrity-selfcheck: selfcheck.h (ac/include) + the TU-local pe_parse.h
    # (ac/src/selfcheck). The cores are in hk_ac, already linked below.
    ${CMAKE_SOURCE_DIR}/ac/include
    ${CMAKE_SOURCE_DIR}/ac/src/selfcheck
)

# macos-codesign-integrity: compile the probe TUs' PURE cores only — the impure
# csops()/Sec*/ES bodies #ifdef out under this define, so no macOS framework /
# header is needed on a non-macOS CI host. This applies to the whole test target;
# no other source references HK_CS_PROBE_PURE_ONLY.
target_compile_definitions(hk_unit_tests PRIVATE HK_CS_PROBE_PURE_ONLY)

target_link_libraries(hk_unit_tests PRIVATE
    hk_platform
    hk_attestation
    hk_drm
    hk_ac
    GTest::gtest
    GTest::gtest_main
)

gtest_discover_tests(hk_unit_tests)
