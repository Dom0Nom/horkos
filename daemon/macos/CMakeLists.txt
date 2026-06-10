# daemon/macos/CMakeLists.txt
# Role: Build the horkosd launchd/XPC daemon for macOS.
#       Produces the `horkosd` executable that launchd starts via
#       com.horkos.daemon.plist.  No anti-cheat logic yet — this is the
#       Phase 4 Step 4.4 bring-up skeleton.
# Target platforms: macOS only (guarded by APPLE check in parent).
# Interface: standalone executable; no Horkos library headers required at
#            this stage.

if(NOT APPLE)
    return()
endif()

# HORKOS_MACOS_INJECT_POLLERS (default ON on APPLE) — compile the
# process-inspection / injection pollers (signals 113/114/116/117) and the
# shared game-task handle + mmap baseline. The privileged task-handle path is a
# no-op without the entitlement / SIP-disabled box (mirrors the ES _PROVISIONED
# story), so building ON by default is safe: the pollers degrade to no-ops.
option(HORKOS_MACOS_INJECT_POLLERS
    "Build the macOS process-inspection/injection daemon pollers (signals 113/114/116/117)"
    ON)

set(horkosd_src horkosd.cpp)

if(HORKOS_MACOS_INJECT_POLLERS)
    list(APPEND horkosd_src
        HKGameTaskHandle.cpp
        HKMmapBaseline.cpp
        HKPtraceWatch.cpp
        HKExceptionPortBaseline.cpp
        HKThreadIntegrity.cpp
        HKTextIntegrity.cpp
    )
    message(STATUS
        "daemon/macos: HORKOS_MACOS_INJECT_POLLERS=ON — building injection "
        "pollers (privileged task path is a no-op without entitlement/SIP).")
else()
    message(STATUS
        "daemon/macos: HORKOS_MACOS_INJECT_POLLERS=OFF — injection pollers skipped.")
endif()

# -------------------------------------------------------------------------
# macos-codesign-integrity: code-signing / platform-trust probes (signals
# 118-126). The orchestrator + shared substrate (CsScanOrchestrator) always
# build; each per-signal probe is gated by its HK_MACOS_CS_* option. A probe
# whose option is OFF still compiles (its impure body is present) but is
# registered disabled by the orchestrator — so the daemon links with any subset.
# Defaults follow the plan's catalog-FP tuning.
# -------------------------------------------------------------------------
option(HK_MACOS_CS_FLAGS        "Signal 118 — csflags drift"                 ON)
option(HK_MACOS_CS_CDHASH       "Signal 119 — live-vs-disk cdhash"           ON)
option(HK_MACOS_CS_ENTITLEMENT  "Signal 126 — entitlement-blob diff"         ON)
option(HK_MACOS_CS_DYNAMIC      "Signal 120 — dynamic SecCode validity"      ON)
option(HK_MACOS_CS_AMFI_POSTURE "Signal 124 — AMFI/SIP posture (report-only)" ON)
option(HK_MACOS_CS_GATEKEEPER   "Signal 125 — Gatekeeper (corroborating)"    OFF)
option(HK_MACOS_CS_INVALIDATION "Signal 121 — CS_INVALIDATED correlator (ES)" OFF)
option(HK_MACOS_CS_DYLIB_LV     "Signal 122 — dylib team-id / LV (ES)"       OFF)
option(HK_MACOS_CS_AMFID        "Signal 123 — amfid task-port watch (ES)"    OFF)

# The orchestrator + the always-on poll probes' TUs. The ES-driven probe TUs
# (121/122/123) are also always compiled (their consume bodies are cheap and the
# orchestrator gates registration), so the daemon links whether or not ES is
# built; they only RECEIVE observations when HORKOS_MACOS_ES feeds the tap.
list(APPEND horkosd_src
    csops/CsScanOrchestrator.cpp
    csops/CsFlagsProbe.cpp
    csops/CdHashProbe.cpp
    csops/EntitlementDiffProbe.cpp
    csops/CsInvalidationCorrelator.cpp
    csops/AmfidWatch.cpp
    seccode/DynamicValidityProbe.cpp
    seccode/DylibTeamIdProbe.cpp
    trust/AmfiPostureProbe.cpp
    trust/GatekeeperProbe.cpp
)
message(STATUS
    "daemon/macos: building macos-codesign-integrity probes (118-126); "
    "ES-driven 121/122/123 receive observations only when HORKOS_MACOS_ES is ON.")

# -------------------------------------------------------------------------
# hardware-input-devices: macOS IOHIDDevice transport audit (signal 141) +
# pointer-delta feature extractor (142, macOS half). Userspace IOHIDManager poll — no
# entitlement, NOT the ES auth path (impl-plan §141), so default ON for the bring-up
# path. The IORegistry dext-bundle-id walk (server-correlation pairing) is an
# HK-UNCERTAIN stub pending on-box; the transport audit + the pointer fold are live.
# The two TUs include their façade (input/DeviceTrustMac.h), the wire schema
# (horkos/device_trust_schema.h, already on the sdk/include path below), and the shared
# pointer fold (common/PointerFeatureFold.h under sdk/src/backends) — both include dirs
# added below.
# -------------------------------------------------------------------------
option(HORKOS_MACOS_DEVICE_TRUST
    "Build the macOS IOHID device-trust input sensors (signals 141/142)"
    ON)
if(HORKOS_MACOS_DEVICE_TRUST)
    list(APPEND horkosd_src
        input/IOHIDTransportAuditMac.mm
        input/PointerDeltaStatsMac.mm)
    message(STATUS
        "daemon/macos: HORKOS_MACOS_DEVICE_TRUST=ON — building IOHID transport audit "
        "(141) + pointer-delta features (142).")
endif()

# -------------------------------------------------------------------------
# memory-integrity-selfcheck: macOS self-read backend (signals 145/146/148/152).
# SelfCheckRead.mm reads the AC's OWN task port (mach_vm_read_overwrite /
# mach_vm_region_recurse / thread_get_state DEBUG_STATE). Default ON for the bring-up
# path — the live mach calls are HK-UNCERTAIN no-ops until entitlement-free self-task
# introspection is confirmed on Apple Silicon AND Intel, so building ON is safe (it
# degrades to no-ops, like the injection pollers). NOT an ES auth path (guardrail #7
# N/A). Uses only libSystem (mach_vm_*/thread_get_state) — no extra framework.
# -------------------------------------------------------------------------
option(HORKOS_MACOS_SELFCHECK_READ
    "Build the macOS self-integrity self-read backend (signals 145/146/148/152)"
    ON)
if(HORKOS_MACOS_SELFCHECK_READ)
    list(APPEND horkosd_src SelfCheckRead.mm)
    message(STATUS
        "daemon/macos: HORKOS_MACOS_SELFCHECK_READ=ON — building self-read backend "
        "(self-task mach_vm_* is a no-op until entitlement-free introspection confirmed).")
endif()

add_executable(horkosd ${horkosd_src})

# Map each per-signal option to its compile definition (1/0) so the orchestrator
# registers only the enabled probes.
foreach(_cs_opt
        HK_MACOS_CS_FLAGS HK_MACOS_CS_CDHASH HK_MACOS_CS_ENTITLEMENT
        HK_MACOS_CS_DYNAMIC HK_MACOS_CS_AMFI_POSTURE HK_MACOS_CS_GATEKEEPER
        HK_MACOS_CS_INVALIDATION HK_MACOS_CS_DYLIB_LV HK_MACOS_CS_AMFID)
    if(${_cs_opt})
        target_compile_definitions(horkosd PRIVATE ${_cs_opt}=1)
    else()
        target_compile_definitions(horkosd PRIVATE ${_cs_opt}=0)
    endif()
endforeach()

# The CS probe TUs include their headers under daemon/macos/csops and the shared
# platform.h (AmfiPosture/AmfidWatch route IORegistry/csr/SIP reads through it).
target_include_directories(horkosd PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/csops
    ${CMAKE_SOURCE_DIR}/platform
)

# Injection-poller TUs include horkos/event_schema_macos.h (the macOS-only wire
# plane); horkosd.cpp itself does not, but the include dir is harmless for it.
# The device-trust input TUs include their façade ("input/DeviceTrustMac.h", relative to
# daemon/macos) and the shared pointer fold ("common/PointerFeatureFold.h", relative to
# sdk/src/backends).
target_include_directories(horkosd PRIVATE
    ${CMAKE_SOURCE_DIR}/sdk/include
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/sdk/src/backends
)

target_compile_options(horkosd PRIVATE
    -Wall
    -Wextra
    -Werror
)

# xpc/xpc.h and dispatch/dispatch.h ship inside the macOS SDK.  Linking
# against Foundation brings in libSystem, the XPC runtime, and libdispatch
# through the umbrella framework — no separate -lxpc or -ldispatch needed.
# The injection pollers use task_*/mach_vm_*/sysctl/csops, all in libSystem
# (no extra framework). Reference: Xcode SDK headers, WWDC 2012 session 241.
target_link_libraries(horkosd PRIVATE
    "-framework Foundation"
    # XPC peer validation (SecTaskCreateWithAuditToken + signing-identifier
    # check in horkosd.cpp) lives in the Security framework.
    "-framework Security"
    # macos-codesign-integrity: the AMFI-posture / amfid probes route their
    # IORegistry + csr_* + SIP reads through hk::platform (guardrail #1); link the
    # platform backend (which itself pulls CoreFoundation + IOKit).
    hk_platform
)

# audit_token_to_pid (used by HKGameTaskHandle's audit-token validation) lives in
# libbsm. Foundation does not export it for direct callers, so link it explicitly
# when the injection pollers are built.
if(HORKOS_MACOS_INJECT_POLLERS)
    target_link_libraries(horkosd PRIVATE bsm)
endif()

# hardware-input-devices: the IOHID transport audit (141) + pointer extractor (142) use
# the IOKit HID API (IOHIDManager/IOHIDDevice) and CoreFoundation. hk_platform already
# pulls CoreFoundation + IOKit transitively, but link IOKit explicitly so the IOHID
# symbols resolve when only this option is enabled.
if(HORKOS_MACOS_DEVICE_TRUST)
    target_link_libraries(horkosd PRIVATE
        "-framework IOKit"
        "-framework CoreFoundation"
    )
endif()

# Installation path mirrors what the plist's ProgramArguments entry expects.
# Adjust DESTINATION for packaging; the placeholder matches the plist comment.
install(TARGETS horkosd
    RUNTIME DESTINATION libexec
)
