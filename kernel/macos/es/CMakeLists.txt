# kernel/macos/es/CMakeLists.txt
# Role: Build configuration for the macOS EndpointSecurity (ES) client.
#       Produces a static library (horkos_es) that the daemon links against.
#       Compilation and entitlement embedding are independently gated so that
#       a dev machine without the ES entitlement can still build and run the
#       daemon in a degraded/no-ES mode.
# Target platform: macOS (Apple Silicon and x86_64 via Universal binary).
# Interface: declares HKEsClientStart() / HKEsClientStop() (EsClient.mm).
#
# Two options control the build:
#
#   HORKOS_MACOS_ES            (default OFF)
#     Build the ES client. Requires the macOS 12+ SDK and the
#     EndpointSecurity framework. The resulting binary still needs the
#     com.apple.developer.endpoint-security.client entitlement at runtime,
#     but the entitlement is NOT embedded by default — see the second flag.
#
#   HORKOS_MACOS_ES_PROVISIONED  (default OFF, requires HORKOS_MACOS_ES)
#     Embed the endpoint-security entitlement into the System Extension
#     Info.plist and codesign step. Only set this when building a production
#     System Extension with Apple-approved provisioning profiles. Setting it
#     without the correct profile will cause notarisation to fail.
#
# See docs/macos-es.md for the full bring-up procedure.

cmake_minimum_required(VERSION 3.22)

option(HORKOS_MACOS_ES
    "Build the EndpointSecurity client (requires macOS 12+ SDK)"
    OFF)

option(HORKOS_MACOS_ES_PROVISIONED
    "Embed the endpoint-security entitlement in the System Extension (requires Apple approval)"
    OFF)

if(NOT HORKOS_MACOS_ES)
    message(STATUS
        "kernel/macos/es: HORKOS_MACOS_ES=OFF — ES client skipped. "
        "Enable with -DHORKOS_MACOS_ES=ON (requires macOS 12+ SDK). "
        "See docs/macos-es.md.")
    return()
endif()

# ---- Platform guard -------------------------------------------------------
# This directory must only be included on macOS. The root CMakeLists is
# responsible for the add_subdirectory guard; this is a belt-and-suspenders
# check.
if(NOT APPLE)
    message(FATAL_ERROR
        "kernel/macos/es: HORKOS_MACOS_ES is ON but the host is not macOS. "
        "This target is macOS-only.")
endif()

# ---- EndpointSecurity framework -------------------------------------------
find_library(ES_FRAMEWORK EndpointSecurity
    PATHS /System/Library/Frameworks
    REQUIRED)
if(NOT ES_FRAMEWORK)
    message(FATAL_ERROR
        "kernel/macos/es: EndpointSecurity.framework not found. "
        "Install the macOS 12+ SDK via Xcode Command Line Tools.")
endif()

# ---- Static library target ------------------------------------------------
add_library(horkos_es STATIC
    EsClient.mm)

target_include_directories(horkos_es PRIVATE
    ${CMAKE_SOURCE_DIR}/sdk/include)   # horkos/event_schema.h

target_link_libraries(horkos_es PUBLIC
    ${ES_FRAMEWORK}
    "-framework Foundation")

# ARC is off by default for Objective-C++ in CMake; enable it explicitly.
# EsClient.mm uses autorelease pools implicitly via NSError, so ARC is
# required for correct memory management.
target_compile_options(horkos_es PRIVATE
    -fobjc-arc
    -Wall -Wextra -Werror
    -fmodules)

# Minimum deployment target: 12.0. MACOSX_DEPLOYMENT_TARGET is NOT a real target
# property (CMake honors only the CMAKE_OSX_DEPLOYMENT_TARGET variable / the
# Xcode attribute), so set the floor via the actual compiler+linker flag.
target_compile_options(horkos_es PRIVATE -mmacosx-version-min=12.0)
target_link_options(horkos_es PRIVATE -mmacosx-version-min=12.0)

# ---- Entitlement embedding (provisioned builds only) ----------------------
# When HORKOS_MACOS_ES_PROVISIONED is ON, a post-build step re-codesigns the
# System Extension bundle with the endpoint-security entitlement plist.
# In an un-provisioned dev build the step is omitted; the daemon falls back to
# a stub/disabled path or the user SIP-disables and runs as root.
#
# The entitlement file is expected at:
#   kernel/macos/es/entitlements/endpoint-security.entitlements
# and must be signed with an Apple-approved provisioning profile before
# distribution.
#
# Reference: https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution
# and `man codesign` for the --entitlements flag.
if(HORKOS_MACOS_ES_PROVISIONED)
    set(HK_ES_ENTITLEMENTS
        "${CMAKE_CURRENT_SOURCE_DIR}/entitlements/endpoint-security.entitlements")

    if(NOT EXISTS "${HK_ES_ENTITLEMENTS}")
        message(FATAL_ERROR
            "kernel/macos/es: HORKOS_MACOS_ES_PROVISIONED=ON but entitlements "
            "file not found at ${HK_ES_ENTITLEMENTS}. "
            "Create it with the endpoint-security key from your provisioning profile.")
    endif()

    # The System Extension bundle is built and signed at the daemon layer.
    # Propagate the entitlements path as a cache variable so daemon/macos/
    # CMakeLists can pick it up in the codesign step.
    set(HORKOS_ES_ENTITLEMENTS_PATH "${HK_ES_ENTITLEMENTS}"
        CACHE FILEPATH
        "Entitlements plist for the ES System Extension (provisioned builds)")

    message(STATUS
        "kernel/macos/es: PROVISIONED build — entitlement at "
        "${HK_ES_ENTITLEMENTS}")
else()
    message(STATUS
        "kernel/macos/es: HORKOS_MACOS_ES_PROVISIONED=OFF — entitlement NOT "
        "embedded. The binary requires SIP disabled + root to load ES at runtime, "
        "or HORKOS_MACOS_ES_PROVISIONED=ON with a valid provisioning profile. "
        "See docs/macos-es.md.")
endif()
