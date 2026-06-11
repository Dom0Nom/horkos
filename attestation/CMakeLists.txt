# attestation/CMakeLists.txt
# Builds hk_attestation static library from the platform-matching backend.
# Console backends are excluded from the default build (no proprietary SDK).

if(WIN32)
    # Windows + Linux share the tpm2-tss ESAPI quote routine; the platform file
    # is a thin factory over it.
    set(attestation_backend
        backends/win/AttestationTpm2Win.cpp
        backends/common/Tpm2EsapiQuote.cpp)
elseif(APPLE)
    set(attestation_backend backends/macos/AttestationSecureEnclave.cpp)
elseif(UNIX)
    set(attestation_backend
        backends/linux/AttestationTpm2Linux.cpp
        backends/common/Tpm2EsapiQuote.cpp)
else()
    message(FATAL_ERROR "attestation: unsupported platform (no backend)")
endif()

add_library(hk_attestation STATIC ${attestation_backend})
target_include_directories(hk_attestation PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(hk_attestation PUBLIC hk_platform)

if(APPLE)
    # Secure Enclave backend: Security (SecKey*) + CoreFoundation.
    target_link_libraries(hk_attestation PUBLIC
        "-framework Security" "-framework CoreFoundation")
elseif(UNIX)
    # Linux tpm2-tss backend: ESAPI. Found via pkg-config (tss2-esys) with a
    # plain find_library fallback. Skipped (STATUS, not fatal) if absent so the
    # host build still configures.
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(TSS2_ESYS QUIET tss2-esys)
    endif()
    if(NOT TSS2_ESYS_FOUND)
        find_library(TSS2_ESYS_LIBRARIES NAMES tss2-esys
            PATHS /usr/lib /usr/lib/x86_64-linux-gnu /usr/local/lib)
    endif()
    if(TSS2_ESYS_LINK_LIBRARIES OR TSS2_ESYS_LIBRARIES)
        target_include_directories(hk_attestation PRIVATE ${TSS2_ESYS_INCLUDE_DIRS})
        target_link_libraries(hk_attestation PUBLIC
            ${TSS2_ESYS_LINK_LIBRARIES} ${TSS2_ESYS_LIBRARIES})
    else()
        message(STATUS "attestation: libtss2-esys not found; the Linux TPM "
                       "backend will not link until it is installed "
                       "(apt install libtss2-dev).")
    endif()
endif()
