# attestation/CMakeLists.txt
# Builds hk_attestation static library from the platform-matching backend.
# Console backends are excluded from the default build (no proprietary SDK).

if(WIN32)
    set(attestation_backend backends/win/AttestationTpm2Win.cpp)
elseif(APPLE)
    set(attestation_backend backends/macos/AttestationSecureEnclave.cpp)
elseif(UNIX)
    set(attestation_backend backends/linux/AttestationTpm2Linux.cpp)
endif()

add_library(hk_attestation STATIC ${attestation_backend})
target_include_directories(hk_attestation PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(hk_attestation PUBLIC hk_platform)
