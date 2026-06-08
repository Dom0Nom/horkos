# sdk/CMakeLists.txt
# hk_sdk — public SDK static library (Phase 3). Platform-neutral core plus a
# per-platform driver-probe backend selected here (mirrors the platform/ split;
# guardrail #1 keeps platform API inside backends/).

if(WIN32)
    set(hk_sdk_backend src/backends/win/DriverProbeWin.cpp)
else()
    set(hk_sdk_backend src/backends/posix/DriverProbePosix.cpp)
endif()

add_library(hk_sdk STATIC
    src/sdk.cpp
    ${hk_sdk_backend})

target_include_directories(hk_sdk
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_link_libraries(hk_sdk PUBLIC hk_drm hk_ac hk_platform)
