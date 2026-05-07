# tests/CMakeLists.txt
# Fetches GoogleTest and composes the test suite.

include(FetchContent)

set(GTEST_VERSION v1.17.0)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/${GTEST_VERSION}.zip
    DOWNLOAD_EXTRACT_TIMESTAMP ON
)

# Do not install GTest into the system prefix.
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(googletest)

add_subdirectory(unit)
