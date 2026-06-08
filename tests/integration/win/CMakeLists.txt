# tests/integration/win/CMakeLists.txt
# Windows-only integration smoke test for the kernel IOCTL bridge. Built only on
# WIN32; requires the driver loaded to do anything beyond a clean skip.

add_executable(hk_ioctl_smoke ioctl_smoke.cpp)
target_include_directories(hk_ioctl_smoke PRIVATE ${CMAKE_SOURCE_DIR}/sdk/include)
add_test(NAME hk_ioctl_smoke COMMAND hk_ioctl_smoke)
