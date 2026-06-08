# examples/CMakeLists.txt
# SDK integration examples (Phase 3). Built on every PC host; on Linux/macOS
# pc_basic runs in degraded mode (no kernel driver until Phase 4).

add_executable(pc_basic pc_basic/main.cpp)
target_link_libraries(pc_basic PRIVATE hk_sdk)
