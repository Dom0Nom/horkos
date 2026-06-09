# bypass-tests/cross/CMakeLists.txt
# Cross-platform bypass-test merge gate (guardrail #12) for the hardware-input-devices
# pointer-feature sensor (signal 142). Platform-clean: the fixture exercises the shared
# platform-free pointer-feature fold (sdk/src/backends/common/PointerFeatureFold.h) and
# runs a REAL privacy-invariant assertion on every host (no raw delta in the emitted
# struct), so this is added UNCONDITIONALLY (like bypass-tests/dma_hardware), not under
# a platform gate. The model-scoring half stays behind HK_DEVICE_TRUST_BYPASS_ENABLED
# until the 142 ONNX path lands.

add_executable(hk_bypass_pointer_lattice pointer_lattice_synthetic.cpp)
target_include_directories(hk_bypass_pointer_lattice PRIVATE
    ${CMAKE_SOURCE_DIR}/sdk/include
    ${CMAKE_SOURCE_DIR}/sdk/src/backends)
add_test(NAME hk_bypass_pointer_lattice COMMAND hk_bypass_pointer_lattice)
