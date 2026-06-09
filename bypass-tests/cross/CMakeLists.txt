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

# anti-analysis-environment merge gate (guardrail #12, signal 194 — dynamic-
# instrumentation/DBI residency). Added UNCONDITIONALLY like the pointer-lattice
# gate above. The fixture drives the REAL signal-194 sampler
# (anti_analysis_sample_instrumentation) and the pure confidence-tier core, both
# of which live in hk_ac, so it links hk_ac (which PUBLIC-links hk_platform and
# thereby puts platform/ + ac/include on the path). The repo never commits a real
# instrumentation runtime — the fixture synthesizes an anon-RX worker thread on
# platforms that permit an executable anonymous mapping and otherwise falls back
# to the platform-free combination assertions.
add_executable(hk_bypass_frida_gadget_residency frida_gadget_residency.cpp)
target_include_directories(hk_bypass_frida_gadget_residency PRIVATE
    ${CMAKE_SOURCE_DIR}/sdk/include
    ${CMAKE_SOURCE_DIR}/ac/include)
target_link_libraries(hk_bypass_frida_gadget_residency PRIVATE hk_ac)
add_test(NAME hk_bypass_frida_gadget_residency
         COMMAND hk_bypass_frida_gadget_residency)
