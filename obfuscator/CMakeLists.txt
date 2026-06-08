# obfuscator/CMakeLists.txt
# Standalone LLVM-19 obfuscation pass plugin (Phase 5). NEVER shipped to end
# users — a build-time tool only (Locked Decision #5). Built out-of-tree against
# a pinned llvm@19; not added to the root horkos CMake.
#
# Configure with:
#   cmake -S obfuscator -B obfuscator/build \
#         -DLLVM_DIR=$(brew --prefix llvm@19)/lib/cmake/llvm
# Build:
#   cmake --build obfuscator/build
# The plugin loads into opt:
#   opt -load-pass-plugin=obfuscator/build/libHkObfuscator.* \
#       -passes=hk-opaque,hk-cff,hk-strenc in.ll -S

cmake_minimum_required(VERSION 3.20)
# C is enabled because LLVM's bundled CMake modules (FindLibEdit, AddLLVM linker
# checks) require it even though our sources are C++.
project(hk_obfuscator LANGUAGES C CXX)

# LLVM's package version file rejects a bare "19" request against 19.1.7, so
# match without a version and assert the major ourselves (Locked Decision #5
# pins LLVM 19).
find_package(LLVM REQUIRED CONFIG)
if(NOT LLVM_VERSION_MAJOR EQUAL 19)
    message(FATAL_ERROR "hk_obfuscator requires LLVM 19; found ${LLVM_PACKAGE_VERSION}. "
                        "Configure with -DLLVM_DIR=$(brew --prefix llvm@19)/lib/cmake/llvm")
endif()
message(STATUS "hk_obfuscator: LLVM ${LLVM_PACKAGE_VERSION} at ${LLVM_DIR}")

list(APPEND CMAKE_MODULE_PATH ${LLVM_CMAKE_DIR})
include(AddLLVM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(HkObfuscator MODULE
    src/Plugin.cpp
    src/passes/ControlFlowFlattening.cpp
    src/passes/OpaquePredicates.cpp
    src/passes/StringEncryption.cpp)

target_include_directories(HkObfuscator PRIVATE
    ${LLVM_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_definitions(HkObfuscator PRIVATE ${LLVM_DEFINITIONS})

# LLVM is typically built without RTTI; match it or linking/typeinfo breaks.
if(NOT LLVM_ENABLE_RTTI)
    target_compile_options(HkObfuscator PRIVATE -fno-rtti)
endif()

# Out-of-tree pass plugin: symbols are resolved by opt at load time.
if(APPLE)
    target_link_options(HkObfuscator PRIVATE -Wl,-undefined,dynamic_lookup)
endif()
