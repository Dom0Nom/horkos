# kernel/linux/bpf/CMakeLists.txt
# Role: Build driver for the eBPF object files (.bpf.c → .bpf.o) and the
#       corresponding libbpf skeleton headers (.skel.h) via bpftool gen skeleton.
#       Both steps are skipped (with a STATUS message, not a fatal error) when
#       clang or bpftool are absent so the rest of the CMake tree still configures
#       on a host that has neither (e.g., macOS dev box, Windows CI).
# Target platforms: Linux eBPF build host only.
# Interface: declares IMPORTED targets hk_bpf_lsm_file_open_skel and
#            hk_bpf_tracepoints_skel (custom targets that generate the skel.h
#            files); the userspace loader at kernel/linux/userspace adds those
#            targets as dependencies and appends the generated include dir.
# API ref: https://libbpf.readthedocs.io/en/latest/bpftool-gen.html
#          https://docs.ebpf.io/linux/concepts/CO-RE/

cmake_minimum_required(VERSION 3.20)

# ---- Require Linux ----------------------------------------------------------
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(STATUS
        "kernel/linux/bpf: not Linux, skipping eBPF build targets.")
    return()
endif()

# ---- Locate tools -----------------------------------------------------------
find_program(CLANG_BPF  clang   DOC "clang with BPF back-end")
find_program(BPFTOOL    bpftool DOC "bpftool for skeleton generation")

if(NOT CLANG_BPF OR NOT BPFTOOL)
    message(STATUS
        "kernel/linux/bpf: clang='${CLANG_BPF}' bpftool='${BPFTOOL}'. "
        "One or both absent — eBPF targets skipped. "
        "Install clang (>=14) and bpftool (>=6.0), then re-run cmake.")
    return()
endif()

message(STATUS "kernel/linux/bpf: clang=${CLANG_BPF}  bpftool=${BPFTOOL}")

# ---- Paths ------------------------------------------------------------------
set(BPF_SRC_DIR  "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(BPF_GEN_DIR  "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${BPF_GEN_DIR}")

# ---- Kernel and libbpf headers ----------------------------------------------
# vmlinux.h is expected at kernel/linux/bpf/include/vmlinux.h.
# Generate it on the build host with:
#   bpftool btf dump file /sys/kernel/btf/vmlinux format c > \
#       kernel/linux/bpf/include/vmlinux.h
# It is NOT committed (large, kernel-version-specific). CI generates it before
# invoking cmake.  The include guard is provided by vmlinux.h itself.
set(BPF_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")

# System bpf/bpf_helpers.h / bpf/bpf_tracing.h come from libbpf-dev headers.
# Typical location: /usr/include  (Debian/Ubuntu: apt install libbpf-dev).
# We add /usr/include explicitly so the path is visible in compile_commands.json.
set(BPF_SYS_INCLUDE "/usr/include")

# ---- Helper: compile one .bpf.c → .bpf.o -----------------------------------
# clang flags:
#   -target bpf          — produce BPF ELF (not the host arch)
#   -O2                  — required by the verifier; unoptimised code may exceed
#                          complexity limits
#   -g                   — emit BTF (DWARF-like) needed by CO-RE and bpftool
#   -Wall -Wextra -Werror — guardrail #6
#   -D__TARGET_ARCH_x86  — arch-specific BPF tracing helpers; adjust per target
#   -mcpu=v3             — target BPF ISA v3 (widely supported since kernel 5.2)
#   -nostdinc            — eBPF C may not use libc headers; vmlinux.h replaces them
#   -isystem             — provide compiler builtins via clang's own resource dir

# Retrieve the clang resource directory (contains stddef.h, etc. for -nostdinc)
# BEFORE building the flags list, so ${CLANG_BPF_RESOURCE_DIR} expands to a real
# path inside -isystem rather than an empty string.
execute_process(
    COMMAND "${CLANG_BPF}" --print-resource-dir
    OUTPUT_VARIABLE CLANG_BPF_RESOURCE_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE)

# bpf_tracing.h's PT_REGS_* macros pick the register layout from __TARGET_ARCH_*,
# so this must match the host arch or tracepoint/uprobe programs read the wrong
# pt_regs fields at runtime (silent wrong data, not a compile error).
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    set(HK_BPF_ARCH_DEF -D__TARGET_ARCH_arm64)
else()
    set(HK_BPF_ARCH_DEF -D__TARGET_ARCH_x86)
endif()

set(BPF_COMPILE_FLAGS
    -target bpf
    -O2
    -g
    -Wall
    -Wextra
    -Werror
    -mcpu=v3
    ${HK_BPF_ARCH_DEF}
    -nostdinc
    -isystem "${CLANG_BPF_RESOURCE_DIR}/include"   # __builtin_* etc.
    -I "${BPF_INCLUDE_DIR}"
    -I "${BPF_SYS_INCLUDE}"
)

# ---- Macro: bpf_program(name) -----------------------------------------------
# Registers compile + skeleton-gen custom commands for src/<name>.bpf.c.
# Creates custom target hk_bpf_<name>_skel that other targets can depend on.
macro(bpf_program name)
    set(_src "${BPF_SRC_DIR}/${name}.bpf.c")
    set(_obj "${BPF_GEN_DIR}/${name}.bpf.o")
    set(_skel "${BPF_GEN_DIR}/${name}.skel.h")

    # Step 1: compile .bpf.c → .bpf.o
    add_custom_command(
        OUTPUT  "${_obj}"
        COMMAND "${CLANG_BPF}" ${BPF_COMPILE_FLAGS} -c "${_src}" -o "${_obj}"
        DEPENDS "${_src}"
        COMMENT "BPF compile: ${name}.bpf.c"
        VERBATIM
    )

    # Step 2: generate skeleton header .bpf.o → .skel.h
    # bpftool gen skeleton docs:
    #   https://libbpf.readthedocs.io/en/latest/bpftool-gen.html
    # bpftool writes the skeleton to stdout only; the '>' redirect must run
    # through a shell. A bare COMMAND with VERBATIM would pass '>' and the path
    # as literal argv tokens to bpftool, which then errors and writes no header.
    add_custom_command(
        OUTPUT  "${_skel}"
        COMMAND ${CMAKE_COMMAND} -E env sh -c "'${BPFTOOL}' gen skeleton '${_obj}' > '${_skel}'"
        DEPENDS "${_obj}"
        COMMENT "BPF skeleton: ${name}.skel.h"
        VERBATIM
    )

    # Named target so other CMakeLists can add_dependencies on it.
    add_custom_target("hk_bpf_${name}_skel" DEPENDS "${_skel}")
endmacro()

# ---- Register eBPF programs -------------------------------------------------
bpf_program(lsm_file_open)
bpf_program(tracepoints)

# ---- Install generated directory as an INTERFACE include path ---------------
# The userspace loader CMakeLists adds this exported target and gets the skel.h
# include path automatically.
add_library(hk_bpf_generated INTERFACE)
target_include_directories(hk_bpf_generated INTERFACE "${BPF_GEN_DIR}")
add_dependencies(hk_bpf_generated
    hk_bpf_lsm_file_open_skel
    hk_bpf_tracepoints_skel)
