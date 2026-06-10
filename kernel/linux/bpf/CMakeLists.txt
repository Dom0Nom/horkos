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

# ---- DMA / peripheral-hardware-trust IOMMU-fault sensor (signal 135) --------
# iommu_fault.bpf.c attaches the iommu:io_page_fault tracepoint and counts faults
# per source-BDF into the shared hk_ringbuf; the loader gates a stream on the BDF
# also being a structural suspect (catalog gate). Default ON within the eBPF subtree
# (this whole subdirectory is already behind the parent HORKOS_LINUX_EBPF gate,
# default OFF / CI-on, per locked-decision #3). The tracepoint field layout +
# report_iommu_fault kprobe fallback are version-sensitive (impl-plan Risk #3); the
# program reads everything CO-RE-relocatably and leaves the kprobe arm an
# HK-UNCERTAIN stub, so -Werror (guardrail #6) still passes.
option(HORKOS_LINUX_EBPF_IOMMU
    "Build the eBPF IOMMU-fault sensor (catalog signal 135)"
    ON)

set(HK_IOMMU_SKEL_DEPS)
if(HORKOS_LINUX_EBPF_IOMMU)
    bpf_program(iommu_fault)
    list(APPEND HK_IOMMU_SKEL_DEPS hk_bpf_iommu_fault_skel)
endif()

# ---- hardware-input-devices evdev/uinput provenance sensor (signal 140) ------
# input_provenance.bpf.c kprobes input_register_device and CO-RE-reads
# input_dev->id.{bustype,vendor,product} + the EV_REL/EV_KEY capability bits into the
# shared hk_ringbuf; the userspace half (EvdevProvenanceLinux.cpp) supplements with
# EVIOCGID/EVIOCGPHYS and attaches the uinput creator PID. Default ON within the eBPF
# subtree (this whole subdirectory is already behind the parent HORKOS_LINUX_EBPF gate,
# default OFF / CI-on; required-ON for the Steam Deck Game Mode profile per locked-
# decision #3). The parent-chain usb_device walk + the creator-PID context are
# HK-UNCERTAIN (impl-plan Risks §140) and left as documented stubs in the .bpf.c, so
# -Werror (guardrail #6) still passes; confirm the CO-RE chain + kprobe-ability on the
# target Deck-kernel BTF before relying on has_usb_parent / creator_pid.
option(HORKOS_LINUX_EBPF_INPUT_PROV
    "Build the eBPF evdev/uinput device-provenance sensor (catalog signal 140)"
    ON)

set(HK_INPUT_PROV_SKEL_DEPS)
if(HORKOS_LINUX_EBPF_INPUT_PROV)
    bpf_program(input_provenance)
    list(APPEND HK_INPUT_PROV_SKEL_DEPS hk_bpf_input_provenance_skel)
endif()

# ---- timing-side-channels HW-breakpoint census (signal 158) -----------------
# hw_breakpoint_census.bpf.c counts PERF_TYPE_BREAKPOINT events whose owner is outside
# the game's thread group, scoped to the game tgid by the loader. Default OFF (locked
# decision 3) within the eBPF subtree; AUDIT-ONLY on Steam Deck Game Mode. The real
# perf_event_open/breakpoint-install attach point + CO-RE field paths are HK-UNCERTAIN
# (see the .bpf.c) and left as a documented stub, so the verifier-clean program still
# builds -Werror (guardrail #6). No lsm/* hook here, so the lsm= boot-arg prerequisite
# does not apply to this program.
option(HORKOS_LINUX_EBPF_HWBP_CENSUS
    "Build the eBPF HW-breakpoint census sensor (catalog signal 158)"
    OFF)

set(HK_HWBP_CENSUS_SKEL_DEPS)
if(HORKOS_LINUX_EBPF_HWBP_CENSUS)
    bpf_program(hw_breakpoint_census)
    list(APPEND HK_HWBP_CENSUS_SKEL_DEPS hk_bpf_hw_breakpoint_census_skel)
endif()

# ---- Memory-access sensor set (signals 73-81) -------------------------------
# Default ON (core AC on Linux) but only built when the parent eBPF gate
# (HORKOS_LINUX_EBPF) is enabled — this subdirectory is only added in that case.
# The userspace loader compiles the memory translation arms only when
# HK_BPF_MEMORY_ACCESS is defined (set on the loader target by the userspace
# CMakeLists when this option is ON), so the two stay in lockstep.
option(HORKOS_LINUX_EBPF_MEMORY
    "Build the eBPF memory-access sensors (signals 73-81)"
    ON)

if(HORKOS_LINUX_EBPF_MEMORY)
    bpf_program(lsm_ptrace)
    bpf_program(fexit_process_vm)
    bpf_program(fentry_proc_mem)
    bpf_program(lsm_mmap_mprotect)
    bpf_program(memfd_exec)
    bpf_program(lsm_devmem)
    bpf_program(iter_task_vma)
endif()

# ---- process-genealogy launch-trust set (signals 205/206) --------------------
# genealogy.bpf.c (205): ptrace x exec join + a BPF LSM ptrace_access_check hook
# (audit-only). loader_trust.bpf.c (206): bounded envp scan at sys_enter_execve
# for LD_PRELOAD/LD_AUDIT/LD_LIBRARY_PATH. Both share hk_ringbuf and compile
# -Werror; the LSM half (205) attach-gates on CONFIG_BPF_LSM availability in
# Loader.cpp (the tracepoint-join fallback stands alone), and the envp read (206)
# is HK-UNCERTAIN per kernel (verifier-bounded loop) — confirm on the target.
option(HORKOS_LINUX_EBPF_GENEALOGY
    "Build the eBPF process-genealogy launch-trust sensors (signals 205/206)"
    OFF)
if(HORKOS_LINUX_EBPF_GENEALOGY)
    bpf_program(genealogy)
    bpf_program(loader_trust)
endif()

# ---- memory-integrity-selfcheck self-read set (signals 145/146/148/152) ------
# selfcheck_read.bpf.c cooperates with the libbpf loader to foreign-read the AC
# task's OWN memory (145) + soft-dirty/private state (146) + exec-VMA prot (152);
# hwbp_audit.bpf.c observes hardware-breakpoint installs targeting the AC's address
# space (148). Default OFF (locked decision 3); the LKM path is the self-read fallback
# for non-Deck self-hosted servers. The actual cross-context bpf_probe_read_user of the
# AC task + the hw-breakpoint attach point are HK-UNCERTAIN (see the .bpf.c files) and
# left as documented stubs, so the verifier-clean programs still build -Werror
# (guardrail #6). BPF-LSM PREREQUISITE for any lsm/* half: kernel >= 5.7,
# CONFIG_BPF_LSM=y, AND "bpf" in the lsm= boot parameter (document, do not assume).
option(HORKOS_LINUX_EBPF_SELFCHECK
    "Build the eBPF self-integrity self-read sensors (signals 145/146/148/152)"
    OFF)

set(HK_SELFCHECK_SKEL_DEPS)
if(HORKOS_LINUX_EBPF_SELFCHECK)
    bpf_program(selfcheck_read)
    bpf_program(hwbp_audit)
    list(APPEND HK_SELFCHECK_SKEL_DEPS
        hk_bpf_selfcheck_read_skel
        hk_bpf_hwbp_audit_skel)
endif()

# ---- Loader / library-injection sensor set (signals 82-90) ------------------
# linux-ebpf-injection. Each signal ships behind its own feature flag so it can
# ship dark. Defaults: low-FP signals (82/84/85/86/89) ON; high-FP or
# performance-sensitive sampling signals (83 GOT, 88 _r_debug via /proc/pid/mem,
# 90 pagemap/smaps) OFF until field-validated. Signal 87 reuses 82's
# dl_map_object program and is corroborating-only in scoring (server-side).
# The whole subtree is already gated default-OFF behind HORKOS_LINUX_EBPF in the
# parent kernel/linux/CMakeLists.txt; these are sub-options under it.
option(HK_BPF_INJECTION_DSO     "Signals 82/87 (DSO provenance/order)"  ON)
option(HK_BPF_INJECTION_GOT     "Signal 83 (GOT/PLT)"                   OFF)
option(HK_BPF_INJECTION_INTERP  "Signal 84 (PT_INTERP)"                 ON)
option(HK_BPF_INJECTION_PRELOAD "Signals 85/89 (preload/LD_AUDIT)"      ON)
option(HK_BPF_INJECTION_DLOPEN  "Signal 86 (fileless dlopen)"           ON)
option(HK_BPF_INJECTION_RDEBUG  "Signal 88 (_r_debug)"                  OFF)
option(HK_BPF_INJECTION_TEXT    "Signal 90 (text COW)"                  OFF)

set(HK_INJECTION_SKEL_DEPS)

if(HK_BPF_INJECTION_DSO)
    bpf_program(dl_map_object)
    list(APPEND HK_INJECTION_SKEL_DEPS hk_bpf_dl_map_object_skel)
endif()
if(HK_BPF_INJECTION_GOT)
    bpf_program(got_sample)
    list(APPEND HK_INJECTION_SKEL_DEPS hk_bpf_got_sample_skel)
endif()
if(HK_BPF_INJECTION_INTERP)
    bpf_program(interp_entry)
    list(APPEND HK_INJECTION_SKEL_DEPS hk_bpf_interp_entry_skel)
endif()
if(HK_BPF_INJECTION_PRELOAD)
    bpf_program(bprm_env)
    bpf_program(dl_audit)
    list(APPEND HK_INJECTION_SKEL_DEPS hk_bpf_bprm_env_skel hk_bpf_dl_audit_skel)
endif()
if(HK_BPF_INJECTION_DLOPEN)
    bpf_program(dlopen_uprobe)
    list(APPEND HK_INJECTION_SKEL_DEPS hk_bpf_dlopen_uprobe_skel)
endif()
if(HK_BPF_INJECTION_RDEBUG)
    bpf_program(rdebug_sample)
    list(APPEND HK_INJECTION_SKEL_DEPS hk_bpf_rdebug_sample_skel)
endif()
if(HK_BPF_INJECTION_TEXT)
    bpf_program(text_sample)
    list(APPEND HK_INJECTION_SKEL_DEPS hk_bpf_text_sample_skel)
endif()

# ---- Proton/Wine/Steam-Deck sensor set (signals 100-108) --------------------
# linux-proton-wine. Default OFF — ships dark behind the parent HORKOS_LINUX_EBPF
# gate; CI enables it on a BTF-capable Deck-class runner to enforce -Werror
# (guardrail #6). The tracepoint/LSM-only programs (100/101/102/103/104/105/106)
# are the low-API-risk set. The kprobe/file_mprotect-fragile programs (107 W^X arm,
# 108 uinput/evdev kprobes) are gated behind HORKOS_LINUX_EBPF_PROTON_KPROBES
# (default OFF) per the impl-plan Risks: file_mprotect attach-ability + prior-prot
# reachability, and input_inject_event/uinput_create_device kprobe-ability, are
# version-sensitive and MUST be confirmed against the target Deck kernel BTF before
# they are relied on (the verifier/tracepoint set still builds without them).
#
# BPF-LSM PREREQUISITE (document, do not assume): the lsm/* programs here
# (mmap_file 101, ptrace_access_check 102, sb_remount/sb_mount/file_open 105,
# kernel_module_request/kernel_read_file 104, file_mprotect 107) require kernel
# >= 5.7, CONFIG_BPF_LSM=y, AND "bpf" present in the lsm= boot parameter /
# CONFIG_LSM list — otherwise they will NOT attach. See bpf/README / the parent
# kernel/linux/CMakeLists.txt.
option(HORKOS_LINUX_EBPF_PROTON
    "Build the eBPF Proton/Wine/Deck sensors (signals 100-108)"
    OFF)
option(HORKOS_LINUX_EBPF_PROTON_KPROBES
    "Build the kprobe/file_mprotect-fragile Proton/Wine sensors (107/108) — confirm Deck-kernel BTF first"
    OFF)

set(HK_PROTON_SKEL_DEPS)

if(HORKOS_LINUX_EBPF_PROTON)
    bpf_program(proton_env)            # 100 sched_process_exec
    bpf_program(mmap_exec_audit)       # 101 lsm/mmap_file
    bpf_program(cross_mem_audit)       # 102 process_vm_readv/_writev + ptrace + mem_open
    bpf_program(namespace_entry)       # 103 sys_enter_setns + commit_nsset kprobe
    bpf_program(module_load_audit)     # 104 lsm/kernel_module_request + module:module_load
    bpf_program(rootfs_ro_audit)       # 105 lsm/sb_remount + sb_mount + file_open
    bpf_program(compositor_consumer)   # 106 sys_enter_connect + sys_enter_ioctl
    list(APPEND HK_PROTON_SKEL_DEPS
        hk_bpf_proton_env_skel
        hk_bpf_mmap_exec_audit_skel
        hk_bpf_cross_mem_audit_skel
        hk_bpf_namespace_entry_skel
        hk_bpf_module_load_audit_skel
        hk_bpf_rootfs_ro_audit_skel
        hk_bpf_compositor_consumer_skel)

    if(HORKOS_LINUX_EBPF_PROTON_KPROBES)
        bpf_program(mprotect_wx_audit)     # 107 lsm/file_mprotect (UNCERTAIN: confirm hook)
        bpf_program(uinput_inject_audit)   # 108 uinput/evdev kprobes (UNCERTAIN: confirm kprobe-ability)
        list(APPEND HK_PROTON_SKEL_DEPS
            hk_bpf_mprotect_wx_audit_skel
            hk_bpf_uinput_inject_audit_skel)
    endif()
endif()

# ---- Install generated directory as an INTERFACE include path ---------------
# The userspace loader CMakeLists adds this exported target and gets the skel.h
# include path automatically.
add_library(hk_bpf_generated INTERFACE)
target_include_directories(hk_bpf_generated INTERFACE "${BPF_GEN_DIR}")
add_dependencies(hk_bpf_generated
    hk_bpf_lsm_file_open_skel
    hk_bpf_tracepoints_skel)

if(HORKOS_LINUX_EBPF_MEMORY)
    add_dependencies(hk_bpf_generated
        hk_bpf_lsm_ptrace_skel
        hk_bpf_fexit_process_vm_skel
        hk_bpf_fentry_proc_mem_skel
        hk_bpf_lsm_mmap_mprotect_skel
        hk_bpf_memfd_exec_skel
        hk_bpf_lsm_devmem_skel
        hk_bpf_iter_task_vma_skel)
endif()

# IOMMU-fault sensor skeleton (signal 135) when its flag is ON above.
if(HK_IOMMU_SKEL_DEPS)
    add_dependencies(hk_bpf_generated ${HK_IOMMU_SKEL_DEPS})
endif()

# evdev/uinput provenance sensor skeleton (signal 140) when its flag is ON above.
if(HK_INPUT_PROV_SKEL_DEPS)
    add_dependencies(hk_bpf_generated ${HK_INPUT_PROV_SKEL_DEPS})
endif()

# timing-side-channels HW-breakpoint census skeleton (signal 158) when ON above.
if(HK_HWBP_CENSUS_SKEL_DEPS)
    add_dependencies(hk_bpf_generated ${HK_HWBP_CENSUS_SKEL_DEPS})
endif()

# Injection sensor skeletons (only those whose feature flag is ON above).
if(HK_INJECTION_SKEL_DEPS)
    add_dependencies(hk_bpf_generated ${HK_INJECTION_SKEL_DEPS})
endif()

# memory-integrity-selfcheck self-read skeletons (only when the flag is ON above).
if(HK_SELFCHECK_SKEL_DEPS)
    add_dependencies(hk_bpf_generated ${HK_SELFCHECK_SKEL_DEPS})
endif()

# Proton/Wine/Deck sensor skeletons (only when HORKOS_LINUX_EBPF_PROTON is ON, and
# 107/108 only when the kprobe sub-option is also ON).
if(HK_PROTON_SKEL_DEPS)
    add_dependencies(hk_bpf_generated ${HK_PROTON_SKEL_DEPS})
endif()
