# kernel/linux/CMakeLists.txt
# Aggregates the Linux kernel-side targets. Included from the root CMakeLists on
# UNIX (non-APPLE) hosts.
#
# The eBPF programs + userspace loader need a BPF toolchain (clang with a bpf
# target, libbpf, bpftool) that is not present on every build host, so they are
# gated behind HORKOS_LINUX_EBPF (default OFF). CI enables it on a runner that
# has the toolchain to enforce the -Wall -Wextra -Werror guardrail. bpf MUST be
# added before userspace: bpf defines the hk_bpf_generated target that the
# loader's include path depends on.
#
# The LKM self-gates on HORKOS_LINUX_LKM inside lkm/CMakeLists.txt.

option(HORKOS_LINUX_EBPF
    "Build the eBPF programs + userspace loader (requires clang-bpf, libbpf, bpftool)"
    OFF)

if(HORKOS_LINUX_EBPF)
    add_subdirectory(bpf)
    add_subdirectory(userspace)
endif()

add_subdirectory(lkm)
