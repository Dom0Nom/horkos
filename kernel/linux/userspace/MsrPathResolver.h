/*
 * kernel/linux/userspace/MsrPathResolver.h
 * Role: Userspace half of signals 98/99 fd→device + MSR-index sensitivity
 *       resolution (§1.2 / §7-A). The BPF side emits raw (pid, fd, file_offset);
 *       this resolver decides whether the written fd is /dev/cpu/N/msr and
 *       whether the offset (= MSR index) is in the sensitive set. Pure logic:
 *       the MSR-index classifier is fully host-testable; the live fd→path read
 *       (/proc/<pid>/fd/<fd>) is a thin wrapper around it.
 * Target platform: Linux userspace (guardrail #4).
 * Interface: IsSensitiveMsr / ResolveFdIsMsr; consumed by Loader.cpp's translate
 *            arm for the HK_BPF_MSR_WRITE tag. Audit-only / read-only.
 */

#pragma once

#include <cstdint>
#include <string>

namespace horkos::modint {

/* Sensitive MSR indices the catalog gates ON (§6/§99):
 *   LSTAR             0xC0000082  (syscall entry)
 *   SYSENTER_EIP      0x00000176  (legacy syscall entry)
 *   IA32_FEATURE_CTL  0x0000003A
 *   DEBUGCTL          0x000001D9
 *   the DR-shadow / LBR MSRs are added here as the set is field-validated.
 * Power/perf MSRs (0x150, 0x199, 0x1A0) are benign and NOT in this set. */
bool IsSensitiveMsr(uint64_t msr_index);

/* Resolve whether `fd_target` (the readlink of /proc/<pid>/fd/<fd>) is an MSR
 * device node of the form /dev/cpu/<N>/msr. Pure string check (testable). */
bool FdTargetIsMsr(const std::string& fd_target);

/* Live: read /proc/<pid>/fd/<fd> symlink and test it. Returns true if the fd
 * resolves to an msr node. On any read failure returns false (a missed
 * resolution suppresses the report — coverage, never a false MSR detection). */
bool ResolveFdIsMsr(uint32_t pid, uint32_t fd, const std::string& proc_root = "/proc");

}  // namespace horkos::modint
