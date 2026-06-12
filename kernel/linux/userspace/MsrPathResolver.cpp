/*
 * Role: Implementation of the signal-98/99 fd→device + MSR-sensitivity resolver
 *       declared in MsrPathResolver.h.
 * Target platform: Linux userspace.
 * Interface: implements horkos::modint::IsSensitiveMsr / FdTargetIsMsr /
 *            ResolveFdIsMsr.
 *
 * Guardrail compliance: #1, #3, #4. Read-only / audit-only.
 */

#include "MsrPathResolver.h"

#include <array>
#include <cstdio>

/* readlink wrapper, defined at the bottom of this TU, so <unistd.h> does not leak
 * into the pure-logic test TUs that include MsrPathResolver.h. */
extern "C" long hk_readlink_(const char* path, char* buf, unsigned long sz);

namespace horkos::modint {

bool IsSensitiveMsr(uint64_t msr_index) {
    switch (msr_index) {
        case 0xC0000082ull:   /* IA32_LSTAR */
        case 0x00000176ull:   /* IA32_SYSENTER_EIP */
        case 0x0000003Aull:   /* IA32_FEATURE_CONTROL */
        case 0x000001D9ull:   /* IA32_DEBUGCTL */
        case 0xC0000081ull:   /* IA32_STAR */
        case 0xC0000083ull:   /* IA32_CSTAR */
            return true;
        default:
            return false;
    }
}

bool FdTargetIsMsr(const std::string& fd_target) {
    /* /dev/cpu/<N>/msr */
    static const std::string kPrefix = "/dev/cpu/";
    static const std::string kSuffix = "/msr";
    if (fd_target.size() < kPrefix.size() + kSuffix.size()) return false;
    if (fd_target.compare(0, kPrefix.size(), kPrefix) != 0) return false;
    if (fd_target.compare(fd_target.size() - kSuffix.size(), kSuffix.size(),
                          kSuffix) != 0) {
        return false;
    }
    /* The middle must be a non-empty run of digits. */
    size_t mid_begin = kPrefix.size();
    size_t mid_end = fd_target.size() - kSuffix.size();
    if (mid_end <= mid_begin) return false;
    for (size_t i = mid_begin; i < mid_end; ++i) {
        if (fd_target[i] < '0' || fd_target[i] > '9') return false;
    }
    return true;
}

bool ResolveFdIsMsr(uint32_t pid, uint32_t fd, const std::string& proc_root) {
    /* readlink /proc/<pid>/fd/<fd>. We avoid <unistd.h> readlink portability in
     * the testable core; this live path uses it directly. */
    char link[64];
    std::snprintf(link, sizeof(link), "%s/%u/fd/%u", proc_root.c_str(), pid, fd);
    std::array<char, 256> buf{};
    long n = hk_readlink_(link, buf.data(), buf.size() - 1);
    if (n <= 0) return false;
    buf[static_cast<size_t>(n)] = '\0';
    return FdTargetIsMsr(std::string(buf.data(), static_cast<size_t>(n)));
}

}  // namespace horkos::modint

/* readlink wrapper kept out of the header so <unistd.h> does not leak into the
 * pure-logic test TUs that include MsrPathResolver.h. */
#include <unistd.h>
extern "C" long hk_readlink_(const char* path, char* buf, unsigned long sz) {
    return static_cast<long>(::readlink(path, buf, static_cast<size_t>(sz)));
}
