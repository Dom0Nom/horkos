/*
 * kernel/linux/userspace/LockdownPosture.cpp
 * Role: Implementation of signal 96 (kernel posture) declared in
 *       LockdownPosture.h.
 * Target platform: Linux userspace.
 * Interface: implements the Parse* helpers + ComputePosture + hk_sensor_posture.
 *
 * Guardrail compliance: #1, #3, #4. Read-only / audit-only.
 */

#include "LockdownPosture.h"

#include <cstdlib>
#include <fstream>
#include <sstream>

namespace horkos::modint {

namespace {

std::string TrimWs(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return {};
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

std::string ReadFileBest(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

}  // namespace

uint32_t ParseLockdownLevel(const std::string& content) {
    std::string t = TrimWs(content);
    if (t.empty()) return HK_POSTURE_UNKNOWN;
    /* The active level is the one in [brackets]. */
    size_t lb = t.find('[');
    size_t rb = t.find(']');
    if (lb == std::string::npos || rb == std::string::npos || rb <= lb) {
        return HK_POSTURE_UNKNOWN;
    }
    std::string active = t.substr(lb + 1, rb - lb - 1);
    if (active == "none") return 0;
    if (active == "integrity") return 1;
    if (active == "confidentiality") return 2;
    return HK_POSTURE_UNKNOWN;
}

uint32_t ParseSigEnforce(const std::string& content) {
    std::string t = TrimWs(content);
    if (t.empty()) return HK_POSTURE_UNKNOWN;
    if (t == "Y" || t == "y" || t == "1") return 1;
    if (t == "N" || t == "n" || t == "0") return 0;
    return HK_POSTURE_UNKNOWN;
}

uint32_t ParseTainted(const std::string& content) {
    std::string t = TrimWs(content);
    if (t.empty()) return 0;
    char* end = nullptr;
    errno = 0;
    unsigned long v = std::strtoul(t.c_str(), &end, 10);
    if (end == t.c_str() || errno != 0) return 0;
    return static_cast<uint32_t>(v);
}

uint32_t ParseSecureBoot(const std::string& raw_bytes) {
    /* efivarfs SecureBoot-<guid>: 4 attribute bytes + 1 value byte. */
    if (raw_bytes.size() < 5) return HK_POSTURE_UNKNOWN;
    unsigned char val = static_cast<unsigned char>(raw_bytes[4]);
    return (val == 1) ? 1u : 0u;
}

void ComputePosture(uint32_t lockdown, uint32_t sig_enforce, uint32_t secure_boot,
                    uint32_t taint, HkEventSink sink) {
    HkEvtKernelPosture ev{};
    ev.lockdown_level = lockdown;
    ev.sig_enforce = sig_enforce;
    ev.secure_boot = secure_boot;
    ev.taint_flags = taint;
    HkEmit(sink, kEvtKernelPosture, &ev, sizeof(ev));
}

int hk_sensor_posture(const HkSymbolMap* map, HkEventSink sink) {
    (void)map;   /* posture does not need the symbol map */

    uint32_t lockdown = ParseLockdownLevel(
        ReadFileBest("/sys/kernel/security/lockdown"));
    uint32_t sig_enforce = ParseSigEnforce(
        ReadFileBest("/sys/module/module/parameters/sig_enforce"));
    uint32_t taint = ParseTainted(ReadFileBest("/proc/sys/kernel/tainted"));

    /* SecureBoot efivar GUID 8be4df61-93ca-11d2-aa0d-00e098032b8c (§3). */
    uint32_t secure_boot = ParseSecureBoot(ReadFileBest(
        "/sys/firmware/efi/efivars/"
        "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"));

    ComputePosture(lockdown, sig_enforce, secure_boot, taint, sink);
    return 0;
}

}  // namespace horkos::modint
