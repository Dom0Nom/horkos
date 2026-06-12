/*
 * Role: Implementation of the signed overlay/allocator allowlist declared in
 *       OverlayAllowlist.h. Canonical body format is a simple line-oriented text
 *       so it is trivially testable and the signature covers exact bytes:
 *           # comment
 *           <soname>\t<buildid-hex-or-*>\t<scope>
 *       Verify-before-use: a failed signature leaves the list empty so no FP
 *       suppression can be driven by an unverified/tampered list.
 * Target platform: Linux userspace.
 * Interface: implements horkos::allowlist::OverlayAllowlist.
 *
 * Guardrail compliance: #1, #3, #4 (no BPF headers).
 */

#include "OverlayAllowlist.h"

#include <sstream>

namespace horkos::allowlist {

namespace {

std::vector<uint8_t> HexToBytes(const std::string& hex) {
    std::vector<uint8_t> out;
    if (hex == "*" || hex.empty()) return out;  // any-build sentinel
    if (hex.size() % 2 != 0) return out;
    auto nyb = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = nyb(hex[i]);
        int lo = nyb(hex[i + 1]);
        if (hi < 0 || lo < 0) return {};  // malformed -> empty
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

std::string Trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return {};
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

}  // namespace

std::vector<AllowEntry> OverlayAllowlist::ParseBody(const std::vector<uint8_t>& body) {
    std::vector<AllowEntry> out;
    std::string text(body.begin(), body.end());
    std::istringstream lines(text);
    std::string line;
    while (std::getline(lines, line)) {
        std::string t = Trim(line);
        if (t.empty() || t[0] == '#') continue;
        // Tab- or whitespace-separated: soname, buildid-hex|*, scope
        std::istringstream fields(t);
        std::string soname, buildid_hex, scope;
        fields >> soname >> buildid_hex >> scope;
        if (soname.empty()) continue;
        AllowEntry e;
        e.soname = soname;
        e.build_id = HexToBytes(buildid_hex);
        e.scope = scope.empty() ? "*" : scope;
        out.push_back(std::move(e));
    }
    return out;
}

bool OverlayAllowlist::LoadSigned(const std::vector<uint8_t>& body,
                                  const std::vector<uint8_t>& signature,
                                  const SignatureVerifier& verify) {
    entries_.clear();
    verified_ = false;
    if (!verify || !verify(body, signature)) {
        return false;  // fail toward "nothing is allowlisted"
    }
    entries_ = ParseBody(body);
    verified_ = true;
    return true;
}

bool OverlayAllowlist::IsAllowed(const std::string& soname,
                                 const std::vector<uint8_t>& build_id,
                                 const std::string& scope) const {
    if (!verified_) return false;
    for (const auto& e : entries_) {
        if (e.soname != soname) continue;
        if (e.scope != "*" && e.scope != scope) continue;
        if (e.build_id.empty()) return true;          // any build of this soname
        if (e.build_id == build_id) return true;      // exact build match
    }
    return false;
}

}  // namespace horkos::allowlist
