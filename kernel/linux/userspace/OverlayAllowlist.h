/*
 * kernel/linux/userspace/OverlayAllowlist.h
 * Role: Load and query the server-signed soname+build-id allowlist (the
 *       legitimate overlay / layer / allocator ecosystem: MangoHud, jemalloc,
 *       tcmalloc, ASan, libfaketime, Steam runtime libs, ...), scoped per
 *       distro / Steam-runtime. The allowlist is the FP-control backbone:
 *       nearly every signal (82-90) gates on "outside the signed allowlist"
 *       before scoring, so this is built once and shared. The signature MUST be
 *       verified before the allowlist is queried (a tampered list is rejected
 *       and the query path then suppresses NOTHING — fail toward not-suppressing
 *       is wrong; see Verify()).
 * Target platform: Linux userspace.
 * Interface: queried by every correlator via IsAllowed(soname, build_id, scope).
 */

#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace horkos::allowlist {

/* One allowlist entry: a soname (e.g. "libMangoHud.so") plus an OPTIONAL exact
 * build-id (empty = any build of that soname under the scope is allowed). */
struct AllowEntry {
    std::string soname;
    std::vector<uint8_t> build_id;   /* empty = soname-only match */
    std::string scope;               /* distro / Steam-runtime tag; "*" = any */
};

/* Signature verifier seam. Returns true iff `signature` is a valid signature over
 * `body` under the trusted server key. The production verifier is Ed25519/ECDSA
 * (reuse the attestation backend's verify, else libsodium); tests inject a stub.
 *
 * HK-UNCERTAIN(allowlist-crypto): the exact signing scheme + key distribution is
 * a server-side operational decision not finalized here. The interface is fixed
 * (verify-before-use); the concrete Ed25519/ECDSA backend is wired in M5/ops. Do
 * NOT ship a no-op verifier in production — an unverified allowlist that an
 * attacker can edit disables every FP gate AND can be abused to suppress real
 * detections. */
using SignatureVerifier =
    std::function<bool(const std::vector<uint8_t>& body,
                       const std::vector<uint8_t>& signature)>;

class OverlayAllowlist {
public:
    OverlayAllowlist() = default;

    /* Parse + signature-verify a signed allowlist document. `body` is the
     * canonical serialized entries; `signature` is the detached signature.
     * Returns true on success (entries loaded). On ANY failure — bad signature,
     * malformed body — the allowlist is left EMPTY and verified()==false, so
     * IsAllowed() returns false for everything (fail toward "treat as not
     * allowlisted", i.e. let the server score it; the server holds ban authority
     * and is fail-closed separately). */
    bool LoadSigned(const std::vector<uint8_t>& body,
                    const std::vector<uint8_t>& signature,
                    const SignatureVerifier& verify);

    /* True once a correctly-signed allowlist has been loaded. */
    bool verified() const { return verified_; }

    /* Query: is (soname, build_id) allowlisted under `scope`? A scope of "*" in
     * an entry matches any query scope. An entry with an empty build_id matches
     * any build of that soname. Returns false when the allowlist is unverified. */
    bool IsAllowed(const std::string& soname,
                   const std::vector<uint8_t>& build_id,
                   const std::string& scope) const;

    size_t size() const { return entries_.size(); }

    /* Parse the canonical body format (line-oriented; see .cpp) WITHOUT verifying
     * — exposed for unit tests of the parser. Production code uses LoadSigned. */
    static std::vector<AllowEntry> ParseBody(const std::vector<uint8_t>& body);

private:
    std::vector<AllowEntry> entries_;
    bool verified_ = false;
};

}  // namespace horkos::allowlist
