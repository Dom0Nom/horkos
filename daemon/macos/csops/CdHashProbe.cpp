/*
 * daemon/macos/csops/CdHashProbe.cpp
 * Role: Signal 119 — live-vs-disk cdhash / notarization parity probe. Reads the
 *       kernel's live cdhash for a game PID via csops(pid, CS_OPS_PIDCDHASH) and
 *       cross-checks it against the on-disk bundle's cdhash from
 *       SecCodeCopySigningInformation (kSecCodeInfoUnique / kSecCodeInfoCdHashes),
 *       translocation-resolved and fat-slice-correct. Emits HK_CS_CDHASH_MISMATCH
 *       with a compact fold discriminant; the full hex rides the report plane.
 * Target platform: macOS only (built behind if(APPLE) + HK_MACOS_CS_CDHASH).
 * Interface: implements cs_cdhash_fold()/cs_cdhash_equal() (PURE, host-tested)
 *            and HkCdHashProbeSample() from CsIntegrityProbe.h. Userspace daemon
 *            TU (guardrail #4).
 *
 * Guardrail compliance:
 *   #1  No platform #ifdef — CMake gates the TU.
 *   #13 The live cdhash read, the buffer sizing, and the translocation/fat-slice
 *       resolution are HK-UNCERTAIN (plan Risk 1 + Risk 6) and left unimplemented;
 *       the PURE fold/compare cores ARE implemented and host-unit-tested.
 *   #14 cs_cdhash_fold / cs_cdhash_equal are pure and host-tested.
 */

#include "CsIntegrityProbe.h"

#include <string.h>

/* cdhash sizes: SHA-1 truncated to 20 bytes (legacy), SHA-256 to 32 bytes. The
 * kernel returns one of these via CS_OPS_PIDCDHASH. */
#define HK_CDHASH_MAX 32u

extern "C" uint32_t cs_cdhash_fold(const uint8_t *cdhash, size_t len)
{
    if (cdhash == nullptr || len == 0) {
        return 0u;
    }
    /* XOR-fold over 4-byte words; trailing bytes folded individually. A coarse
     * change discriminant only — NOT a verification hash (the full hex is the
     * authority, server-side). Endianness is irrelevant: both the live and disk
     * folds are computed the same way and compared as opaque u32s. */
    uint32_t acc = 0;
    size_t i = 0;
    for (; i + 4 <= len; i += 4) {
        uint32_t word;
        memcpy(&word, cdhash + i, sizeof(word));
        acc ^= word;
    }
    for (; i < len; ++i) {
        acc ^= static_cast<uint32_t>(cdhash[i]) << ((i & 3u) * 8u);
    }
    return acc;
}

extern "C" bool cs_cdhash_equal(const uint8_t *a, size_t a_len,
                                const uint8_t *b, size_t b_len)
{
    if (a == nullptr || b == nullptr) {
        return false;
    }
    if (a_len == 0 || a_len != b_len) {
        return false;  /* a length mismatch is a mismatch, never an over-read */
    }
    return memcmp(a, b, a_len) == 0;
}

/* -------------------------------------------------------------------------
 * Impure probe body (excluded from the pure host-test TU).
 * ------------------------------------------------------------------------- */
#ifndef HK_CS_PROBE_PURE_ONLY

/* HK-UNCERTAIN(csops-header): <sys/codesign.h> is not in the public SDK (plan
 * Risk 1); the CS_OPS_PIDCDHASH op number + buffer-size contract are SPI and
 * unverified across macOS 12-15. The live cdhash read is routed through a stub
 * (returns unavailable) rather than guessing the op number / size. */
#include <unistd.h>
#include <os/log.h>

/* Fills *out (up to cap bytes), sets *out_len; returns 0 on success, non-zero on
 * failure/unavailable. Stubbed until the CS_OPS_PIDCDHASH contract is verified. */
static int hk_csops_pidcdhash_read(pid_t /*pid*/, uint8_t * /*out*/,
                                   size_t /*cap*/, size_t * /*out_len*/)
{
    return -1;  /* unavailable — see HK-UNCERTAIN above */
}

namespace {
os_log_t hk_log() {
    static os_log_t log = os_log_create("io.horkos.daemon", "cs-cdhash");
    return log;
}
}  // namespace

extern "C" bool HkCdHashProbeSample(const HkCsProbeTarget *target, HkCsFinding *out)
{
    if (target == nullptr || out == nullptr || target->pid == 0) {
        return false;
    }

    /* Live cdhash from the kernel. */
    uint8_t live[HK_CDHASH_MAX];
    size_t  live_len = 0;
    memset(live, 0, sizeof(live));
    /* HK-UNCERTAIN(cs-pidcdhash): the exact CS_OPS_PIDCDHASH buffer-size contract
     * (whether the kernel writes 20 or 32 bytes, and whether CS_OPS_TEISDISABLED
     * is the correct guard) is uncertain across macOS 12-15 (plan Risk 1). The
     * read is routed through hk_csops_pidcdhash_read() which is stubbed until
     * verified; and the DISK-side comparand requires SecCodeCopySigningInformation
     * + translocation/fat-slice resolution (plan Risk 6) which is ALSO unverified.
     * Per guardrail #13 neither is guessed; the probe emits nothing until both are
     * verified on real macOS 12/13/14/15 boxes. */
    if (hk_csops_pidcdhash_read(static_cast<pid_t>(target->pid),
                                live, sizeof(live), &live_len) != 0) {
        return false;  /* read failed / unavailable — abort cleanly */
    }
    (void)live_len;

    /* HK-UNCERTAIN(cs-disk-cdhash): the on-disk comparand path is unimplemented
     * (SecStaticCodeCreateWithPath -> SecCodeCopySigningInformation ->
     * kSecCodeInfoUnique, with SecTranslocateCreateOriginalPathForURL and the
     * executing fat-slice selection — plan Risk 6). When wired:
     *   uint32_t live_fold = cs_cdhash_fold(live, live_len);
     *   if (!cs_cdhash_equal(live, live_len, disk, disk_len)) { emit with
     *       detail = live_fold; evidence = {live_hex, disk_hex}; }
     * Until then, emit nothing rather than a half-checked finding. */
    os_log_debug(hk_log(),
        "HKCdHashProbe: live cdhash read for pid %u; disk comparand "
        "HK-UNCERTAIN (translocation/fat-slice unverified) — not compared",
        target->pid);
    return false;
}

#endif /* HK_CS_PROBE_PURE_ONLY */
