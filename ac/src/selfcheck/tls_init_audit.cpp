/*
 * Role: Signal 153 — TLS-callback & static-initializer table integrity. Re-parses the
 *       in-memory TLS callback array + CRT .CRT$XC* (Windows) / .init_array (Linux) /
 *       __mod_init_func (macOS), compares the count + each rebased pointer vs the
 *       on-disk table, and verifies each resolves into our text. Catches early-
 *       execution injection invisible to .text byte-hashing (it tampers data-directory
 *       pointers, not code bytes).
 * Target platforms: all (format via HK_PLATFORM_*; guardrail #1). Compiled into hk_ac
 *       behind HK_SELFCHECK.
 * Interface: emits HK_EVENT_SELF_TLS_INIT (hk_event_self_compat, signal_id 153). Uses
 *       the pure tls_table_tampered core in self_logic.cpp.
 */

#include "horkos/selfcheck.h"
#include "self_wire.h"
#include "platform.h"

namespace hk {
namespace selfcheck {

#if defined(HK_SELFCHECK)

uint32_t tls_init_audit_run(uint64_t image_base, uint32_t tls_dir_rva) {
    (void)image_base;
    (void)tls_dir_rva;

    /* HK-UNCERTAIN(tls-walk): the live in-memory TLS/init-array re-parse is not
     * wired. Win: IMAGE_TLS_DIRECTORY.AddressOfCallBacks walked to the null
     * terminator, each rebased pointer compared vs the on-disk table, each PC checked
     * via RtlPcToFileHeader into our .text; also validate .CRT$XCA..XCZ. Linux:
     * .init_array / DT_INIT_ARRAY. macOS: __DATA,__mod_init_func. The pure compare
     * (tls_table_tampered) is wired and tested: given {live_count, disk_count, the
     * rebased pointer arrays, and a per-entry in-text flag} it returns whether the
     * table was tampered. FP gate: suppress on instrumented/sanitizer build flavors
     * reported via attestation (server-side). Left unimplemented per guardrail #13
     * until the per-OS table walk + rebase math are confirmed; the disk baseline it
     * compares against is itself pending (image_baseline.cpp). */
    return HK_SELF_FLAG_NONE;
}

#endif /* HK_SELFCHECK */

} // namespace selfcheck
} // namespace hk
