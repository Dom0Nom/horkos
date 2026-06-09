/*
 * ac/src/selfcheck/selfcheck.cpp
 * Role: Client self-integrity orchestrator (memory-integrity-selfcheck, catalog
 *       signals 145-153). Owns the scan cadence/budget, dispatches each per-signal
 *       sensor, batches the raw evidence into the large-record drain path, and feeds
 *       ac_get_last_flag. Pure glue: no platform API here (guardrail #1). It ships
 *       raw evidence only — never a verdict; all ban authority is server-side.
 * Target platforms: all (compiled into hk_ac). Built only when HK_SELFCHECK is
 *       defined (CMake option HK_ENABLE_SELFCHECK, default ON); otherwise this TU
 *       compiles to link-safe no-ops so hk_ac links with the feature off.
 * Interface: implements hk::selfcheck::SelfCheck + guard_entry (selfcheck.h).
 */

#include "horkos/selfcheck.h"

namespace hk {
namespace selfcheck {

#if defined(HK_SELFCHECK)

/* The annotate("hk_obfuscate") attribute on guard_entry (declared in selfcheck.h)
 * marks this as an init/integrity symbol for the opt-in LLVM-19 pass (guardrail #9).
 * The body is intentionally minimal here: the real 147 capture lives in
 * retaddr_provenance.cpp, which this entry point forwards to once that sensor's
 * platform unwind backend is wired. Keeping guard_entry tiny keeps the obfuscated
 * surface off the game hot loop. */
void guard_entry(uint32_t fn_id) {
    /* HK-TODO(147): forward to retaddr_provenance once the platform unwind +
     * module-attribution backend is wired. Today this is a reachable no-op so the
     * HK_GUARD_ENTRY() call sites compile and the obfuscation annotation is present
     * for the pass to honor. It must NOT block or allocate — it runs at a critical
     * function prologue. */
    (void)fn_id;
}

SelfCheck::SelfCheck() noexcept
    : armed_(false), last_flag_(HK_SELF_FLAG_NONE) {}

SelfCheck::~SelfCheck() = default;

bool SelfCheck::arm(const ImageBaseline& baseline) noexcept {
    (void)baseline;
    /* HK-TODO(arm): once image_baseline.cpp's parse lands a populated baseline,
     * validate it here and cache the expected tables. A failed/empty baseline must
     * leave armed_==false so run_once() emits nothing (fail-closed) rather than
     * sampling against a baseline it does not trust. */
    armed_ = true;
    last_flag_ = HK_SELF_FLAG_NONE;
    return armed_;
}

int SelfCheck::run_once() noexcept {
    if (!armed_) {
        return 0;
    }
    last_flag_ = HK_SELF_FLAG_NONE;

    /* HK-TODO(dispatch): one budgeted pass over signals 145-153. Each sensor TU
     * (text_crossview / page_cow_audit / retaddr_provenance / dr_audit /
     * iat_target_audit / got_target_audit / veh_unwind_audit / sig_handler_audit /
     * loader_consistency / wx_pte_audit / tls_init_audit) samples, runs its pure
     * core (self_logic.cpp), and on raw evidence emits a hk_event_self_* record via
     * the large-record drain plane and ORs its HK_SELF_FLAG_* into last_flag_.
     *
     * The dispatch is not wired here yet because the large-record drain plane
     * (HK_EVENT_MEM_PAYLOAD_MAX / HK_IOCTL_DRAIN_MEM_EVENTS) the records ride is
     * pre-Schema (see ac/src/selfcheck/self_wire.h) — emitting a 120-byte crossview
     * record over the frozen 40-byte envelope would truncate it. Per the schema
     * constraint we do NOT widen the frozen ring from this domain; the sensors are
     * implemented and their pure cores tested, but the budgeted emit loop activates
     * once the shared large-record plane lands. */
    return 0;
}

uint32_t SelfCheck::last_flag() const noexcept {
    return last_flag_;
}

#else /* HK_SELFCHECK not defined — link-safe no-ops. */

void guard_entry(uint32_t fn_id) { (void)fn_id; }

SelfCheck::SelfCheck() noexcept : armed_(false), last_flag_(0u) {}
SelfCheck::~SelfCheck() = default;
bool SelfCheck::arm(const ImageBaseline& baseline) noexcept { (void)baseline; return false; }
int SelfCheck::run_once() noexcept { return 0; }
uint32_t SelfCheck::last_flag() const noexcept { return 0u; }

#endif /* HK_SELFCHECK */

} // namespace selfcheck
} // namespace hk
