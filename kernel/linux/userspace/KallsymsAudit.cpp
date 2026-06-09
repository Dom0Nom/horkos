/*
 * kernel/linux/userspace/KallsymsAudit.cpp
 * Role: Implementation of signal 91 (kallsyms text-address drift) declared in
 *       KallsymsAudit.h. Pure analysis over the shared HkSymbolMap.
 * Target platform: Linux userspace.
 * Interface: implements horkos::modint::AnalyzeKsym / hk_sensor_kallsyms.
 *
 * Guardrail compliance: #1, #3, #4. Read-only / audit-only.
 */

#include "KallsymsAudit.h"

#include <unordered_map>

namespace horkos::modint {

bool IsLivepatchModule(const std::string& module_name) {
    static const char* kPrefixes[] = {"klp_", "kpatch_", "livepatch_"};
    for (const char* p : kPrefixes) {
        std::string pre(p);
        if (module_name.size() >= pre.size() &&
            module_name.compare(0, pre.size(), pre) == 0) {
            return true;
        }
    }
    return false;
}

int AnalyzeKsym(const HkSymbolMap& map, HkEventSink sink) {
    /* Coverage gate: a sensible drift verdict needs both visible addresses and a
     * valid core range. Missing either is a coverage gap, NOT a detection —
     * treating "can't read" as "tampered" is the dominant FP failure mode here. */
    if (!map.addrs_visible || !map.core_valid) {
        HkEmitUnavailable(sink, kSignalKsymDrift, 0);
        return 0;
    }

    int emitted = 0;

    /* Collision detection: two distinct sensitive symbols sharing one address is
     * a relocation/trampoline tell. */
    std::unordered_map<uint64_t, std::string> seen_addr;

    for (const auto& [name, addr] : map.sensitive_addr) {
        if (addr == 0) continue;   /* individually hidden; map.addrs_visible
                                      already gated the global case */

        uint32_t sym_id = HkSensitiveSymbolId(name);

        /* Collision. */
        auto col = seen_addr.find(addr);
        if (col != seen_addr.end() && col->second != name) {
            HkEvtKsymDrift ev{};
            ev.resolved_addr = addr;
            ev.expected_lo = map.core.lo;
            ev.expected_hi = map.core.hi;
            ev.reason = HK_KSYM_COLLISION;
            ev.symbol_id = sym_id;
            HkEmit(sink, kEvtKsymDrift, &ev, sizeof(ev));
            ++emitted;
        } else {
            seen_addr.emplace(addr, name);
        }

        const TextRange* owner = map.OwnerOf(addr);
        if (owner == nullptr) {
            /* Out of every known text range — strongest drift signal. */
            HkEvtKsymDrift ev{};
            ev.resolved_addr = addr;
            ev.expected_lo = map.core.lo;
            ev.expected_hi = map.core.hi;
            ev.reason = HK_KSYM_OOB;
            ev.symbol_id = sym_id;
            HkEmit(sink, kEvtKsymDrift, &ev, sizeof(ev));
            ++emitted;
        } else if (!owner->owner.empty()) {
            /* A CORE sensitive symbol resolving inside a module's .text is a
             * shadow/relocation — unless that module is an allowlisted
             * livepatch, which legitimately relocates the function. */
            if (!IsLivepatchModule(owner->owner)) {
                HkEvtKsymDrift ev{};
                ev.resolved_addr = addr;
                ev.expected_lo = owner->lo;
                ev.expected_hi = owner->hi;
                ev.reason = HK_KSYM_SHADOW;
                ev.symbol_id = sym_id;
                HkEmit(sink, kEvtKsymDrift, &ev, sizeof(ev));
                ++emitted;
            }
        }
        /* owner is the core range with empty name → in-bounds, no drift. */
    }

    return emitted;
}

int hk_sensor_kallsyms(const HkSymbolMap* map, HkEventSink sink) {
    if (map == nullptr) return -1;
    AnalyzeKsym(*map, sink);
    return 0;
}

}  // namespace horkos::modint
