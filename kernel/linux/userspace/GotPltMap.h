/*
 * Role: Signal 83 correlator — GOT/PLT redirection detection. Computes .got.plt
 *       slot offsets from ELF section headers + load bias, hands them to the
 *       got_sample BPF program via the hk_got_cfg map, and resolves each sampled
 *       slot pointer against the live VMA map. Flags slots whose resolved target
 *       lands in an anon / RWX / foreign-DSO mapping. SKIPS IFUNC slots
 *       (R_*_IRELATIVE) and treats "points into the process's own PLT stub" as
 *       benign (lazy binding not yet resolved is not a hook).
 * Target platform: Linux userspace.
 * Interface: produces the slot-VA config (BuildSlotConfig) for the BPF map;
 *            consumes GotSampleEvent + a ProcReader; emits InjectionFinding
 *            (kEvtGotAnomaly).
 */

#pragma once

#include <vector>

#include "ElfModel.h"
#include "InjectionEvents.h"
#include "OverlayAllowlist.h"

namespace horkos::inject {

/* Userspace mirror of got_sample.bpf.c's record (count + resolved slot values).
 * slot_va[i] is the slot ADDRESS userspace configured; slot_target[i] is the
 * pointer VALUE the kernel read from it. */
struct GotSampleEvent {
    uint32_t pid = 0;
    std::vector<uint64_t> slot_va;       /* the configured slot addresses */
    std::vector<uint64_t> slot_target;   /* resolved pointer values */
    std::vector<bool> is_ifunc;          /* per-slot IFUNC marker (skip if true) */
    uint64_t own_plt_start = 0;          /* the process's own .plt range (benign) */
    uint64_t own_plt_end = 0;
};

class GotPltMap {
public:
    GotPltMap(const allowlist::OverlayAllowlist& allow, std::string scope);

    /* Evaluate one GOT sample against the live VMA snapshot. Emits at most one
     * finding (the first offending slot). Returns true if any slot is anomalous.
     * A slot is anomalous when its target is NOT in an allowlisted/file-backed
     * exec mapping and is NOT IFUNC and is NOT inside the own-PLT range. */
    bool OnSample(const GotSampleEvent& ev, const std::vector<elfmodel::VmaEntry>& vmas,
                  InjectionFinding* out);

private:
    const allowlist::OverlayAllowlist& allow_;
    std::string scope_;
};

}  // namespace horkos::inject
