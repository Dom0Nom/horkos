/*
 * Role: Signal 90 correlator — in-memory inline-hook / COW-broken text
 *       detection. On a text_sample tick it reads /proc/<pid>/smaps_rollup,
 *       per-VMA /proc/<pid>/smaps (Private_Dirty) and /proc/<pid>/pagemap
 *       (file-backed bit) for r-xp file-backed mappings; flags exec pages gone
 *       private-dirty / anonymous outside documented IFUNC/reloc prologue spans.
 *       Suppresses when a tracer is attached.
 * Target platform: Linux userspace.
 * Interface: consumes TextTickEvent + parsed smaps; emits InjectionFinding
 *            (kEvtTextPatch).
 */

#pragma once

#include <string>
#include <vector>

#include "ElfModel.h"
#include "InjectionEvents.h"

namespace horkos::inject {

/* One executable VMA's dirty-page summary, parsed from /proc/<pid>/smaps. */
struct SmapsExecVma {
    uint64_t start = 0;
    uint64_t end = 0;
    bool file_backed = false;     /* had a real backing path */
    uint64_t private_dirty_kb = 0;/* Private_Dirty from smaps */
};

struct TextTickEvent {
    uint32_t pid = 0;
    bool tracer_attached = false;
};

class TextPageBacking {
public:
    TextPageBacking() = default;

    /* Parse the executable, file-backed mappings + their Private_Dirty out of a
     * /proc/<pid>/smaps text blob. Exposed for testing. */
    static std::vector<SmapsExecVma> ParseExecSmaps(const std::string& smaps_text);

    /* Evaluate one tick against pre-parsed exec smaps. Flags a finding when a
     * file-backed r-xp mapping has non-zero Private_Dirty (COW broken on code)
     * AND it is not within an allowed IFUNC/reloc prologue span. Suppressed when
     * a tracer is attached. Returns true on an anomaly. */
    bool OnTick(const TextTickEvent& ev, const std::vector<SmapsExecVma>& exec_vmas,
                const std::vector<std::pair<uint64_t, uint64_t>>& allowed_spans,
                InjectionFinding* out);
};

}  // namespace horkos::inject
