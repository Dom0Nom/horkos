/*
 * Role: Signal 97 — foreign eBPF program enumeration on the game/client's hook
 *       points. Walks loaded BPF objects via BPF_PROG_GET_NEXT_ID +
 *       BPF_OBJ_GET_INFO_BY_FD (and links via BPF_LINK_GET_NEXT_ID), then flags
 *       programs whose attach target is the protected client's own symbols/
 *       uprobes and whose tag is not the client's own. Emits
 *       HK_EVENT_FOREIGN_BPF. Flags by ATTACH-TARGET, not mere presence (§6).
 * Target platform: Linux userspace (guardrail #4). The enumeration syscalls live
 *                   in the live entry; the decision core is pure and host-testable.
 * Interface: pure ClassifyBpfProg(...) over a fixture set; live entry
 *            hk_sensor_bpf_enum() (links libbpf). Audit-only / read-only.
 */

#pragma once

#include <cstdint>
#include <set>
#include <string>
#include <vector>

#include "HostIntegritySensors.h"
#include "SymbolMap.h"

namespace horkos::modint {

/* A normalized view of one enumerated BPF program (subset of bpf_prog_info we
 * use). `tag` is the 8-byte program tag; `attach_target` is the resolved
 * attach-target name (symbol for fentry/kprobe/tracepoint, uprobe path:offset
 * for uprobes), filled by the live entry. */
struct BpfProgRecord {
    uint32_t id = 0;
    uint32_t type = 0;            /* enum bpf_prog_type */
    uint64_t tag = 0;            /* 8-byte prog tag, folded to u64 */
    std::string attach_target;   /* resolved by the live entry, "" if unknown */
};

/* The client's identity for the comparison: the set of attach targets the
 * protected client itself hooks (so a program on those targets that is NOT one
 * of the client's own tags is foreign), plus the set of the client's own program
 * tags (allowlisted). */
struct BpfClientIdentity {
    std::set<std::string> protected_targets;   /* client's own hook points */
    std::set<uint64_t> own_tags;               /* client's own prog tags */
    std::set<uint64_t> systemd_allowlist_tags; /* known systemd-loaded progs */
};

/* Pure classifier: returns true and fills `out` when `prog` is FOREIGN on a
 * protected target — i.e. its attach_target is in identity.protected_targets and
 * its tag is neither an own_tag nor a systemd-allowlisted tag. A program on a
 * non-protected target, or one of the client's own/allowlisted tags, returns
 * false (no event). */
bool ClassifyBpfProg(const BpfProgRecord& prog, const BpfClientIdentity& identity,
                     HkEvtForeignBpf* out);

/* Live sensor entry (HkHostSensorFn). Degrades to SENSOR_UNAVAILABLE(97) if
 * enumeration is denied (CAP_BPF / unprivileged_bpf_disabled) — never infers
 * tampering from an enumeration denial (§3). */
int hk_sensor_bpf_enum(const HkSymbolMap* map, HkEventSink sink);

}  // namespace horkos::modint
