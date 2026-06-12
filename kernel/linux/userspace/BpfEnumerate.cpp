/*
 * Role: Implementation of signal 97 (foreign BPF enumeration) declared in
 *       BpfEnumerate.h. The pure classifier is host-testable; the live entry
 *       uses the libbpf bpf_prog_get_next_id / bpf_obj_get_info_by_fd surface and
 *       is compiled only into the libbpf-linked loader target.
 * Target platform: Linux userspace.
 * Interface: implements horkos::modint::ClassifyBpfProg (always) and
 *            hk_sensor_bpf_enum (only when HK_HOSTINT_LIBBPF is defined — the
 *            CMake sets it on the libbpf-linked build; the non-libbpf static lib
 *            and the host unit-test build get a degrade-to-unavailable stub).
 *
 * Guardrail compliance: #1, #3, #4 (no kernel/BPF program headers — libbpf
 * userspace headers only). Read-only / audit-only.
 */

#include "BpfEnumerate.h"

namespace horkos::modint {

bool ClassifyBpfProg(const BpfProgRecord& prog, const BpfClientIdentity& identity,
                     HkEvtForeignBpf* out) {
    if (out == nullptr) return false;

    /* Only programs attached to a PROTECTED target matter (§6: flag by attach-
     * target, not presence). */
    if (prog.attach_target.empty()) return false;
    if (identity.protected_targets.find(prog.attach_target) ==
        identity.protected_targets.end()) {
        return false;
    }

    /* The client's own programs and known systemd-loaded programs are allowed. */
    if (identity.own_tags.count(prog.tag) != 0) return false;
    if (identity.systemd_allowlist_tags.count(prog.tag) != 0) return false;

    out->prog_tag_hash = prog.tag;
    out->prog_id = prog.id;
    out->prog_type = prog.type;
    return true;
}

}  // namespace horkos::modint

#ifdef HK_HOSTINT_LIBBPF

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <cerrno>
#include <cstring>
#include <unistd.h>

namespace horkos::modint {

namespace {

/* Fold the 8-byte prog tag into a u64. */
uint64_t FoldTag(const uint8_t tag[8]) {
    uint64_t v = 0;
    std::memcpy(&v, tag, sizeof(v));
    return v;
}

}  // namespace

int hk_sensor_bpf_enum(const HkSymbolMap* map, HkEventSink sink) {
    (void)map;

    /* HK-UNCERTAIN(bpf-attach-target-resolve): bpf_prog_info exposes prog type,
     * tag, attach_type, and attach_btf_id for some types, but mapping a loaded
     * program back to "it hooks /game/bin:0xNNN" or "kprobe commit_creds"
     * robustly across types/kernels is non-trivial. BPF_LINK_GET_INFO_BY_FD
     * carries the attach target for link-based attaches (Linux 5.7+, bpf(2)) but
     * not for legacy socket/perf-event attaches. bpf_prog_info.attach_btf_id is
     * present in the kernel ABI since Linux 5.0 but resolving it to a symbol name
     * requires BTF lookup (not just the ID). The specific fields populated per
     * prog type (kprobe, uprobe, tracepoint, cgroup, …) vary by kernel version and
     * are not fully enumerated in a single public doc. The pure classifier above is
     * exercised by tests; live attach-target resolution is left unimplemented
     * pending on-box confirmation of which info fields are populated per prog type.
     * (docs: BPF_LINK_GET_INFO_BY_FD for link-based attaches confirmed Linux 5.7+
     * bpf(2); attach_btf_id in bpf_prog_info since 5.0 — still needs on-target
     * per-type field verification) */

    /* Build the client identity (own targets/tags) — populated by the loader once
     * the protected-set identity is wired; empty here means "no protected targets
     * known yet", which makes every classification a no-op (correct: we cannot
     * call a program foreign-on-our-hooks if we do not yet know our hooks). */
    BpfClientIdentity identity;

    __u32 id = 0;
    int walked = 0;
    int err;
    while ((err = bpf_prog_get_next_id(id, &id)) == 0) {
        int fd = bpf_prog_get_fd_by_id(id);
        if (fd < 0) {
            /* EACCES on another task's prog under hardening — coverage, not a
             * detection. Keep walking the ids we can see. */
            if (errno == EPERM || errno == EACCES) continue;
            continue;
        }
        struct bpf_prog_info info {};
        __u32 len = sizeof(info);
        if (bpf_obj_get_info_by_fd(fd, &info, &len) == 0) {
            BpfProgRecord rec;
            rec.id = info.id;
            rec.type = info.type;
            rec.tag = FoldTag(info.tag);
            /* rec.attach_target intentionally left empty — see HK-UNCERTAIN. */
            HkEvtForeignBpf out_ev{};
            if (ClassifyBpfProg(rec, identity, &out_ev)) {
                HkEmit(sink, kEvtForeignBpf, &out_ev, sizeof(out_ev));
            }
            ++walked;
        }
        close(fd);
    }

    /* err == -ENOENT marks the end of the id space (normal). Any other errno on
     * the FIRST step means enumeration is denied → coverage gap. */
    if (walked == 0 && err != 0 && errno != ENOENT) {
        HkEmitUnavailable(sink, kSignalForeignBpf, errno);
    }
    return 0;
}

}  // namespace horkos::modint

#else  /* !HK_HOSTINT_LIBBPF — no libbpf in this build */

namespace horkos::modint {

int hk_sensor_bpf_enum(const HkSymbolMap* /*map*/, HkEventSink sink) {
    /* Without libbpf the enumeration surface is unavailable; report it as a
     * coverage gap (errno 0 = "not built with libbpf"), never as a detection. */
    HkEmitUnavailable(sink, kSignalForeignBpf, 0);
    return 0;
}

}  // namespace horkos::modint

#endif  /* HK_HOSTINT_LIBBPF */
