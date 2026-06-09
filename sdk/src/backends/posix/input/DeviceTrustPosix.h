/*
 * sdk/src/backends/posix/input/DeviceTrustPosix.h
 * Role: SDK-internal façade for the Linux/POSIX device-trust usermode sensors
 *       (hardware-input-devices domain, catalog signals 140 evdev/uinput provenance
 *       and 142 pointer-delta features, Linux half). Declares the two sensor entry
 *       points and the pure evdev-classification core (BUS_VIRTUAL vs BUS_USB,
 *       creator-PID allowlist resolution) that the host unit test drives with no
 *       /dev/input and no live bpf ringbuf.
 * Target platforms: Linux (userspace). The pure core is platform-free for host tests.
 * Interface: declares the entry points the POSIX sdk tick calls; implemented by
 *       EvdevProvenanceLinux.cpp + PointerDeltaStatsPosix.cpp. Findings ride the
 *       device-trust JSON plane (device_trust_schema.h), never a kernel TU
 *       (guardrail #4 — the eBPF .bpf.c uses its own hk_input_prov_bpf record).
 */

#pragma once

#include <cstdint>
#include <vector>

#include "horkos/device_trust_schema.h"

namespace hk { namespace sdk { namespace posix {

/* The minimal evdev provenance facts the userspace correlator resolves from the bpf
 * record + EVIOCGID/EVIOCGPHYS + the uinput-creator lookup, before classifying. */
struct EvdevProvenanceInput {
    bool     query_failed;     /* a /dev/input read or the bpf drain failed */
    uint16_t bustype;          /* input_dev->id.bustype (HK_BUS_* maps below) */
    bool     has_usb_parent;   /* sysfs/EVIOCGPHYS resolved a USB parent */
    bool     emits_rel_or_key; /* device advertises EV_REL/EV_KEY (a real input source) */
    uint32_t creator_pid;      /* uinput creator PID, 0 = none/kernel device */
    bool     creator_resolved; /* the creator PID was attributable to a process */
};

/* Map a Linux bustype to the wire HK_BUS_* bucket. */
inline uint8_t map_bustype(uint16_t bustype)
{
    switch (bustype) {
    case 0x03: return HK_BUS_USB;       /* BUS_USB */
    case 0x05: return HK_BUS_BLUETOOTH; /* BUS_BLUETOOTH */
    case 0x06: return HK_BUS_VIRTUAL;   /* BUS_VIRTUAL */
    default:   return HK_BUS_UNKNOWN;
    }
}

/* Pure evdev classifier. Returns the audit_flags bitmask and writes the verdict.
 * Conservative: a failed query is INCONCLUSIVE/UNRESOLVED, never an anomaly. A
 * BUS_VIRTUAL pointer/keyboard with no USB parent is the uinput shape — reported with
 * the creator PID and HK_DAUD_NO_USB_PARENT, but the VERDICT stays PHYSICAL_KNOWN
 * (not incoherent): the server's creator-PID allowlist (Steam Input / antimicro /
 * accessibility remappers all use uinput) decides, NOT the client (catalog high-FP
 * gate). The client only resolves and reports; it never bans on uinput presence. */
inline uint8_t classify_evdev_provenance(const EvdevProvenanceInput &in,
                                         uint32_t &out_verdict)
{
    uint8_t flags = 0;
    if (in.query_failed) {
        out_verdict = HK_INPUT_SRC_UNRESOLVED;
        return HK_DAUD_INCONCLUSIVE;
    }
    out_verdict = HK_INPUT_SRC_PHYSICAL_KNOWN;
    if (map_bustype(in.bustype) == HK_BUS_VIRTUAL && !in.has_usb_parent &&
        in.emits_rel_or_key) {
        flags |= HK_DAUD_NO_USB_PARENT;
        if (in.creator_resolved && in.creator_pid != 0) {
            flags |= HK_DAUD_CREATOR_KNOWN; /* server allowlists the creator */
        }
    }
    return flags;
}

/* Drain the bpf input-provenance records, supplement with EVIOCGID/EVIOCGPHYS, attach
 * the uinput creator PID, classify, and emit hk_device_descriptor_audit findings.
 * Returns the count emitted, or -1 on a drain failure. Read-only. */
int sense_evdev_provenance(std::vector<hk_device_descriptor_audit> &out);   /* 140 */

/* Accumulate EV_REL REL_X/REL_Y deltas and emit the pointer feature vector (142).
 * Returns the count emitted. Never ships raw movement. */
int sense_pointer_stats(std::vector<hk_event_pointer_features> &out);       /* 142 */

} } } // namespace hk::sdk::posix
