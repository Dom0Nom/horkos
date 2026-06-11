/*
 * sdk/src/backends/win/input/DeviceTrustWin.h
 * Role: SDK-internal façade for the Windows USB/HID device-trust usermode sensors
 *       (hardware-input-devices domain, catalog signals 136/137/139/142/143/144 and
 *       the 138 device-trust reconciliation framing). Declares the descriptor-audit
 *       sensor entry points, the shared USB-hub/node descriptor SNAPSHOT type used by
 *       137/139/143, and the small PLATFORM-FREE decision cores (descriptor-coherence
 *       classification, composite-interface flagging, bInterval ceiling math, HID
 *       canonicalization fold) that the host unit tests drive with no live device and
 *       no Win32. The Win32/SetupAPI/WinUSB-touching builders + sensors are declared
 *       here and implemented in the *Win.cpp siblings.
 * Target platforms: Windows (userspace). The pure cores are platform-free so they are
 *       host-testable (mirrors InputSensorWin.h / RenderSensorWin.h conventions).
 * Interface: declares the entry points the Windows sdk.cpp AC tick calls; implemented
 *       by UsbTopologyWin.cpp + the per-signal *Win.cpp files under this folder.
 *       Findings ride the device-trust JSON plane (device_trust_schema.h), never the
 *       kernel ring (guardrail #4 — no kernel TU includes this header). 138 reuses the
 *       sibling RawInputInventoryWin + hk_input_finding from input_prov_schema.h.
 */

#pragma once

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "horkos/device_trust_schema.h"

namespace hk { namespace sdk { namespace win {

/* -------------------------------------------------------------------------
 * Shared USB hub/node descriptor snapshot (signals 137/139/143).
 * One entry per enumerated USB device, keyed by an opaque per-session container
 * token (NOT the raw ContainerID — privacy). Carries the raw 18-byte device
 * descriptor fields, the parsed config-descriptor interface-class set + IAD presence,
 * and the interrupt-IN endpoint bInterval the cadence sensor needs. Built by
 * UsbTopologyWin.cpp; the consuming sensors read it with no platform call so they are
 * host-testable.
 * ------------------------------------------------------------------------- */
struct UsbNode {
    uint64_t container_token;   /* opaque per-session ContainerID hash; 0 = unresolved */
    uint16_t vendor_id;         /* idVendor */
    uint16_t product_id;        /* idProduct */
    uint16_t bcd_usb;           /* bcdUSB */
    uint16_t bcd_device;        /* bcdDevice */
    uint8_t  max_packet_size0;  /* bMaxPacketSize0 */
    uint8_t  iface_class_mask;  /* HK_IFACE_* from the config descriptor */
    uint8_t  has_iad;           /* a USB_INTERFACE_ASSOCIATION_DESCRIPTOR was present */
    uint8_t  serial_present;    /* iSerialNumber != 0 */
    uint8_t  in_interrupt_binterval; /* interrupt-IN endpoint bInterval, 0 = none/unknown */
    uint8_t  high_speed;        /* device negotiated high/super speed (bInterval is exponent) */
    uint8_t  wireless_dongle;   /* parent re-clocks (RF/dongle); cadence ceiling exempt */
    uint8_t  query_failed;      /* an IOCTL/descriptor read failed -> inconclusive, never anomaly */
};

struct UsbTopology {
    std::vector<UsbNode> nodes;
};

/* -------------------------------------------------------------------------
 * Pure descriptor-coherence classifier (signal 137). No platform calls — the host
 * unit test drives the full decision table. Deliberately conservative: a failed
 * query is HK_DAUD_INCONCLUSIVE + HK_INPUT_SRC_UNRESOLVED, never a fabricated
 * anomaly. The CLIENT only reports the resolved bucket; the known-hardware corpus
 * correlation is server-side (catalog mandate).
 * ------------------------------------------------------------------------- */
struct DescriptorCoherenceInput {
    bool     query_failed;        /* a hub-IOCTL / descriptor read failed */
    bool     major_vendor_vid;    /* the claimed VID is a known major peripheral vendor */
    bool     bridge_chip_signature; /* bcdDevice/bMaxPacketSize0 matches a CH340/CP2102/FTDI bridge */
    bool     serial_present;      /* iSerialNumber populated */
    bool     serial_expected;     /* the claimed VID class normally ships a serial */
};

/* Returns the audit_flags bitmask AND writes the verdict through `out_verdict`. The
 * narrow catalog condition for HK_INPUT_SRC_DESCRIPTOR_INCOHERENT is: a major-vendor
 * VID combined with a bridge-chip descriptor signature (a real major vendor does not
 * ship its mouse behind a CH340). Everything else stays PHYSICAL_KNOWN/benign or
 * UNRESOLVED. A missing-but-expected serial is a SOFT flag only (server fuses it),
 * never sufficient alone. */
inline uint8_t classify_descriptor_coherence(const DescriptorCoherenceInput &in,
                                             uint32_t &out_verdict)
{
    uint8_t flags = 0;
    if (in.query_failed) {
        out_verdict = HK_INPUT_SRC_UNRESOLVED;
        return HK_DAUD_INCONCLUSIVE;
    }
    if (in.bridge_chip_signature) {
        flags |= HK_DAUD_BRIDGE_SIGNATURE;
    }
    if (!in.serial_present && in.serial_expected) {
        flags |= HK_DAUD_NULL_SERIAL; /* soft; not sufficient alone */
    }
    /* The incoherent verdict requires the narrow joint condition. */
    if (in.major_vendor_vid && in.bridge_chip_signature) {
        out_verdict = HK_INPUT_SRC_DESCRIPTOR_INCOHERENT;
    } else {
        out_verdict = HK_INPUT_SRC_PHYSICAL_KNOWN;
    }
    return flags;
}

/* -------------------------------------------------------------------------
 * Pure composite-interface flag fold (signal 143). HID co-resident with a
 * CDC-ACM / vendor-serial interface under ONE ContainerID is the catalog anomaly
 * (HK_DAUD_CONTAINER_MISMATCH). A device exposing only HID, or only CDC, is benign;
 * a genuine vendor composite (HID + CDC RGB channel) is reported-but-benign and the
 * server allowlists the known layout. FP gate is low; the client only flags the
 * co-residency, never bans.
 * ------------------------------------------------------------------------- */
inline uint8_t fold_composite_interface_flags(uint8_t iface_class_mask, bool has_iad)
{
    const bool hid = (iface_class_mask & HK_IFACE_HID) != 0;
    const bool cdc = (iface_class_mask & HK_IFACE_CDC) != 0;
    const bool vendor = (iface_class_mask & HK_IFACE_VENDOR) != 0;
    uint8_t flags = 0;
    /* HID alongside a serial-shaped interface (CDC or vendor-bulk) under one
     * container is the flag. has_iad only sharpens it (an IAD groups the functions);
     * its absence does not suppress, since a non-IAD composite still co-resides. */
    if (hid && (cdc || vendor)) {
        flags |= HK_DAUD_CONTAINER_MISMATCH;
        (void)has_iad;
    }
    return flags;
}

/* -------------------------------------------------------------------------
 * Pure cadence-ceiling math (signal 139). FEATURES ONLY — fills the cadence feature
 * block from an observed report rate + the descriptor-permitted ceiling. The ceiling
 * derivation reuses the SAME bInterval->Hz mapping the sibling poll-rate sensor uses
 * (declared_hz_from_binterval in InputSensorWin.h); here we additionally compute the
 * ratio observed/ceiling. A wireless dongle re-clocks the endpoint, so the comparison
 * is suppressed (HK_CAD_WIRELESS_EXEMPT) and the server reads no ceiling violation.
 *
 * HK-VERIFIED(binterval-ceiling): USB bInterval ceiling per speed class is fully
 * documented in the USB specification:
 *   - Full-speed (12 Mbps): bInterval is frame count in ms; max 255ms, min 1ms
 *     (USB 2.0 spec §9.6.6, Table 9-13). At bInterval=1 → 1000 Hz ceiling.
 *   - High-speed (480 Mbps): polling period = 2^(bInterval-1) × 125 µs
 *     microframes. bInterval range 1–16; bInterval=1 → 125µs → 8000 Hz ceiling.
 *   - SuperSpeed (5/10/20 Gbps): same 2^(bInterval-1) × 125 µs formula, range 1–16.
 *   ref: USB 2.0 spec §9.6.6; USB 3.2 spec §9.6.6
 *   ref (declared_hz_from_binterval impl): InputSensorWin.h applies this mapping.
 * The wireless-dongle re-clock behavior (receiver clocks independently of bInterval)
 * is an empirical characteristic, not a USB spec guarantee — it still needs on-box
 * validation with real 1000Hz/8000Hz mice and RF dongles on the Phase-3 box.
 * (docs: bInterval math per USB spec confirmed — still needs on-box ratio validation
 * with actual high-speed / wireless devices before server threshold is tuned)
 * ------------------------------------------------------------------------- */
inline void compute_cadence_ceiling(float observed_rate_hz, uint32_t ceiling_hz,
                                    bool wireless_dongle,
                                    hk_pointer_cadence_features &out)
{
    out.observed_rate_hz = observed_rate_hz;
    if (ceiling_hz == 0u) {
        out.declared_interval_ms = 0.0f;
        out.ceiling_violation_ratio = 0.0f;
        out.flags |= HK_CAD_INCONCLUSIVE;
        return;
    }
    out.declared_interval_ms = 1000.0f / (float)ceiling_hz;
    if (wireless_dongle) {
        /* Receiver re-clocks; a >1.0 ratio here is not physically meaningful. */
        out.ceiling_violation_ratio = 0.0f;
        out.flags |= HK_CAD_WIRELESS_EXEMPT;
        return;
    }
    out.ceiling_violation_ratio = observed_rate_hz / (float)ceiling_hz;
}

/* -------------------------------------------------------------------------
 * Pure HID canonicalization fold (signal 136). The structural fingerprint is the
 * SHA-256 of a CANONICALIZED byte buffer; the canonicalization (and not the hash) is
 * the correctness axis the host test pins: reordering the same set of usage pages
 * must yield the SAME canonical buffer (hence the same hash). This builds the
 * canonical buffer from the parsed caps; the platform sensor then SHA-256s it (via
 * BCrypt). Pure + header-only so the host unit test drives it with no Win32, mirroring
 * compute_timing_features in InputSensorWin.h.
 *
 * Canonical layout (little-endian, deterministic):
 *   [u16 usage_page_count][u16 field_count][u16 report_id_count]
 *   then usage_pages SORTED ASCENDING, each as u16
 *   then report_ids SORTED ASCENDING, each as u8
 * The sort makes the buffer invariant to enumeration order; counts pin structure size.
 * ------------------------------------------------------------------------- */
struct HidCanonicalInput {
    std::vector<uint16_t> usage_pages; /* distinct usage pages, any order on input */
    std::vector<uint8_t>  report_ids;  /* distinct report IDs, any order on input */
    uint16_t              field_count; /* total button + value caps */
};

inline std::vector<uint8_t> canonicalize_hid_descriptor(HidCanonicalInput in)
{
    /* De-dup + sort both sets so two descriptors that differ only in declaration
     * order canonicalize identically. std::sort + unique is deterministic. */
    std::sort(in.usage_pages.begin(), in.usage_pages.end());
    in.usage_pages.erase(std::unique(in.usage_pages.begin(), in.usage_pages.end()),
                         in.usage_pages.end());
    std::sort(in.report_ids.begin(), in.report_ids.end());
    in.report_ids.erase(std::unique(in.report_ids.begin(), in.report_ids.end()),
                        in.report_ids.end());

    const uint16_t up_count = (uint16_t)in.usage_pages.size();
    const uint16_t rid_count = (uint16_t)in.report_ids.size();

    std::vector<uint8_t> buf;
    buf.reserve(6 + in.usage_pages.size() * 2 + in.report_ids.size());
    auto put16 = [&buf](uint16_t v) {
        buf.push_back((uint8_t)(v & 0xFFu));
        buf.push_back((uint8_t)((v >> 8) & 0xFFu));
    };
    put16(up_count);
    put16(in.field_count);
    put16(rid_count);
    for (uint16_t p : in.usage_pages) {
        put16(p);
    }
    for (uint8_t r : in.report_ids) {
        buf.push_back(r);
    }
    return buf;
}

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

/* Build the shared USB hub/node descriptor snapshot (137/139/143). Returns false on
 * enumeration failure; dependent sensors then degrade to HK_DAUD_INCONCLUSIVE /
 * HK_INPUT_SRC_UNRESOLVED rather than guessing. Read-only: opens the USB hub
 * interface and issues GET_DESCRIPTOR/GET_NODE_CONNECTION_INFORMATION IOCTLs; it never
 * writes to or controls a device. (The _WIN32 fallback in the guard mirrors the other
 * backends/win headers; the implementation lives strictly under backends/win/ per
 * guardrail #1.) */
bool build_usb_topology(UsbTopology &out);

/* Per-signal sensor entry points. Each appends zero or more records to its output
 * vector and returns the count appended, or -1 on a sensor-level failure (itself
 * reported as an inconclusive finding, not a silent drop). All are read-only and must
 * not let an exception cross this C++ ABI seam. */
int sense_hid_descriptor(std::vector<hk_event_hid_descriptor> &out);            /* 136 */
int sense_usb_descriptor_audit(const UsbTopology &topo,
                               std::vector<hk_device_descriptor_audit> &out);   /* 137 */
int sense_rawinput_reconcile(std::vector<hk_input_finding> &out);              /* 138 */
int sense_poll_interval(const UsbTopology &topo,
                        std::vector<hk_pointer_cadence_features> &out);         /* 139 */
int sense_composite_interface(const UsbTopology &topo,
                              std::vector<hk_device_descriptor_audit> &out);    /* 143 */
int sense_device_arrival(std::vector<hk_pointer_cadence_features> &out);        /* 144 */
int sense_pointer_stats(std::vector<hk_event_pointer_features> &out);          /* 142 (win half) */

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */

} } } // namespace hk::sdk::win
