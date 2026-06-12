/*
 * Role: Host-runnable unit tests for the PLATFORM-FREE decision cores of the
 *       win-input-automation input-provenance sensors (catalog signals 55-63).
 *       Exercises the pure provenance classifier, ratio folding, RAWMOUSE/scan-code
 *       flag folding, deterministic timing-feature math, and poll-rate derivation
 *       from InputSensorWin.h, plus the schema size guards from input_prov_schema.h —
 *       all with no live process and no Win32 (the header's platform-touching
 *       declarations are #if-guarded out on this host).
 * Target platforms: all (host unit test; no Windows headers pulled in).
 * Interface: drives hk::sdk::win::* pure cores.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

/* The input-sensor façade's pure cores live above the HK_PLATFORM_WINDOWS guard, so
 * this header is includable on the host without Win32. */
#include "backends/win/InputSensorWin.h"
#include "horkos/input_prov_schema.h"

using namespace hk::sdk::win;

/* -------------------------------------------------------------------------
 * Schema size guards. The HK_STATIC_ASSERTs in the header are the compile-time pin;
 * these runtime checks additionally document the 48/104-byte contract the Rust
 * mirror (server/telemetry/src/input_prov.rs) tracks.
 * ------------------------------------------------------------------------- */
TEST(InputSchema, FindingIsFortyEightBytes) {
    EXPECT_EQ(sizeof(hk_input_finding), 48u);
}

TEST(InputSchema, TimingFeaturesAreOneHundredFourBytes) {
    EXPECT_EQ(sizeof(hk_input_timing_features), 104u);
    EXPECT_EQ(HK_INPUT_TIMING_BUCKETS, 16u);
}

/* -------------------------------------------------------------------------
 * Provenance classifier (signals 55/56/57). Table-driven over the decision surface,
 * including the UNRESOLVED guard and the accessibility-gated NULL-hDevice FP case.
 * ------------------------------------------------------------------------- */
TEST(Provenance, QueryFailureIsUnresolved) {
    InputSourceInput in{};
    in.query_failed = true;
    in.hdevice_null = true; /* even with an anomaly present, a failed query wins */
    EXPECT_EQ(classify_input_source(in), HK_INPUT_SRC_UNRESOLVED);
}

TEST(Provenance, NullHDeviceNoGateIsSynthetic) {
    InputSourceInput in{};
    in.hdevice_null = true;
    EXPECT_EQ(classify_input_source(in), HK_INPUT_SRC_SYNTHETIC);
}

TEST(Provenance, NullHDeviceWithAccessibilityGateIsGated) {
    /* OSK / Steam Input / AHK remapper / RDP legitimately produce NULL hDevice when
     * an approved accessibility/remote session is set (plan R7 FP floor). */
    InputSourceInput in{};
    in.hdevice_null = true;
    in.accessibility_gate = true;
    EXPECT_EQ(classify_input_source(in), HK_INPUT_SRC_ACCESSIBILITY_GATED);
}

TEST(Provenance, KnownHDeviceIsPhysical) {
    InputSourceInput in{};
    EXPECT_EQ(classify_input_source(in), HK_INPUT_SRC_PHYSICAL_KNOWN);
}

TEST(Provenance, UnsignedClassFilterIsFilterUnsigned) {
    InputSourceInput in{};
    in.is_class_filter = true;
    in.filter_signed = false;
    EXPECT_EQ(classify_input_source(in), HK_INPUT_SRC_FILTER_UNSIGNED);
}

TEST(Provenance, SignedNonAllowlistedFilterIsFilterForeign) {
    InputSourceInput in{};
    in.is_class_filter = true;
    in.filter_signed = true;
    in.filter_allowlisted = false;
    EXPECT_EQ(classify_input_source(in), HK_INPUT_SRC_FILTER_FOREIGN_SIGNED);
}

TEST(Provenance, SignedAllowlistedFilterIsBenign) {
    /* kbdclass/mouclass/Synaptics/ELAN/etc.: signed + vendor-allowlisted -> benign. */
    InputSourceInput in{};
    in.is_class_filter = true;
    in.filter_signed = true;
    in.filter_allowlisted = true;
    EXPECT_EQ(classify_input_source(in), HK_INPUT_SRC_PHYSICAL_KNOWN);
}

TEST(Provenance, HidSerialBridgeIsEmulatorBridge) {
    InputSourceInput in{};
    in.is_hid_transport = true;
    in.emulator_bridge = true;
    EXPECT_EQ(classify_input_source(in), HK_INPUT_SRC_EMULATOR_BRIDGE);
}

TEST(Provenance, HidNormalTransportIsPhysical) {
    InputSourceInput in{};
    in.is_hid_transport = true;
    in.emulator_bridge = false;
    EXPECT_EQ(classify_input_source(in), HK_INPUT_SRC_PHYSICAL_KNOWN);
}

/* -------------------------------------------------------------------------
 * Ratio folding (signal 55): report the ratio, never a single event.
 * ------------------------------------------------------------------------- */
TEST(Ratio, SingleAnomalyBelowWindowDoesNotReport) {
    RatioWindow w{1, 1}; /* one event, one anomaly: below the min-events floor */
    EXPECT_FALSE(ratio_window_reportable(w, 32));
}

TEST(Ratio, SustainedAnomalyAboveWindowReports) {
    RatioWindow w{256, 9};
    EXPECT_TRUE(ratio_window_reportable(w, 32));
}

TEST(Ratio, NoAnomalyNeverReports) {
    RatioWindow w{256, 0};
    EXPECT_FALSE(ratio_window_reportable(w, 32));
}

/* -------------------------------------------------------------------------
 * RAWMOUSE mode folding (signal 60): oscillation only on the local-console,
 * no-absolute-device case (Wacom/touch/RDP suppressed).
 * ------------------------------------------------------------------------- */
TEST(RawMouse, AbsoluteSetsAbsoluteBit) {
    RawMouseModeInput in{};
    in.flag_absolute = true;
    EXPECT_TRUE(fold_rawmouse_flags(in) & HK_INFLAG_MOUSE_ABSOLUTE);
}

TEST(RawMouse, OscillationOnLocalConsoleNoAbsoluteDevice) {
    RawMouseModeInput in{};
    in.flag_absolute = true;
    in.prior_was_relative = true;
    in.absolute_device_present = false;
    in.remote_session = false;
    EXPECT_TRUE(fold_rawmouse_flags(in) & HK_INFLAG_MODE_OSCILLATION);
}

TEST(RawMouse, AbsoluteDevicePresentSuppressesOscillation) {
    /* A Wacom/touchscreen actually enumerated -> absolute is legitimate, no flag. */
    RawMouseModeInput in{};
    in.flag_absolute = true;
    in.prior_was_relative = true;
    in.absolute_device_present = true;
    EXPECT_FALSE(fold_rawmouse_flags(in) & HK_INFLAG_MODE_OSCILLATION);
}

TEST(RawMouse, RemoteSessionSuppressesOscillation) {
    /* RDP/VNC legitimately reports absolute coordinates. */
    RawMouseModeInput in{};
    in.flag_absolute = true;
    in.prior_was_relative = true;
    in.remote_session = true;
    const uint32_t bits = fold_rawmouse_flags(in);
    EXPECT_FALSE(bits & HK_INFLAG_MODE_OSCILLATION);
    EXPECT_TRUE(bits & HK_INFLAG_REMOTE_SESSION);
}

/* -------------------------------------------------------------------------
 * Synthetic-artifact folding (signal 63): SOFT flags only.
 * ------------------------------------------------------------------------- */
TEST(Synthetic, ScancodeZeroAndExtrainfoUnknownFold) {
    SyntheticArtifactInput in{};
    in.scancode_zero = true;
    in.extrainfo_unknown = true;
    in.gameplay_context = true;
    const uint32_t bits = fold_synthetic_flags(in);
    EXPECT_TRUE(bits & HK_INFLAG_NO_SCANCODE);
    EXPECT_TRUE(bits & HK_INFLAG_EXTRAINFO_UNKNOWN);
    EXPECT_TRUE(bits & HK_INFLAG_GAMEPLAY_CONTEXT);
    EXPECT_FALSE(bits & HK_INFLAG_LLMHF_INJECTED);
}

/* -------------------------------------------------------------------------
 * Timing-feature math (signals 58/62): deterministic, FEATURES ONLY.
 * ------------------------------------------------------------------------- */
TEST(Timing, FixedPeriodHasZeroCovAndMaxRegularity) {
    /* A perfectly regular 1 ms stream (fixed-period macro): CoV == 0, regularity max,
     * and every sample lands in the same histogram bucket. */
    std::vector<uint64_t> deltas(50, 1'000'000ull); /* 1 ms in ns */
    hk_input_timing_features t{};
    compute_timing_features(deltas.data(), (uint32_t)deltas.size(),
                            500'000ull /* 0.5 ms bucket */, t);
    EXPECT_EQ(t.sample_count, 50u);
    EXPECT_EQ(t.cov_x10000, 0u);
    EXPECT_EQ(t.regularity_x10000, 10000u);
    /* 1ms / 0.5ms bucket = bucket index 2; all samples there. */
    EXPECT_EQ(t.period_hist[2], 50u);
    EXPECT_EQ(t.period_hist[0], 0u);
}

TEST(Timing, JitteryStreamHasNonZeroCov) {
    /* Alternating 1 ms / 3 ms deltas: a real (non-macro) jitter -> CoV > 0 and
     * regularity below max. The exact value is deterministic. */
    std::vector<uint64_t> deltas;
    for (int i = 0; i < 50; ++i) {
        deltas.push_back(i % 2 == 0 ? 1'000'000ull : 3'000'000ull);
    }
    hk_input_timing_features t{};
    compute_timing_features(deltas.data(), (uint32_t)deltas.size(),
                            1'000'000ull, t);
    EXPECT_GT(t.cov_x10000, 0u);
    EXPECT_LT(t.regularity_x10000, 10000u);
    EXPECT_EQ(t.sample_count, 50u);
}

TEST(Timing, EmptyOrZeroBucketIsSafe) {
    hk_input_timing_features t{};
    compute_timing_features(nullptr, 0, 1'000'000ull, t);
    EXPECT_EQ(t.sample_count, 0u);
    EXPECT_EQ(t.cov_x10000, 0u);
    for (uint32_t i = 0; i < HK_INPUT_TIMING_BUCKETS; ++i) {
        EXPECT_EQ(t.period_hist[i], 0u);
    }
}

TEST(Timing, LongTailClampsToTopBucket) {
    /* A delta far beyond the histogram range must clamp to the top bucket, not read
     * OOB. */
    std::vector<uint64_t> deltas{100'000'000ull}; /* 100 ms, bucket index >> 15 */
    hk_input_timing_features t{};
    compute_timing_features(deltas.data(), 1, 1'000'000ull, t);
    EXPECT_EQ(t.period_hist[HK_INPUT_TIMING_BUCKETS - 1], 1u);
}

/* -------------------------------------------------------------------------
 * Poll-rate derivation (signal 62) + exemption.
 * ------------------------------------------------------------------------- */
TEST(PollRate, FullSpeedBintervalToHz) {
    /* Full/low-speed: bInterval is the period in ms. bInterval 1 -> 1000 Hz,
     * 10 -> 100 Hz. */
    EXPECT_EQ(declared_hz_from_binterval(1, false), 1000u);
    EXPECT_EQ(declared_hz_from_binterval(10, false), 100u);
}

TEST(PollRate, HighSpeedBintervalToHz) {
    /* High-speed: period = 2^(bInterval-1) microframes of 125us. bInterval 1 ->
     * 8000 Hz, 2 -> 4000 Hz, 4 -> 1000 Hz. */
    EXPECT_EQ(declared_hz_from_binterval(1, true), 8000u);
    EXPECT_EQ(declared_hz_from_binterval(2, true), 4000u);
    EXPECT_EQ(declared_hz_from_binterval(4, true), 1000u);
}

TEST(PollRate, UnknownBintervalIsZero) {
    EXPECT_EQ(declared_hz_from_binterval(0, false), 0u);
    EXPECT_EQ(declared_hz_from_binterval(0, true), 0u);
    EXPECT_EQ(declared_hz_from_binterval(17, true), 0u); /* out of range */
}

TEST(PollRate, BluetoothTransportSuppressesComparison) {
    /* BLE connection-interval legitimately differs from HID bInterval (exemption). */
    hk_input_timing_features t{};
    t.declared_hz = 1000;
    t.transport_flags = HK_INTRANSPORT_BLUETOOTH;
    EXPECT_FALSE(pollrate_comparison_valid(t));
}

TEST(PollRate, ZeroDeclaredSuppressesComparison) {
    hk_input_timing_features t{};
    t.declared_hz = 0; /* hub-walk failed -> no contradiction, never a false positive */
    t.transport_flags = HK_INTRANSPORT_USB;
    EXPECT_FALSE(pollrate_comparison_valid(t));
}

TEST(PollRate, UsbWithDeclaredRateIsComparable) {
    hk_input_timing_features t{};
    t.declared_hz = 1000;
    t.transport_flags = HK_INTRANSPORT_USB;
    EXPECT_TRUE(pollrate_comparison_valid(t));
}
