/*
 * Role: Signal 96 — kernel lockdown level + module-signature-enforcement
 *       posture. Reads /sys/kernel/security/lockdown,
 *       /sys/module/module/parameters/sig_enforce, /proc/sys/kernel/tainted, and
 *       the efivarfs SecureBoot variable; emits HK_EVENT_KERNEL_POSTURE. This is
 *       a POSTURE WEIGHT, never standalone ban evidence (catalog: high FP) — an
 *       absent securityfs/efivarfs is "unknown", not "insecure".
 * Target platform: Linux userspace (guardrail #4).
 * Interface: pure parsers for each source + ComputePosture(...) over fixtures;
 *            live entry hk_sensor_posture(). Audit-only / read-only.
 */

#pragma once

#include <cstdint>
#include <string>

#include "HostIntegritySensors.h"
#include "SymbolMap.h"

namespace horkos::modint {

constexpr uint32_t HK_POSTURE_UNKNOWN = 0xFFFFFFFFu;

/* Parse /sys/kernel/security/lockdown content of the form:
 *   "[none] integrity confidentiality"   (brackets mark the active level)
 * Returns 0=none, 1=integrity, 2=confidentiality, or HK_POSTURE_UNKNOWN. */
uint32_t ParseLockdownLevel(const std::string& content);

/* Parse sig_enforce ("Y"/"N"/"1"/"0"). Returns 1, 0, or HK_POSTURE_UNKNOWN. */
uint32_t ParseSigEnforce(const std::string& content);

/* Parse /proc/sys/kernel/tainted (a decimal bitmask). Returns 0 if unreadable. */
uint32_t ParseTainted(const std::string& content);

/* Decode the efivarfs SecureBoot variable raw bytes. The variable is a 4-byte
 * attribute prefix followed by a 1-byte value (1 = enabled). Returns 1, 0, or
 * HK_POSTURE_UNKNOWN for a malformed/empty buffer. */
uint32_t ParseSecureBoot(const std::string& raw_bytes);

/* Build the posture payload from the four already-read sources. Always emits one
 * HK_EVENT_KERNEL_POSTURE (posture is reported every cycle, even when fields are
 * unknown — the server weights unknowns as coverage, not insecurity). */
void ComputePosture(uint32_t lockdown, uint32_t sig_enforce, uint32_t secure_boot,
                    uint32_t taint, HkEventSink sink);

/* Live sensor entry (HkHostSensorFn). */
int hk_sensor_posture(const HkSymbolMap* map, HkEventSink sink);

}  // namespace horkos::modint
