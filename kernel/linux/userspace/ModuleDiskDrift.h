/*
 * kernel/linux/userspace/ModuleDiskDrift.h
 * Role: Signal 95 (userspace half) — in-memory-vs-on-disk module integrity by
 *       build-id. Reads each loaded module's GNU build-id from
 *       /sys/module/<m>/notes/.note.gnu.build-id and compares it against the
 *       build-id parsed from the backing on-disk .ko under
 *       /lib/modules/$(uname -r). A same-name mismatch, or a module with no
 *       backing .ko, is the substitution tell. Emits HK_EVENT_MODULE_DISK_DRIFT.
 *       (The in-memory ksymtab-CRC half needs the gated LKM — §1.3 — and is not
 *       implemented here.)
 * Target platform: Linux userspace (guardrail #4).
 * Interface: pure helpers ParseBuildIdNote / CompareBuildId over fixtures; live
 *            entry hk_sensor_module_disk(). Audit-only / read-only.
 *
 * FP gate (§6): the ON-DISK .ko build-id is the reference (NOT a central
 * baseline), so DKMS rebuilds (NVIDIA/VBox/ZFS/v4l2loopback) do not trip — a
 * rebuild changes BOTH the memory and disk build-id consistently. Only a memory-
 * vs-disk divergence for the SAME file, or a missing backing .ko, is flagged.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "HostIntegritySensors.h"
#include "SymbolMap.h"

namespace horkos::modint {

/* Extract the build-id bytes from a raw .note.gnu.build-id ELF note section
 * (4-byte namesz, 4-byte descsz, 4-byte type=NT_GNU_BUILD_ID(3), "GNU\0" name,
 * then descsz id bytes). Returns the id bytes, or empty on a malformed note. */
std::vector<uint8_t> ParseBuildIdNote(const std::string& raw_note);

/* Compare two build-ids. Returns true when both are non-empty and equal. */
bool CompareBuildId(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);

/* Decision over one module given its in-memory and on-disk build-ids and whether
 * the on-disk .ko was found. Emits at most one HK_EVENT_MODULE_DISK_DRIFT:
 *   - disk missing            → NO_DISK_KO
 *   - both present but differ → BUILDID_MISMATCH
 *   - match                   → nothing
 * Returns 1 if an event was emitted, else 0. A module whose IN-MEMORY build-id
 * is unreadable is skipped (coverage gap handled by the caller, not a drift). */
int AnalyzeModuleDisk(const std::string& module_name,
                      const std::vector<uint8_t>& mem_build_id,
                      const std::vector<uint8_t>& disk_build_id,
                      bool disk_found, HkEventSink sink);

/* Live sensor entry (HkHostSensorFn). */
int hk_sensor_module_disk(const HkSymbolMap* map, HkEventSink sink);

}  // namespace horkos::modint
