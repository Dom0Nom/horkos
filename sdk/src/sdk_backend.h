/*
 * sdk/src/sdk_backend.h
 * Role: Internal SDK backend interface. The one platform-specific operation the
 *       SDK needs — probing whether the Horkos kernel driver is present and
 *       reachable — is declared here and implemented per-platform under
 *       sdk/src/backends/ (guardrail #1: platform API only in a backends/ dir).
 * Target platforms: all (declaration only).
 * Interface: implemented by sdk/src/backends/<platform>/DriverProbe*.cpp.
 */

#pragma once

#include "platform.h"

namespace hk { namespace sdk {

/* Returns true if the kernel driver's control device can be opened. A false
 * result means the SDK runs in degraded (userspace-only) mode. */
bool probe_driver();

#if defined(HK_PLATFORM_WINDOWS)
/* Windows-only minifilter altitude census (signal 6). Returns the count of
 * minifilters classified as altitude-squatting / failed-Authenticode
 * adjacent-above Horkos, or -1 on enumeration failure. Read-only; implemented in
 * backends/win/MinifilterCensusWin.cpp. Feeds the SDK report plane, not the
 * kernel ring. */
int minifilter_census();

/* Signal 36 (user-mode half, win-kernel-driver-integrity). Reads
 * HKLM\SYSTEM\CurrentControlSet\Control\ServiceGroupOrder\List and, for the
 * Horkos service, its Start/Group, from a signed user-mode context, and returns a
 * verdict the kernel half (BootLoadAudit.c) correlates with. Read-only.
 * Returns:
 *    0  Horkos appears as a boot/early-start service in an expected group;
 *    1  Horkos's Start/Group is missing or demoted (suppression suspect);
 *   -1  the registry could not be read (indeterminate; not a verdict).
 * Implemented in backends/win/DriverProbeWin.cpp. Feeds the SDK report plane, not
 * the kernel ring; correlation is server-side, never client-thresholded. */
int probe_service_group_order();
#endif

} } // namespace hk::sdk
