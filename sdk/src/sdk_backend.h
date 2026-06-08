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

namespace hk { namespace sdk {

/* Returns true if the kernel driver's control device can be opened. A false
 * result means the SDK runs in degraded (userspace-only) mode. */
bool probe_driver();

} } // namespace hk::sdk
