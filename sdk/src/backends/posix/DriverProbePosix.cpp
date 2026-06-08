/*
 * sdk/src/backends/posix/DriverProbePosix.cpp
 * Role: POSIX (Linux/macOS) implementation of the SDK driver probe. Phase 3
 *       has no Linux/macOS kernel component yet (Phase 4), so the probe always
 *       reports "no driver" and the SDK runs in degraded mode. Phase 4 replaces
 *       this with a real eBPF/daemon liveness check. Keeping the probe in a
 *       backends/ folder satisfies guardrail #1 and lets the SDK + example
 *       build and run on the macOS/Linux dev host today.
 * Target platforms: Linux, macOS.
 * Interface: implements hk::sdk::probe_driver from sdk/src/sdk_backend.h.
 */

#include "sdk_backend.h"

namespace hk { namespace sdk {

bool probe_driver()
{
    return false;
}

} } // namespace hk::sdk
