# network-anomaly — Implementation Plan

**Scope:** Network-Layer Integrity — read-only sensors that compare the application's own send cadence/clock/queue/route/socket-ownership view against independent OS- and NIC-level ground truth to unmask lag-switches, packet-pacing shims, time-dilation/speed-hacks, and local MITM proxies. Clients sample and report only; all classification and ban authority is server-side. No tampering, injection, or evasion code — every probe is a read-only observation.

**Catalog signals covered:** 181, 182, 183, 184, 185, 186, 187, 188, 189 (`docs/detection-catalog.md` §`network-anomaly`, lines 1887–1977).

Split by where the sensor physically lives (per the catalog's `Horkos slot` lines):

- **Windows-only SDK backends (`sdk/src/backends/win/`):** 181 (NIC HW TX timestamp vs QPC), 183 (kernel `TCP_INFO` vs perceived stall), 185 (raw-input frame timestamp coherence), 188 (route/interface change without OS event), 189 (loopback/local-proxy interposition on the 5-tuple).
- **Cross-platform SDK core (`sdk/src/`), dispatching through `platform/platform.h`:** 182 (monotonic-vs-realtime clock-domain drift), 184 (socket-buffer backlog without OS congestion), 187 (dual-channel RTT via an independent probe socket). Each has a `backends/win/` + `backends/posix/` implementation pair; the core file owns the platform-neutral aggregation and dispatch only.
- **POSIX counterparts (`sdk/src/backends/posix/`):** Linux/macOS halves of 183, 184, 187, 188, 189 (getsockopt `TCP_INFO`, `SIOCOUTQ`/`SO_NWRITE`, rtnetlink, sock_diag).
- **Server-only (`server/ban-engine/src/`):** 186 (client-send-interval vs server-receive-interval auto-correlation). Pure consumer of `TickPayload` fields already present plus the new ones; no client API.

All client probes return fixed POD structs to a single `hk::net` aggregator, which folds them into the per-tick/periodic telemetry sub-payload uploaded over the existing `POST /api/telemetry` plane (`server/telemetry/src/schema.rs::TickPayload`). The client ships raw deltas/flags/pairs; the server is the only classifier (consistent with guardrail: all ban authority server-side).

> **Wire-plane note.** These signals reach the server over the **HTTP/JSON `TickPayload`** plane, NOT the C99 kernel-event ring in `sdk/include/horkos/event_schema.h` / `ioctl.h`. No new `hk_event_type`, no new IOCTL code, no `HK_EVENT_SCHEMA_VERSION` bump is required for any of these nine signals — they are userspace network observations, not kernel callbacks. The `event_schema.h`/`ioctl.h` `HK_STATIC_ASSERT` size pins are therefore untouched. (Signal 185's catalog line mentions "declared alongside event_schema.h additions"; see Risks — the OS-capture input timestamp is a userspace `GetMessageTime`/`RAWINPUT` read, so it belongs on the `TickPayload` plane, not the kernel ring. Flagged below rather than guessed.)

---

## New files

All Windows-only network sensors live under `sdk/src/backends/win/`, all POSIX halves under `sdk/src/backends/posix/`, honoring guardrail #1 (platform API only inside a `backends/` dir; every OS call gated behind `HK_PLATFORM_WINDOWS`/`HK_PLATFORM_LINUX`/`HK_PLATFORM_MACOS`, never raw `_WIN32`/`__linux__`/`__APPLE__`). The cross-platform cores (`sdk/src/*.cpp`) contain NO platform headers — they dispatch through the per-platform backend declared in `net_backend.h` and use `platform/platform.h` time primitives. No userspace TU is shared with any kernel TU (guardrail #4) — none of these files is ever compiled into a kernel image. Every file opens with the role / target-platform / interface module comment (guardrail #3).

| Path | Role | Module-comment summary |
|---|---|---|
| `sdk/include/horkos/net_timing.h` | Public-internal interface declaring the `hk::net` probe surface: one sampler per signal returning a fixed POD result; a `net_collect_all()` aggregator. Plain C99/C++ POD, **no platform headers**. | Role: network-layer integrity sensor interface. Target: all (decl only). Interface: this header IS the `hk::net` sensor surface; `sdk/src/backends/*` + `sdk/src/*Probe*.cpp` implement it; consumed by `sdk/src/sdk.cpp` (`horkos_ac_start`). |
| `sdk/src/net_backend.h` | Internal per-platform dispatch seam for the cross-platform probes (182/184/187): declares the platform ops each `backends/<plat>/Net*.cpp` implements, mirroring `sdk_backend.h`. | Role: internal network backend interface. Target: all (decl only). Interface: implemented per-platform under `sdk/src/backends/<plat>/`; called by the cross-platform cores. |
| `sdk/src/backends/win/NetTimingWin.cpp` | Signal 181: `SIO_TIMESTAMPING` (`WSAIoctl`) + `SO_TIMESTAMP` control messages via `WSARecvMsg`/`WSASendMsg` (`LPFN_WSARECVMSG`) to read NIC/kernel TX timestamp of each uplink datagram vs `QueryPerformanceCounter` app-send time; emits `(qpc_ts, hw_tx_ts)` delta + bound-adapter media type. | Role: NIC-HW-TX-timestamp vs QPC send-cadence sensor. Target: Windows. Interface: implements `hk::net::TxCadenceProbe` from `net_timing.h`. |
| `sdk/src/backends/win/TcpInfoProbeWin.cpp` | Signal 183: `WSAIoctl SIO_TCP_INFO` (`TCP_INFO_v1`) on the game TCP control channel — `SmoothedRtt`, `RetransmitCount`, congestion state — sampled alongside perceived stall. | Role: kernel-TCP_INFO vs perceived-stall sensor. Target: Windows. Interface: implements `hk::net::ConnHealthProbe` (Windows half). |
| `sdk/src/backends/win/InputFrameProbeWin.cpp` | Signal 185: `GetMessageTime` / `GetRawInputData` (`RAWINPUT`) OS-capture timestamps + `GetCurrentInputMessageSource` (injected-vs-hardware origin) correlated against the outbound input-frame send sequence; flags non-monotonic/duplicate/backdated frames. | Role: raw-input frame timestamp-coherence sensor. Target: Windows. Interface: implements `hk::input::FrameCoherenceProbe`. |
| `sdk/src/backends/win/RouteWatchWin.cpp` | Signal 188: `NotifyRouteChange2` / `NotifyIpInterfaceChange` / `NotifyUnicastIpAddressChange` (iphlpapi) callbacks + `GetBestInterfaceEx` for the game destination; snapshots bound-interface/route identity hash + a "changed-without-event" flag. | Role: route/interface-change-without-OS-event sensor. Target: Windows. Interface: implements `hk::net::RouteIntegrityProbe` (Windows half). |
| `sdk/src/backends/win/SocketTableProbeWin.cpp` | Signal 189: `GetExtendedTcpTable`/`GetExtendedUdpTable` (`TCP/UDP_TABLE_OWNER_PID_ALL`) to map the game flow to owning PID + remote endpoint; flags loopback/local owner and emits owner image hash. | Role: loopback/local-proxy interposition (5-tuple owner) sensor. Target: Windows. Interface: implements `hk::net::FlowOwnerProbe` (Windows half). |
| `sdk/src/backends/win/NetBackendWin.cpp` | Windows half of the cross-platform probes (182/184/187): `QueryPerformanceCounter` vs `GetSystemTimePreciseAsFileTime`/`QueryUnbiasedInterruptTimePrecise`/`__rdtsc`; `SIO_IDEAL_SEND_BACKLOG_QUERY`; dedicated probe socket. | Role: Windows backend for clock-drift/backlog/probe-RTT probes. Target: Windows. Interface: implements `net_backend.h`. |
| `sdk/src/backends/posix/TcpInfoProbePosix.cpp` | Signal 183 POSIX half: `getsockopt(SOL_TCP, TCP_INFO)` `tcpi_rtt`/`tcpi_retrans` (Linux) and the macOS `TCP_CONNECTION_INFO` equivalent. | Role: kernel-TCP_INFO sensor (POSIX). Target: Linux + macOS. Interface: implements `hk::net::ConnHealthProbe` (POSIX half). |
| `sdk/src/backends/posix/RouteWatchPosix.cpp` | Signal 188 POSIX half: rtnetlink `NETLINK_ROUTE` (`RTMGRP_IPV4_ROUTE`/`RTM_NEWROUTE`/`RTM_NEWLINK`) link/route event watch + bound-interface snapshot. | Role: route/interface integrity sensor (POSIX). Target: Linux (macos via PF_ROUTE — see Risks). Interface: implements `hk::net::RouteIntegrityProbe` (POSIX half). |
| `sdk/src/backends/posix/SocketTableProbePosix.cpp` | Signal 189 POSIX half: Linux sock_diag `INET_DIAG` (netlink) / `/proc/net/{tcp,udp}`; macOS `proc_pidfdinfo`/`PROC_PIDFDSOCKETINFO`. | Role: flow-owner / loopback-interposer sensor (POSIX). Target: Linux + macOS. Interface: implements `hk::net::FlowOwnerProbe` (POSIX half). |
| `sdk/src/backends/posix/NetBackendPosix.cpp` | POSIX half of 182/184/187: `clock_gettime(CLOCK_MONOTONIC_RAW)` vs `CLOCK_REALTIME`; `ioctl(SIOCOUTQ)`/`TIOCOUTQ` (Linux) + `getsockopt(SO_NWRITE)`/`FIONWRITE` (macOS); probe socket with `SO_TIMESTAMPING` RX times (Linux). | Role: POSIX backend for clock-drift/backlog/probe-RTT probes. Target: Linux + macOS. Interface: implements `net_backend.h`. |
| `sdk/src/ClockDomainProbe.cpp` | Signal 182 cross-platform core: computes the per-window rate ratio of the two clock domains; dispatches the raw reads through `net_backend.h`; step-vs-slope discrimination of NTP corrections done server-side, client ships the ratio. | Role: monotonic-vs-realtime clock-domain drift sensor (core). Target: cross. Interface: implements `hk::net::ClockDomainProbe`; uses `platform/platform.h` + `net_backend.h`. |
| `sdk/src/SendBacklogProbe.cpp` | Signal 184 cross-platform core: pairs app-side send-ring depth with kernel unsent bytes; dispatches the kernel-buffer read through `net_backend.h`. | Role: held-uplink / send-backlog sensor (core). Target: cross. Interface: implements `hk::net::SendBacklogProbe`. |
| `sdk/src/ProbeChannel.cpp` | Signal 187 cross-platform core: owns a dedicated low-rate UDP echo socket to the same server IP (separate ephemeral port), timestamps RTT, emits `(game_rtt, probe_rtt)` pairs; raw socket I/O via `net_backend.h`. | Role: dual-channel probe-RTT divergence sensor (core). Target: cross. Interface: implements `hk::net::ProbeChannelProbe`. |
| `server/ban-engine/src/arrival_cadence.rs` | Signal 186 server-only: running auto-correlation / gap-then-burst detector over `TickPayload` arrival deltas vs tick deltas; conservation-ratio test; threshold carried as a signed rule via existing bundle plumbing. Fully async-safe (pure compute, no I/O), `thiserror`, no `unwrap()` outside tests (guardrail #8). | Role: relativistic-burst (lag-switch) arrival-cadence detector. Target: server. Interface: `mod arrival_cadence` under `server/ban-engine`; consumes `telemetry::schema::TickPayload`. |
| `bypass-tests/win/network/*`, `bypass-tests/linux/network/*`, `bypass-tests/macos/network/*` | Bypass tests, one per merge-gated network sensor (guardrail #12). See Test strategy. | Role: network-sensor bypass merge gate. Target: per-platform. Interface: drives each `hk::net` probe against a synthetic interposer/shim. |

**Header additions (not new files):**
- `server/telemetry/src/schema.rs`: new `TickPayload` fields (see below); `SCHEMA_VERSION` bumped 1 → 2.
- `server/api/data-categories.md`: one new row per new telemetry field, in the same PR (guardrail #11).
- `sdk/CMakeLists.txt`: add the new sources to the `hk_sdk` backend selection (Build wiring).
- `server/ban-engine/src/lib.rs`: `pub mod arrival_cadence;`.

No change to `sdk/include/horkos/event_schema.h` or `sdk/include/horkos/ioctl.h` (see wire-plane note).

---

## Interfaces & data structures

### Client sensor surface (`sdk/include/horkos/net_timing.h`)

Plain POD result structs, fixed-size, **no platform headers** in the header (platform calls live in the `.cpp` backends). Sketch (field names chosen to map 1:1 onto the new `schema.rs` fields):

```c
namespace hk { namespace net {

typedef struct tx_cadence {            /* signal 181 */
    int64_t  tx_cadence_skew_ns;       /* sustained (qpc_ts - hw_tx_ts) cadence delta, ns */
    uint32_t queue_depth_growth;       /* monotone TX-lag growth over the window (0 = none) */
    uint32_t adapter_is_tunnel;        /* 1 if bound media type is tunnel/virtual (excludes FP) */
} tx_cadence;

typedef struct conn_health {           /* signal 183 */
    uint32_t conn_rtt_us;              /* kernel SmoothedRtt / tcpi_rtt (microseconds) */
    uint32_t conn_retrans;             /* RetransmitCount / tcpi_retrans over window */
    uint32_t app_perceived_stall;      /* 1 if app saw a stall this window */
    uint32_t reserved;
} conn_health;

typedef struct send_backlog {          /* signal 184 */
    uint32_t app_queue_depth;          /* unsent bytes in the app send ring */
    uint32_t kernel_unsent_bytes;      /* SIOCOUTQ / SO_NWRITE / ideal-send-backlog query */
    uint32_t link_congested;           /* OS-reported congestion (0 = link idle) */
    uint32_t proc_starved;             /* 1 if scheduler-starved (FP gate) */
} send_backlog;

typedef struct clock_drift {           /* signal 182 */
    int32_t  clock_ratio_ppm;          /* sustained monotonic/realtime rate drift, ppm */
    uint32_t step_detected;            /* 1 if a discrete step (NTP-like) occurred in window */
} clock_drift;

typedef struct rtt_divergence {        /* signal 187 */
    uint32_t game_rtt_us;
    uint32_t probe_rtt_us;             /* independent probe-socket RTT to same server IP */
    uint32_t same_port_class;          /* 1 if probe shares port-range class (benign-QoS gate) */
    uint32_t reserved;
} rtt_divergence;

typedef struct route_integrity {       /* signal 188 */
    uint64_t route_identity_hash;      /* hash of bound-iface idx + gateway + src addr */
    uint32_t route_change_unattested;  /* 1 if path identity changed with NO OS route/link event */
    uint32_t reserved;
} route_integrity;

typedef struct flow_owner {            /* signal 189 */
    uint32_t flow_owner_local;         /* 1 if game flow terminates at loopback/local PID */
    uint32_t reserved;
    uint8_t  owner_image_hash[32];     /* SHA-256 of the interposing owner image, if any */
} flow_owner;

typedef struct input_frame_coherence { /* signal 185 */
    uint32_t input_frame_anomaly_flags; /* bitfield: non-monotonic / duplicate / backdated / synthetic-origin */
} input_frame_coherence;

/* Aggregate -> one network sub-payload per upload window. */
typedef struct net_report {
    tx_cadence            tx;          /* 181 */
    clock_drift           clk;         /* 182 */
    conn_health           conn;        /* 183 */
    send_backlog          backlog;     /* 184 */
    input_frame_coherence input;       /* 185 */
    rtt_divergence        rtt;         /* 187 */
    route_integrity       route;       /* 188 */
    flow_owner            owner;       /* 189 */
} net_report;                          /* 186 is server-only; absent here */

net_report net_collect_all(void);

} } /* namespace hk::net */
```

`input_frame_anomaly_flags` bit assignments (mirror server-side):
`0x1` non-monotonic, `0x2` duplicate-timestamp, `0x4` backdated, `0x8` `GetCurrentInputMessageSource` reports synthetic origin (soft signal, scored not verdict).

### Server ingest contract (`server/telemetry/src/schema.rs`)

Add the network fields to `TickPayload`. These are JSON serde fields (this plane is **not** `#[repr(C)]`; no `HK_STATIC_ASSERT` applies — those pins live only on the C99 `event_schema.h`/`ioctl.h` plane and are untouched). `#[serde(default)]` on every new field so older clients (schema_version 1) still deserialize, with the ingest handler accepting both versions during rollout. Bump `SCHEMA_VERSION` 1 → 2.

```rust
// appended to TickPayload, all #[serde(default)]:
pub tx_cadence_skew_ns: i64,        // 181
pub clock_ratio_ppm: i32,          // 182
pub conn_rtt_us: u32,              // 183
pub conn_retrans: u32,             // 183
pub app_queue_depth: u32,          // 184
pub kernel_unsent_bytes: u32,      // 184
pub input_frame_anomaly_flags: u32,// 185
pub game_rtt_us: u32,              // 187
pub probe_rtt_us: u32,             // 187
pub route_change_unattested: u32,  // 188 (0/1)
pub flow_owner_local: u32,         // 189 (0/1)
pub owner_image_hash: String,      // 189 (hex SHA-256; "" = none)
```

Signal 186 (`arrival_cadence.rs`) adds **no** field — it consumes the existing `tick` and `server_received_ts` (already set by `ingest()` server-side). Its threshold parameters ride as a signed rule through the existing `RuleBundle`/`BundleLoader` plumbing in `server/ban-engine/src/bundle.rs`.

### data-categories.md (guardrail #11 — same PR)

New rows under **§3 Telemetry stream (per-tick)** for each of the 12 new fields above, each: Source = `client (hk::net probe)` (or `server clock` for 186-derived intervals), Retention = `session lifetime + 30 days`, Legal basis = `Legitimate interest — anti-cheat enforcement`, Operator = `Horkos Service Operator`. `owner_image_hash` cross-references the existing `image_sha256` catalog (§1) for signed-known-good interposer allowlisting (189's FP gate). The PR is rejected at review if any field above lacks a row.

---

## Mechanism implementation notes

Grouped by platform-safety concern. Every API name below is taken from the catalog `Refs` lines.

### Windows usermode (no kernel TU; IRQL/IRP not in scope)

These probes run at PASSIVE_LEVEL in the game process — no driver code, so no IRQL/IRP-lifetime concerns and no `event_schema.h`/`ioctl.h` impact.

- **181 (`NetTimingWin.cpp`):** enable `SIO_TIMESTAMPING` via `WSAIoctl`, request TX timestamps; receive them through `WSASendMsg`/`WSARecvMsg` `WSAMSG` control buffers (`SO_TIMESTAMP`). Resolve `LPFN_WSARECVMSG` via `WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER)`. Read app-send time with `QueryPerformanceCounter`. **FP/correctness gate (in the report, not the verdict):** only set `queue_depth_growth` on sustained directional TX-lag; set `adapter_is_tunnel` from the bound adapter media type so the server can exclude VPN/virtual NICs (LSO/coalescing FP). Timestamp support is NIC/driver-dependent — when unsupported, emit a sentinel (skew = `INT64_MIN`) so the server treats it as "no data," never as a positive.
- **183 (`TcpInfoProbeWin.cpp`):** `WSAIoctl(SIO_TCP_INFO)` with `TCP_INFO_v1`; this only applies to the TCP control/matchmaking channel, not the UDP game channel (the contradiction it surfaces is "TCP healthy while UDP stalls"). `GetPerTcpConnectionEStats` is the documented fallback if `SIO_TCP_INFO` is unavailable on the target Windows build.
- **185 (`InputFrameProbeWin.cpp`):** `GetMessageTime` and `GetRawInputData` (`RAWINPUT`, `RIM_INPUT`/`RIM_INPUTSINK`) for OS-capture timestamps; `GetCurrentInputMessageSource` to tag injected vs hardware origin. Synthetic-origin frames are a **soft** flag (`0x8`) scored server-side — legitimate macro/remap/remote-desktop software synthesizes input. Read-only: the probe never injects or rewrites input.
- **188 (`RouteWatchWin.cpp`):** register `NotifyRouteChange2`/`NotifyIpInterfaceChange`/`NotifyUnicastIpAddressChange` callbacks; snapshot the `GetBestInterfaceEx` result for the game destination each window. The positive is specifically *path identity changed AND no notification fired* — benign reroutes go through the OS stack and DO fire, so the absence is the discriminator. Callbacks run on an OS worker thread → the snapshot store must be lock-free or mutex-guarded; no blocking in the callback.
- **189 (`SocketTableProbeWin.cpp`):** `GetExtendedTcpTable`/`GetExtendedUdpTable` with `TCP_TABLE_OWNER_PID_ALL`/`UDP_TABLE_OWNER_PID_ALL`; resolve the game 5-tuple's owning PID and remote endpoint. **High FP risk** (corporate TLS inspection, Steam/Epic overlay, NetLimiter): `flow_owner_local` is a low-weight contextual signal, escalated server-side only when it coincides with cadence/RTT anomalies; `owner_image_hash` lets the server allowlist signed known-good interposers against the existing `image_sha256` catalog.

### Cross-platform cores + POSIX backends (Linux `-Wall -Wextra -Werror`; macOS)

Cores in `sdk/src/*.cpp` carry no platform headers; the POSIX `.cpp` halves do and must build clean under the project's kernel-grade flags where they touch Linux. CO-RE applies only to eBPF — these are **userspace** POSIX sources, so no BTF/CO-RE relocation concerns, but they still compile `-Wall -Wextra -Werror`: initialize every `struct sockaddr`/`msghdr`/`nlmsghdr`, check every `getsockopt`/`ioctl`/`recvmsg` return, no unused-variable/sign-compare warnings.

- **182 (`ClockDomainProbe.cpp` + `NetBackend*.cpp`):** Linux/macOS `clock_gettime(CLOCK_MONOTONIC_RAW)` vs `clock_gettime(CLOCK_REALTIME)`; Windows `QueryPerformanceCounter` vs `GetSystemTimePreciseAsFileTime`/`QueryUnbiasedInterruptTimePrecise`/`__rdtsc`. Client computes the per-window rate ratio and ships it plus a `step_detected` flag; the *NTP-step vs smooth-scale* discrimination (the real classifier) is server-side per the catalog FP gate.
- **184 (`SendBacklogProbe.cpp` + backends):** Linux `ioctl(SIOCOUTQ)`/`TIOCOUTQ`; macOS `getsockopt(SO_NWRITE)`/`FIONWRITE`; Windows `SIO_IDEAL_SEND_BACKLOG_QUERY`/`SIO_IDEAL_SEND_BACKLOG_CHANGE`. Pairs `app_queue_depth` with `kernel_unsent_bytes`. FP gate: also report `proc_starved` (cross-check scheduler health) so a CPU-starved send thread isn't misread as a held uplink.
- **187 (`ProbeChannel.cpp` + backends):** a dedicated low-rate UDP echo socket on a separate ephemeral port to the same server IP, timestamped with `QueryPerformanceCounter`/`clock_gettime`; Linux `SO_TIMESTAMPING` for kernel RX times. Emits `(game_rtt, probe_rtt)`. The socket is the integrity client's own; the server endpoint must run a matching echo responder (a dependency milestone). FP gate: `same_port_class` lets the server discount benign per-port QoS.

### macOS

No System Extension / EndpointSecurity involvement — these are userspace BSD-socket reads in the SDK, so guardrail #7 (never drop an ES event without a reply) does not apply here. macOS halves use `TCP_CONNECTION_INFO` (183), `SO_NWRITE` (184), `proc_pidfdinfo`/`PROC_PIDFDSOCKETINFO` (189). macOS route-watch (188) uses `PF_ROUTE` sockets rather than Linux rtnetlink — see UNCERTAINTY FLAGS.

### Server (tokio / no-unwrap — guardrail #8)

- **186 (`arrival_cadence.rs`):** pure synchronous compute invoked from the async ingest path — no blocking syscalls, no `.await` inside, so it cannot stall a tokio worker. Maintains a per-`player_id` ring of `(tick, server_received_ts)` and computes the gap-then-burst auto-correlation + conservation ratio (burst displacement ≈ gap duration × tick rate). Errors via `thiserror` (`BanEngineError`-style); zero `unwrap()`/`expect()`/`panic!` outside `#[cfg(test)]`. Per-player state behind a bounded structure to cap memory (DoS gate). Thresholds arrive as a signed rule through `BundleLoader` — the fail-closed verifier in `bundle.rs` still governs; no unsigned rule path.
- **Ingest of new fields:** `server/telemetry/src/lib.rs::ingest` already validates `schema_version`; extend it to accept `2` and (during rollout) `1`. New fields are `#[serde(default)]`, so a v1 client deserializes with zeros. No `unwrap()` added.

---

## Build wiring

- **`sdk/CMakeLists.txt`:** extend the existing `if(WIN32)/else()` backend split. Append the Windows network sources (`NetTimingWin.cpp`, `TcpInfoProbeWin.cpp`, `InputFrameProbeWin.cpp`, `RouteWatchWin.cpp`, `SocketTableProbeWin.cpp`, `NetBackendWin.cpp`) to the WIN32 branch and the POSIX sources (`TcpInfoProbePosix.cpp`, `RouteWatchPosix.cpp`, `SocketTableProbePosix.cpp`, `NetBackendPosix.cpp`) to the `else()` branch. The cross-platform cores (`ClockDomainProbe.cpp`, `SendBacklogProbe.cpp`, `ProbeChannel.cpp`) go in the unconditional `hk_sdk` source list. Windows backends link `ws2_32` + `iphlpapi`; Linux needs no extra lib (netlink/ioctl are in libc); macOS links nothing extra (`proc_pidfdinfo` is in libSystem).
- **Feature flag:** gate the whole network-sensor set behind a CMake option `HK_NET_SENSORS` (**default ON** — these are core AC sensors, unlike the eBPF gate). Signal 187's probe socket additionally behind `HK_NET_PROBE_CHANNEL` (**default OFF** until the server echo responder ships, since it opens an extra socket and needs the server side).
- **Toolchain:** SDK is the existing C++17 `hk_sdk` static lib (clang/MSVC), no new toolchain. Windows backends need the Win10+ SDK headers for `SIO_TCP_INFO`/`TCP_INFO_v1` and `SIO_TIMESTAMPING` — pin the minimum SDK in the WIN32 branch (flag if the CI image lacks it). No WDK (no kernel code), no clang-19/obfuscator, no libbpf (no eBPF), no Xcode SysExt.
- **Server:** `server/ban-engine/src/lib.rs` gains `pub mod arrival_cadence;`. No new crate; reuses `telemetry::schema::TickPayload` (add `ban-engine` → `telemetry` dep in `server/ban-engine/Cargo.toml` if not already present, or move the shared `TickPayload` to a common crate — flag the dependency direction at review). No new runtime deps; `ort` untouched.

---

## Test strategy

### Unit tests
- **Client (CTest, per backend):** each probe samples against a synthetic baseline and asserts the POD result shape + sentinel-on-unsupported behavior. `ClockDomainProbe`: feed two synthetic clock sources at a known ratio, assert `clock_ratio_ppm`. `SendBacklogProbe`: mock kernel-unsent vs app-queue, assert the discriminator. `ProbeChannel`: loopback echo, assert `(game_rtt, probe_rtt)` populated.
- **Server (`cargo test`):** `arrival_cadence.rs` table tests — (a) stationary jittered arrivals → no detection; (b) engineered gap-then-burst with conservation ratio ≈ 1 repeated N times → detection; (c) single NAT-rebind gap-then-burst (once) → no detection (FP gate). `schema.rs`: a v1 JSON payload (no network fields) still deserializes (`#[serde(default)]`); a v2 payload round-trips. No `unwrap()` in non-test code asserted by `clippy`/grep gate.

### Bypass tests (guardrail #12 — merge gate; one per security-folder sensor)
Each lives under `bypass-tests/<plat>/network/` with a CMake target + `add_test` mirroring `bypass-tests/win/CMakeLists.txt`, built disabled in scaffold form and enabled (with fixture) when the sensor logic lands under `/tdd`:

| Bypass test | Must demonstrate |
|---|---|
| `hk_bypass_net_txcadence` (win) | A userland send-shim that buffers+re-bursts datagrams produces TX-vs-QPC divergence the `TxCadenceProbe` reports (and that a clean send loop does not). |
| `hk_bypass_net_clockdrift` (linux/macos/win) | A scaled clock source (monotonic at 0.8× realtime) yields the expected `clock_ratio_ppm`, while an NTP-style step does not trip the smooth-scale path. |
| `hk_bypass_net_tcpinfo` (win/linux) | A selective UDP-drop lag-switch leaves kernel `TCP_INFO` healthy while the app perceives stall — the contradiction is captured. |
| `hk_bypass_net_backlog` (linux/macos/win) | A held-uplink (paused send thread) shows app-queue rising while kernel unsent stays ~0 and link reports no congestion; a genuinely congested link does not. |
| `hk_bypass_net_inputframe` (win) | A replayed/duplicated input frame breaks the OS-capture monotonic timestamp invariant and sets the anomaly flag; a hardware-origin frame does not. |
| `hk_bypass_net_arrival_cadence` (server, `cargo test`) | The relativistic gap-then-burst signature is detected over repeated occurrences and not on a single benign handover. |
| `hk_bypass_net_probertt` (linux/macos/win) | A game-port-only throttle diverges `probe_rtt` from `game_rtt`; symmetric path congestion hits both equally (no divergence). |
| `hk_bypass_net_route` (win/linux) | A TAP/proxy that shifts the on-wire path without an OS route/link event sets `route_change_unattested`; a real OS-mediated reroute fires the notification and does not. |
| `hk_bypass_net_flowowner` (win/linux/macos) | A loopback MITM proxy on the game 5-tuple is observed as a local owner PID; a direct connection to the server IP is not. A signed allowlisted interposer is reported but down-weighted. |

`bypass-tests/<plat>/network/CMakeLists.txt` added to each platform's existing bypass CMake. Any future change under `sdk/src/backends/*/Net*` or `arrival_cadence.rs` without touching the matching bypass test is rejected (guardrail #12).

---

## Sequencing

1. **Schema + data-categories first (server, no client dep).** Add the 12 `TickPayload` fields (`#[serde(default)]`), bump `SCHEMA_VERSION` → 2, extend `ingest()` to accept v1+v2, add data-categories.md rows. Unblocks every downstream signal and satisfies guardrail #11 up front. Land with `schema.rs` round-trip tests.
2. **`net_timing.h` + `net_backend.h` interfaces.** POD result structs + aggregator + dispatch seam. No logic. Lets backends and the SDK aggregator compile against a stable surface (guardrail #10 spirit).
3. **Signal 186 (`arrival_cadence.rs`).** Server-only, zero client dependency, highest immediate value (catches lag-switch from data already flowing). Land with its bypass test + FP-gate unit tests.
4. **Cross-platform cores 182 / 184 (clock drift, backlog).** Both have low FP risk and need only `platform/` primitives + simple socket reads. Land core + Win/POSIX backends + bypass tests together.
5. **Windows backends 181 / 183 / 185 / 188 / 189.** Independent of each other; sequence by FP risk ascending: 183 → 185 → 188 → 181 → 189 (189 is highest-FP, lands last with the image-hash allowlist wired to the §1 catalog).
6. **Signal 187 (probe channel)** last among client signals — requires the **server-side echo responder** (a paired server milestone) before `HK_NET_PROBE_CHANNEL` flips ON. Until then it ships flag-OFF.
7. **POSIX parity pass.** Fill remaining Linux/macOS halves (rtnetlink/PF_ROUTE for 188, sock_diag/`proc_pidfdinfo` for 189) once the Windows reference behavior is validated.

Dependencies: all of 1 → everything; 2 → all client signals; 187 → server echo responder; 186 is independent and can land in parallel with 2.

---

## Risks & UNCERTAINTY FLAGS

Flagged rather than guessed (guardrail #13 — when uncertain about an OS API or signing/route semantic, stop and flag):

- **[FLAG — schema-plane ambiguity, 185]** The catalog's signal-185 slot says "declared alongside `event_schema.h` additions." I have placed signal 185 (and all nine) on the **HTTP `TickPayload` JSON plane, NOT** the C99 kernel-event ring. Rationale: `GetMessageTime`/`RAWINPUT`/`GetCurrentInputMessageSource` are userspace reads, not kernel callbacks, and the kernel ring (`event_schema.h`/`ioctl.h`) is for KMDF/eBPF/daemon process/image/handle records (guardrail #4 — never a shared TU). **Confirm before coding** whether the product wants any of these mirrored onto the kernel ring (would require a new `hk_event_type`, payload struct, `HK_STATIC_ASSERT`, and `HK_EVENT_SCHEMA_VERSION` bump). My plan assumes NO kernel-ring change.
- **[FLAG — Windows `SIO_TIMESTAMPING` availability, 181]** NIC/software TX timestamping via `SIO_TIMESTAMPING` (`WSAIoctl`) is **driver- and Windows-build-dependent**; not all NICs expose hardware TX timestamps and the WSA timestamping API surface has shifted across Win10/11 builds. I have **not** asserted a minimum build or guaranteed HW-timestamp support. Verify the exact `WSAIoctl SIO_TIMESTAMPING` control structure and per-adapter capability query on the target Windows baseline before relying on it; emit the no-data sentinel where unsupported rather than a false positive.
- **[FLAG — `SIO_TCP_INFO` / `TCP_INFO_v1` version, 183]** `TCP_INFO_v0` vs `_v1` availability is Windows-build-gated. Confirm the minimum supported build exposes `_v1` (else fall back to `GetPerTcpConnectionEStats`). Not assumed.
- **[FLAG — macOS route-watch mechanism, 188]** Linux uses rtnetlink (`NETLINK_ROUTE`); macOS has no rtnetlink. The macOS equivalent is a `PF_ROUTE` socket (`RTM_*` messages). I have **not** verified the exact `PF_ROUTE` message set needed to detect "path changed without OS event" on current macOS — flag for verification; macOS 188 may ship later than the Win/Linux halves.
- **[FLAG — `GetCurrentInputMessageSource` injected-origin fidelity, 185]** Whether this API reliably distinguishes hardware vs every class of synthetic input (some remote-desktop/accessibility stacks may present as hardware) is **not certain**. Treated strictly as a soft, server-scored flag, never a standalone verdict.
- **[FP — high, 189]** Loopback/local-proxy interposition has high benign-software overlap (TLS inspection, overlays, NetLimiter). Mitigation is server-side low weight + signed-image allowlist; the client must never act on it. Documented, not a code uncertainty.
- **[Dependency, 187]** Requires a server-side UDP echo responder that does not yet exist; signal ships flag-OFF until that lands. Not an API uncertainty, a sequencing dependency.
- **[Crate dependency direction]** `arrival_cadence.rs` consuming `telemetry::schema::TickPayload` introduces a `ban-engine` → `telemetry` dependency. Confirm the workspace dependency direction at review (or extract `TickPayload` into a shared `schema` crate) to avoid a cycle if `telemetry` ever needs `ban-engine`.
- **No kernel-API (IRQL/IRP/Ob), no ES auth-deadline, and no code-signing uncertainties apply** to this domain: every sensor is userspace BSD/Winsock/iphlpapi or server-side Rust. The one genuine kernel-adjacent concern (Windows route-change callbacks running on an OS worker thread) is a threading concern, not an IRQL one — handled with a lock-free/guarded snapshot store.
