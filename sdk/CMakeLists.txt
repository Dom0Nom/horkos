# sdk/CMakeLists.txt
# hk_sdk — public SDK static library (Phase 3). Platform-neutral core plus a
# per-platform driver-probe backend selected here (mirrors the platform/ split;
# guardrail #1 keeps platform API inside backends/).

# win-kernel-thread-injection: the live ETW-TI consumer needs a PPL/ELAM-signed
# host, which dev builds do not have. Default OFF; the kernel notify plane and the
# non-ETW enrichment (signals 23/24/25) work without it.
option(HK_WIN_ETWTI
       "Build the protected ETW Threat-Intelligence consumer (needs PPL/ELAM; OFF until signing lands)"
       OFF)

# win-usermode-overlay: read-only usermode render/overlay sensors (catalog signals
# 46-54). Usermode only (no WDK); these are the core platform sensors, so default
# ON. Turned off only for a slim build that excludes render telemetry.
option(HK_RENDER_SENSORS_WIN
       "Build the Windows render/overlay usermode sensors (signals 46-54)"
       ON)

# win-input-automation: read-only usermode input-provenance sensors (catalog signals
# 55-63). Usermode only (no WDK; no driver build, no test-signing); these are core
# platform sensors, so default ON. Turned off only for a slim build that excludes
# input-provenance telemetry.
option(HK_INPUT_SENSORS_WIN
       "Build the Windows input-provenance usermode sensors (signals 55-63)"
       ON)

# win-handle-memory-access: read-only usermode external-memory-access samplers
# (catalog signals 65/70/71). These are HIGH-FP alone and only useful once the kernel
# VM/Ob plane exists to correlate against, so they ship DARK — default OFF, matching
# the kernel HK_WIN_VMWATCH posture. The pure decision cores (VmAccessLogicWin.h /
# VmWatchWin.h) are header-only and always host-tested regardless of this flag.
option(HK_WIN_VMWATCH_SENSORS
       "Build the Windows external-memory-access usermode samplers (signals 65/70/71; ship dark)"
       OFF)

# hardware-input-devices: read-only usermode USB/HID device-trust sensors (catalog
# signals 136/137/138/139/142/143/144). Usermode only (no WDK; no driver build); these
# are core platform sensors, so default ON. Turned off only for a slim build that
# excludes device-trust telemetry. The pure decision cores (descriptor coherence,
# composite-interface fold, cadence ceiling, HID canonicalization, pointer-feature fold)
# live header-only in input/DeviceTrustWin.h + common/PointerFeatureFold.h so the host
# unit test links them with no platform TU (guardrail #4 — no kernel TU includes them).
option(HK_DEVICE_TRUST_SENSORS_WIN
       "Build the Windows USB/HID device-trust usermode sensors (signals 136-144)"
       ON)

# hardware-input-devices (Linux/POSIX userspace half): the evdev/uinput provenance
# correlator (140) + the pointer-delta feature extractor (142, Linux half). Default ON
# (core AC on Linux); these are pure userspace TUs (no eBPF link — the eBPF object is
# built under kernel/linux/bpf and consumed by the loader, not the SDK). Turned off only
# for a slim build.
option(HK_DEVICE_TRUST_SENSORS_POSIX
       "Build the Linux/POSIX device-trust userspace sensors (signals 140/142)"
       ON)

# behavioral-aim: read-only usermode aim-input provenance/biomechanics sensors
# (catalog signals 163-171). The provenance/cadence/cursor/injection sensors
# (163/164/165/170/171) read the GAME'S OWN raw-HID sink / LL-hook / cursor state
# per platform; the kinematic signals (166/167/168/169) add NO OS API — the client
# forwards engine state and the ban-engine (server/ban-engine/src/aim_kinematics.rs)
# segments + scores. Usermode only (no WDK; no driver) — core platform sensors, so
# default ON. The platform-free per-tick fold (input/AimAccumulator.cpp) is built
# unconditionally under this flag and host-tested with no platform TU
# (tests/unit/test_aim_accumulator.cpp, guardrail #4).
option(HK_AIM_SENSORS
       "Build the behavioral-aim provenance/biomechanics sensors (signals 163-171)"
       ON)

# network-anomaly: read-only userspace network-layer-integrity sensors (catalog
# signals 181-189, minus the server-only 186). The cross-platform cores
# (ClockDomainProbe/SendBacklogProbe/ProbeChannel/NetCollect) compare the app's own
# send cadence/clock/queue/route/socket-owner view against OS/NIC ground truth; the
# per-platform backends under backends/{win,posix}/ hold the OS reads (guardrail #1).
# Usermode only (no WDK; no kernel TU) — core platform sensors, so default ON. Turned
# off only for a slim build that excludes network telemetry.
option(HK_NET_SENSORS
       "Build the network-anomaly network-layer-integrity sensors (signals 181-189)"
       ON)

# network-anomaly probe channel (signal 187): the dedicated UDP echo probe socket.
# Default OFF — it opens an EXTRA socket and REQUIRES a server-side UDP echo
# responder that does not yet exist (impl-plan Sequencing §6 / Risks: Dependency
# 187). The ProbeChannel core + backend stubs compile regardless; this flag only
# enables the (still no-data) probe-socket I/O path. Do NOT flip ON until the paired
# server echo milestone lands.
option(HK_NET_PROBE_CHANNEL
       "Build the network-anomaly probe-RTT UDP echo socket path (signal 187; needs server echo responder; OFF until it ships)"
       OFF)

if(WIN32)
    # Windows backend: driver probe + minifilter altitude census (signal 6) +
    # thread-provenance enrichment (signals 22/23/24/25). Enrichment ships ON;
    # the ETW-TI consumer (signals 20/21/27) is added below only under HK_WIN_ETWTI.
    set(hk_sdk_backend
        src/backends/win/DriverProbeWin.cpp
        src/backends/win/MinifilterCensusWin.cpp
        src/backends/win/ThreadProvenanceWin.cpp
        # win-kernel-memory-injection signal 18 userspace half: WinVerifyTrust
        # signer verdict over the kernel-shipped backing path+hash. Confined to
        # backends/win (guardrail #1); links wintrust below.
        src/backends/win/ImageSigningWin.cpp
        # process-genealogy userspace sensors (signals 201/202/203/204). Documented
        # Toolhelp/VirtualQuery/token/job APIs; the pure token-delta + reparent
        # helpers are host-tested in genealogy_logic.h.
        src/backends/win/ancestry_walker.cpp   # 201 chain
        src/backends/win/region_walk.cpp        # 202 exec-region inventory
        src/backends/win/token_check.cpp        # 203 token-integrity delta
        src/backends/win/job_silo_check.cpp)    # 204 job/silo advisory
    if(HK_WIN_ETWTI)
        list(APPEND hk_sdk_backend src/backends/win/EtwTiConsumer.cpp)
    endif()
    if(HK_RENDER_SENSORS_WIN)
        # win-usermode-overlay sensors (signals 46-54): the shared signed-module
        # map + the nine sensor TUs. PeRelocate.h is header-only (compiled into
        # PresentPrologueReconcileWin.cpp's TU; the kernel image-load path includes
        # it in its OWN TU, so guardrail #4 holds — no shared object).
        list(APPEND hk_sdk_backend
            src/backends/win/ModuleMapWin.cpp
            src/backends/win/PresentVtableProvenanceWin.cpp
            src/backends/win/PresentPrologueReconcileWin.cpp
            src/backends/win/PresentFrameStatsCorrelateWin.cpp
            src/backends/win/LayeredWindowScanWin.cpp
            src/backends/win/DwmThumbnailConsumerWin.cpp
            src/backends/win/MagnifierHostScanWin.cpp
            src/backends/win/HookDllFootprintWin.cpp
            src/backends/win/GdiCapturePressureWin.cpp
            src/backends/win/VulkanLayerChainWin.cpp)
    endif()
    if(HK_INPUT_SENSORS_WIN)
        # win-input-automation sensors (signals 55-63): the shared raw-input device
        # inventory + the nine sensor TUs. The pure decision cores (provenance/ratio/
        # flag folding, timing-feature math, poll-rate derivation) live header-only in
        # InputSensorWin.h so the host unit test links them with no platform TU
        # (guardrail #4 — no kernel TU includes the header).
        list(APPEND hk_sdk_backend
            src/backends/win/RawInputInventoryWin.cpp
            src/backends/win/RawInputProvenanceWin.cpp
            src/backends/win/InputClassFilterWin.cpp
            src/backends/win/HidTransportProvenanceWin.cpp
            src/backends/win/InputTimingFeaturesWin.cpp
            src/backends/win/LowLevelHookChainWin.cpp
            src/backends/win/RawMouseModeWin.cpp
            src/backends/win/InputQueueAttachWin.cpp
            src/backends/win/HidPollRateWin.cpp
            src/backends/win/SyntheticInputArtifactWin.cpp)
    endif()
    if(HK_DEVICE_TRUST_SENSORS_WIN)
        # hardware-input-devices USB/HID device-trust sensors (signals 136-144). The
        # shared USB-hub topology snapshot + the per-signal sensor TUs under input/. The
        # pure decision cores live header-only in input/DeviceTrustWin.h +
        # common/PointerFeatureFold.h (host-tested with no platform TU, guardrail #4 — no
        # kernel TU includes them). The live USB-hub IOCTL walk in UsbTopologyWin.cpp and
        # the WM_INPUT/arrival joins in the cadence/arrival/reconcile sensors are
        # HK-UNCERTAIN stubs pending on-box (Win11 25H2) verification (impl-plan Risks);
        # the TUs compile and degrade to inconclusive until then.
        list(APPEND hk_sdk_backend
            src/backends/win/input/UsbTopologyWin.cpp
            src/backends/win/input/HidDescriptorFingerprintWin.cpp
            src/backends/win/input/UsbDescriptorAuditWin.cpp
            src/backends/win/input/RawInputSourceReconcileWin.cpp
            src/backends/win/input/PollIntervalCoherenceWin.cpp
            src/backends/win/input/CompositeInterfaceAuditWin.cpp
            src/backends/win/input/DeviceArrivalCorrelationWin.cpp
            src/backends/win/input/PointerDeltaStatsWin.cpp)
    endif()
    if(HK_AIM_SENSORS)
        # behavioral-aim sensors (signals 163-171), Windows backends. The platform-
        # neutral per-tick fold (input/AimAccumulator.cpp) is appended once below the
        # platform branches. RawHidSamplerWin drains the game's own WM_INPUT/RAWMOUSE
        # sink (163/164/165); CursorConfinementWin reads GetClipCursor/GetCursorInfo/
        # GetCursorPos (170); InjectionFlagWin reads MSLLHOOKSTRUCT.flags over the
        # game's own WH_MOUSE_LL (171) — the LL-hook install is an HK-UNCERTAIN stub
        # pending the LowLevelHooksTimeout confirmation (plan R3).
        list(APPEND hk_sdk_backend
            src/input/backends/win/RawHidSamplerWin.cpp
            src/input/backends/win/CursorConfinementWin.cpp
            src/input/backends/win/InjectionFlagWin.cpp)
    endif()
    if(HK_WIN_VMWATCH_SENSORS)
        # win-handle-memory-access samplers (signals 65/70/71). The pure cores live
        # header-only in VmAccessLogicWin.h / VmWatchWin.h (host-tested with no platform
        # TU, guardrail #4 — no kernel TU includes them). WorkingSetWatchWin.cpp and
        # SelfHandleAuditWin.cpp are documented on-box-verified stubs (working-set diff /
        # SystemExtendedHandleInformation are version-gated); PageProtectAuditWin.cpp's
        # in-process VirtualQueryEx + PE-section compare is live.
        list(APPEND hk_sdk_backend
            src/backends/win/WorkingSetWatchWin.cpp
            src/backends/win/SelfHandleAuditWin.cpp
            src/backends/win/PageProtectAuditWin.cpp)
    endif()
    if(HK_NET_SENSORS)
        # network-anomaly Windows backends (signals 181/183/185/188/189 + the
        # 182/184/187 platform half in NetBackendWin). Usermode Winsock/iphlpapi;
        # the SIO_TIMESTAMPING (181), SIO_TCP_INFO version (183),
        # GetCurrentInputMessageSource fidelity (185), macOS-absent route/owner
        # enrichments are HK-UNCERTAIN stubs pending on-box (Win11 25H2) verification
        # (impl-plan Risks); the TUs compile and emit the no-data sentinel until then.
        list(APPEND hk_sdk_backend
            src/backends/win/NetBackendWin.cpp
            src/backends/win/NetTimingWin.cpp
            src/backends/win/TcpInfoProbeWin.cpp
            src/backends/win/InputFrameProbeWin.cpp
            src/backends/win/RouteWatchWin.cpp
            src/backends/win/SocketTableProbeWin.cpp)
    endif()
else()
    set(hk_sdk_backend src/backends/posix/DriverProbePosix.cpp)
    if(HK_NET_SENSORS)
        # network-anomaly POSIX backends (signals 183/188/189 + the 182/184/187
        # platform half in NetBackendPosix). Linux: clock_gettime/SIOCOUTQ/rtnetlink/
        # sock_diag; macOS: TCP_CONNECTION_INFO/SO_NWRITE/PF_ROUTE/proc_pidfdinfo. The
        # macOS PF_ROUTE watch (188), the Linux rtnetlink/sock_diag readers (188/189),
        # and the owner-image hash (189) are HK-UNCERTAIN stubs pending on-box
        # verification (impl-plan Risks); the macOS loopback-foreign-address read (189)
        # and the clock/backlog/TCP_INFO reads are live. No extra link lib (netlink/
        # ioctl/proc_pidfdinfo are in libc/libSystem).
        list(APPEND hk_sdk_backend
            src/backends/posix/NetBackendPosix.cpp
            src/backends/posix/TcpInfoProbePosix.cpp
            src/backends/posix/RouteWatchPosix.cpp
            src/backends/posix/SocketTableProbePosix.cpp)
    endif()
    if(HK_DEVICE_TRUST_SENSORS_POSIX)
        # hardware-input-devices Linux/POSIX userspace half (signals 140/142). The
        # evdev/uinput provenance correlator's bpf ringbuf drain + EVIOCGID/EVIOCGPHYS
        # supplement are HK-UNCERTAIN stubs pending on-box (Deck-kernel) verification
        # (impl-plan Risks §140); the pure classifier + the pointer-feature fold are live
        # and host-tested. No eBPF link here — the eBPF object is built under
        # kernel/linux/bpf and consumed by the loader, not the SDK (guardrail #4).
        list(APPEND hk_sdk_backend
            src/backends/posix/input/EvdevProvenanceLinux.cpp
            src/backends/posix/input/PointerDeltaStatsPosix.cpp)
    endif()
    if(HK_AIM_SENSORS)
        if(APPLE)
            # behavioral-aim macOS backends (signals 163/164/165 via IOHIDManager,
            # 170/171 via a listen-only CGEventTap). Obj-C++ (.mm) for IOKit/CG. The
            # TCC Input-Monitoring grant + the CG source-state semantics (R4/R5) are
            # HK-UNCERTAIN stubs; the tap/manager are not wired until confirmed on-box.
            list(APPEND hk_sdk_backend
                src/input/backends/macos/RawHidSamplerMac.mm
                src/input/backends/macos/CursorConfinementMac.mm
                src/input/backends/macos/InjectionFlagMac.mm)
        else()
            # behavioral-aim Linux backends (signals 163/164/165 via evdev EV_REL,
            # 171 via libudev uinput-provenance). There is no 170 cursor-confinement
            # analog on Linux (no GetClipCursor equivalent in this sensor set). The
            # evdev node-access (R6) + the uinput ID_INPUT property (R6) are
            # HK-UNCERTAIN stubs pending on-box (Steam Deck) confirmation.
            list(APPEND hk_sdk_backend
                src/input/backends/linux/RawHidSamplerLinux.cpp
                src/input/backends/linux/InjectionFlagLinux.cpp)
        endif()
    endif()
endif()

# behavioral-aim platform-neutral per-tick fold (signals 163/165/171). No platform
# header — appended once for every platform under HK_AIM_SENSORS. Host-tested with
# no platform TU (tests/unit/test_aim_accumulator.cpp, guardrail #4).
if(HK_AIM_SENSORS)
    list(APPEND hk_sdk_backend src/input/AimAccumulator.cpp)
endif()

# network-anomaly cross-platform cores (signals 182/184/187 + the aggregator). No
# platform header — appended once for every platform under HK_NET_SENSORS; all OS
# access is dispatched through the per-platform NetBackend*.cpp seam (guardrail #1).
# Host-tested with no platform TU (tests/unit/test_net_collect.cpp, guardrail #4).
# ProbeChannel.cpp compiles regardless of HK_NET_PROBE_CHANNEL; the flag only gates
# its (still no-data) socket-I/O path.
if(HK_NET_SENSORS)
    list(APPEND hk_sdk_backend
        src/ClockDomainProbe.cpp
        src/SendBacklogProbe.cpp
        src/ProbeChannel.cpp
        src/NetCollect.cpp)
endif()

add_library(hk_sdk STATIC
    src/sdk.cpp
    # behavioral-aim: the platform-free per-tick TickPayload serializer that
    # echoes the server sim tick (TelemetrySerialize.cpp). No platform header;
    # host-tested (tests/unit/test_telemetry_serialize.cpp, guardrail #4).
    src/TelemetrySerialize.cpp
    ${hk_sdk_backend})

# src/backends is on the include path so the device-trust sensor TUs resolve their
# façade + shared-fold headers ("input/DeviceTrust*.h", "common/PointerFeatureFold.h")
# relative to backends/{win,posix}/ and backends/.
target_include_directories(hk_sdk
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
            ${CMAKE_CURRENT_SOURCE_DIR}/src/backends
            ${CMAKE_CURRENT_SOURCE_DIR}/src/backends/win
            ${CMAKE_CURRENT_SOURCE_DIR}/src/backends/posix)

target_link_libraries(hk_sdk PUBLIC hk_drm hk_ac hk_platform)

# network-anomaly probe-channel flag, visible to ProbeChannel.cpp + the per-platform
# NetBackend*.cpp probe stubs on every platform (the flag gates the signal-187 socket
# I/O path, which is still no-data until the server echo responder ships).
if(HK_NET_PROBE_CHANNEL)
    target_compile_definitions(hk_sdk PRIVATE HK_NET_PROBE_CHANNEL=1)
endif()

# Thread-provenance enrichment reuses the platform-free page-hash helper exposed
# by hk_dma_detect (dma_detect/include/horkos/page_hash.h, signal 24).
target_link_libraries(hk_sdk PRIVATE hk_dma_detect)

if(WIN32)
    # fltlib provides FilterInstanceFindFirst/Next for the minifilter census.
    target_link_libraries(hk_sdk PRIVATE fltlib)
    # wintrust: WinVerifyTrust for ImageSigningWin.cpp (signal 18).
    target_link_libraries(hk_sdk PRIVATE wintrust)
    if(HK_NET_SENSORS)
        # network-anomaly Windows link deps, confined to the Windows branch
        # (guardrail #1). ws2_32: Winsock (WSAIoctl SIO_TCP_INFO/SIO_IDEAL_SEND_BACKLOG,
        # GetExtendedUdpTable's AF_INET socket addrs, htons/ntohs). iphlpapi:
        # NotifyRouteChange2 / NotifyIpInterfaceChange / NotifyUnicastIpAddressChange /
        # CancelMibChangeNotify2 / GetBestInterfaceEx (188) + GetExtendedUdpTable (189).
        # SIO_TIMESTAMPING (181) adds nothing beyond ws2_32. The owner-image-hash
        # enrichment (189) would add bcrypt once the cross-process read lands on-box
        # (HK-UNCERTAIN) — not referenced by the compiled scaffold today, so not added.
        target_link_libraries(hk_sdk PRIVATE ws2_32 iphlpapi)
    endif()
    if(HK_WIN_ETWTI)
        # ETW-TI consumer flag visible to the compiled TU.
        target_compile_definitions(hk_sdk PRIVATE HK_WIN_ETWTI=1)
        # The live consumer links the ETW trace controller/consumer APIs (sechost /
        # advapi32 / tdh) once the PPL path is written; the current stub needs none.
    endif()
    if(HK_RENDER_SENSORS_WIN)
        # Win32 link deps for the render sensors, confined to the Windows branch
        # (guardrail #1). Present/frame-stats use DXGI/D3D (46/47/48); window/cloak
        # scans use dwmapi + user32 (49/50/51); the module map + footprint use psapi
        # (46/47/52/54); the signer resolve uses wintrust + crypt32; GDI pressure
        # uses gdi32 (53); Vulkan layer enumeration uses advapi32 registry reads
        # (54). The current scaffolded TUs only reference user32/dwmapi/psapi; the
        # remaining libs link in as the live present-path/signer bodies land. Kept
        # minimal to what the compiled code references today.
        target_link_libraries(hk_sdk PRIVATE
            user32 dwmapi psapi gdi32 advapi32)
    endif()
    if(HK_INPUT_SENSORS_WIN)
        # Win32 link deps for the input-provenance sensors, confined to the Windows
        # branch (guardrail #1). Raw-input inventory + raw-mouse + queue-attach use
        # user32 (GetRawInputDeviceList/Info, GetSystemMetrics, GetGUIThreadInfo); the
        # class-filter scan uses advapi32 (Control\Class registry reads). The
        # remaining declared deps link in as the live bodies land:
        #   setupapi cfgmgr32 (device-class enum + parent-bus props — 56/57/62)
        #   hid              (HidD_*/HidP_* — 57/62)
        #   wintrust crypt32 (filter/HID image signer — 56/57)
        #   wtsapi32         (WTSGetActiveConsoleSessionId — 55)
        # The current scaffolded TUs only reference user32/advapi32 (both already
        # linked above), so no new lib is added today; kept minimal to what the
        # compiled code references, mirroring the render branch.
    endif()
    if(HK_DEVICE_TRUST_SENSORS_WIN)
        # Win32 link deps for the USB/HID device-trust sensors, confined to the Windows
        # branch (guardrail #1). The TUs reference, today:
        #   setupapi  — SetupDiGetClassDevsW / EnumDeviceInterfaces / detail (136/137/143)
        #   hid       — HidD_GetHidGuid / GetPreparsedData / HidP_Get*Caps (136)
        #   bcrypt    — SHA-256 of the canonicalized HID structure (136)
        #   wtsapi32  — WTSGetActiveConsoleSessionId / session gate (138)
        #   user32    — GetSystemMetrics(SM_REMOTESESSION) (138) — already linked above
        # cfgmgr32 (DEVPKEY_Device_ContainerId fallback) and winusb (hub-IOCTL fallback)
        # link in as the live UsbTopologyWin hub-IOCTL path lands on-box (HK-UNCERTAIN);
        # not referenced by the compiled scaffold today, so not added yet — kept minimal
        # to what the compiled code references, mirroring the input/render branches.
        target_link_libraries(hk_sdk PRIVATE setupapi hid bcrypt wtsapi32)
    endif()
    if(HK_AIM_SENSORS)
        # behavioral-aim Windows link deps, confined to the Windows branch (guardrail
        # #1). The compiled scaffold references, today:
        #   user32 — GetRawInputData/RAWMOUSE (163/164/165), GetClipCursor/
        #            GetCursorInfo/GetCursorPos (170), SetWindowsHookEx/CallNextHookEx
        #            (171). user32 may already be linked under the render/input
        #            branches; listing it here keeps the aim deps self-contained when
        #            those flags are OFF. No other lib is referenced by the scaffold
        #            (the live raw-input registration adds nothing beyond user32).
        target_link_libraries(hk_sdk PRIVATE user32)
    endif()
elseif(APPLE)
    if(HK_AIM_SENSORS)
        # behavioral-aim macOS frameworks, confined to the APPLE branch (guardrail #1).
        # The compiled .mm scaffold #imports Foundation only; the live IOHIDManager
        # (163/164/165) and CGEventTap (170/171) bodies add IOKit + CoreGraphics, which
        # are listed now so the live wiring links without a CMake change. hk_platform
        # already pulls CoreFoundation + IOKit transitively on APPLE.
        target_link_libraries(hk_sdk PRIVATE
            "-framework Foundation"
            "-framework IOKit"
            "-framework CoreGraphics")
    endif()
else()
    if(HK_AIM_SENSORS)
        # behavioral-aim Linux link deps, confined to the non-Win/non-APPLE branch
        # (guardrail #1). The evdev raw-HID drain (163/164/165) is read() on
        # /dev/input — no extra lib (CLOCK_MONOTONIC_RAW via libc). The uinput-
        # provenance flag (171) uses libudev once the ID_INPUT property is confirmed
        # (HK-UNCERTAIN, plan R6); the current stub references no udev symbol, so
        # libudev is NOT linked yet — kept minimal to what the compiled code
        # references, mirroring the device-trust posix branch.
    endif()
endif()
