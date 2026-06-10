# kernel/win/CMakeLists.txt
# Windows KMDF driver build target (Phase 3). Only included from the root
# CMakeLists on WIN32 hosts. Requires the Windows Driver Kit (WDK) matching the
# installed SDK. The canonical build is `msbuild kernel/win/horkos.vcxproj`
# inside an EWDK or a VS+WDK environment. This CMake target mirrors that build
# for CMake-native Windows setups and is documented in docs/windows-build.md.
#
# A KMDF driver links the kernel runtime (ntoskrnl, wdf), excludes the C
# runtime, and produces a .sys. CMake has no native driver target, so we drive
# it as an executable with a .sys suffix and kernel link flags. If WDK headers
# are not found, the target is skipped with a warning rather than failing the
# whole configure (so the C++/test build still works on a WDK-less Windows box).

# ---- Locate the WDK -------------------------------------------------------
# WDKContentRoot is set by the EWDK setup; otherwise look under the SDK root.
set(_hk_wdk_root "$ENV{WDKContentRoot}")
if(NOT _hk_wdk_root)
    set(_hk_wdk_root "$ENV{ProgramFiles\(x86\)}/Windows Kits/10")
endif()

find_path(HK_WDK_KMDF_INCLUDE
    NAMES wdf.h
    PATHS "${_hk_wdk_root}/Include"
    PATH_SUFFIXES
        "wdf/kmdf/1.33"
        "wdf/kmdf/1.31"
    NO_DEFAULT_PATH)

find_path(HK_WDK_KM_INCLUDE
    NAMES ntddk.h
    PATHS "${_hk_wdk_root}/Include"
    PATH_SUFFIXES
        "10.0.26100.0/km"
        "10.0.22621.0/km"
        "10.0.22000.0/km"
    NO_DEFAULT_PATH)

if(NOT HK_WDK_KMDF_INCLUDE OR NOT HK_WDK_KM_INCLUDE)
    message(WARNING
        "kernel/win: WDK not found under '${_hk_wdk_root}'. "
        "Skipping the horkos.sys target. Install the WDK or build with "
        "msbuild kernel/win/horkos.vcxproj. See docs/windows-build.md.")
    return()
endif()

message(STATUS "kernel/win: WDK KMDF headers at ${HK_WDK_KMDF_INCLUDE}")

set(HK_DRIVER_SRC
    src/DriverEntry.c
    src/IrpDispatch.c
    src/Notify.c
    src/ThreadProvenance.c
    src/RingBuffer.c
    src/Callbacks.c
    src/CallbackSelfCheck.c
    src/RegistryCallback.c
    src/Whitelist.c
    # win-kernel-driver-integrity (signals 28-36). ModuleMap + HkIntegrityScan are
    # the always-compiled shared substrate; each sensor .c compiles to a no-op
    # stub unless its HK_WIN_INTEGRITY_* flag is ON (target_compile_definitions
    # below). The driver links with any subset of sensors enabled.
    src/ModuleMap.c
    src/HkIntegrityScan.c
    src/MinifilterAudit.c
    src/ImageHashAudit.c
    src/CodeIntegrityProbe.c
    src/CallbackResidency.c
    src/NonImageCodeScan.c
    src/DebugStateProbe.c
    src/DriverObjectAudit.c
    src/SsdtIntegrity.c
    src/BootLoadAudit.c
    # win-kernel-syscall-etw-integrity (signals 208-216). KernelImageMap is the
    # always-compiled shared cache; SyscallIntegrity/EtwIntegrity sensors compile
    # to no-op stubs unless their HK_WIN_SYSCALL_*/HK_WIN_ETW_* flag is ON.
    src/KernelImageMap.c
    src/SyscallIntegrity.c
    src/EtwIntegrity.c
    # win-handle-memory-access (signals 64-72). Both TUs compile to link-safe no-op
    # stubs unless HK_WIN_VMWATCH is ON (default OFF). The ETW-TI VM consumer + the
    # canary spawn are documented STATUS_NOT_SUPPORTED stubs even when ON (no kernel
    # TI consumer under current signing; process-spawn-from-driver unverified) — only
    # the section-flag cache + Ob post-op provenance are live. Callbacks.c's Ob post-op
    # (#66/#67) is also gated by HK_WIN_VMWATCH (same flag, no new TU).
    src/EtwTiVmWatch.c
    src/CanaryProc.c
    # memory-integrity-selfcheck self-read handler (signals 145/146/148/151/152).
    # Compiles to a link-safe REFUSING stub unless HK_WIN_SELFCHECK_READ is ON
    # (default OFF). Even when ON the handler refuses (STATUS_NOT_SUPPORTED) until the
    # HK_IOCTL_SELF_READ_VA caller-identity binding is settled — a foreign-read IOCTL
    # is a privilege boundary; mis-scoping it is worse than shipping fewer signals.
    src/selfcheck_read.c
    # timing-side-channels signal 155 — APERF/MPERF-vs-RDTSC freq-skew probe. Compiles
    # to a no-op stub unless HK_WIN_TIMING_FREQSKEW is ON (default OFF). Even when ON
    # the MSR busy-loop window is UNIMPLEMENTED (HK-UNCERTAIN: IRQL/CPU-pin choice
    # unresolved — a BSOD is worse than an unfinished function, guardrail #13); only
    # the migration-safe nominal/HV-present CPUID half runs. The wire emit is further
    # gated by HK_TIMING_SCHEMA_READY (undefined until the Schema phase lands the type).
    src/TimingProbe.c
    # win-kernel-memory-injection scan plane (signals 10-18). Read-only VAD/PEB/PTE
    # sampling from a PASSIVE_LEVEL worker that attaches per-target. The pure
    # decision cores are host-tested (kernel/win/include/mem_logic_*.h); these TUs
    # are the sampling shells. Layout-dependent reads are fenced behind
    # vad_layout.h's allow-list, which ships EMPTY (HK-UNCERTAIN) so the plane fails
    # closed and emits nothing until per-build offsets are confirmed on the box.
    src/MemScanWorker.c
    src/VadWalk.c
    src/MemScanVad.c
    src/LdrCrosscheck.c
    src/HollowDetect.c
    src/ExecOrigin.c
    src/MemScanPte.c
    src/ModuleStomp.c)

# memory-integrity-selfcheck self-read IOCTL (signals 145/146/148/151/152). Default
# OFF: the caller-identity binding that makes a self-foreign-read safe is unsettled,
# and the oversized replies need a large-record drain plane that is pre-Schema. When
# OFF, selfcheck_read.c compiles to its refusing stub and HkHandleSelfRead returns
# STATUS_NOT_SUPPORTED; IrpDispatch routes the IOCTL either way (the stub refuses).
option(HK_WIN_SELFCHECK_READ
       "Signals 145/146/148/151/152 self-read IOCTL handler (OFF: caller-identity gate unsettled)"
       OFF)

# Self-check feature flags (win-kernel-object-callbacks). Default OFF: the
# undocumented Ob CallbackList / PspCreateProcessNotifyRoutine offset paths
# (signal 2 raw walk, signal 4 absolute array scan) only compile in once the
# per-build offset tables have been validated on the target build.
option(HK_SELFCHECK_UNDOC_OFFSETS
       "Enable undocumented Ob CallbackList / Psp* array offset paths (OFF until validated)"
       OFF)
# Self-check timer period in milliseconds (plan default 5000).
set(HK_SELFCHECK_TIMER_MS "5000" CACHE STRING "Self-check timer period (ms)")

# -------------------------------------------------------------------------
# Driver/module-integrity sensor feature flags (win-kernel-driver-integrity).
# Defaults tuned to the catalog FP/risk profile (see docs/windows-build.md):
#   - low-FP, low-risk sensors default ON;
#   - sensors gated on an UNCERTAINTY flag (Flt lifetime, ELAM timing, reloc
#     normalization, undocumented callback table, big-pool executability) default
#     OFF until verified on-box. Each flag maps to a target_compile_definition so
#     the matching sensor .c compiles to a no-op stub when OFF, keeping the driver
#     linkable with any subset. ModuleMap.c + HkIntegrityScan.c are always built.
# -------------------------------------------------------------------------
option(HK_WIN_INTEGRITY_DEBUGSTATE "Signal 33 kernel-debugger attach probe (low FP)" ON)
option(HK_WIN_INTEGRITY_CISTATE    "Signal 30 code-integrity/DSE/HVCI state probe (low FP)" ON)
option(HK_WIN_INTEGRITY_SSDT       "Signal 35 SSDT range integrity (non-shadow half; low FP)" ON)
option(HK_WIN_INTEGRITY_DRVOBJ     "Signal 34 DRIVER_OBJECT divergence audit (low FP)" ON)
option(HK_WIN_INTEGRITY_FLT        "Signal 28 minifilter callback-owner audit (OFF: Flt lifetime unverified)" OFF)
option(HK_WIN_INTEGRITY_CALLBACKS  "Signal 31 callback residency, self-sentinel half only (OFF)" OFF)
option(HK_WIN_INTEGRITY_IMAGEHASH  "Signal 29 in-memory vs on-disk .text hash (OFF: reloc norm unproven)" OFF)
option(HK_WIN_INTEGRITY_NONIMAGE   "Signal 32 non-image executable scan (OFF: HIGH FP)" OFF)
option(HK_WIN_INTEGRITY_BOOTLOAD   "Signal 36 boot-start/ELAM load-order audit (OFF: ELAM timing unverified)" OFF)
# Integrity-scan timer period in milliseconds (plan default 30000; heavier than
# the callback self-check, so it runs less often).
set(HK_INTEGRITY_TIMER_MS "30000" CACHE STRING "Integrity-scan timer period (ms)")

# -------------------------------------------------------------------------
# Syscall / ETW / PatchGuard surface-integrity sensor flags (win-kernel-syscall-
# etw-integrity, signals 208-216). Defaults tuned to the catalog FP/uncertainty
# profile (see docs/windows-build.md):
#   - low-FP, exported-only / off-hot-path sensors default ON;
#   - sensors depending on an unexported global, an unconfirmed kernel API, or an
#     unvalidated struct layout default OFF until verified on-box. Each flag maps
#     to a target_compile_definition so its sensor .c compiles to a no-op stub when
#     OFF. KernelImageMap.c is always built (shared substrate).
# -------------------------------------------------------------------------
option(HK_WIN_SYSCALL_SSDT        "Signals 208+216 SSDT entry + base-swap (exported KeServiceDescriptorTable; low FP)" ON)
option(HK_WIN_SYSCALL_LSTAR       "Signal 210 IA32_LSTAR per-CPU via off-hot-path IPI (low FP; divergence half always safe)" ON)
option(HK_WIN_SYSCALL_IDT         "Signal 214 IDT gate bounds via __sidt IPI (low FP; PENDING __sidt/IPI on-box confirmation)" ON)
option(HK_WIN_SYSCALL_SHADOW_SSDT "Signal 209 shadow SSDT/W32pServiceTable (OFF: unexported table + KeStackAttachProcess pairing risk)" OFF)
option(HK_WIN_SYSCALL_PROLOGUE    "Signal 213 KiSystemCall64 prologue scan (OFF: boot self-patch stable-window unvalidated)" OFF)
option(HK_WIN_ETW_TI              "Signal 212 ETW-TI liveness (keepalive half ON; raw-handle half offset-gated to UNVERIFIABLE)" ON)
option(HK_WIN_ETW_SESSION         "Signal 215 ETW logger-session census (OFF: kernel NtTraceControl surface unconfirmed)" OFF)
option(HK_WIN_ETW_INFINITYHOOK    "Signal 211 infinity-hook perf-trace probe (OFF: undocumented WMI_LOGGER_CONTEXT)" OFF)
# ETW-TI keepalive per-interval floor (signal 212); 0 => any advance is liveness.
set(HK_ETW_KEEPALIVE_MIN_DELTA "0" CACHE STRING "ETW-TI keepalive min advance per scan")

# -------------------------------------------------------------------------
# External-memory-access watch (win-handle-memory-access, signals 64-72). Default
# OFF until validated on a signed test driver, same posture as the Ob rights-strip
# policy. When ON: the section-flag cache + Ob post-op provenance (#66/#67) compile
# in; the ETW-TI VM consumer (#64/#69/#72) and the canary spawn (#68) remain
# documented STATUS_NOT_SUPPORTED stubs (no kernel TI consumer under current signing;
# process-spawn-from-driver unverified). The 28/24-byte payloads exceed the frozen
# HK_EVENT_PAYLOAD_MAX, so the provenance emit is additionally gated by
# HK_VMWATCH_SCHEMA_READY (defined only once the Schema phase grows the envelope).
# -------------------------------------------------------------------------
option(HK_WIN_VMWATCH
       "Signals 64-72 external-memory-access watch (OFF: ETW-TI needs PPL/ELAM; payloads exceed frozen envelope)"
       OFF)

# -------------------------------------------------------------------------
# timing-side-channels signal 155 — APERF/MPERF-vs-RDTSC frequency-skew probe.
# Default OFF and additionally field-gatable by runtime policy (plan §Build wiring).
# Even when ON the MSR busy-loop window stays UNIMPLEMENTED until the IRQL/CPU-pin
# uncertainty is resolved on-box (guardrail #13) — only the CPUID nominal/HV-present
# half runs. The wire emit is gated by HK_TIMING_SCHEMA_READY (undefined here; the
# frozen schema does not yet carry HK_EVENT_TIMING_FREQ_SKEW). A VM-context tag only,
# never an autonomous ban.
# -------------------------------------------------------------------------
option(HK_WIN_TIMING_FREQSKEW
       "Signal 155 APERF/MPERF-vs-RDTSC freq-skew probe (OFF: raised-IRQL MSR window unverified)"
       OFF)

add_executable(horkos_sys ${HK_DRIVER_SRC})
set_target_properties(horkos_sys PROPERTIES
    OUTPUT_NAME "horkos"
    SUFFIX ".sys"
    LINKER_LANGUAGE C)

target_include_directories(horkos_sys PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/sdk/include
    ${HK_WDK_KMDF_INCLUDE}
    ${HK_WDK_KM_INCLUDE})

# KMDF drivers are C, no CRT, /kernel. These flags mirror the WDK MSBuild
# defaults; the .vcxproj remains the source of truth for production signing.
target_compile_definitions(horkos_sys PRIVATE
    _KERNEL_MODE=1
    KMDF_VERSION_MAJOR=1
    KMDF_VERSION_MINOR=33
    HK_SELFCHECK_TIMER_MS=${HK_SELFCHECK_TIMER_MS}
    HK_INTEGRITY_TIMER_MS=${HK_INTEGRITY_TIMER_MS})
if(HK_SELFCHECK_UNDOC_OFFSETS)
    target_compile_definitions(horkos_sys PRIVATE HK_SELFCHECK_UNDOC_OFFSETS=1)
endif()

# Per-sensor integrity feature defines. When a flag is OFF the sensor .c compiles
# to its no-op stub branch (the #else in each file).
if(HK_WIN_INTEGRITY_DEBUGSTATE)
    target_compile_definitions(horkos_sys PRIVATE HK_WIN_INTEGRITY_DEBUGSTATE=1)
endif()
if(HK_WIN_INTEGRITY_CISTATE)
    target_compile_definitions(horkos_sys PRIVATE HK_WIN_INTEGRITY_CISTATE=1)
endif()
if(HK_WIN_INTEGRITY_SSDT)
    target_compile_definitions(horkos_sys PRIVATE HK_WIN_INTEGRITY_SSDT=1)
endif()
if(HK_WIN_INTEGRITY_DRVOBJ)
    target_compile_definitions(horkos_sys PRIVATE HK_WIN_INTEGRITY_DRVOBJ=1)
endif()
if(HK_WIN_INTEGRITY_CALLBACKS)
    target_compile_definitions(horkos_sys PRIVATE HK_WIN_INTEGRITY_CALLBACKS=1)
endif()
if(HK_WIN_INTEGRITY_IMAGEHASH)
    target_compile_definitions(horkos_sys PRIVATE HK_WIN_INTEGRITY_IMAGEHASH=1)
endif()
if(HK_WIN_INTEGRITY_NONIMAGE)
    target_compile_definitions(horkos_sys PRIVATE HK_WIN_INTEGRITY_NONIMAGE=1)
endif()
if(HK_WIN_INTEGRITY_BOOTLOAD)
    target_compile_definitions(horkos_sys PRIVATE HK_WIN_INTEGRITY_BOOTLOAD=1)
endif()
# Signal 28 (minifilter audit) links fltMgr.lib when ON; the default-OFF build
# pulls no FltMgr dependency.
if(HK_WIN_INTEGRITY_FLT)
    target_compile_definitions(horkos_sys PRIVATE HK_WIN_INTEGRITY_FLT=1)
endif()

# Per-sensor syscall/ETW surface-integrity defines (signals 208-216). OFF => the
# sensor .c compiles to its no-op stub branch.
target_compile_definitions(horkos_sys PRIVATE
    HK_ETW_KEEPALIVE_MIN_DELTA=${HK_ETW_KEEPALIVE_MIN_DELTA})
if(HK_WIN_SYSCALL_SSDT)
    target_compile_definitions(horkos_sys PRIVATE HK_WIN_SYSCALL_SSDT=1)
endif()
if(HK_WIN_SYSCALL_LSTAR)
    target_compile_definitions(horkos_sys PRIVATE HK_WIN_SYSCALL_LSTAR=1)
endif()
if(HK_WIN_SYSCALL_IDT)
    target_compile_definitions(horkos_sys PRIVATE HK_WIN_SYSCALL_IDT=1)
endif()
if(HK_WIN_SYSCALL_SHADOW_SSDT)
    target_compile_definitions(horkos_sys PRIVATE HK_WIN_SYSCALL_SHADOW_SSDT=1)
endif()
if(HK_WIN_SYSCALL_PROLOGUE)
    target_compile_definitions(horkos_sys PRIVATE HK_WIN_SYSCALL_PROLOGUE=1)
endif()
if(HK_WIN_ETW_TI)
    target_compile_definitions(horkos_sys PRIVATE HK_WIN_ETW_TI=1)
endif()
if(HK_WIN_ETW_SESSION)
    target_compile_definitions(horkos_sys PRIVATE HK_WIN_ETW_SESSION=1)
endif()
if(HK_WIN_ETW_INFINITYHOOK)
    target_compile_definitions(horkos_sys PRIVATE HK_WIN_ETW_INFINITYHOOK=1)
endif()
# win-handle-memory-access (signals 64-72). OFF => EtwTiVmWatch.c/CanaryProc.c and
# the Callbacks.c Ob post-op compile to their no-op-stub branches. HK_VMWATCH_SCHEMA_
# READY is intentionally NOT defined here: it stays undefined until the Schema phase
# grows HK_EVENT_PAYLOAD_MAX, keeping the oversized provenance emit truncation-gated.
if(HK_WIN_VMWATCH)
    target_compile_definitions(horkos_sys PRIVATE HK_WIN_VMWATCH=1)
endif()
# memory-integrity-selfcheck self-read handler. OFF => selfcheck_read.c compiles to its
# refusing stub. HK_WIN_SELFCHECK_READ=1 enables the (still STATUS_NOT_SUPPORTED)
# gated body that documents the caller-identity / MmCopyVirtualMemory / leaf-PTE /
# _KTRAP_FRAME-DR uncertainties — it never foreign-reads until those are settled.
if(HK_WIN_SELFCHECK_READ)
    target_compile_definitions(horkos_sys PRIVATE HK_WIN_SELFCHECK_READ=1)
endif()
# timing-side-channels signal 155. OFF => TimingProbe.c compiles to its no-op stub.
# HK_TIMING_SCHEMA_READY is intentionally NOT defined: it stays undefined until the
# Schema phase lands HK_EVENT_TIMING_FREQ_SKEW, keeping the freq-skew emit gated.
if(HK_WIN_TIMING_FREQSKEW)
    target_compile_definitions(horkos_sys PRIVATE HK_WIN_TIMING_FREQSKEW=1)
endif()
target_compile_options(horkos_sys PRIVATE
    /kernel /GS /W4 /WX)

# ---- WDK kernel + KMDF import libraries -----------------------------------
# /NODEFAULTLIB means nothing is linked implicitly: every ntoskrnl / WDF / GS
# symbol (incl. GsDriverEntry) must be linked explicitly or the link fails with
# unresolved externals. Locate the km and kmdf lib dirs under the kit root.
find_path(HK_WDK_KM_LIB
    NAMES ntoskrnl.lib
    PATHS "${_hk_wdk_root}/Lib"
    PATH_SUFFIXES
        "10.0.26100.0/km/x64"
        "10.0.22621.0/km/x64"
        "10.0.22000.0/km/x64"
    NO_DEFAULT_PATH)

find_path(HK_WDK_KMDF_LIB
    NAMES WdfDriverEntry.lib
    PATHS "${_hk_wdk_root}/Lib/wdf/kmdf/x64"
    PATH_SUFFIXES "1.33" "1.31"
    NO_DEFAULT_PATH)

if(NOT HK_WDK_KM_LIB OR NOT HK_WDK_KMDF_LIB)
    message(WARNING
        "kernel/win: WDK km/kmdf lib dirs not found; skipping the horkos.sys "
        "target. Build via msbuild kernel/win/horkos.vcxproj instead.")
    return()  # Do NOT fall through to link with NOTFOUND paths.
endif()

target_link_directories(horkos_sys PRIVATE
    ${HK_WDK_KM_LIB}
    ${HK_WDK_KMDF_LIB})

target_link_libraries(horkos_sys PRIVATE
    ntoskrnl.lib
    hal.lib
    wmilib.lib
    BufferOverflowFastFailK.lib   # /GS stack-cookie support (GsDriverEntry)
    wdmsec.lib                    # WdfControlDeviceInitAllocate SDDL strings
    WdfLdr.lib
    WdfDriverEntry.lib)

# Signal 28 (minifilter audit) needs FltMgr; link it only when that sensor is ON
# so the default build does not pull the filter-manager import library.
if(HK_WIN_INTEGRITY_FLT)
    target_link_libraries(horkos_sys PRIVATE fltMgr.lib)
endif()

target_link_options(horkos_sys PRIVATE
    /DRIVER /NODEFAULTLIB /SUBSYSTEM:NATIVE
    /ENTRY:FxDriverEntry /INTEGRITYCHECK)
