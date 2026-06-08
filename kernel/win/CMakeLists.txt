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
    src/RingBuffer.c
    src/Callbacks.c
    src/Whitelist.c)

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
    KMDF_VERSION_MINOR=33)
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

target_link_options(horkos_sys PRIVATE
    /DRIVER /NODEFAULTLIB /SUBSYSTEM:NATIVE
    /ENTRY:FxDriverEntry /INTEGRITYCHECK)
