/*
 * Role: The ONE place undocumented Windows-kernel struct layout lives, fenced
 *       behind a per-build allow-list. The memory-scan plane reads fields of
 *       _MMVAD / _MMVAD_SHORT / _SUBSECTION / _CONTROL_AREA / _PEB_LDR_DATA /
 *       _LDR_DATA_TABLE_ENTRY / _ETHREAD that are NOT stable documented ABI;
 *       their byte offsets shift across Windows builds and are the single largest
 *       BSOD risk in the driver. This header provides a versioned offset table
 *       keyed by OS build, and a lookup that returns NULL for any build NOT in
 *       the allow-list. The scan worker MUST treat a NULL table as "refuse to
 *       dereference layout-dependent fields" — i.e. it FAILS CLOSED on an unknown
 *       build rather than dereferencing a wrong offset (guardrail #13).
 *
 *       HK-VERIFIED (offsets): the allow-list now carries four builds (26100,
 *       26200, 22631, 19045) sourced from the Vergilius Project public PDB
 *       database (vergiliusproject.com). Every offset must still be confirmed
 *       against `dt nt!_MMVAD` / `dt nt!_EPROCESS VadRoot` on the exact running
 *       build on the Windows box before enabling real scan emission; Vergilius
 *       is the right starting point, not the verification endpoint. Until
 *       on-box confirmation happens, emit remains gated by HkVadLayoutComplete
 *       (which would pass for these builds) AND by the HK_WIN_VAD_SCAN build
 *       flag — keep that flag OFF until box-verified.
 * Target platforms: Windows kernel (KMDF).
 * Interface: HkVadLayoutForCurrentBuild() consumed by VadWalk.c / the scanners.
 */

#pragma once

#include <ntddk.h>

/* Sentinel: this offset has not been confirmed for the running build. Any field
 * left at this value MUST NOT be dereferenced; the table is rejected wholesale. */
#define HK_VAD_OFF_UNKNOWN ((ULONG)0xFFFFFFFFu)

/* Sentinel: confirmed offset whose numeric value is 0.  Needed because 0 is a
 * legitimate struct offset (e.g. VadShort_LeftChild on build 26100) but is also
 * the zero-initialised default of an unpopulated table entry.  Set a field to
 * HK_VAD_OFF_ZERO to assert "this is really offset 0"; the accessor in VadWalk.c
 * translates it back to 0 before the dereference, and HkVadLayoutComplete treats
 * raw 0 as unpopulated (== HK_VAD_OFF_UNKNOWN for the completeness check). */
#define HK_VAD_OFF_ZERO    ((ULONG)0xFFFFFFFEu)

/* Per-build offset table. All offsets are byte offsets from the start of the
 * named structure. A field at HK_VAD_OFF_UNKNOWN invalidates the whole table. */
typedef struct _HK_VAD_LAYOUT {
    ULONG BuildNumber;            /* NtBuildNumber this table was confirmed against. */

    /* _EPROCESS */
    ULONG Eprocess_VadRoot;       /* RTL_AVL_TREE / MM_AVL_TABLE root. */

    /* _MMVAD_SHORT (the common prefix of _MMVAD). */
    ULONG VadShort_StartingVpn;   /* ULONG_PTR low. */
    ULONG VadShort_EndingVpn;
    ULONG VadShort_StartingVpnHigh; /* UCHAR; 0 if this build has no high byte. */
    ULONG VadShort_EndingVpnHigh;
    ULONG VadShort_VadFlags;      /* MMVAD_FLAGS bitfield word. */
    ULONG VadShort_LeftChild;     /* RTL_BALANCED_NODE left / Left. */
    ULONG VadShort_RightChild;

    /* MMVAD_FLAGS sub-fields, expressed as (shift, width) into the flags word. */
    ULONG VadFlags_ProtectionShift; ULONG VadFlags_ProtectionWidth;
    ULONG VadFlags_PrivateMemoryShift;
    ULONG VadFlags_VadTypeShift;    ULONG VadFlags_VadTypeWidth;

    /* _MMVAD (long) — section backing. */
    ULONG Vad_Subsection;         /* _SUBSECTION*. */
    ULONG Subsection_ControlArea; /* _CONTROL_AREA*. */
    ULONG ControlArea_FilePointer;/* _EX_FAST_REF to _FILE_OBJECT. */

    /* _PEB / _PEB_LDR_DATA / _LDR_DATA_TABLE_ENTRY (read while attached). */
    ULONG PebLdr_InLoadOrder;     /* offset of InLoadOrderModuleList. */
    ULONG PebLdr_InMemoryOrder;
    ULONG PebLdr_InInitOrder;
    ULONG LdrEntry_DllBase;
    ULONG LdrEntry_FullDllName;   /* UNICODE_STRING. */

    /* _ETHREAD — only used if the documented Zw path is unavailable (see
     * ExecOrigin.c); preferred path is ZwQueryInformationThread. */
    ULONG Ethread_Win32StartAddress;

    /* _PEB.Ldr pointer offset (to reach _PEB_LDR_DATA from PsGetProcessPeb). */
    ULONG Peb_Ldr;
} HK_VAD_LAYOUT, *PHK_VAD_LAYOUT;

/*
 * The allow-list. Offsets are PDB-derived (Vergilius Project,
 * vergiliusproject.com) for the listed build; any build NOT present here fails
 * closed (HkVadLayoutForCurrentBuild returns NULL). Append confirmed builds here.
 *
 * HK-VERIFIED (Vergilius Project, vergiliusproject.com, PDB-derived): offsets
 * confirmed per build against the public symbol database. Before ENABLING emit on
 * the box, confirm each against `dt nt!_MMVAD`, `dt nt!_EPROCESS VadRoot`, etc. on
 * the exact running build; the SEH guards in VadWalk.c and the per-build gate remain
 * the safety net (a wrong/changed offset degrades to "skip node", not a bugcheck).
 *
 * Windows 11 24H2 (NtBuildNumber 26100).
 *   Source: vergiliusproject.com/kernels/x64/windows-11/24h2/
 *   _EPROCESS.VadRoot 0x558; _MMVAD_SHORT {VadNode@0x0 (Left 0x0/Right 0x8),
 *   StartingVpn 0x18, EndingVpn 0x1C, StartingVpnHigh 0x20, EndingVpnHigh 0x21,
 *   LongFlags 0x30}; _MMVAD_FLAGS {VadType bit4 w3, Protection bit7 w5,
 *   PrivateMemory bit21 w1}; _MMVAD.Subsection 0x48; _SUBSECTION.ControlArea 0x0;
 *   _CONTROL_AREA.FilePointer 0x40; _PEB.Ldr 0x18; _PEB_LDR_DATA {InLoadOrder
 *   0x10, InMemoryOrder 0x20, InInitOrder 0x30}; _LDR_DATA_TABLE_ENTRY {DllBase
 *   0x30, FullDllName 0x48}; _ETHREAD.Win32StartAddress 0x560.
 *
 * Windows 11 25H2 (NtBuildNumber 26200) -- ships as enablement package on 26100 base.
 *   Source: vergiliusproject.com/kernels/x64/windows-11/25h2/
 *   All layout fields identical to 26100 above; the 24H2->25H2 enablement package
 *   did not change any of the structures this driver reads.
 *
 * Windows 11 23H2 (NtBuildNumber 22631).
 *   Source: vergiliusproject.com/kernels/x64/windows-11/23h2/
 *   _EPROCESS.VadRoot 0x7D8 (differs from 24H2/25H2 which moved VadRoot to 0x558);
 *   _MMVAD_SHORT offsets identical to 24H2; _MMVAD_FLAGS identical to 24H2;
 *   _ETHREAD.Win32StartAddress 0x520 (differs from 24H2/25H2 at 0x560).
 *
 * Windows 10 22H2 (NtBuildNumber 19045).
 *   Source: vergiliusproject.com/kernels/x64/windows-10/22h2/
 *   _EPROCESS.VadRoot 0x7D8; _MMVAD_SHORT offsets identical to Win11 builds;
 *   _MMVAD_FLAGS: PrivateMemory at bit 20 (not 21) because PreferredNode is 6 bits
 *   (bits 12-17) here vs 7 bits on Win11, shifting PageSize to 18-19, PrivateMemory
 *   to bit 20; _ETHREAD.Win32StartAddress 0x4D0.
 */
static const HK_VAD_LAYOUT kHkVadLayouts[] = {
    /* Windows 11 24H2 -- vergiliusproject.com/kernels/x64/windows-11/24h2/ */
    {
        /* BuildNumber              */ 26100,
        /* Eprocess_VadRoot         */ 0x558,
        /* VadShort_StartingVpn     */ 0x18,
        /* VadShort_EndingVpn       */ 0x1C,
        /* VadShort_StartingVpnHigh */ 0x20,
        /* VadShort_EndingVpnHigh   */ 0x21,
        /* VadShort_VadFlags        */ 0x30,
        /* VadShort_LeftChild       */ HK_VAD_OFF_ZERO,
        /* VadShort_RightChild      */ 0x08,
        /* VadFlags_ProtectionShift */ 7,
        /* VadFlags_ProtectionWidth */ 5,
        /* VadFlags_PrivateMemShift */ 21,
        /* VadFlags_VadTypeShift    */ 4,
        /* VadFlags_VadTypeWidth    */ 3,
        /* Vad_Subsection           */ 0x48,
        /* Subsection_ControlArea   */ HK_VAD_OFF_ZERO,
        /* ControlArea_FilePointer  */ 0x40,
        /* PebLdr_InLoadOrder       */ 0x10,
        /* PebLdr_InMemoryOrder     */ 0x20,
        /* PebLdr_InInitOrder       */ 0x30,
        /* LdrEntry_DllBase         */ 0x30,
        /* LdrEntry_FullDllName     */ 0x48,
        /* Ethread_Win32StartAddress*/ 0x560,
        /* Peb_Ldr                  */ 0x18,
    },
    /* Windows 11 25H2 -- vergiliusproject.com/kernels/x64/windows-11/25h2/ */
    {
        /* BuildNumber              */ 26200,
        /* Eprocess_VadRoot         */ 0x558,
        /* VadShort_StartingVpn     */ 0x18,
        /* VadShort_EndingVpn       */ 0x1C,
        /* VadShort_StartingVpnHigh */ 0x20,
        /* VadShort_EndingVpnHigh   */ 0x21,
        /* VadShort_VadFlags        */ 0x30,
        /* VadShort_LeftChild       */ HK_VAD_OFF_ZERO,
        /* VadShort_RightChild      */ 0x08,
        /* VadFlags_ProtectionShift */ 7,
        /* VadFlags_ProtectionWidth */ 5,
        /* VadFlags_PrivateMemShift */ 21,
        /* VadFlags_VadTypeShift    */ 4,
        /* VadFlags_VadTypeWidth    */ 3,
        /* Vad_Subsection           */ 0x48,
        /* Subsection_ControlArea   */ HK_VAD_OFF_ZERO,
        /* ControlArea_FilePointer  */ 0x40,
        /* PebLdr_InLoadOrder       */ 0x10,
        /* PebLdr_InMemoryOrder     */ 0x20,
        /* PebLdr_InInitOrder       */ 0x30,
        /* LdrEntry_DllBase         */ 0x30,
        /* LdrEntry_FullDllName     */ 0x48,
        /* Ethread_Win32StartAddress*/ 0x560,
        /* Peb_Ldr                  */ 0x18,
    },
    /* Windows 11 23H2 -- vergiliusproject.com/kernels/x64/windows-11/23h2/ */
    {
        /* BuildNumber              */ 22631,
        /* Eprocess_VadRoot         */ 0x7D8,
        /* VadShort_StartingVpn     */ 0x18,
        /* VadShort_EndingVpn       */ 0x1C,
        /* VadShort_StartingVpnHigh */ 0x20,
        /* VadShort_EndingVpnHigh   */ 0x21,
        /* VadShort_VadFlags        */ 0x30,
        /* VadShort_LeftChild       */ HK_VAD_OFF_ZERO,
        /* VadShort_RightChild      */ 0x08,
        /* VadFlags_ProtectionShift */ 7,
        /* VadFlags_ProtectionWidth */ 5,
        /* VadFlags_PrivateMemShift */ 21,
        /* VadFlags_VadTypeShift    */ 4,
        /* VadFlags_VadTypeWidth    */ 3,
        /* Vad_Subsection           */ 0x48,
        /* Subsection_ControlArea   */ HK_VAD_OFF_ZERO,
        /* ControlArea_FilePointer  */ 0x40,
        /* PebLdr_InLoadOrder       */ 0x10,
        /* PebLdr_InMemoryOrder     */ 0x20,
        /* PebLdr_InInitOrder       */ 0x30,
        /* LdrEntry_DllBase         */ 0x30,
        /* LdrEntry_FullDllName     */ 0x48,
        /* Ethread_Win32StartAddress*/ 0x520,
        /* Peb_Ldr                  */ 0x18,
    },
    /* Windows 10 22H2 -- vergiliusproject.com/kernels/x64/windows-10/22h2/
     * PrivateMemory is at bit 20 (not 21): PreferredNode is 6 bits wide on this build
     * vs 7 on Win11, shifting PageSize to bits 18-19 and PrivateMemory to bit 20. */
    {
        /* BuildNumber              */ 19045,
        /* Eprocess_VadRoot         */ 0x7D8,
        /* VadShort_StartingVpn     */ 0x18,
        /* VadShort_EndingVpn       */ 0x1C,
        /* VadShort_StartingVpnHigh */ 0x20,
        /* VadShort_EndingVpnHigh   */ 0x21,
        /* VadShort_VadFlags        */ 0x30,
        /* VadShort_LeftChild       */ HK_VAD_OFF_ZERO,
        /* VadShort_RightChild      */ 0x08,
        /* VadFlags_ProtectionShift */ 7,
        /* VadFlags_ProtectionWidth */ 5,
        /* VadFlags_PrivateMemShift */ 20,
        /* VadFlags_VadTypeShift    */ 4,
        /* VadFlags_VadTypeWidth    */ 3,
        /* Vad_Subsection           */ 0x48,
        /* Subsection_ControlArea   */ HK_VAD_OFF_ZERO,
        /* ControlArea_FilePointer  */ 0x40,
        /* PebLdr_InLoadOrder       */ 0x10,
        /* PebLdr_InMemoryOrder     */ 0x20,
        /* PebLdr_InInitOrder       */ 0x30,
        /* LdrEntry_DllBase         */ 0x30,
        /* LdrEntry_FullDllName     */ 0x48,
        /* Ethread_Win32StartAddress*/ 0x4D0,
        /* Peb_Ldr                  */ 0x18,
    },
};

/* TRUE only if every field in the table is a confirmed (non-sentinel) value.
 * HK_VAD_OFF_UNKNOWN rejects the whole table — partial layouts are unsafe.
 * Raw 0 in a byte-offset field also rejects: it is indistinguishable from a
 * zero-initialised (unpopulated) entry.  Legitimate offset 0 must be expressed
 * as HK_VAD_OFF_ZERO (which != 0 and != HK_VAD_OFF_UNKNOWN).
 * Note: shift/width fields (VadFlags_*Shift, VadFlags_*Width) live after the
 * byte-offset block; a shift of 0 is legitimate, so the loop uses HK_VAD_OFF_UNKNOWN
 * as the sole sentinel for those fields.  Byte-offset fields that need offset 0
 * must use HK_VAD_OFF_ZERO — HkReadAt translates it before the dereference. */
static __forceinline BOOLEAN HkVadLayoutComplete(const HK_VAD_LAYOUT* L)
{
    const ULONG* p;
    const ULONG* end;

    if (L == NULL) {
        return FALSE;
    }
    p   = (const ULONG*)&L->Eprocess_VadRoot;
    end = (const ULONG*)((const UCHAR*)L + sizeof(HK_VAD_LAYOUT));
    for (; p < end; ++p) {
        if (*p == HK_VAD_OFF_UNKNOWN) {
            return FALSE;
        }
    }
    /* Separately verify that every byte-offset field that could legitimately be 0
     * uses HK_VAD_OFF_ZERO, not the zero-initialisation default.  The only fields
     * in this struct whose confirmed value is 0 are byte offsets, not shifts/widths
     * (shifts of 0 are legitimate; the check below covers only the known-problematic
     * structural offsets). */
    if (L->VadShort_LeftChild == 0u  ||
        L->VadShort_RightChild == 0u ||
        L->Subsection_ControlArea == 0u) {
        return FALSE;
    }
    return TRUE;
}

/*
 * Returns the confirmed layout for the running build, or NULL if the build is not
 * in the allow-list (the default — fails closed). Callers MUST treat NULL as
 * "do not dereference any layout-dependent field".
 */
static __forceinline const HK_VAD_LAYOUT* HkVadLayoutForCurrentBuild(void)
{
    ULONG build = 0;
    ULONG i;
    ULONG count = (ULONG)(sizeof(kHkVadLayouts) / sizeof(kHkVadLayouts[0]));
    RTL_OSVERSIONINFOW vi;
    RtlZeroMemory(&vi, sizeof(vi));
    vi.dwOSVersionInfoSize = sizeof(vi);
    /* RtlGetVersion is documented and PASSIVE/DISPATCH-safe; NTSTATUS checked. */
    if (!NT_SUCCESS(RtlGetVersion((PRTL_OSVERSIONINFOW)&vi))) {
        return NULL;
    }
    build = vi.dwBuildNumber;
    for (i = 0; i < count; ++i) {
        if (kHkVadLayouts[i].BuildNumber == build &&
            HkVadLayoutComplete(&kHkVadLayouts[i])) {
            return &kHkVadLayouts[i];
        }
    }
    return NULL; /* unknown build OR incomplete table -> fail closed. */
}
