/*
 * kernel/win/include/vad_layout.h
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
 *       HK-UNCERTAIN (load-bearing): the allow-list ships EMPTY. Every offset is
 *       a placeholder of HK_VAD_OFF_UNKNOWN until it is confirmed per target
 *       build on the Windows box (admin@192.168.178.80) against public symbols
 *       (PDB / `dt nt!_MMVAD`) and a kernel reviewer, then added to
 *       kHkVadLayouts with the real values. Until then HkVadLayoutForCurrentBuild
 *       returns NULL everywhere and the scan plane emits nothing — by design.
 * Target platforms: Windows kernel (KMDF).
 * Interface: HkVadLayoutForCurrentBuild() consumed by VadWalk.c / the scanners.
 */

#pragma once

#include <ntddk.h>

/* Sentinel: this offset has not been confirmed for the running build. Any field
 * left at this value MUST NOT be dereferenced; the table is rejected wholesale. */
#define HK_VAD_OFF_UNKNOWN ((ULONG)0xFFFFFFFFu)

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
} HK_VAD_LAYOUT, *PHK_VAD_LAYOUT;

/*
 * The allow-list. EMPTY by design (HK-UNCERTAIN) — populate on the Windows box
 * once offsets are confirmed per build. Keeping a single all-UNKNOWN exemplar so
 * the table's shape is documented; it is rejected by the validity check below.
 */
static const HK_VAD_LAYOUT kHkVadLayouts[] = {
    {
        /* BuildNumber */ 0,
        /* every offset UNKNOWN -> table invalid -> fails closed. */
        HK_VAD_OFF_UNKNOWN, HK_VAD_OFF_UNKNOWN, HK_VAD_OFF_UNKNOWN,
        HK_VAD_OFF_UNKNOWN, HK_VAD_OFF_UNKNOWN, HK_VAD_OFF_UNKNOWN,
        HK_VAD_OFF_UNKNOWN, HK_VAD_OFF_UNKNOWN, HK_VAD_OFF_UNKNOWN,
        HK_VAD_OFF_UNKNOWN, HK_VAD_OFF_UNKNOWN, HK_VAD_OFF_UNKNOWN,
        HK_VAD_OFF_UNKNOWN, HK_VAD_OFF_UNKNOWN, HK_VAD_OFF_UNKNOWN,
        HK_VAD_OFF_UNKNOWN, HK_VAD_OFF_UNKNOWN, HK_VAD_OFF_UNKNOWN,
        HK_VAD_OFF_UNKNOWN, HK_VAD_OFF_UNKNOWN, HK_VAD_OFF_UNKNOWN,
        HK_VAD_OFF_UNKNOWN,
    },
};

/* TRUE only if every offset in the table is a confirmed (non-sentinel) value. A
 * single HK_VAD_OFF_UNKNOWN rejects the whole table — partial layouts are unsafe. */
static __forceinline BOOLEAN HkVadLayoutComplete(const HK_VAD_LAYOUT* L)
{
    const ULONG* p = (const ULONG*)&L->Eprocess_VadRoot;
    const ULONG* end = (const ULONG*)((const UCHAR*)L + sizeof(HK_VAD_LAYOUT));
    if (L == NULL) {
        return FALSE;
    }
    for (; p < end; ++p) {
        if (*p == HK_VAD_OFF_UNKNOWN) {
            return FALSE;
        }
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
