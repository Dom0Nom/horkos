/*
 * Role: Shared read-only walk of a target process's VAD tree for the memory-scan
 *       plane (signals 10/13/14/15/16/17). Runs while the worker is ATTACHED to
 *       the target (KeStackAttachProcess) so the VAD node virtual addresses are
 *       valid, and normalises each leaf into the host-safe HK_VAD_NODE the pure
 *       classifiers (mem_logic_vad.h) consume. Every target-memory read is
 *       SEH-guarded; a torn node degrades to "skip", never a bugcheck (guardrail
 *       #5 + #13). Layout-dependent field offsets come exclusively from
 *       vad_layout.h's fail-closed allow-list; a NULL layout yields zero nodes.
 *       READ-ONLY: walks and copies; mutates no target memory.
 * Target platforms: Windows kernel (KMDF). Builds only with the WDK.
 * Interface: implements HkVadEnumerate from mem_scan.h.
 */

#include "mem_scan.h"

/* Read a field of width sizeof(T) at byte offset `off` from base `p`, into `out`,
 * SEH-guarded. Returns FALSE (and leaves out untouched) on a fault or an
 * unconfirmed (sentinel) offset.
 * HK_VAD_OFF_ZERO encodes a confirmed offset of 0 (e.g. LeftChild on 26100);
 * it is translated to 0 here before the dereference.  A raw value of 0 is
 * treated as unpopulated (HK_VAD_OFF_UNKNOWN) and rejected. */
static BOOLEAN HkReadAt(const void* p, ULONG off, void* out, SIZE_T width)
{
    ULONG real_off;
    if (off == HK_VAD_OFF_UNKNOWN || off == 0u || p == NULL) {
        return FALSE;
    }
    real_off = (off == HK_VAD_OFF_ZERO) ? 0u : off;
    __try {
        RtlCopyMemory(out, (const UCHAR*)p + real_off, width);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

/* Extract a (shift,width) bitfield from a 32-bit flags word. */
static ULONG HkBits(ULONG word, ULONG shift, ULONG width)
{
    if (width == 0 || width >= 32) {
        return 0;
    }
    return (word >> shift) & ((1u << width) - 1u);
}

/* Normalise one MMVAD's protection mask (the MM_* protection enum stored in the
 * VadFlags Protection field) into the wire HK_MEM_PROT_* bits. The MM protection
 * enum encodes execute as values 2,3,6,7 (EXECUTE / EXECUTE_READ /
 * EXECUTE_READWRITE / EXECUTE_WRITECOPY) — documented across the public PTE/VAD
 * literature; HK-UNCERTAIN across builds, so this mapping is confirmed together
 * with the offsets on the box. */
static ULONG HkNormalizeProtection(ULONG mm_protect)
{
    ULONG p = 0;
    switch (mm_protect) {
    case 1: p = HK_MEM_PROT_READ; break;                                   /* READONLY */
    case 2: p = HK_MEM_PROT_EXECUTE; break;                                /* EXECUTE */
    case 3: p = HK_MEM_PROT_EXECUTE | HK_MEM_PROT_READ; break;             /* EXECUTE_READ */
    case 4: p = HK_MEM_PROT_READ | HK_MEM_PROT_WRITE; break;               /* READWRITE */
    case 5: p = HK_MEM_PROT_READ | HK_MEM_PROT_WRITE; break;               /* WRITECOPY */
    case 6: p = HK_MEM_PROT_EXECUTE | HK_MEM_PROT_READ | HK_MEM_PROT_WRITE; break; /* EXECUTE_RW */
    case 7: p = HK_MEM_PROT_EXECUTE | HK_MEM_PROT_READ | HK_MEM_PROT_WRITE; break; /* EXECUTE_WC */
    default: p = 0; break;
    }
    return p;
}

/* Resolve whether a VAD has section/file backing by following
 * Vad->Subsection->ControlArea->FilePointer. Any broken link => unbacked. All
 * reads SEH-guarded. Sets *has_control_area. */
static void HkResolveBacking(const HK_VAD_LAYOUT* L, const void* vad, ULONG* has_control_area)
{
    void* subsection = NULL;
    void* control_area = NULL;
    ULONG_PTR file_ptr = 0;
    *has_control_area = 0;

    if (!HkReadAt(vad, L->Vad_Subsection, &subsection, sizeof(subsection)) || subsection == NULL) {
        return;
    }
    if (!HkReadAt(subsection, L->Subsection_ControlArea, &control_area, sizeof(control_area)) ||
        control_area == NULL) {
        return;
    }
    if (!HkReadAt(control_area, L->ControlArea_FilePointer, &file_ptr, sizeof(file_ptr))) {
        return;
    }
    /* FilePointer is an EX_FAST_REF: the low bits are a ref count, mask them off. */
    file_ptr &= ~((ULONG_PTR)0xF);
    *has_control_area = (file_ptr != 0) ? 1u : 0u;
}

/* Normalise one VAD node (pointed to by `vad`) into out. Returns FALSE if the
 * essential fields could not be read (caller skips it). */
static BOOLEAN HkNormalizeVad(const HK_VAD_LAYOUT* L, const void* vad, HK_VAD_NODE* out)
{
    ULONG start_lo = 0, end_lo = 0, flags = 0;
    UCHAR start_hi = 0, end_hi = 0;
    ULONG64 start_vpn, end_vpn;
    ULONG mm_protect, vad_type_raw, private_mem;

    if (!HkReadAt(vad, L->VadShort_StartingVpn, &start_lo, sizeof(start_lo))) return FALSE;
    if (!HkReadAt(vad, L->VadShort_EndingVpn, &end_lo, sizeof(end_lo))) return FALSE;
    if (!HkReadAt(vad, L->VadShort_VadFlags, &flags, sizeof(flags))) return FALSE;
    /* High VPN bytes are optional (older builds lack them; offset 0 => skip). */
    if (L->VadShort_StartingVpnHigh != 0) {
        (void)HkReadAt(vad, L->VadShort_StartingVpnHigh, &start_hi, sizeof(start_hi));
        (void)HkReadAt(vad, L->VadShort_EndingVpnHigh, &end_hi, sizeof(end_hi));
    }

    start_vpn = ((ULONG64)start_hi << 32) | start_lo;
    end_vpn = ((ULONG64)end_hi << 32) | end_lo;

    /* A torn node under concurrent target-process mutation can produce an
     * end_vpn that is less than start_vpn.  The resulting region_size would
     * wrap to ~2^64 and feed wildly out-of-range values to the classifiers.
     * Reject the node rather than propagate garbage. */
    if (end_vpn < start_vpn) {
        return FALSE;
    }

    mm_protect = HkBits(flags, L->VadFlags_ProtectionShift, L->VadFlags_ProtectionWidth);
    vad_type_raw = HkBits(flags, L->VadFlags_VadTypeShift, L->VadFlags_VadTypeWidth);
    private_mem = HkBits(flags, L->VadFlags_PrivateMemoryShift, 1);

    RtlZeroMemory(out, sizeof(*out));
    out->region_base = start_vpn << PAGE_SHIFT;
    out->region_size = (end_vpn - start_vpn + 1) << PAGE_SHIFT;
    out->protection = HkNormalizeProtection(mm_protect);
    /* Normalise the build-specific MI_VAD_TYPE enum into the wire HK_MEM_VAD_*.
     * VadNone=0, VadDevicePhysicalMemory, VadImageMap, VadAwe, VadWriteWatch,
     * VadLargePages, VadRotatePhysical, VadLargePageSection (public ReactOS /
     * RE literature; HK-UNCERTAIN per build, confirmed with offsets). */
    switch (vad_type_raw) {
    case 0: out->vad_type = private_mem ? HK_MEM_VAD_NONE : HK_MEM_VAD_NONE; break;
    case 2: out->vad_type = HK_MEM_VAD_IMAGE; break;
    case 3: out->vad_type = HK_MEM_VAD_AWE; break;
    case 5: out->vad_type = HK_MEM_VAD_LARGE_PAGES; break;
    case 6: out->vad_type = HK_MEM_VAD_ROTATE; break;
    default: out->vad_type = HK_MEM_VAD_OTHER; break;
    }
    out->large_page = (out->vad_type == HK_MEM_VAD_LARGE_PAGES) ? 1u : 0u;

    HkResolveBacking(L, vad, &out->has_control_area);
    /* has_jit_owner is annotated later by the scanners against the loaded-module
     * JIT ranges; left 0 here. */
    return TRUE;
}

ULONG HkVadEnumerate(PHK_MEM_SCAN_CTX Ctx)
{
    /* Explicit bounded stack for iterative in-order traversal; sized to the node
     * cap so a pathological/torn tree cannot overflow it. */
    const HK_VAD_LAYOUT* L;
    void* vadRoot = NULL;
    void* stack[64];
    ULONG sp = 0;
    void* node;
    ULONG visited = 0;

    if (Ctx == NULL) {
        return 0;
    }
    Ctx->NodeCount = 0;
    L = Ctx->Layout;
    if (L == NULL || !Ctx->Attached || Ctx->Process == NULL) {
        return 0; /* fail closed on unconfirmed build or not attached. */
    }

    /* VadRoot is an RTL_AVL_TREE whose first field is the root RTL_BALANCED_NODE*
     * (or, on older builds, the MM_AVL_TABLE BalancedRoot). Read the root pointer. */
    if (!HkReadAt(Ctx->Process, L->Eprocess_VadRoot, &vadRoot, sizeof(vadRoot)) ||
        vadRoot == NULL) {
        return 0;
    }

    node = vadRoot;
    /* Iterative in-order: go left, visit, go right. Bounded by node cap + a
     * visited ceiling so a cyclic torn tree terminates. */
    while ((sp > 0 || node != NULL) &&
           Ctx->NodeCount < HK_MEM_MAX_VAD_NODES &&
           visited < (HK_MEM_MAX_VAD_NODES * 2u)) {
        if (node != NULL) {
            void* left = NULL;
            if (sp < RTL_NUMBER_OF(stack)) {
                stack[sp++] = node;
            }
            if (!HkReadAt(node, L->VadShort_LeftChild, &left, sizeof(left))) {
                left = NULL;
            }
            node = left;
            ++visited;
            continue;
        }
        node = stack[--sp];
        {
            void* right = NULL;
            HK_VAD_NODE* slot = &Ctx->Nodes[Ctx->NodeCount];
            if (HkNormalizeVad(L, node, slot)) {
                ++Ctx->NodeCount;
            }
            if (!HkReadAt(node, L->VadShort_RightChild, &right, sizeof(right))) {
                right = NULL;
            }
            node = right;
        }
        ++visited;
    }
    return Ctx->NodeCount;
}
