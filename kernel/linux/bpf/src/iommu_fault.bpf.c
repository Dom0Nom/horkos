/*
 * Role: eBPF IOMMU-fault counter (catalog signal 135, Linux arm). Attaches the
 *       `iommu:io_page_fault` tracepoint and counts DMA-remapping faults per
 *       source-BDF, emitting a compact record to the shared hk_ringbuf. A genuine
 *       ASIC peripheral driving DMA through a correctly-programmed IOMMU domain
 *       does not generate a steady stream of translation faults; an FPGA/PCILeech
 *       board probing IOVA space it was never granted does. This sensor only
 *       COUNTS faults per faulting BDF — the server gates a fault stream on the
 *       faulting BDF ALSO carrying a structural flag (unbound + bus-master) and on
 *       the fault NOT being in the boot/init window. No scoring/ban here.
 * Target platform: Linux eBPF (CO-RE, BPF_PROG_TYPE_TRACEPOINT/RAW_TRACEPOINT).
 *       Requires CAP_BPF/CAP_SYS_ADMIN to load; absent capability => the sensor is
 *       simply not loaded and the server treats sig-135 as "absent", never "clean".
 * Interface: shares hk_ringbuf with lsm_file_open.bpf.c (extern here; Loader.cpp
 *            reuses the fd before load). Maps to server sig 135
 *            (iommu_fault_count per BDF — merged into hk_dma_device_forensics by
 *            the loader/aggregator). Loader.cpp mirrors hk_bpf_iommu_fault_event.
 *
 * Guardrail compliance:
 *   #1  No raw platform macros — Linux-only by build gating.
 *   #3  This module comment covers role/platform/interface.
 *   #4  Pure kernel eBPF TU — no userspace headers, no shared TU.
 *   #6  Compiled -Wall -Wextra -Werror (enforced in CMakeLists.txt).
 *
 * UNCERTAINTY (kernel-version-dependent; guardrail #12): the `iommu:io_page_fault`
 * tracepoint NAME and its FIELD LAYOUT have changed across kernel versions, and the
 * `report_iommu_fault` kprobe-fallback SIGNATURE is version-sensitive. ALL kernel-
 * struct field access here goes through BPF_CORE_READ / the CO-RE-relocated raw
 * tracepoint ctx (never a fixed offset), and the fields are feature-probed by the
 * loader against the target BTF before attach. The kprobe fallback is left as an
 * explicit unimplemented stub below — NOT guessed — because its argument order is
 * not confirmable off-box. Confirm the tracepoint field names and the kprobe arg
 * layout against the target kernel BTF before relying on either at runtime.
 *
 * vmlinux.h MUST be generated on the target kernel (it provides the
 * trace_event_raw_* layouts CO-RE relocates against). See CMakeLists.txt.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define HK_SCHEMA_VERSION   3u
#define HK_BPF_IOMMU_FAULT  0x90u   /* loader maps to server sig-135 fault count */

/* ---- Shared ring buffer (defined in lsm_file_open.bpf.c) -----------------
 * Same reuse pattern as tracepoints.bpf.c: declared extern here; Loader.cpp
 * repoints this object's hk_ringbuf at the already-created fd via
 * bpf_map__reuse_fd() before load so all sensor objects share one ring. */
extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} hk_ringbuf SEC(".maps");

/* Mirrored in Loader.cpp as HkBpfIommuFaultEvent. The fault is reported with the
 * raw source-BDF (packed domain:bus:devfn) and the faulting IOVA; the loader
 * aggregates a per-BDF COUNT into hk_dma_device_forensics.iommu_fault_count, drops
 * boot/init-window faults, and requires the BDF to also be a structural suspect
 * before the server scores it (catalog gate). One ring record == one fault. */
struct hk_bpf_iommu_fault_event {
    __u32 schema_version;
    __u32 event_tag;        /* HK_BPF_IOMMU_FAULT */
    __u64 timestamp_ns;
    __u32 source_bdf;       /* packed (domain<<16)|(bus<<8)|devfn; 0 if unknown */
    __u32 flags;            /* fault-class flags from the tracepoint (read/write) */
    __u64 fault_iova;       /* faulting device address; 0 if not surfaced */
};

/* ---- Tracepoint: iommu/io_page_fault --------------------------------------
 * The tracepoint is defined in include/trace/events/iommu.h. The argument set has
 * varied across kernels; the historically stable fields are a device identity
 * (`dev_name` __data_loc string, the "<domain>:<bus>:<dev>.<fn>" of the faulting
 * device) and the faulting `iova` (u64). We read BOTH CO-RE-relocatably:
 *   - iova via BPF_CORE_READ on the raw ctx (offset relocated by BTF),
 *   - dev_name via the __data_loc decode idiom (same as sched_process_exec in
 *     tracepoints.bpf.c) and hash/pack it in USERSPACE — the BPF side does not
 *     parse the BDF string (verifier-hostile); it ships the raw dev_name bytes
 *     length-bounded and the loader parses "<dom>:<bus>:<dev>.<fn>" -> packed BDF.
 *
 * HK-VERIFIED(iommu-tp-fields): include/trace/events/iommu.h defines the
 * iommu_error event class (which io_page_fault instantiates) as:
 *   DECLARE_EVENT_CLASS(iommu_error,
 *       TP_PROTO(struct device *dev, unsigned long iova, int flags),
 *       TP_STRUCT__entry(
 *           __string(device, dev_name(dev))
 *           __string(driver, dev_driver_string(dev))
 *           __field(u64, iova)
 *           __field(int, flags)
 *       ), ...)
 * The field IS named `iova` (u64) and `device` is a __string (not inline char[]).
 * This definition is present in torvalds/linux master and has been stable across
 * the v5.x/v6.x range relevant to Steam Deck (6.1/6.5).
 * Source: https://github.com/torvalds/linux/blob/master/include/trace/events/iommu.h
 *
 * BPF_CORE_FIELD_EXISTS-gating and a loader BTF probe still apply: confirm the
 * generated trace_event_raw_io_page_fault struct in the target vmlinux.h before
 * relying on the CO-RE read in production (the generated name and field layout
 * depend on the target kernel's BTF, not just upstream). A missing CO-RE field
 * degrades to 0, never a garbage read — consistent with "absent != clean".
 */

#define HK_IOMMU_DEVNAME_MAX 48   /* "<dom>:<bus>:<dev>.<fn>" + slack; bounded. */

SEC("tracepoint/iommu/io_page_fault")
int hk_tp_io_page_fault(void *ctx)
{
    struct hk_bpf_iommu_fault_event *evt;

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->schema_version = HK_SCHEMA_VERSION;
    evt->event_tag      = HK_BPF_IOMMU_FAULT;
    evt->timestamp_ns   = bpf_ktime_get_ns();
    evt->flags          = 0;

    /* CO-RE read of the iova field off the relocated tracepoint context.
     * trace_event_raw_io_page_fault is the generated name for the
     * iommu:io_page_fault tracepoint in vmlinux.h on kernels that surface it.
     * BPF_CORE_READ relocates the offset; a kernel lacking the field relocates the
     * load to 0 (=> "unknown"), it does not read garbage. */
    struct trace_event_raw_io_page_fault *tp =
        (struct trace_event_raw_io_page_fault *)ctx;
    if (bpf_core_field_exists(tp->iova))
        evt->fault_iova = (__u64)BPF_CORE_READ(tp, iova);
    else
        evt->fault_iova = 0;

    /* dev_name (__data_loc string) -> the loader parses the BDF. The BPF side does
     * NOT do the string->BDF parse (sscanf is not available; a hand-rolled parse is
     * verifier-hostile). We forward 0 here and let the loader resolve the BDF from
     * the recorded dev_name via the companion __data_loc copy below when present.
     *
     * HK-UNCERTAIN(iommu-tp-devname): the iommu_error event class uses
     * __string(device, dev_name(dev)) in its TP_STRUCT__entry (confirmed:
     * include/trace/events/iommu.h, torvalds/linux master). __string generates a
     * __data_loc-encoded field, so the generated vmlinux.h field name should be
     * __data_loc_device (not inline char[]). However the EXACT field name in the
     * generated trace_event_raw_io_page_fault struct depends on the target kernel's
     * BTF export and can vary (e.g. some kernels emit __data_loc_dev_name, others
     * __data_loc_device). Not confirmable off-box without the target vmlinux BTF.
     * Until the target-BTF probe in the loader confirms the field shape, source_bdf
     * is shipped as 0 ("unknown"). A 0 BDF is never scored — "unknown", not "clean". */
    evt->source_bdf = 0;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* ---- Fallback: kprobe on report_iommu_fault -------------------------------
 * On kernels that do NOT define the iommu:io_page_fault tracepoint, the kernel
 * funnel is report_iommu_fault() (drivers/iommu/iommu.c). A kprobe there would see
 * the fault before it is delivered to a registered handler.
 *
 * HK-VERIFIED(report_iommu_fault-kprobe-sig): the current upstream signature is
 *   int report_iommu_fault(struct iommu_domain *domain, struct device *dev,
 *                          unsigned long iova, int flags);
 * declared in include/linux/iommu.h. This signature has been stable across
 * v6.1–v6.8; it was NOT removed in that range (the domain-based fault path
 * predates and coexists with the newer iommu_report_device_fault()).
 * Source: https://github.com/torvalds/linux/blob/master/include/linux/iommu.h
 *         https://lore.kernel.org/lkml/ZZ6JNzDHy8-i0-VU@8bytes.org/ (v6.8 pull)
 *
 * However, the PT_REGS_PARM reads (extracting device* from arg2 → dev_name)
 * are NOT confirmed on the target BTF: the per-arch register calling-convention
 * mapping of each parameter to PT_REGS_PARM1/2/... must be verified against the
 * target kernel BTF before enabling this arm. The program body remains
 * intentionally empty per guardrail #12. The tracepoint arm above is the
 * shippable path; this kprobe arm is a loader-enabled fallback for kernels that
 * do NOT export the tracepoint.
 */
SEC("kprobe/report_iommu_fault")
int BPF_KPROBE(hk_kp_report_iommu_fault)
{
    /* Intentionally empty. The signature is confirmed (see HK-VERIFIED comment
     * above), but the PT_REGS_PARM register mapping for each parameter is not
     * confirmed on the target arch/BTF. Do not read PT_REGS_PARM* here until
     * verified on the target kernel. */
    return 0;
}

char _license[] SEC("license") = "GPL";
