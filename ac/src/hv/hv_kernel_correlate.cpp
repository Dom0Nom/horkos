/*
 * Role: Drains the kernel HV records (signals 39/41/42/44, hk_event_type
 *       14..17 on the existing 16-byte ring) via the SDK IOCTL bridge and folds
 *       their flag words into hv_kernel_summary, then runs every usermode sampler
 *       and assembles the hv_report. Server is the only classifier; this only
 *       collects raw observations.
 *       READ-ONLY.
 * Target platforms: Windows. Guardrail #1: the device IOCTL is confined here.
 * Interface: implements hv_collect_kernel + hv_collect_all from hv_signals.h.
 */

#include "horkos/hv_signals.h"

#if defined(HK_PLATFORM_WINDOWS)

#include <windows.h>

#include "horkos/ioctl.h"

extern "C" int hv_collect_kernel(hv_kernel_summary* out)
{
    HANDLE dev;
    BYTE buf[sizeof(hk_drain_header) + 64 * sizeof(hk_event_record)];
    DWORD returned = 0;

    if (out == nullptr) {
        return HK_AC_NOT_IMPLEMENTED;
    }
    RtlSecureZeroMemory(out, sizeof(*out));

    dev = CreateFileA(HK_DEVICE_PATH_USER, GENERIC_READ | GENERIC_WRITE,
                      FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (dev == INVALID_HANDLE_VALUE) {
        return HK_AC_DEGRADED; /* driver not present — usermode samplers still run. */
    }

    /* HK-UNCERTAIN: this shares the single event drain with the main AC consumer;
     * in production the correlator reads a copy fed by the AC's own drain loop
     * rather than draining the device directly. Kept as a direct best-effort drain
     * until that plumbing lands. */
    if (DeviceIoControl(dev, HK_IOCTL_DRAIN_EVENTS, nullptr, 0, buf, sizeof(buf),
                        &returned, nullptr) &&
        returned >= sizeof(hk_drain_header)) {
        const hk_drain_header* hdr = (const hk_drain_header*)buf;
        const hk_event_record* recs = (const hk_event_record*)(hdr + 1);
        uint32_t n = hdr->records_written;
        uint32_t maxn = (uint32_t)((sizeof(buf) - sizeof(hk_drain_header)) / sizeof(hk_event_record));
        if (n > maxn) n = maxn;
        for (uint32_t i = 0; i < n; ++i) {
            const hk_event_record* r = &recs[i];
            switch (r->header.type) {
            case HK_EVENT_HV_SYNTH_MSR: {
                const hk_event_hv_synth_msr* p = (const hk_event_hv_synth_msr*)r->payload;
                out->synth_msr_flags = p->flags;
                ++out->records_seen;
                break;
            }
            case HK_EVENT_HV_EPT_SPLIT: {
                const hk_event_hv_ept_split* p = (const hk_event_hv_ept_split*)r->payload;
                out->ept_flags = p->flags;
                ++out->records_seen;
                break;
            }
            case HK_EVENT_HV_SK_LIVENESS: {
                const hk_event_hv_sk_liveness* p = (const hk_event_hv_sk_liveness*)r->payload;
                out->sk_flags = p->flags;
                ++out->records_seen;
                break;
            }
            case HK_EVENT_HV_APIC_IDT: {
                const hk_event_hv_apic_idt* p = (const hk_event_hv_apic_idt*)r->payload;
                out->apic_idt_flags = p->flags;
                ++out->records_seen;
                break;
            }
            default:
                break; /* not an HV record — ignore (other consumers own it). */
            }
        }
    }

    CloseHandle(dev);
    return HK_AC_OK;
}

extern "C" int hv_collect_all(hv_report* out)
{
    if (out == nullptr) {
        return HK_AC_NOT_IMPLEMENTED;
    }
    RtlSecureZeroMemory(out, sizeof(*out));

    if (hv_sample_tlfs_leaves(&out->tlfs) == HK_AC_OK)        out->sensors_ok |= HK_HV_OK_TLFS;
    if (hv_sample_vmexit_latency(&out->vmexit) == HK_AC_OK)   out->sensors_ok |= HK_HV_OK_VMEXIT;
    if (hv_sample_vbs_attest(&out->vbs) == HK_AC_OK)          out->sensors_ok |= HK_HV_OK_VBS;
    if (hv_sample_vm_identity(&out->identity) == HK_AC_OK)    out->sensors_ok |= HK_HV_OK_IDENTITY;
    if (hv_sample_tsc_coherence(&out->tsc) == HK_AC_OK)       out->sensors_ok |= HK_HV_OK_TSC;
    if (hv_collect_kernel(&out->kern) == HK_AC_OK)            out->sensors_ok |= HK_HV_OK_KERNEL;

    return HK_AC_OK;
}

#else

extern "C" int hv_collect_kernel(hv_kernel_summary* out) { (void)out; return HK_AC_NOT_IMPLEMENTED; }
extern "C" int hv_collect_all(hv_report* out) { (void)out; return HK_AC_NOT_IMPLEMENTED; }

#endif
