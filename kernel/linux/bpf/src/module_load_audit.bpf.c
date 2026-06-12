/*
 * Role: Signal 104 — post-boot / unsigned module-load audit (Deck BYOVD). Stable
 *       arms: module:module_load tracepoint (hashes the module name) and lsm/
 *       kernel_module_request. Uncertain arm: lsm/kernel_read_file with the
 *       READING_MODULE enum — stub pending on-target enum-value BTF verification
 *       (hook signature + READING_MODULE==2 are partially confirmed, see below).
 *       The boot-baseline / signed-module /
 *       update-window gates are userspace (DeckModuleBaseline.cpp).
 * Target platform: Linux eBPF (LSM + tracepoint).
 * Interface: shares hk_ringbuf; emits HK_BPF_PW_MODULE_LOAD -> HK_EVENT_MODULE_LOAD.
 *
 * Guardrail compliance: #1 Linux-only by gating; #3 module comment; #4 pure BPF
 *   TU; #6 -Wall -Wextra -Werror; lsm/* returns inbound `ret`. #13: the
 *   kernel_read_file/READING_MODULE arm is a flagged stub, not a guess.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "hk_bpf_shared.h"

extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} hk_ringbuf SEC(".maps");

static __always_inline void
hk_emit_module_load(__u64 name_hash, __u64 sig_hash)
{
    struct hk_bpf_pw_module_load *evt;
    __u64 now = bpf_ktime_get_ns();

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return;

    evt->schema_version  = HK_PW_SCHEMA_VERSION;
    evt->event_tag       = HK_BPF_PW_MODULE_LOAD;
    evt->timestamp_ns    = now;
    evt->initiator_tgid  = (__u32)(bpf_get_current_pid_tgid() >> 32);
    evt->flags           = 0;   /* POST_BOOT/OFF_BASELINE/.. set userspace */
    evt->module_name_hash = name_hash;
    evt->module_sig_hash = sig_hash;
    evt->event_time_ns   = now;

    bpf_ringbuf_submit(evt, 0);
}

/*
 * module:module_load tracepoint — fires when a module is loaded. The context
 * carries the module name as a __data_loc string (trace_event_raw_module_load).
 * STABLE arm: hash the module name and emit. The post-boot / off-baseline
 * classification is userspace (it compares against the boot /proc/modules
 * snapshot and the SteamOS signed-module set).
 */
SEC("tracepoint/module/module_load")
int hk_tp_module_load(struct trace_event_raw_module_load *ctx)
{
    char name[HK_PW_HASH_MAX];
    __u64 h = 0;

    __builtin_memset(name, 0, sizeof(name));
    /* The module name is a __data_loc field; BPF_CORE_READ_STR_INTO decodes the
     * offset+len and copies the string (the idiomatic helper for __data_loc). */
    BPF_CORE_READ_STR_INTO(&name, ctx, name);
    h = hk_fnv64(name, HK_PW_HASH_MAX);
    hk_emit_module_load(h, 0);
    return 0;
}

/*
 * lsm/kernel_module_request(char *kmod_name) -> int ret
 * Fires when the kernel auto-requests a module (request_module). STABLE arm:
 * hash the requested name. Audit-only.
 */
SEC("lsm/kernel_module_request")
int BPF_PROG(hk_lsm_kmod_request, char *kmod_name, int ret)
{
    char name[HK_PW_HASH_MAX];
    __u64 h = 0;

    __builtin_memset(name, 0, sizeof(name));
    if (kmod_name &&
        bpf_probe_read_kernel_str(name, sizeof(name), kmod_name) > 0) {
        h = hk_fnv64(name, HK_PW_HASH_MAX);
    }
    hk_emit_module_load(h, 0);
    return ret;   /* audit-only */
}

/*
 * HK-UNCERTAIN(kernel-read-file-reading-module): the impl-plan adds an
 * lsm/kernel_read_file (READING_MODULE) arm to catch finit_module/init_module
 * payload reads. I am NOT certain of (a) the exact lsm/kernel_read_file hook
 * signature on the target Deck kernel (it changed across versions — earlier:
 * (struct file *file, enum kernel_read_file_id id); later added bool contents
 * [added in v5.13 per lkml.kernel.org/lkml/20200729175845.1745471-13-keescook]),
 * nor (b) the numeric value of the READING_MODULE enumerator.
 * (docs: include/linux/kernel_read_file.h defines the enum via the
 * __kernel_read_file_id macro; expansion order is UNKNOWN=0, FIRMWARE=1,
 * MODULE=2, KEXEC_IMAGE=3, ... so READING_MODULE == 2 on kernels that have not
 * reordered the macro list — confirm on the target via BTF enum dump; the 3-arg
 * signature with bool contents is confirmed present on mainline v5.13+.
 * lsm/kernel_read_file is BPF-attachable via the standard lsm/* mechanism.
 * Still needs on-target BTF enum-value verification before wiring.)
 * A wrong enum compare would silently mis-filter every kernel_read_file.
 * Per guardrail #13 this arm is NOT written —
 * confirm the signature + enum against the target kernel BTF, then add:
 *   SEC("lsm/kernel_read_file")
 *   int BPF_PROG(hk_lsm_kread_module, struct file *file,
 *                enum kernel_read_file_id id, ...) {
 *       if (id != <confirmed READING_MODULE>) return ret;
 *       // hash file dentry name, emit, return ret;
 *   }
 * The module:module_load + kernel_module_request arms above carry the signal
 * until this is confirmed.
 */

char _license[] SEC("license") = "GPL";
