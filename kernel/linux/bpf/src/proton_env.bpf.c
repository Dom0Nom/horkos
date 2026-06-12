/*
 * Role: Signal 100 — capture WINEDLLOVERRIDES (and the offending override token)
 *       at exec by scanning the new process's env block, FNV-hashing the
 *       offending token, and pushing a hk_bpf_pw_proton_override to hk_ringbuf.
 *       The manifest diff (which override is anomalous) is ENTIRELY userspace
 *       (ProtonOverrideCheck.cpp); this program only extracts + hashes.
 * Target platform: Linux eBPF (BPF_PROG_TYPE_TRACEPOINT, sched/sched_process_exec).
 * Interface: shares hk_ringbuf (extern, defined in lsm_file_open.bpf.c, repointed
 *            by Loader.cpp); emits the BPF tag HK_BPF_PW_PROTON_OVERRIDE which the
 *            loader maps to the provisional HK_EVENT_PROTON_OVERRIDE type.
 *
 * Guardrail compliance:
 *   #1  No raw platform macros — Linux-only by build gating.
 *   #3  This module comment covers role/platform/interface.
 *   #4  Pure kernel eBPF TU — no userspace headers.
 *   #6  Compiled -Wall -Wextra -Werror (CMakeLists.txt).
 *
 * API references:
 *   - sched_process_exec:  https://docs.ebpf.io/linux/tracepoints/sched/sched_process_exec/
 *   - bpf_probe_read_user: https://docs.ebpf.io/linux/helper-function/bpf_probe_read_user/
 *
 * VERIFIER NOTE (impl-plan §100): the env region (mm->env_start..env_end) is
 * variable length user memory; a bounded fixed loop is required. We scan a capped
 * window (HK_PW_HASH_MAX bytes per token, kProtonEnvScanBudget tokens) so the loop
 * is verifier-provable. Truncation is acceptable: the token is only hashed and
 * userspace re-resolves the full value from /proc/<pid>/environ.
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

/* The env block is scanned in fixed chunks copied from user memory. We look for
 * the literal "WINEDLLOVERRIDES=" and, when found, hash the bytes that follow up
 * to the next NUL. The scan budget bounds total work for the verifier. */
#define HK_PW_ENV_CHUNK   256u
#define HK_PW_ENV_BUDGET  32u   /* up to 32 chunks (~8 KiB) scanned */

static const char kProtonKey[] = "WINEDLLOVERRIDES=";
#define HK_PW_PROTON_KEYLEN 17u  /* strlen("WINEDLLOVERRIDES=") */

/* Compare the start of `buf` against the WINEDLLOVERRIDES= key. Returns 1 on
 * match. Fully unrolled, no helper call. */
static __always_inline int hk_match_key(const char *buf)
{
    for (__u32 i = 0; i < HK_PW_PROTON_KEYLEN; i++) {
        if (buf[i] != kProtonKey[i])
            return 0;
    }
    return 1;
}

SEC("tracepoint/sched/sched_process_exec")
int hk_tp_proton_env(struct trace_event_raw_sched_process_exec *ctx)
{
    struct hk_bpf_pw_proton_override *evt;
    struct task_struct *task;
    struct mm_struct *mm;
    unsigned long env_start = 0, env_end = 0;
    char chunk[HK_PW_ENV_CHUNK];
    __u64 token_hash = 0;
    int found = 0;

    (void)ctx;

    task = (struct task_struct *)bpf_get_current_task();
    mm   = BPF_CORE_READ(task, mm);
    if (!mm)
        return 0;

    env_start = (unsigned long)BPF_CORE_READ(mm, env_start);
    env_end   = (unsigned long)BPF_CORE_READ(mm, env_end);
    if (env_end <= env_start)
        return 0;

    /* Bounded chunked scan of the user env region. Each env entry is a NUL-
     * terminated "KEY=VALUE"; we only need to spot the WINEDLLOVERRIDES= entry
     * and hash its value. We read aligned chunks and look for the key at every
     * offset that follows a NUL (entry boundary) plus offset 0. */
    unsigned long cur = env_start;
    for (__u32 c = 0; c < HK_PW_ENV_BUDGET; c++) {
        if (cur >= env_end)
            break;

        __builtin_memset(chunk, 0, sizeof(chunk));
        /* Copy a bounded chunk from user memory. A failed read (unmapped tail)
         * ends the scan; truncation is acceptable per the verifier note. */
        long rc = bpf_probe_read_user(chunk, sizeof(chunk), (const void *)cur);
        if (rc < 0)
            break;

        /* Walk entry boundaries inside this chunk. Bounded by chunk size.
         * `<=` allows keys whose first byte starts at the last KEYLEN bytes of
         * the chunk; vstart == HK_PW_ENV_CHUNK in that case, so the value-hash
         * inner loop hits the `idx >= HK_PW_ENV_CHUNK` guard immediately and
         * produces an empty-value hash — acceptable for cross-chunk keys. The
         * verifier can prove all chunk[] accesses in bounds because the guards
         * in the inner loop are explicit (if (idx >= HK_PW_ENV_CHUNK) break). */
        for (__u32 off = 0; off + HK_PW_PROTON_KEYLEN <= HK_PW_ENV_CHUNK; off++) {
            int at_boundary = (off == 0) || (chunk[off - 1] == '\0');
            if (!at_boundary)
                continue;
            if (chunk[off] == '\0')
                continue;
            if (hk_match_key(&chunk[off])) {
                /* Hash from just after the '=' to the value's NUL (bounded). */
                __u32 vstart = off + HK_PW_PROTON_KEYLEN;
                __u32 vlen = 0;
                for (__u32 k = 0; k < HK_PW_HASH_MAX; k++) {
                    __u32 idx = vstart + k;
                    if (idx >= HK_PW_ENV_CHUNK)
                        break;
                    if (chunk[idx] == '\0')
                        break;
                    vlen++;
                }
                token_hash = hk_fnv64(&chunk[vstart], vlen);
                found = 1;
                break;
            }
        }
        if (found)
            break;
        cur += HK_PW_ENV_CHUNK;
    }

    if (!found)
        return 0;   /* no WINEDLLOVERRIDES in this exec — nothing to report */

    evt = bpf_ringbuf_reserve(&hk_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->schema_version     = HK_PW_SCHEMA_VERSION;
    evt->event_tag          = HK_BPF_PW_PROTON_OVERRIDE;
    evt->timestamp_ns       = bpf_ktime_get_ns();
    evt->pid                = (__u32)(bpf_get_current_pid_tgid() >> 32);
    evt->flags              = 0;   /* userspace sets HK_PW_PROTON_* after manifest diff */
    evt->override_token_hash = token_hash;
    evt->proton_build_hash  = 0;   /* userspace fills the dist-manifest id */

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
