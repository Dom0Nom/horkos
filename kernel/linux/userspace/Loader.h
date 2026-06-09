/*
 * kernel/linux/userspace/Loader.h
 * Role: Public interface for the Horkos Linux eBPF loader.  Callers open and
 *       attach the BPF programs, then drive a poll loop to receive translated
 *       hk_event_records via the provided sink callback.
 * Target platform: Linux userspace.
 * Interface: declares hk_bpf_loader_start, hk_bpf_loader_poll,
 *            hk_bpf_loader_stop, and the HkEventSink callback type.
 */

#pragma once

#include <horkos/event_schema.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * HkEventSink — callback invoked for each translated BPF event.
 *
 * @hdr     Populated hk_event_header with type, timestamp, and payload_bytes.
 * @payload Pointer to the matching payload struct (lifetime: duration of call).
 *
 * The callback must not block: it runs synchronously inside ring_buffer__poll.
 */
typedef void (*HkEventSink)(const hk_event_header *hdr, const void *payload);

/*
 * hk_bpf_loader_start — open both BPF skeletons, attach all programs, and
 * create the ring-buffer consumer.
 *
 * @sink  Event callback.  Must remain valid until hk_bpf_loader_stop returns.
 * @return 0 on success, negative errno on failure.
 */
int  hk_bpf_loader_start(HkEventSink sink);

/*
 * hk_bpf_loader_poll — drain pending ring-buffer records and block up to
 * timeout_ms for new ones.  Call in a loop until stop is desired.
 *
 * @timeout_ms  Maximum wait in milliseconds.  0 = non-blocking drain.
 */
void hk_bpf_loader_poll(int timeout_ms);

/*
 * hk_bpf_loader_stop — detach programs, free the ring buffer, and destroy
 * the BPF skeletons.  Safe to call even if start never succeeded.
 */
void hk_bpf_loader_stop(void);

/*
 * hk_bpf_loader_protected_map_fd — fd of the shared hk_protected gating map, so
 * the caller (or ProtectedSet.cpp) can insert/clear protected tgids. Returns a
 * negative value if the loader has not started or the memory-access program set
 * was not built/loaded (HORKOS_LINUX_EBPF_MEMORY off, or runtime feature probe
 * disabled it). The fd is owned by the loader; do not close it.
 */
int  hk_bpf_loader_protected_map_fd(void);

/*
 * hk_bpf_loader_trigger_vma_scan — kick the iter/task_vma iterator (signal 80)
 * once, draining its streamed VMA rows through the same sink. Driven on a
 * userspace timer by the caller. No-op (returns 0) when signal 80 is unavailable
 * (kernel < 5.13 at runtime, probed at start) so callers need not special-case
 * older kernels.
 *
 * @return number of VMA rows emitted (>= 0), or negative errno on a hard error.
 */
int  hk_bpf_loader_trigger_vma_scan(void);

#ifdef __cplusplus
}
#endif
