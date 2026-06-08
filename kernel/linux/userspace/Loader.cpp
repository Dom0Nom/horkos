/*
 * kernel/linux/userspace/Loader.cpp
 * Role: libbpf userspace loader for the Horkos Linux eBPF programs.
 *       Opens both BPF skeletons (lsm_file_open + tracepoints), attaches all
 *       programs, then polls the shared ring buffer and translates each raw
 *       BPF event record into an hk_event_record (header + payload) before
 *       dispatching it to a caller-supplied sink callback.
 * Target platform: Linux userspace (glibc/musl).  Never compiled on Windows
 *                  or macOS (guardrail #4: pure userspace TU).
 * Interface: exports hk_bpf_loader_start() / hk_bpf_loader_stop() declared
 *            in Loader.h (same directory).
 *
 * API references:
 *   - libbpf docs:   https://libbpf.readthedocs.io/en/latest/api.html
 *   - ring_buffer:   https://libbpf.readthedocs.io/en/latest/api.html#ring-buffer
 *   - bpf_object:    https://libbpf.readthedocs.io/en/latest/api.html#bpf-object
 *
 * Guardrail compliance:
 *   #1  No raw platform macros — Linux-only by build gating (CMakeLists).
 *   #3  This module comment covers role/platform/interface.
 *   #4  Pure userspace TU: BPF-side structs are redeclared here rather than
 *       including BPF kernel headers.  Skeleton headers (.skel.h) generated
 *       by bpftool are userspace-safe (they include libbpf/bpf.h, not
 *       kernel/bpf.h).
 *   #8  N/A (C++ TU; async model is in the Rust server layer).
 */

#include "Loader.h"

/* Skeleton headers are generated into the cmake binary dir and added to the
 * include path by the hk_bpf_generated INTERFACE target. */
#include "lsm_file_open.skel.h"
#include "tracepoints.skel.h"

/* libbpf userspace headers (libbpf-dev package on Debian/Ubuntu).
 * These are safe to include in userspace — they do not pull in kernel
 * internal headers.
 * Reference: https://libbpf.readthedocs.io/en/latest/api.html */
#include <bpf/libbpf.h>

/* Standard C++ / POSIX headers — permitted in userspace TUs. */
#include <cerrno>
#include <cstdarg>   /* va_list for libbpf_print_fn */
#include <cstdio>
#include <cstring>
#include <atomic>

/* horkos event schema (event_schema.h uses only stdint.h, no kernel headers).
 * Including it here is safe: it is explicitly documented as usable by both
 * kernel TUs and userspace TUs IN SEPARATE translation units (guardrail #4). */
#include <horkos/event_schema.h>

/* ---- BPF-side event tags (mirrored from the .bpf.c files) ---------------- */
/*
 * These must stay in sync with the #defines in lsm_file_open.bpf.c and
 * tracepoints.bpf.c.  A mismatch silently drops or mis-tags events.
 */
static constexpr uint32_t kBpfTagFileOpen  = 0x10u;
static constexpr uint32_t kBpfTagPtrace    = 0x20u;
static constexpr uint32_t kBpfTagProcExec  = 0x21u;

/* ---- BPF-side event struct layouts --------------------------------------- */
/*
 * These structs are redeclared here (not shared via a common header) so that
 * this translation unit never includes BPF kernel headers (guardrail #4).
 * They must exactly match the structs in the .bpf.c source files.
 * Any layout change in the BPF programs must be reflected here.
 */
static constexpr size_t kBpfPathMax = 256;

struct HkBpfFileOpenEvent {
    uint32_t schema_version;
    uint32_t event_tag;
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t reserved;
    char     filename[kBpfPathMax];
};

struct HkBpfPtraceEvent {
    uint32_t schema_version;
    uint32_t event_tag;
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t target_pid;
    uint64_t request;
};

struct HkBpfExecEvent {
    uint32_t schema_version;
    uint32_t event_tag;
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t parent_pid;
    char     filename[kBpfPathMax];
};

/* ---- Internal loader state ----------------------------------------------- */

struct LoaderState {
    lsm_file_open_bpf *lsm_skel   = nullptr;
    tracepoints_bpf   *tp_skel    = nullptr;
    ring_buffer       *ringbuf    = nullptr;
    HkEventSink        sink       = nullptr;
    std::atomic<bool>  stop_flag  { false };
};

static LoaderState g_state;

/* ---- Ring-buffer callback ------------------------------------------------ */
/*
 * Called by ring_buffer__poll for each record committed to hk_ringbuf.
 * Translates the compact BPF event into an hk_event_record and invokes
 * the caller-supplied sink.
 *
 * Return 0 to continue polling; negative to abort.
 * Reference: https://libbpf.readthedocs.io/en/latest/api.html#c.ring_buffer_sample_fn
 */
static int on_ringbuf_sample(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;

    if (data_sz < sizeof(uint32_t) * 2) {
        /* Too small to contain schema_version + event_tag — corrupted record. */
        return 0;
    }

    /* Peek at the tag without aliasing the union through an untyped cast.
     * memcpy is the standards-compliant way to read a field from an opaque
     * buffer without triggering strict-aliasing UB. */
    uint32_t event_tag = 0;
    std::memcpy(&event_tag,
                static_cast<const char *>(data) + offsetof(HkBpfFileOpenEvent, event_tag),
                sizeof(event_tag));

    hk_event_header  hdr  {};
    hdr.version  = HK_EVENT_SCHEMA_VERSION;
    hdr.reserved = 0;

    /*
     * For each event tag, validate the expected minimum size, populate the
     * hk_event_header, and call the sink with a pointer to the translated
     * payload.  We pass (header, payload_ptr, payload_size) rather than a
     * flattened buffer to avoid a heap allocation on the hot path.
     */
    if (event_tag == kBpfTagFileOpen) {
        if (data_sz < sizeof(HkBpfFileOpenEvent)) return 0;
        HkBpfFileOpenEvent bpf_evt {};
        std::memcpy(&bpf_evt, data, sizeof(bpf_evt));

        /* Map BPF file-open to HK_EVENT_HANDLE_OPEN (closest schema match;
         * the server treats it as a watched-file-access event). */
        hdr.type          = HK_EVENT_HANDLE_OPEN;
        hdr.timestamp_ns  = bpf_evt.timestamp_ns;

        hk_event_handle_open payload {};
        payload.requesting_pid = bpf_evt.pid;
        payload.target_pid     = 0;        /* not available at this hook point */
        payload.access_mask    = 0;        /* not available at LSM file_open    */
        payload.reserved       = 0;
        hdr.payload_bytes = static_cast<uint32_t>(sizeof(payload));

        if (g_state.sink)
            g_state.sink(&hdr, &payload);

    } else if (event_tag == kBpfTagPtrace) {
        if (data_sz < sizeof(HkBpfPtraceEvent)) return 0;
        HkBpfPtraceEvent bpf_evt {};
        std::memcpy(&bpf_evt, data, sizeof(bpf_evt));

        /* Map ptrace to HK_EVENT_HANDLE_OPEN: requesting_pid is the tracer,
         * target_pid is the tracee, access_mask encodes the ptrace request. */
        hdr.type          = HK_EVENT_HANDLE_OPEN;
        hdr.timestamp_ns  = bpf_evt.timestamp_ns;

        hk_event_handle_open payload {};
        payload.requesting_pid = bpf_evt.pid;
        payload.target_pid     = bpf_evt.target_pid;
        /* Truncate 64-bit request to 32-bit access_mask field; the server
         * interprets the upper bits as reserved and masks them off. */
        payload.access_mask    = static_cast<uint32_t>(bpf_evt.request & 0xFFFFFFFFu);
        payload.reserved       = 0;
        hdr.payload_bytes = static_cast<uint32_t>(sizeof(payload));

        if (g_state.sink)
            g_state.sink(&hdr, &payload);

    } else if (event_tag == kBpfTagProcExec) {
        if (data_sz < sizeof(HkBpfExecEvent)) return 0;
        HkBpfExecEvent bpf_evt {};
        std::memcpy(&bpf_evt, data, sizeof(bpf_evt));

        hdr.type          = HK_EVENT_PROCESS_CREATE;
        hdr.timestamp_ns  = bpf_evt.timestamp_ns;

        hk_event_process_create payload {};
        payload.pid         = bpf_evt.pid;
        payload.parent_pid  = bpf_evt.parent_pid;
        /* create_time_ns: exec timestamp serves as a best-effort proxy;
         * note the epoch mismatch documented in event_schema.h — the server
         * must not compare this directly with header.timestamp_ns. */
        payload.create_time_ns = bpf_evt.timestamp_ns;
        hdr.payload_bytes = static_cast<uint32_t>(sizeof(payload));

        if (g_state.sink)
            g_state.sink(&hdr, &payload);

    } else {
        /* Unknown tag — future BPF program; silently skip. */
    }

    return 0;
}

/* ---- libbpf log callback ------------------------------------------------- */
/*
 * Routes libbpf diagnostic output through fprintf(stderr) rather than the
 * default print-to-stderr path so the format is consistent with other
 * Horkos log output.
 * Reference: https://libbpf.readthedocs.io/en/latest/api.html#c.libbpf_set_print
 */
static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format,
                           va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;   /* suppress debug noise; enable for loader troubleshooting */
    return vfprintf(stderr, format, args);
}

/* ---- Public API ---------------------------------------------------------- */

int hk_bpf_loader_start(HkEventSink sink)
{
    int err = 0;

    libbpf_set_print(libbpf_print_fn);

    g_state.sink      = sink;
    g_state.stop_flag = false;

    /* --- Open and load LSM skeleton --- */
    /*
     * lsm_file_open_bpf__open_and_load() opens the embedded BPF ELF, verifies
     * all programs through the kernel verifier, and creates the maps.
     * Requires kernel ≥ 5.7 (BPF LSM), CONFIG_BPF_LSM=y, and "bpf" listed in
     * the lsm= kernel command-line parameter.
     * Reference: https://docs.kernel.org/bpf/prog_lsm.html
     */
    g_state.lsm_skel = lsm_file_open_bpf__open_and_load();
    if (!g_state.lsm_skel) {
        err = -errno;
        fprintf(stderr, "hk_loader: failed to open+load lsm_file_open skeleton: %s\n",
                std::strerror(-err));
        goto cleanup;
    }

    err = lsm_file_open_bpf__attach(g_state.lsm_skel);
    if (err) {
        fprintf(stderr, "hk_loader: failed to attach lsm_file_open programs: %s\n",
                std::strerror(-err));
        goto cleanup;
    }

    /* --- Open, share map, load tracepoints skeleton --- */
    /*
     * The tracepoints skeleton declares hk_ringbuf as an EXTERN map. Across two
     * independently-opened skeletons libbpf does NOT auto-resolve that — we must
     * open() first, point its hk_ringbuf at the already-created LSM map fd via
     * bpf_map__reuse_fd(), THEN load(). Using __open_and_load() here would create
     * a second, unread ring buffer and silently drop ptrace/exec events.
     * Reference: https://libbpf.readthedocs.io/en/latest/api.html
     */
    g_state.tp_skel = tracepoints_bpf__open();
    if (!g_state.tp_skel) {
        err = -errno;
        fprintf(stderr, "hk_loader: failed to open tracepoints skeleton: %s\n",
                std::strerror(-err));
        goto cleanup;
    }

    err = bpf_map__reuse_fd(g_state.tp_skel->maps.hk_ringbuf,
                            bpf_map__fd(g_state.lsm_skel->maps.hk_ringbuf));
    if (err) {
        fprintf(stderr, "hk_loader: failed to share hk_ringbuf with tracepoints: %s\n",
                std::strerror(-err));
        goto cleanup;
    }

    err = tracepoints_bpf__load(g_state.tp_skel);
    if (err) {
        fprintf(stderr, "hk_loader: failed to load tracepoints skeleton: %s\n",
                std::strerror(-err));
        goto cleanup;
    }

    err = tracepoints_bpf__attach(g_state.tp_skel);
    if (err) {
        fprintf(stderr, "hk_loader: failed to attach tracepoints programs: %s\n",
                std::strerror(-err));
        goto cleanup;
    }

    /* --- Create ring buffer consumer --- */
    /*
     * ring_buffer__new() takes the map fd from the LSM skeleton's hk_ringbuf
     * map.  Because both skeletons share the same underlying map (extern map
     * resolution), all BPF programs write to this single fd.
     *
     * The callback on_ringbuf_sample is invoked synchronously from within
     * ring_buffer__poll().
     * Reference: https://libbpf.readthedocs.io/en/latest/api.html#c.ring_buffer__new
     */
    {
        int map_fd = bpf_map__fd(g_state.lsm_skel->maps.hk_ringbuf);
        if (map_fd < 0) {
            err = map_fd;
            fprintf(stderr, "hk_loader: could not get hk_ringbuf fd: %s\n",
                    std::strerror(-err));
            goto cleanup;
        }
        g_state.ringbuf = ring_buffer__new(map_fd, on_ringbuf_sample,
                                           nullptr, nullptr);
        if (!g_state.ringbuf) {
            err = -errno;
            fprintf(stderr, "hk_loader: ring_buffer__new failed: %s\n",
                    std::strerror(-err));
            goto cleanup;
        }
    }

    return 0;

cleanup:
    hk_bpf_loader_stop();
    return err;
}

void hk_bpf_loader_poll(int timeout_ms)
{
    /*
     * ring_buffer__poll() drains all pending records (calling on_ringbuf_sample
     * per record) and blocks up to timeout_ms waiting for new ones via epoll.
     * Returns the number of records consumed, or a negative errno on error.
     *
     * THREADING CONTRACT: poll() and stop() are NOT thread-safe against each
     * other (ring_buffer__free races ring_buffer__poll). Run the loop and stop()
     * on the SAME thread, with a finite timeout so the loop can observe the flag:
     *   while (!hk_bpf_loader_should_stop()) hk_bpf_loader_poll(100);
     *   hk_bpf_loader_stop();
     * Once stop has been requested, poll() is a no-op so a late call is safe.
     * Reference: https://libbpf.readthedocs.io/en/latest/api.html#c.ring_buffer__poll
     */
    if (g_state.stop_flag || !g_state.ringbuf) return;

    int consumed = ring_buffer__poll(g_state.ringbuf, timeout_ms);
    if (consumed < 0 && consumed != -EINTR) {
        fprintf(stderr, "hk_loader: ring_buffer__poll error: %s\n",
                std::strerror(-consumed));
    }
}

bool hk_bpf_loader_should_stop(void)
{
    return g_state.stop_flag;
}

void hk_bpf_loader_stop(void)
{
    /* Must run on the same thread as the poll loop (see poll()'s contract):
     * setting the flag first guarantees no concurrent poll() is mid-epoll on
     * the ring buffer we are about to free. */
    g_state.stop_flag = true;

    if (g_state.ringbuf) {
        ring_buffer__free(g_state.ringbuf);
        g_state.ringbuf = nullptr;
    }
    if (g_state.tp_skel) {
        tracepoints_bpf__destroy(g_state.tp_skel);
        g_state.tp_skel = nullptr;
    }
    if (g_state.lsm_skel) {
        lsm_file_open_bpf__destroy(g_state.lsm_skel);
        g_state.lsm_skel = nullptr;
    }
}
