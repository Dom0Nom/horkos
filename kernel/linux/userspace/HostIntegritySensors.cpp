/*
 * Role: Audit aggregator + shared emit helpers for the Linux kernel/module-trust
 *       sensors (signals 91-99). Owns a timer thread that drives each periodic
 *       sensor on its cadence (§5) and forwards events through the shared
 *       HkEventSink. Does NOT poll the BPF ring buffer (that stays in Loader.cpp);
 *       signals 98/99 ride the Loader poll loop, not this thread.
 * Target platform: Linux userspace (guardrail #4).
 * Interface: implements HkNameHash / HkEmit / HkEmitUnavailable and
 *            hk_host_integrity_start / hk_host_integrity_stop (HostIntegritySensors.h).
 *
 * Guardrail compliance: #1, #3, #4. Read-only / audit-only. The stop contract
 * mirrors the Loader: stop on the owning thread, flag-first, join.
 */

#include "HostIntegritySensors.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <thread>

#include "BpfEnumerate.h"
#include "FtraceAudit.h"
#include "KallsymsAudit.h"
#include "KprobeAudit.h"
#include "LockdownPosture.h"
#include "ModuleDiskDrift.h"
#include "ModuleViewDiff.h"

namespace horkos::modint {

uint64_t HkNameHash(const std::string& name) {
    /* FNV-1a 64-bit — a non-reversible digest of the module/file name. The raw
     * name is never placed in the event plane (PII minimisation, §9). */
    uint64_t h = 1469598103934665603ull;   /* FNV offset basis */
    for (unsigned char c : name) {
        h ^= static_cast<uint64_t>(c);
        h *= 1099511628211ull;             /* FNV prime */
    }
    return h;
}

void HkEmit(HkEventSink sink, uint32_t type, const void* payload, uint32_t size) {
    if (sink == nullptr || payload == nullptr) return;

    hk_event_header hdr{};
    hdr.version = HK_EVENT_SCHEMA_VERSION;
    hdr.type = type;
    /* Monotonic ns at emit (header epoch — boot/interrupt epoch like the BPF
     * path). CLOCK_MONOTONIC matches bpf_ktime_get_ns()'s epoch closely enough
     * for the server's coarse correlation. */
    hdr.timestamp_ns = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count());
    hdr.payload_bytes = size;
    hdr.reserved = 0;

    sink(&hdr, payload);
}

void HkEmitUnavailable(HkEventSink sink, uint32_t signal_id, int err) {
    HkEvtSensorUnavailable ev{};
    ev.signal_id = signal_id;
    ev.errno_value = static_cast<uint32_t>(err < 0 ? -err : err);
    HkEmit(sink, kEvtSensorUnavailable, &ev, sizeof(ev));
}

namespace {

/* ---- Aggregator state ----------------------------------------------------- */
struct AggState {
    std::atomic<bool> running{false};
    std::thread thread;
    std::mutex mtx;
    std::condition_variable cv;
    HkEventSink sink = nullptr;
};

AggState g_agg;

/* Cadences from §5 (seconds). */
constexpr int kSymbolMapRefreshSec = 60;
constexpr int kFastAuditSec = 60;        /* 91 / 93 / 94 */
constexpr int kModuleViewSec = 30;       /* 92 */
constexpr int kModuleViewDebounceMs = 500;
constexpr int kDiskDriftSec = 300;       /* 95 */
constexpr int kPostureSec = 600;         /* 96 */
constexpr int kForeignBpfSec = 60;       /* 97 */

/* Sleep on the CV up to `ms`, waking early if a stop is requested. Returns true
 * if still running (continue), false if stop requested. */
bool WaitOrStop(int ms) {
    std::unique_lock<std::mutex> lk(g_agg.mtx);
    g_agg.cv.wait_for(lk, std::chrono::milliseconds(ms),
                      [] { return !g_agg.running.load(); });
    return g_agg.running.load();
}

void AuditLoop() {
    HkEventSink sink = g_agg.sink;

    /* Per-loop elapsed accounting so each cadence fires independently without a
     * separate thread per sensor. We tick the loop at the module-view cadence
     * (the fastest periodic one) and run slower sensors on a counter. */
    HkSymbolMap map = BuildFromProc();
    int since_symbolmap = 0;
    int since_fast = 0;
    int since_disk = 0;
    int since_posture = 0;
    int since_bpf = 0;

    /* Posture once at startup (§5.5). */
    hk_sensor_posture(&map, sink);
    since_posture = 0;

    /* Prime the module-view debounce with one immediate snapshot pair so the
     * first real discrepancy can be confirmed on the next cycle. */
    hk_sensor_module_view(&map, sink);

    while (g_agg.running.load()) {
        if (!WaitOrStop(kModuleViewSec * 1000)) break;

        /* Module view (92): take the second debounce snapshot 500 ms after the
         * first within this cadence tick. */
        hk_sensor_module_view(&map, sink);
        if (!WaitOrStop(kModuleViewDebounceMs)) break;
        hk_sensor_module_view(&map, sink);

        since_symbolmap += kModuleViewSec;
        since_fast += kModuleViewSec;
        since_disk += kModuleViewSec;
        since_posture += kModuleViewSec;
        since_bpf += kModuleViewSec;

        if (since_symbolmap >= kSymbolMapRefreshSec) {
            map = BuildFromProc();
            since_symbolmap = 0;
        }
        if (since_fast >= kFastAuditSec) {
            hk_sensor_kallsyms(&map, sink);
            hk_sensor_ftrace(&map, sink);
            hk_sensor_kprobe(&map, sink);
            since_fast = 0;
        }
        if (since_bpf >= kForeignBpfSec) {
            hk_sensor_bpf_enum(&map, sink);
            since_bpf = 0;
        }
        if (since_disk >= kDiskDriftSec) {
            hk_sensor_module_disk(&map, sink);
            since_disk = 0;
        }
        if (since_posture >= kPostureSec) {
            hk_sensor_posture(&map, sink);
            since_posture = 0;
        }
    }
}

}  // namespace

int hk_host_integrity_start(HkEventSink sink) {
    if (sink == nullptr) return -1;
    if (g_agg.running.exchange(true)) return -1;   /* already running */
    g_agg.sink = sink;
    g_agg.thread = std::thread(AuditLoop);
    return 0;
}

void hk_host_integrity_stop(void) {
    if (!g_agg.running.exchange(false)) {
        /* Not running; still join a possibly-finished thread for cleanliness. */
    }
    {
        std::lock_guard<std::mutex> lk(g_agg.mtx);
        g_agg.cv.notify_all();
    }
    if (g_agg.thread.joinable()) g_agg.thread.join();
    g_agg.sink = nullptr;
}

}  // namespace horkos::modint
