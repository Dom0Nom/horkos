/*
 * Role: Linux config-read TLP latency probe (sig 132 — LOW WEIGHT side-channel).
 *       Tight-loops identical config reads of one register timed with
 *       CLOCK_MONOTONIC_RAW, builds robust stats (median + IQR), and tags the
 *       same-root-port peer cohort so the server compares only within-cohort.
 *       NEVER fires standalone; explicitly low-weight — the server uses it only
 *       as a tie-break corroborator behind the structural signals.
 * Target platforms: Linux only. Selected by CMake elseif(UNIX).
 * Implements: hk_dma_linux_fill_tlp_latency (an opt-in pass over the records the
 *       structural scan already produced).
 */

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#include "../../include/horkos/dma_forensics.h"

static const int    TLP_SAMPLES   = 64;   /* reads per device. */
static const uint32_t TLP_READ_OFF = 0x00; /* VID register — always present. */

static uint64_t now_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ull +
           static_cast<uint64_t>(ts.tv_nsec);
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *static_cast<const uint64_t *>(a);
    uint64_t y = *static_cast<const uint64_t *>(b);
    return (x < y) ? -1 : (x > y) ? 1 : 0;
}

/* -------------------------------------------------------------------------
 * bdf_to_dir — reconstruct the sysfs device dir from the packed hk_pci_bdf.
 * ------------------------------------------------------------------------- */
static void bdf_to_dir(const hk_pci_bdf *bdf, char *out, size_t cap) {
    unsigned dev = (bdf->devfn >> 3) & 0x1Fu;
    unsigned fn  = bdf->devfn & 0x07u;
    std::snprintf(out, cap, "/sys/bus/pci/devices/%04x:%02x:%02x.%x",
                  bdf->domain, bdf->bus, dev, fn);
}

/* -------------------------------------------------------------------------
 * hk_dma_linux_fill_tlp_latency
 *
 * Times TLP_SAMPLES single-dword config reads of TLP_READ_OFF and records the
 * median and inter-quartile range (robust to scheduler-induced outliers, per
 * the catalog's robust-stats requirement). The same-root-port cohort id is the
 * device's bus number truncated to the root-port granularity — a coarse cohort
 * key the server refines; we ship the raw bus so the server's within-cohort
 * comparison only pits peers behind the same root against each other.
 *
 * Pure timing read; no device state changes. Skips devices with scan_error set.
 * ------------------------------------------------------------------------- */
extern "C" void hk_dma_linux_fill_tlp_latency(hk_dma_device_forensics *d) {
    if (d == nullptr || d->scan_error != 0u) return;

    char dir[256];
    bdf_to_dir(&d->bdf, dir, sizeof(dir));
    char path[320];
    std::snprintf(path, sizeof(path), "%s/config", dir);

    int fd = ::open(path, O_RDONLY);
    if (fd < 0) return; /* leave latency fields 0 = "no sample". */

    uint64_t samples[TLP_SAMPLES];
    int n = 0;
    for (int i = 0; i < TLP_SAMPLES; ++i) {
        uint8_t dword[4];
        uint64_t t0 = now_ns();
        ssize_t r = ::pread(fd, dword, sizeof(dword), TLP_READ_OFF);
        uint64_t t1 = now_ns();
        if (r != 4) break;
        samples[n++] = (t1 >= t0) ? (t1 - t0) : 0ull;
    }
    ::close(fd);
    if (n < 8) return; /* too few samples for a robust median/IQR. */

    std::qsort(samples, static_cast<size_t>(n), sizeof(uint64_t), cmp_u64);
    /* For even n, use the average of the two middle elements to avoid the
     * upper-middle bias that samples[n/2] alone produces. */
    uint64_t median;
    if (n % 2 == 0) {
        median = (samples[n / 2 - 1] / 2u) + (samples[n / 2] / 2u)
                 + ((samples[n / 2 - 1] & 1u) + (samples[n / 2] & 1u)) / 2u;
    } else {
        median = samples[n / 2];
    }
    uint64_t q1     = samples[n / 4];
    uint64_t q3     = samples[(3 * n) / 4];
    uint64_t iqr    = (q3 >= q1) ? (q3 - q1) : 0ull;

    d->tlp_latency_median_ns = (median > 0xFFFFFFFFull)
                                   ? 0xFFFFFFFFu : static_cast<uint32_t>(median);
    d->tlp_latency_iqr_ns    = (iqr > 0xFFFFFFFFull)
                                   ? 0xFFFFFFFFu : static_cast<uint32_t>(iqr);
    /* Coarse cohort key: bus number. The server maps bus -> root port and
     * compares only within the same root-port cohort. */
    d->tlp_same_root_port_group = d->bdf.bus;
}
