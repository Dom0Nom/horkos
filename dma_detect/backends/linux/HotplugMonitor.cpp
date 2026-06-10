/*
 * dma_detect/backends/linux/HotplugMonitor.cpp
 * Role: Linux PCIe hot-plug arrival monitor (sig 134). Subscribes to udev
 *       netlink KOBJECT_UEVENT messages on the `pci` subsystem (ADD) and emits a
 *       timestamped arrival per device — subscribe, do NOT poll. A post-AC-start
 *       arrival of an unbound bus-master device with an ID anomaly is the catch;
 *       Thunderbolt/USB4 root-port domains are recognised benign by the server.
 * Target platforms: Linux only. Selected by CMake elseif(UNIX).
 * Implements: dma_detect/include/horkos/dma_forensics.h
 *       (hk_dma_forensics_subscribe / _unsubscribe).
 *
 * This is a netlink matching/notification path, NOT an ES auth event — guardrail
 * #7 (ES auth-reply deadline) does not apply. The monitor thread is detached and
 * stopped cooperatively via an atomic flag plus closing the socket.
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <atomic>
#include <thread>
#include <unistd.h>
#include <time.h>
#include <poll.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "../../include/horkos/dma_forensics.h"

namespace {

struct HotplugHandle {
    int sock = -1;
    std::atomic<bool> stop{false};
    std::thread worker;
    hk_dma_arrival_cb cb = nullptr;
    void *ctx = nullptr;
};

uint64_t mono_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ull +
           static_cast<uint64_t>(ts.tv_nsec);
}

/* -------------------------------------------------------------------------
 * parse_pci_bdf_from_uevent
 *
 * A udev uevent message is a NUL-separated key=value list. For a PCI add we look
 * for SUBSYSTEM=pci and a PCI_SLOT_NAME=<domain>:<bus>:<dev>.<fn> field. Returns
 * true and fills *out when both are present.
 * ------------------------------------------------------------------------- */
bool parse_pci_bdf_from_uevent(const char *msg, size_t len, hk_pci_bdf *out) {
    bool is_pci = false;
    bool got_bdf = false;
    bool is_add = false;
    size_t i = 0;
    /* The first line is "ACTION@DEVPATH"; subsequent NUL-separated KV pairs.
     * Token length is bounded by the known buffer length n so a truncated or
     * non-NUL-terminated receive cannot run past the buffer. */
    while (i < len) {
        const char *tok = msg + i;
        size_t remaining = len - i;
        /* Find the NUL terminator within the remaining buffer instead of
         * calling strlen, which would scan past len on a truncated datagram. */
        size_t toklen = 0;
        while (toklen < remaining && tok[toklen] != '\0') {
            ++toklen;
        }
        if (toklen == 0) { ++i; continue; }

        if (toklen >= 10 && std::strncmp(tok, "ACTION=add", 10) == 0) is_add = true;
        else if (toklen >= 13 && std::strncmp(tok, "SUBSYSTEM=pci", 13) == 0) is_pci = true;
        else if (toklen >= 14 && std::strncmp(tok, "PCI_SLOT_NAME=", 14) == 0) {
            unsigned dom = 0, bus = 0, dev = 0, fn = 0;
            if (std::sscanf(tok + 14, "%x:%x:%x.%x", &dom, &bus, &dev, &fn) == 4) {
                out->domain = static_cast<uint16_t>(dom);
                out->bus    = static_cast<uint8_t>(bus);
                out->devfn  = static_cast<uint8_t>(((dev & 0x1Fu) << 3) | (fn & 0x07u));
                got_bdf = true;
            }
        }
        /* The first line ("add@/devices/...") also carries the action. */
        else if (toklen >= 4 && std::strncmp(tok, "add@", 4) == 0) is_add = true;

        i += toklen + 1;
    }
    return is_pci && is_add && got_bdf;
}

void monitor_loop(HotplugHandle *h) {
    char buf[8192];
    while (!h->stop.load(std::memory_order_acquire)) {
        /* poll() with a 500 ms timeout so a dead/closed socket cannot spin
         * the thread at 100% CPU on repeated zero/error returns from recv(). */
        struct pollfd pfd;
        pfd.fd      = h->sock;
        pfd.events  = POLLIN;
        pfd.revents = 0;
        int pr = ::poll(&pfd, 1, 500);
        if (pr < 0) {
            if (h->stop.load(std::memory_order_acquire)) break;
            continue; /* EINTR — re-poll. */
        }
        if (pr == 0) {
            /* Timeout — no event; re-check stop flag and poll again. */
            continue;
        }
        ssize_t n = ::recv(h->sock, buf, sizeof(buf) - 1, MSG_DONTWAIT);
        if (n <= 0) {
            if (h->stop.load(std::memory_order_acquire)) break;
            continue; /* EINTR / EAGAIN — re-poll. */
        }
        buf[n] = '\0';
        hk_pci_bdf bdf;
        std::memset(&bdf, 0, sizeof(bdf));
        if (parse_pci_bdf_from_uevent(buf, static_cast<size_t>(n), &bdf)) {
            if (h->cb) h->cb(&bdf, mono_ns(), h->ctx);
        }
    }
}

} /* anonymous namespace */

/* -------------------------------------------------------------------------
 * hk_dma_forensics_subscribe — open the udev netlink monitor and spawn a thread.
 * ------------------------------------------------------------------------- */
extern "C" int hk_dma_forensics_subscribe(hk_dma_arrival_cb cb, void *ctx,
                                          void **out_handle) {
    if (cb == nullptr || out_handle == nullptr) return -1;

    int sock = ::socket(PF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_KOBJECT_UEVENT);
    if (sock < 0) return -1;

    struct sockaddr_nl addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid    = 0; /* kernel assigns; 0 lets multiple monitors coexist. */
    addr.nl_groups = 1; /* group 1 = udev monitor multicast. */
    if (::bind(sock, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0) {
        ::close(sock);
        return -1;
    }

    HotplugHandle *h = new (std::nothrow) HotplugHandle();
    if (h == nullptr) {
        ::close(sock);
        return -1;
    }
    h->sock = sock;
    h->cb   = cb;
    h->ctx  = ctx;
    h->worker = std::thread(monitor_loop, h);

    *out_handle = h;
    return 0;
}

/* -------------------------------------------------------------------------
 * hk_dma_forensics_unsubscribe — stop the thread and free the handle.
 * ------------------------------------------------------------------------- */
extern "C" void hk_dma_forensics_unsubscribe(void *handle) {
    if (handle == nullptr) return;
    HotplugHandle *h = static_cast<HotplugHandle *>(handle);
    h->stop.store(true, std::memory_order_release);
    /* Closing the socket unblocks a pending recv(). */
    if (h->sock >= 0) {
        ::shutdown(h->sock, SHUT_RDWR);
        ::close(h->sock);
        h->sock = -1;
    }
    if (h->worker.joinable()) h->worker.join();
    delete h;
}
