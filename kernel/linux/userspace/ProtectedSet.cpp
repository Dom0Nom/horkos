/*
 * Role: Userspace populator for the shared `hk_protected` BPF map. Translates a
 *       hk_protected_entry into the in-kernel `struct hk_protected_val` layout
 *       and writes it via bpf_map_update_elem / bpf_map_delete_elem on the map
 *       fd owned by the loader. This is the single structural gate that arms the
 *       memory-access sensors: until a tgid is inserted here, none of signals
 *       73-81 fire for it.
 * Target platform: Linux userspace (guardrail #4 — manipulates the map fd only;
 *                   never includes BPF kernel headers, never shares a TU with a
 *                   .bpf.c object).
 * Interface: implements ProtectedSet.h. The in-kernel value layout it writes is
 *            redeclared here (HkProtectedVal) rather than included from the BPF
 *            header, exactly like Loader.cpp redeclares the BPF event structs.
 *
 * API references:
 *   - libbpf map ops: https://libbpf.readthedocs.io/en/latest/api.html
 *     bpf_map_update_elem / bpf_map_lookup_elem / bpf_map_delete_elem.
 */

#include "ProtectedSet.h"

/* libbpf userspace map-syscall wrappers. Userspace-safe (no kernel headers). */
#include <bpf/bpf.h>

#include <cerrno>
#include <cstring>

/*
 * Redeclared mirror of the BPF-side `struct hk_protected_val`
 * (include/hk_protected.bpf.h). Layout MUST match byte-for-byte: three u64s,
 * no padding. A change in the BPF header must be reflected here (guardrail #4
 * forbids sharing the header across the kernel/userspace TU boundary).
 */
struct HkProtectedVal {
    uint64_t dev;
    uint64_t inode;
    uint64_t load_done_ns;
};

static_assert(sizeof(HkProtectedVal) == 24,
              "HkProtectedVal must match struct hk_protected_val (3x u64)");

int hk_protected_set_pid(int map_fd, const hk_protected_entry *entry)
{
    if (map_fd < 0 || entry == nullptr)
        return -EINVAL;

    HkProtectedVal val{};
    val.dev          = entry->dev;
    val.inode        = entry->inode;
    val.load_done_ns = entry->load_done_ns;

    uint32_t key = entry->tgid;

    /* BPF_ANY: insert if absent, replace if present. */
    int rc = bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
    if (rc != 0)
        return -errno;   /* libbpf sets errno; rc is -1 on failure */
    return 0;
}

int hk_protected_set_load_done(int map_fd, uint32_t tgid, uint64_t load_done_ns)
{
    if (map_fd < 0)
        return -EINVAL;

    /* Read-modify-write so we do not clobber dev/inode already recorded for the
     * tgid. If the key is absent, seed a row carrying only the timestamp. */
    HkProtectedVal val{};
    int rc = bpf_map_lookup_elem(map_fd, &tgid, &val);
    if (rc != 0) {
        /* Absent (or error): start a fresh row. dev/inode stay 0 until a later
         * hk_protected_set_pid fills them. */
        val.dev   = 0;
        val.inode = 0;
    }
    val.load_done_ns = load_done_ns;

    rc = bpf_map_update_elem(map_fd, &tgid, &val, BPF_ANY);
    if (rc != 0)
        return -errno;
    return 0;
}

int hk_protected_clear(int map_fd, uint32_t tgid)
{
    if (map_fd < 0)
        return -EINVAL;

    int rc = bpf_map_delete_elem(map_fd, &tgid);
    if (rc != 0) {
        /* Absent key is not an error for idempotent teardown. */
        if (errno == ENOENT)
            return 0;
        return -errno;
    }
    return 0;
}
