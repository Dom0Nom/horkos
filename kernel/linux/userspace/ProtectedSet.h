/*
 * kernel/linux/userspace/ProtectedSet.h
 * Role: Public interface for populating the shared `hk_protected` BPF map that
 *       gates every Linux memory-access sensor (signals 73-81). Userspace adds
 *       a protected game process by tgid together with its main-executable
 *       (dev,inode) and a load-done timestamp; the in-kernel sensors then only
 *       fire when the subject is in this set. Clearing an entry on process exit
 *       stops all gated signals for that tgid.
 * Target platform: Linux userspace (guardrail #4 — never shares a TU with any
 *                   BPF kernel object; it only manipulates the map fd).
 * Interface: declares hk_protected_set_pid / hk_protected_set_load_done /
 *            hk_protected_clear and the hk_protected_entry input struct. The
 *            map fd is supplied by the Loader (which owns the skeleton that
 *            created/holds the map).
 */

#pragma once

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * hk_protected_entry — userspace-side mirror of the BPF `struct hk_protected_val`
 * plus the tgid key. Field layout/sizes match include/hk_protected.bpf.h
 * (u64 dev, u64 inode, u64 load_done_ns); kept as a plain POD so a future
 * attestation-backend recorder can fill it directly.
 *
 * HK-TODO(schema): the source of (dev,inode) and load_done_ns is the Linux
 * attestation backend's recorded process identity, which does not yet expose a
 * concrete getter (attestation/backends/linux is TPM-only today). Until that
 * lands, the caller (loader bring-up / a test harness) fills this struct from
 * stat(2) on the game's /proc/<tgid>/exe and a post-link ktime sample.
 */
typedef struct hk_protected_entry {
    uint32_t tgid;
    uint64_t dev;          /* main-executable backing st_dev  */
    uint64_t inode;        /* main-executable backing st_ino  */
    uint64_t load_done_ns; /* ktime after the dynamic linker settled; 0 = unset */
} hk_protected_entry;

/*
 * hk_protected_set_pid — insert/replace the protected row for entry->tgid.
 *
 * @map_fd  fd of the hk_protected BPF map (from the loader's skeleton).
 * @entry   protected identity; copied, not retained.
 * @return  0 on success, negative errno on failure (bad fd, ENOMEM, etc.).
 */
int hk_protected_set_pid(int map_fd, const hk_protected_entry *entry);

/*
 * hk_protected_set_load_done — update only the load_done_ns field for an already
 * present tgid (called once the dynamic linker has settled so signals 76/79/80
 * can separate post-link patches from loader activity). Inserts a row with the
 * given timestamp if the tgid is not yet present (dev/inode left 0).
 *
 * @return 0 on success, negative errno on failure.
 */
int hk_protected_set_load_done(int map_fd, uint32_t tgid, uint64_t load_done_ns);

/*
 * hk_protected_clear — remove the protected row for `tgid` (process exit).
 * Removing an absent key is treated as success (idempotent teardown).
 *
 * @return 0 on success or absent key, negative errno on a real failure.
 */
int hk_protected_clear(int map_fd, uint32_t tgid);

#ifdef __cplusplus
}
#endif
