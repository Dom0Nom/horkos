# Linux — Proton / Wine / Steam Deck (`linux-proton-wine`)

**Scope:** Read-only eBPF + userspace sensors for the Linux/Proton/Wine/Steam-Deck client that detect cheat injection and Deck-immutability breaches inside the Proton/pressure-vessel runtime — DLL-override and foreign-SO injection, cross-process memory scanners, sandbox-namespace breaches, post-boot module loads, read-only-rootfs breaches, gamescope frame siphons, Wine-builtin patching, and synthetic uinput input. All sensors sample and report; **all ban authority is server-side** (guardrail: clients sample + report only).

**Catalog signals covered:** 100, 101, 102, 103, 104, 105, 106, 107, 108.

Signal split by collection plane:

- **eBPF kernel/LSM plane** (`kernel/linux/bpf/src/*.bpf.c`): 100 (env capture at exec), 101 (`security_mmap_file` LSM), 102 (`process_vm_readv`/`mem_open`/ptrace LSM), 103 (`setns`/`commit_nsset`), 104 (`kernel_module_request`/`kernel_read_file` LSM + `module:module_load`), 105 (`sb_remount`/`sb_mount` LSM + `file_open` create/write), 106 (`connect` to gamescope socket + DRM ioctls), 107 (`file_mprotect` LSM W^X arm), 108 (`uinput_create_device`/`input_inject_event` kprobes).
- **Userspace correlation/verifier plane** (`kernel/linux/userspace/*.cpp`): per-signal baseliners that resolve the game/wineserver/launcher process lineage, hold the per-Proton-version SHA256 manifests and overlay/module allowlists, walk `/proc/<pid>/{maps,environ,ns,mounts}`, and translate BPF records into `hk_event_record`s for the server. The eBPF programs are intentionally cheap and allowlist-free; **all manifest diffing and allowlisting is userspace + server**, never in-kernel (verifier-complexity and update-cadence reasons).

The eBPF programs are **audit-only**: every `lsm/*` program returns the inbound `ret` (never overrides another LSM's decision), matching the established pattern in `kernel/linux/bpf/src/lsm_file_open.bpf.c`. No client-side thresholding or banning — feature extraction and scoring are server-side.

---

## New files

| Path | Role | Module-comment summary (role / platform / interface) |
|---|---|---|
| `kernel/linux/bpf/src/proton_env.bpf.c` | eBPF: capture `WINEDLLOVERRIDES` + argv from `bprm->envp`/`bprm->mm` at `sched_process_exec` (100). | Role: env/override capture at exec, pushes a `hk_bpf_proton_env_event` to `hk_ringbuf`. Target: Linux eBPF (`BPF_PROG_TYPE_TRACEPOINT`, `sched/sched_process_exec`). Interface: shares `hk_ringbuf` (declared extern, defined in `lsm_file_open.bpf.c`); loader maps to a new schema type. Guardrail #1 Linux-only by gating; #4 pure kernel TU; #6 `-Wall -Wextra -Werror`. |
| `kernel/linux/bpf/src/mmap_exec_audit.bpf.c` | eBPF: `lsm/mmap_file` filtering `PROT_EXEC` maps, reconstruct backing dentry path + `i_sb` mount (101). | Role: exec-mapping provenance audit. Target: Linux eBPF (`BPF_PROG_TYPE_LSM`, `lsm/mmap_file`, kernel ≥ 5.7). Interface: extends the LSM hook set, shares `hk_ringbuf`. Audit-only: returns inbound `ret`. |
| `kernel/linux/bpf/src/cross_mem_audit.bpf.c` | eBPF: `sys_enter_process_vm_readv`/`_writev` tracepoints + `lsm/ptrace_access_check` + kprobe on `mem_open` (102). | Role: cross-process memory-access audit. Target: Linux eBPF (tracepoint + LSM + kprobe). Interface: shares `hk_ringbuf`; strictly additive to the existing `sys_enter_ptrace` probe in `tracepoints.bpf.c`. |
| `kernel/linux/bpf/src/namespace_entry.bpf.c` | eBPF: `sys_enter_setns` tracepoint + kprobe on `commit_nsset` (103). | Role: namespace-entry audit (pressure-vessel breach). Target: Linux eBPF (tracepoint + kprobe). Interface: shares `hk_ringbuf`; reports target ns inode + caller tgid. |
| `kernel/linux/bpf/src/module_load_audit.bpf.c` | eBPF: `lsm/kernel_module_request` + `lsm/kernel_read_file` (READING_MODULE) + `module:module_load` tracepoint (104). | Role: post-boot / unsigned module-load audit (Deck BYOVD). Target: Linux eBPF (LSM + tracepoint). Interface: shares `hk_ringbuf`; emits module name + initiating tgid. |
| `kernel/linux/bpf/src/rootfs_ro_audit.bpf.c` | eBPF: `lsm/sb_remount` + `lsm/sb_mount` for root-SB `MS_RDONLY` loss, plus `lsm/file_open` create/write on protected subvol (105). | Role: read-only rootfs invariant audit. Target: Linux eBPF (LSM). Interface: shares `hk_ringbuf`; reads `sb->s_flags & SB_RDONLY` via CO-RE. |
| `kernel/linux/bpf/src/compositor_consumer.bpf.c` | eBPF: `sys_enter_connect` to gamescope AF_UNIX socket + `sys_enter_ioctl` filtered to DRM lease/PRIME ioctls (106). | Role: gamescope frame-consumer / DRM-lease siphon audit. Target: Linux eBPF (tracepoint). Interface: shares `hk_ringbuf`; emits connecting/importing tgid + sun_path hash. |
| `kernel/linux/bpf/src/mprotect_wx_audit.bpf.c` | eBPF: `lsm/file_mprotect` flagging RX re-protection of a VMA (107 mprotect arm). | Role: W^X re-arm audit for Wine builtins. Target: Linux eBPF (`BPF_PROG_TYPE_LSM`, `lsm/file_mprotect`). Interface: shares `hk_ringbuf`; emits VMA range + backing dev:ino + new prot. |
| `kernel/linux/bpf/src/uinput_inject_audit.bpf.c` | eBPF: kprobe `uinput_create_device` + kprobe `input_inject_event` (108). | Role: synthetic-input (uinput/evdev) audit. Target: Linux eBPF (kprobe). Interface: shares `hk_ringbuf`; emits injecting tgid + event type. |
| `kernel/linux/bpf/include/hk_bpf_shared.h` | eBPF-only: shared BPF-side record structs + internal tags for the new programs (no `stdint.h`/libc). | Role: BPF-side wire structs reused across the new `.bpf.c` TUs. Target: Linux eBPF. Interface: included only by `.bpf.c` files (mirrors `event_schema.h` literals; never the same TU as userspace — guardrail #4). |
| `kernel/linux/userspace/ProtonOverrideCheck.cpp/.h` | Userspace: `/proc/<pid>/maps` cross-check + Proton-dist override-manifest diff (100). | Role: WINEDLLOVERRIDES anomaly verifier. Target: Linux userspace. Interface: consumes proton-env BPF records via Loader sink; emits `hk_event_record` (proton-anomaly type). |
| `kernel/linux/userspace/PrefixMapAudit.cpp/.h` | Userspace: foreign-exec-mapping classifier against dist/runtime/prefix allowlist + overlay-SO SHA256 set (101). | Role: foreign-SO map verifier. Target: Linux userspace. Interface: consumes mmap-exec BPF records; emits foreign-map records. |
| `kernel/linux/userspace/ContainerNsBaseline.cpp/.h` | Userspace: pv-bwrap launcher lineage + container ns-inode baseline (103). | Role: pressure-vessel namespace baseliner. Target: Linux userspace. Interface: resolves launcher PID chain from `/proc`; classifies `setns` records. |
| `kernel/linux/userspace/DeckModuleBaseline.cpp/.h` | Userspace: boot `/proc/modules` snapshot + SteamOS signed-module + hotplug allowlist (104). | Role: Deck module baseliner. Target: Linux userspace. Interface: classifies module-load records; gates to in-game window. |
| `kernel/linux/userspace/DeckRootfsBaseline.cpp/.h` | Userspace: `/proc/mounts` RO baseline + SteamOS update-window correlation; os-release immutable-distro gate (105). | Role: Deck rootfs baseliner. Target: Linux userspace. Interface: classifies rootfs-RW records. |
| `kernel/linux/userspace/GamescopeConsumerBaseline.cpp/.h` | Userspace: gamescope/pipewire/portal/Steam-stream allowlist for frame consumers (106). | Role: compositor-consumer baseliner. Target: Linux userspace. Interface: classifies consumer records (low-weight corroborator). |
| `kernel/linux/userspace/WineBuiltinIntegrity.cpp/.h` | Userspace: `/proc/<pid>/maps` builtin-SO inode + SHA256 vs Proton dist manifest, correlates W^X mprotect arm (107). | Role: Wine builtin PE-section integrity verifier. Target: Linux userspace. Interface: consumes mprotect-WX records + on-demand maps walk; emits integrity records. |
| `kernel/linux/userspace/DeckInputBaseline.cpp/.h` | Userspace: Steam-Input/hid-steam/gamescope-libinput tgid baseline + pre-focus uinput allowlist (108). | Role: Deck synthetic-input baseliner. Target: Linux userspace. Interface: classifies uinput/evdev records. |
| `server/telemetry/src/linux_proton.rs` | Server: `#[repr(C)]` decoders + feature extraction for the new Linux event records; feeds ban-engine/ONNX. | Role: server decode + feature extraction for Proton/Wine/Deck events. Target: server. Interface: mirrors the new `event_schema.h` structs; pure async, `thiserror`, no `unwrap()` (guardrail #8). |
| `bypass-tests/linux/proton_wine/` (dir) | Bypass-test suite for this domain (guardrail #12); one test per catalog evasion. | Role: merge-gate bypass tests. Target: Linux test host + server decode. Interface: drives synthetic injectors / replays recorded ring records; asserts the record is emitted and the evasion is not silently accepted. |

**Edited (not new):** `sdk/include/horkos/event_schema.h` (new event types + payloads + `HK_EVENT_PAYLOAD_MAX` bump + static-asserts); `sdk/include/horkos/ioctl.h` (re-pin `hk_event_record` size assert — even though Linux records never transit the Windows IOCTL, the record struct is shared wire format); `kernel/linux/userspace/Loader.cpp`/`Loader.h` (extend the BPF-tag→`hk_event_type` mapping switch; wineserver/launcher tgid resolution helpers already partially live here per the catalog's signal-102/103 slot); `kernel/linux/bpf/src/lsm_file_open.bpf.c` (keeps the canonical `hk_ringbuf` definition the new TUs reference extern); `kernel/linux/bpf/CMakeLists.txt` (register the 9 new `bpf_program(...)` entries + add to `hk_bpf_generated` deps); `kernel/linux/userspace/CMakeLists.txt` (add the new `.cpp` to `hk_bpf_loader`); `server/telemetry/src/lib.rs` (wire in `linux_proton` module); `server/api/data-categories.md` (guardrail #11 — all new fields).

---

## Interfaces & data structures

### Wire-schema additions (`sdk/include/horkos/event_schema.h`)

Bump `HK_EVENT_SCHEMA_VERSION` 2u → 3u. Append event types (existing values never change):

```c
HK_EVENT_PROTON_OVERRIDE   = 5,  /* 100 WINEDLLOVERRIDES anomaly        */
HK_EVENT_FOREIGN_MAP       = 6,  /* 101 off-tree PROT_EXEC mapping       */
HK_EVENT_CROSS_MEM         = 7,  /* 102 process_vm_readv/_writev/mem     */
HK_EVENT_NS_ENTRY          = 8,  /* 103 setns into game namespace        */
HK_EVENT_MODULE_LOAD       = 9,  /* 104 post-boot / unsigned LKM         */
HK_EVENT_ROOTFS_RW         = 10, /* 105 RO-rootfs invariant breach       */
HK_EVENT_FRAME_CONSUMER    = 11, /* 106 gamescope/DRM-lease siphon       */
HK_EVENT_WX_ARM            = 12, /* 107 builtin W^X re-protect / inode    */
HK_EVENT_SYNTH_INPUT       = 13, /* 108 uinput/evdev injection           */
```

**Wire change — record growth.** Several payloads carry a 64-bit address/inode plus a path/sun_path hash and so exceed the current `HK_EVENT_PAYLOAD_MAX 16`. Rather than carry full path strings (variable length, ringbuf-hostile, PII-adjacent), the BPF side emits **fixed 64-bit FNV/SHA-truncated hashes** of paths + the raw dev:ino, and the userspace verifier resolves the human-readable path from `/proc/<pid>/maps` at report time. Largest payload below is 40 bytes (`hk_event_cross_mem`, `hk_event_wx_arm`). Therefore:

```c
#define HK_EVENT_PAYLOAD_MAX 40u   /* was 16u — grown for Linux Proton/Wine payloads */
```

This re-pins `hk_event_record` to `24 + 40 = 64` bytes; the `HK_STATIC_ASSERT(sizeof(hk_event_record) == 40, ...)` in `ioctl.h` becomes `== 64`. (Linux records do not flow through the Windows DRAIN IOCTL — the loader produces `hk_event_record`s directly — but the struct is the single shared wire format, so the assert is updated for both build sides.)

Payload structs (sizes pinned with `HK_STATIC_ASSERT`, all fields fixed-width; addresses/inodes are process-local identifiers, **not user content** — noted for data-categories):

```c
/* HK_EVENT_PROTON_OVERRIDE — 24 B. (100) */
typedef struct hk_event_proton_override {
    uint32_t pid;
    uint32_t flags;            /* HK_PROTON_* (native-shadows-builtin, off-manifest, non-dist-path) */
    uint64_t override_token_hash;  /* FNV64 of the offending "dll=native" token */
    uint64_t proton_build_hash;    /* per-version dist-manifest id this was diffed against */
} hk_event_proton_override;
HK_STATIC_ASSERT(sizeof(hk_event_proton_override) == 24, "proton_override size");

/* HK_EVENT_FOREIGN_MAP — 32 B. (101) */
typedef struct hk_event_foreign_map {
    uint32_t pid;
    uint32_t prot_flags;       /* PROT_* bits seen on the mapping */
    uint64_t map_base;         /* vm_area_struct->vm_start */
    uint64_t backing_inode;    /* file->f_inode->i_ino; 0 = anon/memfd */
    uint32_t backing_dev;      /* i_sb->s_dev (mount identity) */
    uint32_t map_flags;        /* HK_MAP_* (anon-then-backed/memfd, off-tree, deleted-inode) */
} hk_event_foreign_map;
HK_STATIC_ASSERT(sizeof(hk_event_foreign_map) == 32, "foreign_map size");

/* HK_EVENT_CROSS_MEM — 40 B. (102) */
typedef struct hk_event_cross_mem {
    uint32_t caller_tgid;      /* reader/writer */
    uint32_t target_tgid;      /* the game */
    uint32_t access_kind;      /* HK_XMEM_READV/WRITEV/PROCMEM/PTRACE */
    uint32_t flags;            /* HK_XMEM_FLAG_* (wineserver-allowlisted, horkos-self, debugger) */
    uint64_t remote_addr;      /* first remote_iov base, 0 if N/A */
    uint64_t remote_len;       /* total iov length, 0 if N/A */
    uint64_t event_time_ns;    /* bpf_ktime_get_ns() — boot epoch */
} hk_event_cross_mem;
HK_STATIC_ASSERT(sizeof(hk_event_cross_mem) == 40, "cross_mem size");

/* HK_EVENT_NS_ENTRY — 32 B. (103) */
typedef struct hk_event_ns_entry {
    uint32_t caller_tgid;
    uint32_t target_ns_type;   /* HK_NS_MNT/PID/USER */
    uint64_t target_ns_inode;  /* ns->inode of the joined namespace */
    uint64_t game_ns_inode;    /* baselined game-container ns inode (filled by loader) */
    uint32_t flags;            /* HK_NS_FLAG_* (off-launcher-lineage, dev-nsenter) */
    uint32_t reserved;
} hk_event_ns_entry;
HK_STATIC_ASSERT(sizeof(hk_event_ns_entry) == 32, "ns_entry size");

/* HK_EVENT_MODULE_LOAD — 32 B. (104) */
typedef struct hk_event_module_load {
    uint32_t initiator_tgid;
    uint32_t flags;            /* HK_MOD_* (post-boot, off-signed-baseline, hotplug-allowlisted, update-window) */
    uint64_t module_name_hash; /* FNV64 of the module name */
    uint64_t module_sig_hash;  /* 0 = unsigned/not-resolved; else truncated sig id */
    uint64_t event_time_ns;
} hk_event_module_load;
HK_STATIC_ASSERT(sizeof(hk_event_module_load) == 32, "module_load size");

/* HK_EVENT_ROOTFS_RW — 24 B. (105) */
typedef struct hk_event_rootfs_rw {
    uint32_t actor_tgid;
    uint32_t flags;            /* HK_ROOTFS_* (remount-rw, protected-write, in-update-window, immutable-distro) */
    uint64_t target_path_hash; /* FNV64 of the protected dentry path written */
    uint64_t event_time_ns;
} hk_event_rootfs_rw;
HK_STATIC_ASSERT(sizeof(hk_event_rootfs_rw) == 24, "rootfs_rw size");

/* HK_EVENT_FRAME_CONSUMER — 24 B. (106) */
typedef struct hk_event_frame_consumer {
    uint32_t consumer_tgid;
    uint32_t flags;            /* HK_FRAME_* (wayland-connect, drm-lease, prime-import, off-allowlist) */
    uint64_t socket_or_fb_hash;/* FNV64 of sun_path / DRM object identity */
    uint64_t event_time_ns;
} hk_event_frame_consumer;
HK_STATIC_ASSERT(sizeof(hk_event_frame_consumer) == 24, "frame_consumer size");

/* HK_EVENT_WX_ARM — 40 B. (107) */
typedef struct hk_event_wx_arm {
    uint32_t pid;
    uint32_t new_prot;         /* prot after mprotect (PROT_EXEC re-arm) */
    uint64_t vma_start;
    uint64_t vma_end;
    uint64_t backing_inode;    /* dev:ino of the builtin SO this VMA maps; 0 = anon */
    uint32_t backing_dev;
    uint32_t flags;            /* HK_WX_* (was-RX, in-builtin-range, inode-off-manifest) */
} hk_event_wx_arm;
HK_STATIC_ASSERT(sizeof(hk_event_wx_arm) == 40, "wx_arm size");

/* HK_EVENT_SYNTH_INPUT — 24 B. (108) */
typedef struct hk_event_synth_input {
    uint32_t injector_tgid;
    uint32_t flags;            /* HK_SYNTH_* (uinput-create, inject-event, mid-session, off-allowlist) */
    uint32_t ev_type;          /* EV_KEY/EV_ABS code class */
    uint32_t ev_code;          /* key/abs code (game-relevance correlated server-side) */
    uint64_t event_time_ns;
} hk_event_synth_input;
HK_STATIC_ASSERT(sizeof(hk_event_synth_input) == 24, "synth_input size");
```

Flag constants (appended, never renumbered) — sketch: `HK_PROTON_NATIVE_SHADOWS_BUILTIN`, `HK_PROTON_OFF_MANIFEST`, `HK_PROTON_NON_DIST_PATH`; `HK_MAP_ANON_THEN_BACKED`, `HK_MAP_MEMFD`, `HK_MAP_OFF_TREE`, `HK_MAP_DELETED_INODE`; `HK_XMEM_READV/WRITEV/PROCMEM/PTRACE` + `HK_XMEM_FLAG_WINESERVER`/`_HORKOS_SELF`/`_DEBUGGER`; `HK_NS_MNT/PID/USER` + `HK_NS_FLAG_OFF_LINEAGE`/`_DEV_NSENTER`; `HK_MOD_POST_BOOT`/`_OFF_BASELINE`/`_HOTPLUG`/`_UPDATE_WINDOW`; `HK_ROOTFS_REMOUNT_RW`/`_PROTECTED_WRITE`/`_UPDATE_WINDOW`/`_IMMUTABLE_DISTRO`; `HK_FRAME_WAYLAND`/`_DRM_LEASE`/`_PRIME`/`_OFF_ALLOWLIST`; `HK_WX_WAS_RX`/`_IN_BUILTIN`/`_INODE_OFF_MANIFEST`; `HK_SYNTH_UINPUT_CREATE`/`_INJECT`/`_MID_SESSION`/`_OFF_ALLOWLIST`.

### BPF-side records (`kernel/linux/bpf/include/hk_bpf_shared.h`)

Per the existing pattern (`lsm_file_open.bpf.c` cannot include `event_schema.h` because it pulls `stdint.h` under `-nostdinc`), each `.bpf.c` emits its own `__u*`-typed struct tagged with a BPF-internal tag (`0x30..0x38`, continuing the `0x10/0x20/0x21` convention). `Loader.cpp` maps each tag to the corresponding `HK_EVENT_*` type and repacks into the fixed `hk_event_record`. The duplicated schema literals are intentional and called out in the module comment, exactly as the existing files do.

### Loader mapping (`kernel/linux/userspace/Loader.cpp`)

Extend the tag-dispatch `if/else` chain (currently `kBpfTagFileOpen`/`kBpfTagPtrace`/`kBpfTagProcExec`) with the 9 new tags. The verifier `.cpp` files own the allowlist/manifest logic and may **enrich/suppress flags** before the sink forwards the record (e.g. set `HK_XMEM_FLAG_WINESERVER` after resolving the game's wineserver tgid; the catalog explicitly places wineserver-tgid resolution in `Loader.cpp`). Enrichment only sets *reported* flags; it never drops a record client-side (server adjudicates).

### IOCTL (`sdk/include/horkos/ioctl.h`)

No new control code. Linux events do not transit the Windows DRAIN envelope. Only the shared `HK_STATIC_ASSERT(sizeof(hk_event_record) == 64, ...)` re-pin (driven by `HK_EVENT_PAYLOAD_MAX 40`).

### Server mirror (`server/telemetry/src/linux_proton.rs`)

`#[repr(C)]` structs mirroring each payload by field name and size, decoded from the loader-produced byte stream. Feature extraction emits normalized records for the ban-engine/ONNX path (e.g. override-off-manifest boolean, foreign-map off-tree+off-allowlist boolean, cross-mem non-wineserver boolean, ns-off-lineage boolean, post-boot-module boolean, rootfs-RW-outside-update boolean, frame-consumer off-allowlist weight, builtin-inode-mismatch boolean, synth-input mid-session weight). Pure async, `thiserror` (extend `telemetry::error`), **no `unwrap()`/`expect()` outside `#[cfg(test)]`** — a short/garbage record yields a typed error, never a panic (guardrail #8).

### Guardrail #11 — `server/api/data-categories.md`

Every field above is telemetry and **must** be declared in the same PR. Add subsection **"2c. Linux Proton/Wine/Deck integrity events"** with rows for each field: `caller_tgid`/`target_tgid`/`initiator_tgid`/`injector_tgid`/`consumer_tgid`/`actor_tgid` (PID-class, 90 days, legitimate interest), the `*_hash` digests (override-token, proton-build, module-name/sig, target-path, socket/fb — note: **truncated hashes, not raw paths/content**), `backing_inode`/`backing_dev`/`map_base`/`vma_start`/`vma_end`/`remote_addr`/`remote_len` (process-local identifiers, not user content), `target_ns_inode`/`game_ns_inode`, `ev_type`/`ev_code` (input class only, not keystroke content), and the `*_flags` bitmasks. Source column: the emitting BPF program + verifier (e.g. "`proton_env.bpf.c` + `ProtonOverrideCheck.cpp` (`hk_event_proton_override`)"). Retention 90 days, legal basis legitimate interest — anti-cheat, operator Horkos Service Operator, matching the existing kernel-event rows.

---

## Mechanism implementation notes

General eBPF safety (all programs): CO-RE via `BPF_CORE_READ` (no kernel-version pinning beyond BTF, kernel ≥ 5.4, per the existing files); `lsm/*` programs return the inbound `ret` to never override another LSM (the `lsm_file_open.bpf.c` invariant); `bpf_ringbuf_reserve` failure drops the record without affecting the decision; compiled `-O2 -g -mcpu=v3 -Wall -Wextra -Werror -nostdinc` by `kernel/linux/bpf/CMakeLists.txt` (guardrail #6). Path-string reads use `bpf_probe_read_kernel_str` into a bounded buffer (the verifier-bounds discipline already in the repo) and are immediately FNV-hashed, not carried whole.

- **100 WINEDLLOVERRIDES (`proton_env.bpf.c`).** Tracepoint `sched/sched_process_exec`. The catalog explicitly rejects the fragile `ntdll.so.fake_dll`/`__wine_dll_set_load_order` uprobe; instead read the env block at exec from `bprm->mm->{env_start,env_end}` (user memory — `bpf_probe_read_user`, bounded scan for the `WINEDLLOVERRIDES=` key). **CO-RE concern:** scanning a variable-length user env region under the verifier needs a fixed bounded loop (`#pragma unroll` or `bpf_loop` on kernel ≥ 5.17) — the scan window is capped (e.g. 4 KiB) and truncation is acceptable since the token is hashed and re-resolved from `/proc/<pid>/environ` userspace. Emit only the offending token hash; **manifest diff is entirely userspace** (`ProtonOverrideCheck.cpp` holds the per-Proton-version override allowlist + DXVK/VKD3D set, diffs against `/proc/<pid>/maps`). FP gates (DXVK/VKD3D/dgVoodoo/reshade/protonfixes) are userspace+server allowlists.
- **101 foreign exec map (`mmap_exec_audit.bpf.c`).** `lsm/mmap_file`; filter `prot & PROT_EXEC` and file-backed maps for the tracked game cgroup. Reconstruct backing path via `file->f_path` dentry chain and the mount via `i_sb` (CO-RE). Also flag `MAP_ANONYMOUS|PROT_EXEC` regions that later gain a memfd backing. **Emit dev:ino + hash; the off-tree/off-allowlist decision (dist tree, sniper sysroot, prefix drive_c, overlay-SO SHA256 set: MangoHud/vkBasalt/obs-vkcapture/gameoverlayrenderer.so/GameMode) is in `PrefixMapAudit.cpp`.** Kernel stays allowlist-free.
- **102 cross-process memory (`cross_mem_audit.bpf.c`).** Tracepoints `sys_enter_process_vm_readv`/`_writev` (read `remote_pid`/`riovcnt`/`riov` from args), `lsm/ptrace_access_check`, and a kprobe on `mem_open` (proc `/proc/pid/mem`). Compare caller tgid against the game's resolved wineserver tgid + the Horkos client. **Strictly additive** to the existing `sys_enter_ptrace` probe in `tracepoints.bpf.c` (the catalog notes the readv/writev probe is currently absent). Wineserver-tgid allowlisting is done in `Loader.cpp` (resolves the wine process tree / WINEPREFIX cgroup) and set as a reported flag; FP risk is low.
- **103 namespace entry (`namespace_entry.bpf.c`).** Tracepoint `sys_enter_setns` + kprobe on `commit_nsset` (the catalog also names `install_nsproxy`). Read the target nsfd's ns inode and the caller task; baseline (game container ns inodes from `/proc/<pid>/ns/{mnt,pid,user}`, pv-bwrap launcher PID lineage) lives in `ContainerNsBaseline.cpp`. Only a `setns` into the game's namespaces whose caller is **not** a descendant of the recorded pv-bwrap/bwrap chain is anomalous; dev `nsenter` is a flaggable manual exception (reported, not banned). **UNCERTAINTY FLAG:** the exact kprobe-able symbol (`commit_nsset` vs `install_nsproxy` vs `validate_nsset`) and its arg layout are version-sensitive — confirm against the target kernel before relying on it (see Risks).
- **104 module load (`module_load_audit.bpf.c`).** `lsm/kernel_module_request` + `lsm/kernel_read_file` (READING_MODULE) + `module:module_load` tracepoint. Emit module name hash + initiating tgid. Baseline (`/proc/modules` at client start, SteamOS signed-module hashes, hotplug set usb-storage/xpad/hid-*) and the in-game-window + update-channel gates are in `DeckModuleBaseline.cpp`. On Game Mode this eBPF path is the only permitted sensor (read-only audit). **UNCERTAINTY FLAG:** the precise enum value for `READING_MODULE` and the `kernel_read_file` LSM signature differ across kernels — confirm.
- **105 rootfs RO breach (`rootfs_ro_audit.bpf.c`).** `lsm/sb_remount` + `lsm/sb_mount` to catch the root superblock losing `MS_RDONLY` (read `sb->s_flags & SB_RDONLY` via CO-RE), plus `lsm/file_open` (extending the existing audit hook) filtering CREATE/WRITE opens whose dentry resolves under the protected subvol. Baseline RO state from `/proc/mounts`; SteamOS update-window (frzr/rauc) correlation and the immutable-distro gate (via os-release) are in `DeckRootfsBaseline.cpp`. Restrict the signal to SteamOS/immutable rootfs (desktop distros have RW root normally). **UNCERTAINTY FLAG:** `lsm/sb_remount` availability/signature varies; confirm the hook exists on the target Deck kernel.
- **106 gamescope siphon (`compositor_consumer.bpf.c`).** Tracepoint `sys_enter_connect` (resolve `sun_path` under `$XDG_RUNTIME_DIR` matching the gamescope display) + `sys_enter_ioctl` filtered to `DRM_IOCTL_MODE_CREATE_LEASE`/`DRM_IOCTL_PRIME_FD_TO_HANDLE`. Emit connecting/importing tgid + identity hash. Allowlist (gamescope, pipewire/xdg-desktop-portal capture chain, Steam streaming PIDs, screenshot-key path) in `GamescopeConsumerBaseline.cpp`. **High FP — explicitly a low-weight server-side corroborator, never standalone** (per catalog).
- **107 Wine builtin integrity (`mprotect_wx_audit.bpf.c` + `WineBuiltinIntegrity.cpp`).** Two arms: (a) userspace verifier walks `/proc/<pid>/maps`, identifies VMAs whose pathname matches Wine builtin SO names (ntdll/kernelbase/win32u), `stat()`s the backing inode, compares dev:ino + SHA256 against the per-Proton-version dist manifest; (b) `lsm/file_mprotect` BPF arm flags `PROT_EXEC` re-protection of a VMA inside a builtin's address range (W^X re-arm). **Gate the mprotect arm to VMAs previously RX and resolving to a builtin SO path; gate the inode arm to the manifest.** ESYNC/FSYNC + Wine PE-loader relocations are accounted for by hashing the **on-disk dist file**, not the in-memory relocated image. **UNCERTAINTY FLAG:** `lsm/file_mprotect` hook name/availability and whether prior-prot is reachable in the hook context — confirm; if unavailable, fall back to periodic `/proc/<pid>/maps` prot re-scan (weaker, no W^X-transition signal).
- **108 synthetic input (`uinput_inject_audit.bpf.c` + `DeckInputBaseline.cpp`).** kprobe `uinput_create_device` (or open of `/dev/uinput`) + kprobe `input_inject_event`, attributing the injecting tgid. Baseline = Steam Input/hid-steam daemon tgid + gamescope's libinput consumer, resolved at session start, in `DeckInputBaseline.cpp`. **High FP** (Steam Input itself uses uinput; AntiMicroX/sc-controller/qjoypad/accessibility remappers): only a uinput device created **mid-session by a non-allowlisted tgid** driving game-relevant EV codes is reportable, **as a weighted signal needing server correlation** — no client decision. **UNCERTAINTY FLAG:** `input_inject_event`/`uinput_create_device` are internal (non-tracepoint) symbols; kprobe attach by name is not ABI-stable and may be inlined on some kernels — confirm kprobe-ability, else fall back to the `/dev/uinput` open path + evdev sysfs polling.
- **Server (`linux_proton.rs`).** Fully async on tokio; decode in the existing telemetry ingest task. `thiserror` variants for short/garbage records; no `unwrap()` outside tests (guardrail #8). Extracts features only — **does not ban** (ban-engine/ONNX path owns adjudication).

---

## Build wiring

- **eBPF (`kernel/linux/bpf/CMakeLists.txt`):** add 9 `bpf_program(...)` calls (`proton_env`, `mmap_exec_audit`, `cross_mem_audit`, `namespace_entry`, `module_load_audit`, `rootfs_ro_audit`, `compositor_consumer`, `mprotect_wx_audit`, `uinput_inject_audit`) and append their `hk_bpf_<name>_skel` targets to `hk_bpf_generated`'s `add_dependencies`. The existing `-target bpf -O2 -g -mcpu=v3 -Wall -Wextra -Werror -nostdinc` flags apply unchanged (guardrail #6). `hk_bpf_shared.h` lands under the existing `BPF_INCLUDE_DIR`.
- **Userspace (`kernel/linux/userspace/CMakeLists.txt`):** add the new `.cpp` verifier files to the `hk_bpf_loader` static lib (same `-Wall -Wextra -Werror`, `cxx_std_17`).
- **Feature flag / default:** all of the above remain under the existing **`HORKOS_LINUX_EBPF` option (default OFF)** in `kernel/linux/CMakeLists.txt` — CI enables it on a BTF-capable runner to enforce the `-Werror` guardrail. The LKM path is unaffected (the catalog signals are all eBPF-plane; Game Mode mandates eBPF per the locked decision). No per-signal sub-option is needed in this phase; if the kprobe-based 107/108 programs prove ABI-fragile on the Deck kernel, gate **those two** behind a `HORKOS_LINUX_EBPF_KPROBES` sub-option (default OFF) so the verifier/tracepoint set still builds.
- **Server (`server/telemetry/`):** add `mod linux_proton;` to `lib.rs`; no new crate, no new dependency (serde + existing decode). Decoding new event types is always compiled; unknown types degrade gracefully.
- **Toolchain:** clang ≥ 14 (BPF back-end) + bpftool ≥ 6.0 + libbpf-dev + a build-host `vmlinux.h` (generated via `bpftool btf dump`), exactly as the existing bpf/userspace CMake already requires. Rust stable for the server crate.

---

## Test strategy

### Unit tests

- `event_schema.h`: the new `HK_STATIC_ASSERT` size pins (24/32/40/32/32/24/24/40/24) and the re-pinned `hk_event_record == 64` are compile-time gates failing the build on any layout drift, on both kernel and userspace sides (the existing `ioctl.h` pattern).
- `linux_proton.rs` (`#[cfg(test)]`): round-trip decode of each record from a fixed byte vector; malformed/short buffer yields the typed error (not a panic); feature-extraction booleans (off-manifest, off-tree, non-wineserver, off-lineage, post-boot, rootfs-RW-outside-window, off-allowlist, inode-mismatch, mid-session) over synthetic event sequences.
- Verifier `.cpp` (behind a query seam, no live kernel): `ProtonOverrideCheck` manifest-diff decision table (DXVK native override → allow; off-manifest native shadowing a builtin → flag); `PrefixMapAudit` off-tree+off-allowlist truth table (overlay SO on-allowlist → no flag; /tmp memfd → flag); `ContainerNsBaseline` lineage check (descendant of pv-bwrap → allow; orphan caller → flag); `WineBuiltinIntegrity` inode/SHA mismatch table; the `Deck*Baseline` update-window/hotplug gates.

### Bypass tests (guardrail #12 — merge gate; one per catalog evasion) — under `bypass-tests/linux/proton_wine/`

- `bypass_dlloverride_inject` (100) — launch Proton with `WINEDLLOVERRIDES=ntdll=n` (native shadowing a builtin-only DLL) and an override naming an off-manifest DLL; assert `HK_EVENT_PROTON_OVERRIDE` with `HK_PROTON_NATIVE_SHADOWS_BUILTIN`/`_OFF_MANIFEST`; assert a legitimate DXVK `d3d11=n` override does **not** flag.
- `bypass_foreign_so_map` (101) — `LD_PRELOAD`/`dlopen` of a cheat SO from `/tmp`, and a `memfd_create`+`mmap PROT_EXEC` reflective load; assert `HK_EVENT_FOREIGN_MAP` with `HK_MAP_OFF_TREE`/`_MEMFD`; assert an on-allowlist overlay SO (MangoHud) does **not** flag.
- `bypass_cross_mem_scan` (102) — external scanner reads the game via `process_vm_readv` and via `/proc/pid/mem`; assert `HK_EVENT_CROSS_MEM` for both (`READV`/`PROCMEM`); assert the game's own wineserver read is flagged `HK_XMEM_FLAG_WINESERVER` (reported, not silently dropped) and a debugger the user attached is `_DEBUGGER`-tagged, not lost.
- `bypass_setns_breach` (103) — `nsenter` into the game's mnt/pid namespace from a process **outside** the pv-bwrap lineage; assert `HK_EVENT_NS_ENTRY` with `HK_NS_FLAG_OFF_LINEAGE`; assert pressure-vessel's own setns (descendant of the launcher) does **not** flag.
- `bypass_post_boot_lkm` (104) — `finit_module` of an unsigned module after the boot window in a simulated Game-Mode baseline; assert `HK_EVENT_MODULE_LOAD` with `HK_MOD_POST_BOOT`/`_OFF_BASELINE`; assert a hotplug `xpad`/`hid-*` load and an update-window load are flagged distinctly (`_HOTPLUG`/`_UPDATE_WINDOW`), not as cheats.
- `bypass_rootfs_remount` (105) — `steamos-readonly disable` + write under `/usr` outside an update window on a simulated immutable rootfs; assert `HK_EVENT_ROOTFS_RW` with `HK_ROOTFS_REMOUNT_RW`/`_PROTECTED_WRITE`; assert a frzr/rauc update-window RW transition is `_UPDATE_WINDOW`-tagged; assert a desktop-distro RW root does **not** flag (immutable-distro gate).
- `bypass_frame_siphon` (106) — a non-gamescope Wayland client connects to the gamescope socket and a non-gamescope process imports the framebuffer DMA-BUF; assert `HK_EVENT_FRAME_CONSUMER` with `HK_FRAME_WAYLAND`/`_PRIME`/`_OFF_ALLOWLIST`; assert OBS-via-portal and Steam Remote Play capture do **not** flag; assert the record is emitted as a **low-weight** corroborator (test checks the server feature weight, not a ban).
- `bypass_builtin_stomp` (107) — swap a Wine builtin (ntdll) with an off-dist SO, and hot-patch a builtin `.text` page W→RX during gameplay; assert `HK_EVENT_WX_ARM` with `HK_WX_IN_BUILTIN`/`_INODE_OFF_MANIFEST` and the inode-mismatch from the maps walk; assert legitimate ESYNC/FSYNC and PE-loader relocation (on-disk hash matches) does **not** flag.
- `bypass_uinput_macro` (108) — a mid-session non-allowlisted process creates a uinput device and injects EV_KEY/EV_ABS correlated with game keys (no-recoil macro); assert `HK_EVENT_SYNTH_INPUT` with `HK_SYNTH_UINPUT_CREATE`/`_MID_SESSION`/`_OFF_ALLOWLIST`; assert Steam Input's own uinput device (created pre-focus, allowlisted) does **not** flag.

Each bypass test asserts (a) the sensor **emits the expected record**, and (b) the named evasion is **not silently accepted** — the spoof either flags or is faithfully reported with its FP-gate flag for server adjudication. Where the live kernel hook is uncertain (103/104/105/107/108 — see Risks), the bypass test also runs in a **replay mode** that feeds recorded ring records into `Loader.cpp` + `linux_proton.rs`, so the decode/feature path is gated even before the live hook is confirmed.

---

## Sequencing

1. **Schema + wire first.** Land `event_schema.h` additions (9 types + payloads), the `HK_EVENT_PAYLOAD_MAX 16→40` bump + `hk_event_record == 64` re-pin in `ioctl.h`, and `data-categories.md` rows (guardrail #11) in one PR. Nothing decodes correctly until the record size is settled. Gate: static-asserts pass on both build sides; server round-trip test compiles.
2. **Loader + server decode.** Extend the `Loader.cpp` tag-dispatch and land `linux_proton.rs` decoders + round-trip tests. Depends on step 1; can proceed against recorded byte streams before any live BPF program exists (enables the bypass replay mode).
3. **Tracepoint/LSM-only sensors (low API risk).** `proton_env` (100), `mmap_exec_audit` (101), `cross_mem_audit` (102), `compositor_consumer` (106) — these use well-established tracepoints/LSM hooks (`sched_process_exec`, `mmap_file`, `sys_enter_*`, `ptrace_access_check`) already proven by the repo's existing programs. Land with their verifiers (`ProtonOverrideCheck`, `PrefixMapAudit`, `Loader` wineserver resolution, `GamescopeConsumerBaseline`) and bypass tests. Gate: `HORKOS_LINUX_EBPF` CI run loads each, DRAIN shows records.
4. **Uncertain-hook sensors.** `namespace_entry` (103), `module_load_audit` (104), `rootfs_ro_audit` (105), `mprotect_wx_audit` (107) — land **after** the kprobe/LSM-availability flags in Risks are confirmed against the target Deck kernel. Their verifiers (`ContainerNsBaseline`, `DeckModuleBaseline`, `DeckRootfsBaseline`, `WineBuiltinIntegrity`) and the on-disk-manifest dependency (107) gate this. Bypass tests run in replay mode until the live hook is confirmed.
5. **Kprobe-fragile input sensor.** `uinput_inject_audit` (108) last — `input_inject_event`/`uinput_create_device` are internal symbols (kprobe-by-name, possibly inlined); confirm kprobe-ability or use the `/dev/uinput`-open fallback. Behind `HORKOS_LINUX_EBPF_KPROBES` if needed.
6. **Bypass-test suite** lands incrementally with each sensor (a sensor PR without its bypass test is rejected by guardrail #12).

Cross-signal dependency: 107's mprotect arm and inode arm both depend on the **per-Proton-version dist manifest** (SHA256 of builtin SOs); 100/101 depend on the **per-Proton-version override manifest + overlay-SO allowlist**. These manifests are a shared data dependency that must be produced (hashed per Proton build) before 100/101/107 can move past report-only.

---

## Risks & UNCERTAINTY FLAGS

**Flagged for confirmation before writing the affected kernel code (guardrail #13 — a wrong kernel hook is worse than a delay):**

- **`setns` install symbol (103).** I am **not certain** which symbol is the stable kprobe target for namespace install (`commit_nsset` vs `install_nsproxy` vs `validate_nsset`) on the target Deck kernel, nor its exact arg layout for reading the target ns inode. `sys_enter_setns` (the syscall tracepoint) is stable; the internal install kprobe is not. **Confirm against the target kernel BTF before relying on the kprobe arm.**
- **`kernel_read_file` / `READING_MODULE` enum (104).** The `lsm/kernel_read_file` hook signature and the `READING_MODULE` enum value differ across kernel versions; `lsm/kernel_module_request` and the `module:module_load` tracepoint are more stable. **Confirm the enum/signature on the Deck kernel.**
- **`lsm/sb_remount` availability (105).** Whether `sb_remount` exists as a BPF-attachable LSM hook (vs only `sb_mount`) and whether the new RO/RW flag transition is reachable in-hook is version-sensitive. **Confirm; fall back to `/proc/mounts` polling if absent** (weaker — misses the precise remount event).
- **`lsm/file_mprotect` + prior-prot reachability (107).** I am **not certain** `file_mprotect` is BPF-attachable on the target kernel, nor that the *previous* protection (needed for the "was-RX, re-arming exec" gate) is reachable in the hook context. **Confirm; fall back to periodic `/proc/<pid>/maps` prot re-scan** (loses the W^X-transition precision, keeps the inode-mismatch arm).
- **kprobe-ability of `uinput_create_device` / `input_inject_event` (108).** These are internal kernel functions; kprobe attach by name is not ABI-stable and they may be inlined. **Confirm on the Deck kernel; fall back to the `/dev/uinput` open path (`security_file_open` filter) + evdev sysfs enumeration.** Gate behind `HORKOS_LINUX_EBPF_KPROBES` (default OFF) if fragile.
- **Bounded user-env scan under the verifier (100).** Reading a variable-length user env region (`bprm->mm->env_start..env_end`) with `bpf_probe_read_user` requires a fixed bounded loop to satisfy the verifier; `bpf_loop` needs kernel ≥ 5.17. **Confirm the minimum supported kernel; truncation of the env scan is acceptable (token is re-resolved from `/proc/<pid>/environ` userspace) but the bound must be verifier-provable.**
- **Per-Proton-version manifests are a data dependency, not code (100/101/107).** The override manifest, overlay-SO SHA256 allowlist, and builtin-SO dist-manifest must be produced per Proton build. Until they exist, 100/101/107 are **report-only, never auto-ban** — and the FP risk the catalog assigns (medium for all three) holds. Server-side adjudication is mandatory. Not a code blocker, but a correctness dependency.
- **High-FP signals 106 and 108.** The catalog marks both **high FP** and explicitly low-weight/needs-server-correlation. They must ship as **corroborators only**, never standalone ban inputs — the test suite asserts the server treats them as weighted features, not decisions. If the server's correlation layer is not yet built, these two should be ingested-and-stored only.
- **Ring footprint.** `HK_EVENT_PAYLOAD_MAX 16→40` grows `hk_event_record` 40→64 B. The Linux side uses the BPF ringbuf (1 MiB, already sized), so the impact is the per-record repack size in the loader, not non-paged pool — low risk on Linux. The shared assert change is the only cross-platform effect (the Windows ring stride also grows; flag for the Windows-domain owner that the shared `event_schema.h` bump touches their `HK_RING` footprint — coordinate the schema-version bump so both domains land it once).
