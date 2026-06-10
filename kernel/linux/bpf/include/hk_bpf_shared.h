/*
 * kernel/linux/bpf/include/hk_bpf_shared.h
 * Role: BPF-side wire-record structs + internal event tags shared across the
 *       linux-proton-wine eBPF translation units (proton_env / mmap_exec_audit /
 *       cross_mem_audit / namespace_entry / module_load_audit / rootfs_ro_audit /
 *       compositor_consumer / mprotect_wx_audit / uinput_inject_audit). Each
 *       .bpf.c includes this header so the per-program ring records and their
 *       BPF-internal tags are defined once instead of copy-pasted per TU.
 * Target platform: Linux eBPF (BPF_PROG_TYPE_{TRACEPOINT,LSM,KPROBE}).
 * Interface: included ONLY by .bpf.c files (never by a userspace TU — guardrail
 *            #4). The struct field layouts intentionally MIRROR the payload
 *            structs the impl-plan adds to sdk/include/horkos/event_schema.h
 *            (hk_event_proton_override .. hk_event_synth_input); the duplication
 *            is deliberate because event_schema.h pulls <stdint.h>, forbidden in
 *            eBPF C under -nostdinc (same rationale as lsm_file_open.bpf.c).
 *            Loader.cpp maps each tag below to the matching provisional event
 *            type and repacks into the fixed hk_event_record.
 *
 * Guardrail compliance:
 *   #1  No raw platform macros — Linux-only by build gating.
 *   #3  This module comment covers role/platform/interface.
 *   #4  BPF-only header; userspace mirrors these structs separately in Loader.cpp.
 *   #6  TUs that include this compile -Wall -Wextra -Werror (CMakeLists.txt).
 *
 * vmlinux.h MUST be included by the .bpf.c BEFORE this header (it provides the
 * __u32/__u64 fixed-width typedefs and the kernel struct layouts CO-RE relocates).
 */

#ifndef HK_BPF_SHARED_H
#define HK_BPF_SHARED_H

/* Mirrors HK_EVENT_SCHEMA_VERSION. The linux-proton-wine set is schema v3 (the
 * impl-plan bumps 2u -> 3u for the grown payload set). Loader.cpp validates this
 * against the version it expects before translating. */
#define HK_PW_SCHEMA_VERSION 3u

/* ---- BPF-internal event tags (0x30..0x38) --------------------------------
 * Continue the 0x10/0x20/0x21 (core) and 0x30/0x31/0x40.. (memory-access)
 * conventions. The memory-access set already claims 0x30/0x31 for its ptrace
 * arms (see Loader.cpp kBpfTagPtraceAccess/kBpfTagPtraceTraceme), so the
 * proton-wine set uses the 0xB0..0xB8 range to avoid a translate-arm collision
 * when both feature sets are compiled into one loader.
 */
#define HK_BPF_PW_PROTON_OVERRIDE  0xB0u
#define HK_BPF_PW_FOREIGN_MAP      0xB1u
#define HK_BPF_PW_CROSS_MEM        0xB2u
#define HK_BPF_PW_NS_ENTRY         0xB3u
#define HK_BPF_PW_MODULE_LOAD      0xB4u
#define HK_BPF_PW_ROOTFS_RW        0xB5u
#define HK_BPF_PW_FRAME_CONSUMER   0xB6u
#define HK_BPF_PW_WX_ARM           0xB7u
#define HK_BPF_PW_SYNTH_INPUT      0xB8u

/* hardware-input-devices domain (signal 140) — evdev/uinput device provenance.
 * 0xC0 range to avoid the 0xB0..0xB8 proton-wine block. */
#define HK_BPF_DT_INPUT_PROV       0xC0u

/* ---- FNV-1a 64-bit over a bounded kernel/user buffer ----------------------
 * Paths/sun_path/module names are NOT carried whole (variable length, ringbuf-
 * hostile, PII-adjacent). The BPF side hashes a bounded copy and emits the
 * 64-bit digest; the userspace verifier re-resolves the human-readable string
 * from /proc/<pid>/{maps,environ} at report time. FNV-1a is chosen for being a
 * trivial verifier-friendly fold (no loop-carried table); collision resistance
 * is not a security property here — the digest is only an identity key the
 * server correlates, never an authenticator.
 */
#define HK_FNV64_OFFSET 1469598103934665603ULL
#define HK_FNV64_PRIME  1099511628211ULL

/* Bound for in-kernel string scans before hashing (verifier-provable). */
#define HK_PW_HASH_MAX 256

/* Verifier constraint: `len` MUST be a compile-time constant or a value provably
 * bounded by HK_PW_HASH_MAX at the call site. The loop bound is fixed at
 * HK_PW_HASH_MAX iterations; if `len` is not a compile-time constant the verifier
 * may reject the program because it cannot prove the loop terminates within the
 * instruction limit. Callers must either pass a literal or clamp to HK_PW_HASH_MAX
 * before calling. */
static __always_inline __u64 hk_fnv64(const char *buf, __u32 len)
{
    __u64 h = HK_FNV64_OFFSET;
    /* Bounded, unrolled fold. len is clamped by the caller to HK_PW_HASH_MAX so
     * the verifier can prove termination. */
    if (len > HK_PW_HASH_MAX)
        len = HK_PW_HASH_MAX;
    for (__u32 i = 0; i < HK_PW_HASH_MAX; i++) {
        if (i >= len)
            break;
        h ^= (__u64)(__u8)buf[i];
        h *= HK_FNV64_PRIME;
    }
    return h;
}

/* ---- Per-signal BPF ring records ------------------------------------------
 * Each carries the common (schema_version, event_tag, timestamp_ns) preamble so
 * Loader.cpp peeks the tag uniformly, then the per-signal fields. The userspace
 * payload these map to (event_schema.h) drops the preamble (it moves into the
 * hk_event_header) and keeps the signal fields — Loader.cpp does the repack.
 */

/* 100 — WINEDLLOVERRIDES anomaly (proton_env.bpf.c). */
struct hk_bpf_pw_proton_override {
    __u32 schema_version;
    __u32 event_tag;            /* HK_BPF_PW_PROTON_OVERRIDE */
    __u64 timestamp_ns;
    __u32 pid;
    __u32 flags;                /* HK_PW_PROTON_* (set userspace; 0 here) */
    __u64 override_token_hash;  /* FNV64 of the offending "dll=native" token */
    __u64 proton_build_hash;    /* 0 here; filled userspace from the manifest id */
};

/* 101 — off-tree PROT_EXEC mapping (mmap_exec_audit.bpf.c). */
struct hk_bpf_pw_foreign_map {
    __u32 schema_version;
    __u32 event_tag;            /* HK_BPF_PW_FOREIGN_MAP */
    __u64 timestamp_ns;
    __u32 pid;
    __u32 prot_flags;           /* PROT_* on the mapping */
    __u64 map_base;             /* file f_pos is N/A; 0 (vm_start unknown at hook) */
    __u64 backing_inode;        /* file->f_inode->i_ino; 0 = anon/memfd */
    __u32 backing_dev;          /* i_sb->s_dev */
    __u32 map_flags;            /* HK_PW_MAP_* (set userspace; MEMFD/anon set here) */
};

/* 102 — cross-process memory access (cross_mem_audit.bpf.c). */
struct hk_bpf_pw_cross_mem {
    __u32 schema_version;
    __u32 event_tag;            /* HK_BPF_PW_CROSS_MEM */
    __u64 timestamp_ns;
    __u32 caller_tgid;
    __u32 target_tgid;
    __u32 access_kind;          /* HK_PW_XMEM_* */
    __u32 flags;                /* HK_PW_XMEM_FLAG_* (set userspace; 0 here) */
    __u64 remote_addr;          /* first remote_iov base, 0 if N/A */
    __u64 remote_len;           /* total iov length, 0 if N/A */
    __u64 event_time_ns;        /* duplicate of timestamp_ns for the payload tail */
};

/* 103 — namespace entry (namespace_entry.bpf.c). */
struct hk_bpf_pw_ns_entry {
    __u32 schema_version;
    __u32 event_tag;            /* HK_BPF_PW_NS_ENTRY */
    __u64 timestamp_ns;
    __u32 caller_tgid;
    __u32 target_ns_type;       /* HK_PW_NS_* */
    __u64 target_ns_inode;      /* joined namespace ns->inode */
    __u64 game_ns_inode;        /* 0 here; filled by the loader/baseliner */
    __u32 flags;                /* HK_PW_NS_FLAG_* (set userspace; 0 here) */
    __u32 reserved;
};

/* 104 — post-boot / unsigned module load (module_load_audit.bpf.c). */
struct hk_bpf_pw_module_load {
    __u32 schema_version;
    __u32 event_tag;            /* HK_BPF_PW_MODULE_LOAD */
    __u64 timestamp_ns;
    __u32 initiator_tgid;
    __u32 flags;                /* HK_PW_MOD_* (set userspace; 0 here) */
    __u64 module_name_hash;     /* FNV64 of the module name */
    __u64 module_sig_hash;      /* 0 = unsigned/not-resolved */
    __u64 event_time_ns;
};

/* 105 — RO-rootfs invariant breach (rootfs_ro_audit.bpf.c). */
struct hk_bpf_pw_rootfs_rw {
    __u32 schema_version;
    __u32 event_tag;            /* HK_BPF_PW_ROOTFS_RW */
    __u64 timestamp_ns;
    __u32 actor_tgid;
    __u32 flags;                /* HK_PW_ROOTFS_* (REMOUNT_RW set here when seen) */
    __u64 target_path_hash;     /* FNV64 of the protected dentry path */
    __u64 event_time_ns;
};

/* 106 — gamescope/DRM-lease frame siphon (compositor_consumer.bpf.c). */
struct hk_bpf_pw_frame_consumer {
    __u32 schema_version;
    __u32 event_tag;            /* HK_BPF_PW_FRAME_CONSUMER */
    __u64 timestamp_ns;
    __u32 consumer_tgid;
    __u32 flags;                /* HK_PW_FRAME_* (WAYLAND/DRM_LEASE/PRIME set here) */
    __u64 socket_or_fb_hash;    /* FNV64 of sun_path / DRM object identity */
    __u64 event_time_ns;
};

/* 107 — builtin W^X re-arm (mprotect_wx_audit.bpf.c). */
struct hk_bpf_pw_wx_arm {
    __u32 schema_version;
    __u32 event_tag;            /* HK_BPF_PW_WX_ARM */
    __u64 timestamp_ns;
    __u32 pid;
    __u32 new_prot;             /* prot after mprotect (PROT_EXEC re-arm) */
    __u64 vma_start;
    __u64 vma_end;
    __u64 backing_inode;        /* dev:ino of the builtin SO; 0 = anon */
    __u32 backing_dev;
    __u32 flags;                /* HK_PW_WX_* (WAS_RX set here; rest userspace) */
};

/* 108 — synthetic uinput/evdev injection (uinput_inject_audit.bpf.c). */
struct hk_bpf_pw_synth_input {
    __u32 schema_version;
    __u32 event_tag;            /* HK_BPF_PW_SYNTH_INPUT */
    __u64 timestamp_ns;
    __u32 injector_tgid;
    __u32 flags;                /* HK_PW_SYNTH_* (UINPUT_CREATE/INJECT set here) */
    __u32 ev_type;              /* EV_KEY/EV_ABS code class; 0 for create */
    __u32 ev_code;              /* key/abs code; 0 for create */
    __u64 event_time_ns;
};

/* 140 — evdev/uinput device provenance (input_provenance.bpf.c, hardware-input-
 * devices domain). The userspace half (EvdevProvenanceLinux.cpp) consumes this,
 * supplements with EVIOCGID/EVIOCGPHYS, and converts to hk_device_descriptor_audit
 * for the wire — the kernel record NEVER reaches the server directly (guardrail #4
 * keeps the kernel struct and the userspace wire struct in different TUs/headers). */
struct hk_input_prov_bpf {
    __u32 schema_version;   /* HK_PW_SCHEMA_VERSION */
    __u32 event_tag;        /* HK_BPF_DT_INPUT_PROV */
    __u64 ts_ns;            /* bpf_ktime_get_ns at the hook */
    __u32 input_dev_id;     /* stable per-device cookie within the session */
    __u32 creator_pid;      /* PID that called input_register_device (uinput) */
    __u16 bustype;          /* input_dev->id.bustype (BUS_USB/BUS_VIRTUAL/...) */
    __u16 vendor;           /* input_dev->id.vendor */
    __u16 product;          /* input_dev->id.product */
    __u8  has_usb_parent;   /* parent-chain walk found a usb_device */
    __u8  evbit_rel_key;    /* emits EV_REL/EV_KEY (pointer/keyboard) */
};

/* 140 flags carried in evbit_rel_key (bit field, not a bus value). */
#define HK_DT_EV_REL 0x1u  /* device advertises EV_REL (relative pointer) */
#define HK_DT_EV_KEY 0x2u  /* device advertises EV_KEY (buttons/keys) */

/* Linux input bustype constants (mirror include/uapi/linux/input.h; vmlinux.h does
 * not always surface the BUS_* macros, so define the two we classify on). */
#ifndef BUS_USB
#define BUS_USB 0x03u
#endif
#ifndef BUS_VIRTUAL
#define BUS_VIRTUAL 0x06u
#endif

/* ---- Flag constants (mirror event_schema.h appends) -----------------------
 * Kernel sets only the flags it can cheaply know (e.g. MEMFD, WAS_RX); the
 * manifest/allowlist/lineage flags are set by the userspace verifier. */

/* 100 */
#define HK_PW_PROTON_NATIVE_SHADOWS_BUILTIN 0x1u
#define HK_PW_PROTON_OFF_MANIFEST           0x2u
#define HK_PW_PROTON_NON_DIST_PATH          0x4u

/* 101 */
#define HK_PW_MAP_ANON_THEN_BACKED 0x1u
#define HK_PW_MAP_MEMFD            0x2u
#define HK_PW_MAP_OFF_TREE         0x4u
#define HK_PW_MAP_DELETED_INODE    0x8u

/* 102 access_kind */
#define HK_PW_XMEM_READV   1u
#define HK_PW_XMEM_WRITEV  2u
#define HK_PW_XMEM_PROCMEM 3u
#define HK_PW_XMEM_PTRACE  4u
/* 102 flags */
#define HK_PW_XMEM_FLAG_WINESERVER  0x1u
#define HK_PW_XMEM_FLAG_HORKOS_SELF 0x2u
#define HK_PW_XMEM_FLAG_DEBUGGER    0x4u

/* 103 ns type */
#define HK_PW_NS_MNT  1u
#define HK_PW_NS_PID  2u
#define HK_PW_NS_USER 3u
/* 103 flags */
#define HK_PW_NS_FLAG_OFF_LINEAGE 0x1u
#define HK_PW_NS_FLAG_DEV_NSENTER 0x2u

/* 104 */
#define HK_PW_MOD_POST_BOOT     0x1u
#define HK_PW_MOD_OFF_BASELINE  0x2u
#define HK_PW_MOD_HOTPLUG       0x4u
#define HK_PW_MOD_UPDATE_WINDOW 0x8u

/* 105 */
#define HK_PW_ROOTFS_REMOUNT_RW     0x1u
#define HK_PW_ROOTFS_PROTECTED_WRITE 0x2u
#define HK_PW_ROOTFS_UPDATE_WINDOW  0x4u
#define HK_PW_ROOTFS_IMMUTABLE_DISTRO 0x8u

/* 106 */
#define HK_PW_FRAME_WAYLAND      0x1u
#define HK_PW_FRAME_DRM_LEASE    0x2u
#define HK_PW_FRAME_PRIME        0x4u
#define HK_PW_FRAME_OFF_ALLOWLIST 0x8u

/* 107 */
#define HK_PW_WX_WAS_RX            0x1u
#define HK_PW_WX_IN_BUILTIN        0x2u
#define HK_PW_WX_INODE_OFF_MANIFEST 0x4u

/* 108 */
#define HK_PW_SYNTH_UINPUT_CREATE 0x1u
#define HK_PW_SYNTH_INJECT        0x2u
#define HK_PW_SYNTH_MID_SESSION   0x4u
#define HK_PW_SYNTH_OFF_ALLOWLIST 0x8u

#endif /* HK_BPF_SHARED_H */
