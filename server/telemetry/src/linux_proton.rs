//! Role: Server-side decode + feature extraction for the Linux Proton/Wine/Steam-
//! Deck integrity event records (domain `linux-proton-wine`, catalog signals
//! 100-108): WINEDLLOVERRIDES anomaly (`hk_event_proton_override`), off-tree
//! PROT_EXEC mapping (`hk_event_foreign_map`), cross-process memory access
//! (`hk_event_cross_mem`), namespace entry (`hk_event_ns_entry`), post-boot/unsigned
//! module load (`hk_event_module_load`), RO-rootfs breach (`hk_event_rootfs_rw`),
//! gamescope/DRM-lease frame siphon (`hk_event_frame_consumer`), builtin W^X re-arm
//! (`hk_event_wx_arm`), and synthetic uinput/evdev injection (`hk_event_synth_input`).
//! Decodes the loader-produced byte stream into `#[repr(C)]` mirrors of the C99 wire
//! structs, then extracts normalized features for the ban-engine/ONNX path. This
//! module extracts features only — it never bans (that authority is the ban-engine's,
//! server-side; the client only samples + reports).
//!
//! Target platforms: server.
//!
//! Guardrail #8: pure/allocation-light, no blocking, `thiserror` error type, NO
//! `unwrap()`/`expect()` outside `#[cfg(test)]`. A malformed/short wire record yields
//! a typed `LinuxProtonError`, never a panic.
//!
//! HK-TODO(schema): the event types (`HK_EVENT_PROTON_OVERRIDE` = 5 .. `HK_EVENT_
//! SYNTH_INPUT` = 13) and the grown `HK_EVENT_PAYLOAD_MAX` (16 -> 40, re-pinning
//! `hk_event_record` to 64) are owned by the Schema phase and are NOT yet present in
//! the frozen `sdk/include/horkos/event_schema.h` (still HK_EVENT_SCHEMA_VERSION=2,
//! enum tops out at HK_EVENT_HANDLE_OPEN=4). The discriminants below are mirrored as
//! local provisional consts until Schema lands. The values 5-13 collide pre-Schema
//! with the Windows vm_access / kernel-event domains' provisional discriminants — the
//! Schema phase assigns the final distinct values; this decoder must be dispatched by
//! the resolved type, not by the provisional value, once Schema lands. The payload
//! field layouts/sizes are pinned here against the documented byte counts
//! (24/32/40/32/32/24/24/40/24) so a future schema header diff is caught.

use thiserror::Error;

// ---------------------------------------------------------------------------
// Provisional event-type discriminants (HK-TODO(schema)).
// ---------------------------------------------------------------------------
pub const HK_EVENT_PROTON_OVERRIDE: u32 = 5;
pub const HK_EVENT_FOREIGN_MAP: u32 = 6;
pub const HK_EVENT_CROSS_MEM: u32 = 7;
pub const HK_EVENT_NS_ENTRY: u32 = 8;
pub const HK_EVENT_MODULE_LOAD: u32 = 9;
pub const HK_EVENT_ROOTFS_RW: u32 = 10;
pub const HK_EVENT_FRAME_CONSUMER: u32 = 11;
pub const HK_EVENT_WX_ARM: u32 = 12;
pub const HK_EVENT_SYNTH_INPUT: u32 = 13;

// ---------------------------------------------------------------------------
// Flag constants (mirror sdk/include/horkos/event_schema.h appends, which mirror
// the kernel HK_PW_* in kernel/linux/bpf/include/hk_bpf_shared.h).
// ---------------------------------------------------------------------------

// 100 — proton_override.flags
pub const HK_PROTON_NATIVE_SHADOWS_BUILTIN: u32 = 0x1;
pub const HK_PROTON_OFF_MANIFEST: u32 = 0x2;
pub const HK_PROTON_NON_DIST_PATH: u32 = 0x4;

// 101 — foreign_map.map_flags
pub const HK_MAP_ANON_THEN_BACKED: u32 = 0x1;
pub const HK_MAP_MEMFD: u32 = 0x2;
pub const HK_MAP_OFF_TREE: u32 = 0x4;
pub const HK_MAP_DELETED_INODE: u32 = 0x8;

// 102 — cross_mem.access_kind
pub const HK_XMEM_READV: u32 = 1;
pub const HK_XMEM_WRITEV: u32 = 2;
pub const HK_XMEM_PROCMEM: u32 = 3;
pub const HK_XMEM_PTRACE: u32 = 4;
// 102 — cross_mem.flags
pub const HK_XMEM_FLAG_WINESERVER: u32 = 0x1;
pub const HK_XMEM_FLAG_HORKOS_SELF: u32 = 0x2;
pub const HK_XMEM_FLAG_DEBUGGER: u32 = 0x4;

// 103 — ns_entry.target_ns_type
pub const HK_NS_MNT: u32 = 1;
pub const HK_NS_PID: u32 = 2;
pub const HK_NS_USER: u32 = 3;
// 103 — ns_entry.flags
pub const HK_NS_FLAG_OFF_LINEAGE: u32 = 0x1;
pub const HK_NS_FLAG_DEV_NSENTER: u32 = 0x2;

// 104 — module_load.flags
pub const HK_MOD_POST_BOOT: u32 = 0x1;
pub const HK_MOD_OFF_BASELINE: u32 = 0x2;
pub const HK_MOD_HOTPLUG: u32 = 0x4;
pub const HK_MOD_UPDATE_WINDOW: u32 = 0x8;

// 105 — rootfs_rw.flags
pub const HK_ROOTFS_REMOUNT_RW: u32 = 0x1;
pub const HK_ROOTFS_PROTECTED_WRITE: u32 = 0x2;
pub const HK_ROOTFS_UPDATE_WINDOW: u32 = 0x4;
pub const HK_ROOTFS_IMMUTABLE_DISTRO: u32 = 0x8;

// 106 — frame_consumer.flags
pub const HK_FRAME_WAYLAND: u32 = 0x1;
pub const HK_FRAME_DRM_LEASE: u32 = 0x2;
pub const HK_FRAME_PRIME: u32 = 0x4;
pub const HK_FRAME_OFF_ALLOWLIST: u32 = 0x8;

// 107 — wx_arm.flags
pub const HK_WX_WAS_RX: u32 = 0x1;
pub const HK_WX_IN_BUILTIN: u32 = 0x2;
pub const HK_WX_INODE_OFF_MANIFEST: u32 = 0x4;

// 108 — synth_input.flags
pub const HK_SYNTH_UINPUT_CREATE: u32 = 0x1;
pub const HK_SYNTH_INJECT: u32 = 0x2;
pub const HK_SYNTH_MID_SESSION: u32 = 0x4;
pub const HK_SYNTH_OFF_ALLOWLIST: u32 = 0x8;

/// Decode errors. A short or otherwise malformed loader-produced record must surface
/// as one of these — never a panic (guardrail #8).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LinuxProtonError {
    #[error("record too short: need {need} bytes for {what}, got {got}")]
    Short {
        what: &'static str,
        need: usize,
        got: usize,
    },

    #[error("unknown linux-proton event type {0}")]
    UnknownType(u32),
}

// ---------------------------------------------------------------------------
// Little-endian fixed-width readers (LE wire; Horkos targets LE hosts). Each
// bounds-checks and returns a typed error rather than panicking.
// ---------------------------------------------------------------------------

fn read_u32(buf: &[u8], off: usize, what: &'static str) -> Result<u32, LinuxProtonError> {
    let end = off + 4;
    if buf.len() < end {
        return Err(LinuxProtonError::Short {
            what,
            need: end,
            got: buf.len(),
        });
    }
    let mut a = [0u8; 4];
    a.copy_from_slice(&buf[off..end]);
    Ok(u32::from_le_bytes(a))
}

fn read_u64(buf: &[u8], off: usize, what: &'static str) -> Result<u64, LinuxProtonError> {
    let end = off + 8;
    if buf.len() < end {
        return Err(LinuxProtonError::Short {
            what,
            need: end,
            got: buf.len(),
        });
    }
    let mut a = [0u8; 8];
    a.copy_from_slice(&buf[off..end]);
    Ok(u64::from_le_bytes(a))
}

// ---------------------------------------------------------------------------
// `#[repr(C)]` mirrors of the wire payloads. Field names/sizes track the
// pinned layout exactly (24/32/40/32/32/24/24/40/24).
// ---------------------------------------------------------------------------

/// Mirror of `hk_event_proton_override` (24 bytes). (100)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtonOverride {
    pub pid: u32,
    pub flags: u32,
    pub override_token_hash: u64,
    pub proton_build_hash: u64,
}

/// Mirror of `hk_event_foreign_map` (32 bytes). (101)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForeignMap {
    pub pid: u32,
    pub prot_flags: u32,
    pub map_base: u64,
    pub backing_inode: u64,
    pub backing_dev: u32,
    pub map_flags: u32,
}

/// Mirror of `hk_event_cross_mem` (40 bytes). (102)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrossMem {
    pub caller_tgid: u32,
    pub target_tgid: u32,
    pub access_kind: u32,
    pub flags: u32,
    pub remote_addr: u64,
    pub remote_len: u64,
    pub event_time_ns: u64,
}

/// Mirror of `hk_event_ns_entry` (32 bytes). (103)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NsEntry {
    pub caller_tgid: u32,
    pub target_ns_type: u32,
    pub target_ns_inode: u64,
    pub game_ns_inode: u64,
    pub flags: u32,
    pub reserved: u32,
}

/// Mirror of `hk_event_module_load` (32 bytes). (104)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleLoad {
    pub initiator_tgid: u32,
    pub flags: u32,
    pub module_name_hash: u64,
    pub module_sig_hash: u64,
    pub event_time_ns: u64,
}

/// Mirror of `hk_event_rootfs_rw` (24 bytes). (105)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootfsRw {
    pub actor_tgid: u32,
    pub flags: u32,
    pub target_path_hash: u64,
    pub event_time_ns: u64,
}

/// Mirror of `hk_event_frame_consumer` (24 bytes). (106)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameConsumer {
    pub consumer_tgid: u32,
    pub flags: u32,
    pub socket_or_fb_hash: u64,
    pub event_time_ns: u64,
}

/// Mirror of `hk_event_wx_arm` (40 bytes). (107)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WxArm {
    pub pid: u32,
    pub new_prot: u32,
    pub vma_start: u64,
    pub vma_end: u64,
    pub backing_inode: u64,
    pub backing_dev: u32,
    pub flags: u32,
}

/// Mirror of `hk_event_synth_input` (24 bytes). (108)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SynthInput {
    pub injector_tgid: u32,
    pub flags: u32,
    pub ev_type: u32,
    pub ev_code: u32,
    pub event_time_ns: u64,
}

// Compile-time size pins mirroring the C HK_STATIC_ASSERTs.
const _: () = assert!(core::mem::size_of::<ProtonOverride>() == 24);
const _: () = assert!(core::mem::size_of::<ForeignMap>() == 32);
const _: () = assert!(core::mem::size_of::<CrossMem>() == 40);
const _: () = assert!(core::mem::size_of::<NsEntry>() == 32);
const _: () = assert!(core::mem::size_of::<ModuleLoad>() == 32);
const _: () = assert!(core::mem::size_of::<RootfsRw>() == 24);
const _: () = assert!(core::mem::size_of::<FrameConsumer>() == 24);
const _: () = assert!(core::mem::size_of::<WxArm>() == 40);
const _: () = assert!(core::mem::size_of::<SynthInput>() == 24);

impl ProtonOverride {
    pub fn decode(buf: &[u8]) -> Result<Self, LinuxProtonError> {
        Ok(Self {
            pid: read_u32(buf, 0, "proton_override.pid")?,
            flags: read_u32(buf, 4, "proton_override.flags")?,
            override_token_hash: read_u64(buf, 8, "proton_override.override_token_hash")?,
            proton_build_hash: read_u64(buf, 16, "proton_override.proton_build_hash")?,
        })
    }
}

impl ForeignMap {
    pub fn decode(buf: &[u8]) -> Result<Self, LinuxProtonError> {
        Ok(Self {
            pid: read_u32(buf, 0, "foreign_map.pid")?,
            prot_flags: read_u32(buf, 4, "foreign_map.prot_flags")?,
            map_base: read_u64(buf, 8, "foreign_map.map_base")?,
            backing_inode: read_u64(buf, 16, "foreign_map.backing_inode")?,
            backing_dev: read_u32(buf, 24, "foreign_map.backing_dev")?,
            map_flags: read_u32(buf, 28, "foreign_map.map_flags")?,
        })
    }
}

impl CrossMem {
    pub fn decode(buf: &[u8]) -> Result<Self, LinuxProtonError> {
        Ok(Self {
            caller_tgid: read_u32(buf, 0, "cross_mem.caller_tgid")?,
            target_tgid: read_u32(buf, 4, "cross_mem.target_tgid")?,
            access_kind: read_u32(buf, 8, "cross_mem.access_kind")?,
            flags: read_u32(buf, 12, "cross_mem.flags")?,
            remote_addr: read_u64(buf, 16, "cross_mem.remote_addr")?,
            remote_len: read_u64(buf, 24, "cross_mem.remote_len")?,
            event_time_ns: read_u64(buf, 32, "cross_mem.event_time_ns")?,
        })
    }
}

impl NsEntry {
    pub fn decode(buf: &[u8]) -> Result<Self, LinuxProtonError> {
        Ok(Self {
            caller_tgid: read_u32(buf, 0, "ns_entry.caller_tgid")?,
            target_ns_type: read_u32(buf, 4, "ns_entry.target_ns_type")?,
            target_ns_inode: read_u64(buf, 8, "ns_entry.target_ns_inode")?,
            game_ns_inode: read_u64(buf, 16, "ns_entry.game_ns_inode")?,
            flags: read_u32(buf, 24, "ns_entry.flags")?,
            reserved: read_u32(buf, 28, "ns_entry.reserved")?,
        })
    }
}

impl ModuleLoad {
    pub fn decode(buf: &[u8]) -> Result<Self, LinuxProtonError> {
        Ok(Self {
            initiator_tgid: read_u32(buf, 0, "module_load.initiator_tgid")?,
            flags: read_u32(buf, 4, "module_load.flags")?,
            module_name_hash: read_u64(buf, 8, "module_load.module_name_hash")?,
            module_sig_hash: read_u64(buf, 16, "module_load.module_sig_hash")?,
            event_time_ns: read_u64(buf, 24, "module_load.event_time_ns")?,
        })
    }
}

impl RootfsRw {
    pub fn decode(buf: &[u8]) -> Result<Self, LinuxProtonError> {
        Ok(Self {
            actor_tgid: read_u32(buf, 0, "rootfs_rw.actor_tgid")?,
            flags: read_u32(buf, 4, "rootfs_rw.flags")?,
            target_path_hash: read_u64(buf, 8, "rootfs_rw.target_path_hash")?,
            event_time_ns: read_u64(buf, 16, "rootfs_rw.event_time_ns")?,
        })
    }
}

impl FrameConsumer {
    pub fn decode(buf: &[u8]) -> Result<Self, LinuxProtonError> {
        Ok(Self {
            consumer_tgid: read_u32(buf, 0, "frame_consumer.consumer_tgid")?,
            flags: read_u32(buf, 4, "frame_consumer.flags")?,
            socket_or_fb_hash: read_u64(buf, 8, "frame_consumer.socket_or_fb_hash")?,
            event_time_ns: read_u64(buf, 16, "frame_consumer.event_time_ns")?,
        })
    }
}

impl WxArm {
    pub fn decode(buf: &[u8]) -> Result<Self, LinuxProtonError> {
        Ok(Self {
            pid: read_u32(buf, 0, "wx_arm.pid")?,
            new_prot: read_u32(buf, 4, "wx_arm.new_prot")?,
            vma_start: read_u64(buf, 8, "wx_arm.vma_start")?,
            vma_end: read_u64(buf, 16, "wx_arm.vma_end")?,
            backing_inode: read_u64(buf, 24, "wx_arm.backing_inode")?,
            backing_dev: read_u32(buf, 32, "wx_arm.backing_dev")?,
            flags: read_u32(buf, 36, "wx_arm.flags")?,
        })
    }
}

impl SynthInput {
    pub fn decode(buf: &[u8]) -> Result<Self, LinuxProtonError> {
        Ok(Self {
            injector_tgid: read_u32(buf, 0, "synth_input.injector_tgid")?,
            flags: read_u32(buf, 4, "synth_input.flags")?,
            ev_type: read_u32(buf, 8, "synth_input.ev_type")?,
            ev_code: read_u32(buf, 12, "synth_input.ev_code")?,
            event_time_ns: read_u64(buf, 16, "synth_input.event_time_ns")?,
        })
    }
}

/// A decoded Linux Proton/Wine/Deck payload, tagged by wire type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxProtonEvent {
    ProtonOverride(ProtonOverride),
    ForeignMap(ForeignMap),
    CrossMem(CrossMem),
    NsEntry(NsEntry),
    ModuleLoad(ModuleLoad),
    RootfsRw(RootfsRw),
    FrameConsumer(FrameConsumer),
    WxArm(WxArm),
    SynthInput(SynthInput),
}

/// Decode one payload buffer given its wire event type. Unknown types yield a typed
/// error; the caller degrades unknown types gracefully (this lets the decoder be used
/// standalone in tests).
pub fn decode_event(event_type: u32, payload: &[u8]) -> Result<LinuxProtonEvent, LinuxProtonError> {
    match event_type {
        HK_EVENT_PROTON_OVERRIDE => Ok(LinuxProtonEvent::ProtonOverride(ProtonOverride::decode(
            payload,
        )?)),
        HK_EVENT_FOREIGN_MAP => Ok(LinuxProtonEvent::ForeignMap(ForeignMap::decode(payload)?)),
        HK_EVENT_CROSS_MEM => Ok(LinuxProtonEvent::CrossMem(CrossMem::decode(payload)?)),
        HK_EVENT_NS_ENTRY => Ok(LinuxProtonEvent::NsEntry(NsEntry::decode(payload)?)),
        HK_EVENT_MODULE_LOAD => Ok(LinuxProtonEvent::ModuleLoad(ModuleLoad::decode(payload)?)),
        HK_EVENT_ROOTFS_RW => Ok(LinuxProtonEvent::RootfsRw(RootfsRw::decode(payload)?)),
        HK_EVENT_FRAME_CONSUMER => Ok(LinuxProtonEvent::FrameConsumer(FrameConsumer::decode(
            payload,
        )?)),
        HK_EVENT_WX_ARM => Ok(LinuxProtonEvent::WxArm(WxArm::decode(payload)?)),
        HK_EVENT_SYNTH_INPUT => Ok(LinuxProtonEvent::SynthInput(SynthInput::decode(payload)?)),
        other => Err(LinuxProtonError::UnknownType(other)),
    }
}

// ---------------------------------------------------------------------------
// Feature extraction. Pure, allocation-free; the ban-engine consumes these as
// ONNX features. No thresholding/ban here — the model decides. Booleans are derived
// evidence, not verdicts. High-FP signals (frame-consumer 106, synth-input 108) are
// expressed as low-weight corroborators (see `corroborator_weight` below) — the
// catalog marks both as needing server correlation, never standalone ban inputs.
// ---------------------------------------------------------------------------

/// Normalized features handed to the ban-engine's model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LinuxProtonFeatures {
    /// (100) A native override shadowing a builtin-only DLL off the FP manifest.
    pub override_off_manifest: bool,
    /// (101) An exec mapping off the dist/runtime/prefix tree and off the overlay allowlist.
    pub foreign_map_off_tree: bool,
    /// (102) A cross-process memory read/write whose caller is NOT the game's wineserver.
    pub cross_mem_non_wineserver: bool,
    /// (103) A setns into the game namespaces by a caller off the pv-bwrap lineage.
    pub ns_off_lineage: bool,
    /// (104) A post-boot module load that is neither a hotplug nor an OS update.
    pub module_post_boot: bool,
    /// (105) A SteamOS rootfs RO->RW / protected write outside an OS update window.
    pub rootfs_rw_outside_window: bool,
    /// (106) A frame consumer off the gamescope/portal/Steam-stream allowlist. LOW WEIGHT.
    pub frame_off_allowlist: bool,
    /// (107) A builtin SO whose dev:ino / on-disk SHA drifted off the dist manifest.
    pub builtin_inode_mismatch: bool,
    /// (108) A mid-session uinput create/inject by an off-allowlist tgid. LOW WEIGHT.
    pub synth_input_mid_session: bool,
    /// True when this feature row is a high-FP corroborator (106/108): the ban-engine
    /// must weigh it as supporting evidence only, never as a standalone ban input.
    pub corroborator_only: bool,
}

impl ProtonOverride {
    pub fn features(&self) -> LinuxProtonFeatures {
        LinuxProtonFeatures {
            // Off-manifest AND shadowing a builtin-only DLL is the load-bearing 100
            // shape; a bare off-manifest native override (e.g. an unknown but plausible
            // DLL) is weaker but still reported. We surface the strong conjunction.
            override_off_manifest: (self.flags & HK_PROTON_OFF_MANIFEST) != 0
                && (self.flags & HK_PROTON_NATIVE_SHADOWS_BUILTIN) != 0,
            ..Default::default()
        }
    }
}

impl ForeignMap {
    pub fn features(&self) -> LinuxProtonFeatures {
        LinuxProtonFeatures {
            // Off-tree OR memfd/anon-then-backed reflective load; the overlay allowlist
            // already suppressed the benign overlays in the verifier (flag cleared).
            foreign_map_off_tree: (self.map_flags & (HK_MAP_OFF_TREE | HK_MAP_MEMFD)) != 0,
            ..Default::default()
        }
    }
}

impl CrossMem {
    pub fn features(&self) -> LinuxProtonFeatures {
        // A read/write/procmem/ptrace whose caller is neither the game's own
        // wineserver nor the Horkos client is the external-scanner shape. The
        // wineserver/self/debugger flags are set by the loader/verifier; their
        // absence (with a real access_kind) is the signal.
        let benign = (self.flags & (HK_XMEM_FLAG_WINESERVER | HK_XMEM_FLAG_HORKOS_SELF)) != 0;
        LinuxProtonFeatures {
            cross_mem_non_wineserver: self.access_kind != 0 && !benign,
            ..Default::default()
        }
    }
}

impl NsEntry {
    pub fn features(&self) -> LinuxProtonFeatures {
        LinuxProtonFeatures {
            ns_off_lineage: (self.flags & HK_NS_FLAG_OFF_LINEAGE) != 0,
            ..Default::default()
        }
    }
}

impl ModuleLoad {
    pub fn features(&self) -> LinuxProtonFeatures {
        LinuxProtonFeatures {
            // Post-boot AND off-baseline (not an allowed hotplug, not an update window):
            // the BYOVD shape. A post-boot hotplug/update load is flagged distinctly and
            // is not this feature.
            module_post_boot: (self.flags & HK_MOD_POST_BOOT) != 0
                && (self.flags & HK_MOD_OFF_BASELINE) != 0,
            ..Default::default()
        }
    }
}

impl RootfsRw {
    pub fn features(&self) -> LinuxProtonFeatures {
        LinuxProtonFeatures {
            // An immutable-distro rootfs RW/protected-write that is NOT inside an OS
            // update window. A desktop distro never sets IMMUTABLE_DISTRO (verifier
            // suppresses the whole signal there), so this is SteamOS-only by construction.
            rootfs_rw_outside_window: (self.flags & HK_ROOTFS_IMMUTABLE_DISTRO) != 0
                && (self.flags & (HK_ROOTFS_REMOUNT_RW | HK_ROOTFS_PROTECTED_WRITE)) != 0
                && (self.flags & HK_ROOTFS_UPDATE_WINDOW) == 0,
            ..Default::default()
        }
    }
}

impl FrameConsumer {
    pub fn features(&self) -> LinuxProtonFeatures {
        LinuxProtonFeatures {
            frame_off_allowlist: (self.flags & HK_FRAME_OFF_ALLOWLIST) != 0,
            corroborator_only: true, // 106 is high-FP: low-weight server corroborator only.
            ..Default::default()
        }
    }
}

impl WxArm {
    pub fn features(&self) -> LinuxProtonFeatures {
        LinuxProtonFeatures {
            // An in-builtin VMA whose inode/SHA drifted off the dist manifest is the
            // builtin-stomp shape; a legitimate relocated load matches on-disk and clears
            // INODE_OFF_MANIFEST. The W^X (WAS_RX) transition strengthens but is not
            // required (the inode arm stands alone when the mprotect hook is unavailable).
            builtin_inode_mismatch: (self.flags & HK_WX_IN_BUILTIN) != 0
                && (self.flags & HK_WX_INODE_OFF_MANIFEST) != 0,
            ..Default::default()
        }
    }
}

impl SynthInput {
    pub fn features(&self) -> LinuxProtonFeatures {
        LinuxProtonFeatures {
            // A mid-session uinput create/inject by an off-allowlist tgid. Steam Input's
            // own pre-focus allowlisted device clears OFF_ALLOWLIST in the verifier.
            synth_input_mid_session: (self.flags & HK_SYNTH_OFF_ALLOWLIST) != 0
                && (self.flags & HK_SYNTH_MID_SESSION) != 0,
            corroborator_only: true, // 108 is high-FP: low-weight server corroborator only.
            ..Default::default()
        }
    }
}

impl LinuxProtonEvent {
    /// Extract the normalized feature row for whichever payload this is.
    pub fn features(&self) -> LinuxProtonFeatures {
        match self {
            LinuxProtonEvent::ProtonOverride(e) => e.features(),
            LinuxProtonEvent::ForeignMap(e) => e.features(),
            LinuxProtonEvent::CrossMem(e) => e.features(),
            LinuxProtonEvent::NsEntry(e) => e.features(),
            LinuxProtonEvent::ModuleLoad(e) => e.features(),
            LinuxProtonEvent::RootfsRw(e) => e.features(),
            LinuxProtonEvent::FrameConsumer(e) => e.features(),
            LinuxProtonEvent::WxArm(e) => e.features(),
            LinuxProtonEvent::SynthInput(e) => e.features(),
        }
    }
}
