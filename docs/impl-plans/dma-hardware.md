# DMA / Peripheral Hardware Trust — Implementation Plan

**Scope:** Read-only PCIe config-space, BAR, MSI-X, option-ROM, ACS/IOMMU-topology,
hot-plug, and IOMMU-fault forensics that distinguish genuine ASIC peripherals from
FPGA/PCILeech DMA-inspection boards. Clients sample structural facts and ship them to
the server; **all scoring and every ban decision is server-side** (catalog FP-risk gates
are explicitly server-evaluated). No tampering or device-state mutation: every probe is a
read or an event subscription.

**Catalog signals covered:** 127, 128, 129, 130, 131, 132, 133, 134, 135.

---

## New files

All backends live under `dma_detect/backends/{win,linux,macos}/` (guardrail #1: no
platform API outside a `backends/` folder; conditional selection happens in CMake, not via
raw `_WIN32`/`__linux__`/`__APPLE__`). Each `.cpp`/`.mm` is platform-confined; the C
interface headers in `dma_detect/include/horkos/` are platform-clean. Signal 135's Linux
arm is an eBPF program under `kernel/linux/bpf/` (kernel TU, never shares a TU with the
userspace backend — guardrail #4). Every file carries the role/platform/interface module
comment (guardrail #3).

| Path | Role | Module-comment summary |
|---|---|---|
| `dma_detect/include/horkos/dma_forensics.h` | Pure-C struct/report interface for all 9 signals; extends the existing `hk_dma_report` model with per-device forensic records. | "Role: C interface for PCIe device forensics (config-space, BAR, MSI-X, ROM, ACS, hot-plug). Target: Win/Linux/macOS. Declares `hk_dma_forensics_scan`, `hk_dma_forensics_subscribe`. NO platform headers." |
| `dma_detect/backends/linux/ConfigSpaceForensics.cpp` | Sig 127/128: pread 4KB ext config via `/sys/bus/pci/devices/<BDF>/config`, walk ext-cap list for DSN (0x0003), check OUI vs VID, sample reserved offsets for aliasing/drift. | "Role: Linux config-space forensics backend. Target: Linux only (sysfs). Implements `dma_forensics.h`." |
| `dma_detect/backends/win/ConfigSpaceForensics.cpp` | Sig 127/128 Windows: `BusInterfaceStandard.GetBusData` / `HalGetBusDataByOffset` via the PCI bus interface for ext config reads. | "Role: Windows config-space forensics backend. Target: Windows only (SetupAPI + PCI bus interface). Implements `dma_forensics.h`." |
| `dma_detect/backends/macos/ConfigSpaceForensics.mm` | Sig 127/128 macOS: `IOPCIDevice::configRead32` sweep over IOKit. | "Role: macOS config-space forensics backend. Target: macOS only (IOKit). Implements `dma_forensics.h`." |
| `dma_detect/backends/{linux,win,macos}/MsixForensics.{cpp,cpp,mm}` | Sig 129: read MSI-X cap (0x11) table size / Table&PBA Offset/BIR, reconstruct referenced BAR size, check containment. | "Role: MSI-X BIR/PBA containment forensics. Target: <one OS>. Implements `dma_forensics.h`." |
| `dma_detect/backends/{linux,win,macos}/OptionRomForensics.{cpp,cpp,mm}` | Sig 130: read Expansion ROM BAR (0x30), parse 0xAA55 + PCIR, compare PCIR VID/DID vs config VID/DID. Linux maps `/sys/.../rom` read-only. | "Role: Option-ROM identity forensics. Target: <one OS>. Implements `dma_forensics.h`." |
| `dma_detect/backends/{linux,win,macos}/BarProfile.{cpp,cpp,mm}` | Sig 131: reconstruct each BAR's {size, 64-bit, prefetchable} from OS-recorded sizing for server-side per-VID/DID reference comparison. | "Role: BAR geometry profiler. Target: <one OS>. Implements `dma_forensics.h`." |
| `dma_detect/backends/{linux,win,macos}/TlpLatencyProbe.{cpp,cpp,mm}` | Sig 132: tight-loop timed config reads of one register, build a latency histogram, tag same-root-port peer set. **Low-weight.** | "Role: config-read TLP latency probe (low-weight side-channel). Target: <one OS>. Implements `dma_forensics.h`." |
| `dma_detect/backends/{linux,win,macos}/AcsTopology.{cpp,cpp,mm}` | Sig 133: walk ACS ext-cap (0x000D) Source-Validation/P2P-Redirect bits on path bridges; Linux corroborates with `/sys/kernel/iommu_groups/<n>/devices/` membership. | "Role: ACS/IOMMU-group topology forensics. Target: <one OS>. Implements `dma_forensics.h`." |
| `dma_detect/backends/{linux,win,macos}/HotplugMonitor.{cpp,cpp,mm}` | Sig 134: subscribe to live device-arrival events (udev netlink / `CM_Register_Notification` / `IOServiceAddMatchingNotification`), emit timestamped arrivals. | "Role: PCIe hot-plug arrival monitor. Target: <one OS>. Implements `dma_forensics.h` subscribe API." |
| `kernel/linux/bpf/src/iommu_fault.bpf.c` | Sig 135 (Linux): CO-RE eBPF attaching the `iommu:io_page_fault` tracepoint (kprobe `report_iommu_fault` fallback), counting faults per source-BDF into the shared ringbuf. | "Role: eBPF IOMMU-fault counter. Target: Linux kernel (eBPF CO-RE). Emits to shared ringbuf; mirrored in Loader.cpp." |
| `dma_detect/backends/win/IommuFaultEtw.cpp` | Sig 135 (Windows): consume DMA-remapping fault events via ETW (DeviceGuard / Kernel-* providers) where surfaced. | "Role: Windows IOMMU-fault ETW consumer. Target: Windows only. Implements `dma_forensics.h`." |
| `dma_detect/src/forensics_report.cpp` | Platform-clean aggregator: merges per-backend records into the wire payloads; **no platform API here.** | "Role: platform-agnostic forensics aggregation + wire serialization. Target: all. Implements `dma_forensics.h`." |
| `server/telemetry/src/dma_forensics.rs` | Rust serde mirror of the DMA forensic telemetry payloads; scoring inputs only (no client-side verdict). | "Role: serde mirror + server-side gating of DMA forensic signals. Async; thiserror; no unwrap." |
| `bypass-tests/dma_hardware/*.cpp` | Merge-gate bypass tests (guardrail #12), enumerated in §Test strategy. | per-file role comment. |

---

## Interfaces & data structures

### `dma_detect/include/horkos/dma_forensics.h` (new C interface)

Models per-device forensic facts. All fields unsigned/fixed-width (mirror the existing
`hk_dma_report` discipline). The existing `hk_dma_scan`/`hk_dma_report` stay unchanged;
this is an additive sibling interface.

```c
typedef struct hk_pci_bdf {            /* 4 bytes */
    uint16_t domain;
    uint8_t  bus;
    uint8_t  devfn;                    /* (dev<<3)|func */
} hk_pci_bdf;

typedef struct hk_dma_device_forensics {     /* one record per PCIe device */
    hk_pci_bdf bdf;
    uint16_t   vendor_id;
    uint16_t   device_id;
    uint16_t   subsys_vendor_id;
    /* --- sig 127/128 --- */
    uint8_t    dsn_present;            /* DSN ext-cap (0x0003) found */
    uint8_t    dsn_oui_matches_vendor; /* EUI-64 OUI consistent with VID */
    uint8_t    extcfg_aliases_low;     /* 0x100-0x1FF mirrors 0x000-0x0FF */
    uint8_t    rsvdp_nonzero;          /* RsvdP invariant violated */
    uint8_t    extcfg_read_unstable;   /* repeated reads not byte-identical */
    /* --- sig 129 --- */
    uint8_t    msix_containment_violation;
    uint16_t   msix_table_size;
    /* --- sig 130 --- */
    uint8_t    rom_present;
    uint8_t    rom_pcir_id_mismatch;
    /* --- sig 131 --- */
    uint8_t    bar_profile_count;
    uint64_t   bar_size[6];
    uint8_t    bar_flags[6];           /* bit0=64bit, bit1=prefetch, bit2=io */
    /* --- sig 133 --- */
    uint8_t    acs_source_validation;
    uint8_t    acs_p2p_redirect;
    uint32_t   iommu_group_membership; /* device count in this device's group */
    /* --- structural gates (set by aggregator) --- */
    uint8_t    bus_master_enabled;
    uint8_t    driver_bound;
    /* --- sig 132 (low-weight) --- */
    uint32_t   tlp_latency_median_ns;
    uint32_t   tlp_latency_iqr_ns;
    uint8_t    tlp_same_root_port_group; /* peer-comparison cohort id */
} hk_dma_device_forensics;

int hk_dma_forensics_scan(hk_dma_device_forensics *out, uint32_t *inout_count);

/* sig 134: live arrival callback; subscribe returns a handle, unsubscribe stops it. */
typedef void (*hk_dma_arrival_cb)(const hk_pci_bdf *bdf, uint64_t mono_ns, void *ctx);
int  hk_dma_forensics_subscribe(hk_dma_arrival_cb cb, void *ctx, void **out_handle);
void hk_dma_forensics_unsubscribe(void *handle);
```

### Wire schema additions (`sdk/include/horkos/event_schema.h`)

These reach the server, so they are schema-versioned. Bump `HK_EVENT_SCHEMA_VERSION 2u → 3u`.
Two additions: a per-device forensic snapshot event and a hot-plug arrival event.

```c
HK_EVENT_DMA_FORENSICS = 5,   /* appended to hk_event_type */
HK_EVENT_DMA_HOTPLUG   = 6,
```

The full `hk_dma_device_forensics` exceeds the current `HK_EVENT_PAYLOAD_MAX 16u`. **Wire
decision: DMA forensics ride the per-tick JSON telemetry plane (§schema 3 in
data-categories.md), NOT the 40-byte fixed `hk_event_record` ring.** Rationale: the ring is
the kernel IOCTL plane (guardrail #4, 40-byte records); DMA forensics are userspace-sampled
structural facts with variable per-device cardinality, a poor fit for the fixed ring. So:

- **No change to `HK_EVENT_PAYLOAD_MAX` or `hk_event_record`** (avoids breaking the
  `HK_STATIC_ASSERT(sizeof(hk_event_record)==40)` pin and the kernel ring layout).
- The hot-plug **arrival** event (sig 134), being a small timestamped fact, MAY also be
  emitted on the ring as a compact 16-byte payload if a kernel-side source is ever added;
  for Phase-2 userspace it ships on the telemetry plane. A compact form fits 16 bytes:

```c
typedef struct hk_event_dma_hotplug {   /* 16 bytes, fits HK_EVENT_PAYLOAD_MAX */
    uint32_t bdf;            /* packed domain:bus:devfn */
    uint32_t flags;          /* bit0 bus_master, bit1 unbound, bit2 id_anomaly */
    uint64_t mono_ns;        /* arrival time, monotonic */
} hk_event_dma_hotplug;
HK_STATIC_ASSERT(sizeof(hk_event_dma_hotplug) == 16, "hk_event_dma_hotplug size");
```

No `ioctl.h` control-code additions are required for the userspace path (forensics do not
traverse the Windows driver). If a future kernel arm lands, it reuses `HK_IOCTL_DRAIN_EVENTS`
with the new event type — no new IOCTL code, so `hk_status`/`hk_policy` pins are untouched.

### Telemetry-plane payload (`server/telemetry/src/dma_forensics.rs` ↔ `data-categories.md`)

The serde struct mirrors `hk_dma_device_forensics` field names. **Guardrail #11: every new
telemetry field below must be added to `server/api/data-categories.md` in the same PR.** New
category block to add (sketch):

> ### 5. DMA / peripheral hardware trust (per device)
>
> | Field | Source | Retention | Legal basis | Operator |
> |---|---|---|---|---|
> | `bdf`, `vendor_id`, `device_id`, `subsys_vendor_id` | PCIe config (sysfs / PCI bus iface / IOKit) | 90 days | Legitimate interest — anti-cheat | Horkos Service Operator |
> | `dsn_present`, `dsn_oui_matches_vendor` | ext config DSN cap (sig 127) | 90 days | Legitimate interest | … |
> | `extcfg_aliases_low`, `rsvdp_nonzero`, `extcfg_read_unstable` | ext config sweep (sig 128) | 90 days | … | … |
> | `msix_containment_violation`, `msix_table_size` | MSI-X cap (sig 129) | 90 days | … | … |
> | `rom_present`, `rom_pcir_id_mismatch` | option ROM (sig 130) | 90 days | … | … |
> | `bar_size[]`, `bar_flags[]` | BAR sizing (sig 131) | 90 days | … | … |
> | `tlp_latency_median_ns`, `tlp_latency_iqr_ns` | timed config reads (sig 132, low-weight) | 90 days | … | … |
> | `acs_source_validation`, `acs_p2p_redirect`, `iommu_group_membership` | ACS cap + iommu_groups (sig 133) | 90 days | … | … |
> | `hotplug` arrival `{bdf, flags, mono_ns}` | device-arrival monitor (sig 134) | 90 days | … | … |
> | `iommu_fault_count` per BDF | eBPF `iommu:io_page_fault` / ETW (sig 135) | 90 days | … | … |

(Note `bdf`/`vendor_id`/`subsys_vendor_id` are hardware-adjacent identifiers — flag for
DPO review whether these join category 4's account-lifetime retention or stay at 90 days.)

---

## Mechanism implementation notes

Real API names are taken from the catalog refs. Grouped per signal.

**Sig 127 (DSN forgery) / 128 (ext-cfg stability):**
- *Linux:* `pread()` on `/sys/bus/pci/devices/<BDF>/config` at offset `0x100+`; walk the
  PCIe extended-capability linked list (next-ptr at bits 4–15 of each cap header) for cap ID
  `0x0003` (DSN); read the EUI-64, extract the OUI, compare to the OUI registered for the VID
  (server-side table). For 128, take ≥N `pread` samples across `0x000–0xFFF`, compare
  `0x000–0x0FF` vs `0x100–0x1FF` for aliasing, assert `RsvdP==0`. Read-only; no privilege
  beyond config read (root or `CAP_SYS_ADMIN` for full 4KB — degrade gracefully on EACCES,
  set `scan_error`).
- *Windows:* PCI `BusInterfaceStandard.GetBusData` (or documented `HalGetBusDataByOffset`).
  **UNCERTAINTY FLAG:** extended config (>256B) access from a userspace AC component on
  Windows is not guaranteed without the kernel driver — flagged in §Risks.
- *macOS:* `IOPCIDevice::configRead32` sweep over IOKit. No kernel; userspace IOKit read.

**Sig 129 (MSI-X containment):** read MSI-X cap (0x11) Message Control (table size), Table
Offset/BIR and PBA Offset/BIR; reconstruct the referenced BAR's decoded length from
OS-recorded sizing (Linux `/sys/.../resource` + config BAR regs; Windows CM translated
resources; macOS `IOPCIDevice::deviceMemoryWithIndex` length). Must correctly combine 64-bit
BAR high dword before the `offset + entries*16 ≤ bar_len` check (catalog's named FP source).

**Sig 130 (option ROM):** read Expansion ROM BAR (config `0x30`). *Linux:* write `'1'` to
`/sys/bus/pci/devices/<BDF>/rom` to enable read, `read()` the AA55+PCIR header, compare PCIR
VID/DID to config VID/DID, then restore. **Side-effect caution (catalog-noted):** enabling
ROM decode has a small device-state effect — gate behind read-only confirmation and skip if
the driver is actively using the ROM region. *Windows/macOS:* ROM BAR via PCI bus iface /
IOKit config read.

**Sig 131 (BAR profile):** reconstruct each BAR's `{size, 64-bit, prefetchable}` from the
OS-recorded masked BAR registers (never issue the write-0xFFFFFFFF sizing ourselves — read
the values the OS already recorded, keeping the probe read-only). Ship raw geometry; the
**server** holds the revision-tolerant per-VID/DID reference table and scores mismatch
(never a standalone ban — catalog gate).

**Sig 132 (TLP latency, low-weight):** tight loop of identical config reads timed with
`clock_gettime(CLOCK_MONOTONIC_RAW)` / `QueryPerformanceCounter` / `mach_absolute_time`;
report median + IQR (robust stats per catalog), tag the same-root-port peer cohort so the
server compares only within-cohort. **Never fires standalone; explicitly low-weight.**

**Sig 133 (ACS/topology):** walk ACS ext-cap (0x000D) control bits (Source Validation, P2P
Request Redirect) on each switch downstream port / bridge in the path; Linux corroborates
with `/sys/kernel/iommu_groups/<n>/devices/` membership size. Server scores only when an
unbound + bus-master suspect shares a group with a sensitive endpoint (catalog gate);
maintain server-side consumer-chipset allowlist.

**Sig 134 (hot-plug):** subscribe, don't poll. *Linux:* udev/netlink `KOBJECT_UEVENT`
monitor on the `pci` subsystem (ADD/REMOVE) + rescan diff. *Windows:*
`CM_Register_Notification` (or `RegisterDeviceNotification`) for `DBT_DEVICEARRIVAL` on the
PCI device-interface GUID, timestamped vs AC start. *macOS:* `IOServiceAddMatchingNotification`
with `kIOMatchedNotification` on `IOPCIDevice`. Correlate arrival with structural flags +
recognize Thunderbolt/USB4 root ports as benign domains (catalog gate). **macOS reply-deadline
note:** this is a matching notification, not an ES auth event — no ES reply deadline applies
(guardrail #7 is N/A to this path; the ES auth-reply concern lives only in `kernel/macos/es`).

**Sig 135 (IOMMU faults):**
- *Linux (eBPF, CO-RE):* attach the `iommu:io_page_fault` tracepoint (fallback kprobe on
  `report_iommu_fault`), count faults per source-BDF into the existing shared ringbuf;
  ignore boot/init windows; require the faulting BDF to also carry a structural flag
  (catalog gate). **CO-RE / -Werror:** compile `-Wall -Wextra -Werror` (guardrail #6), use
  `BPF_CORE_READ` for all kernel-struct field access; the `iommu:io_page_fault` tracepoint
  field layout differs across kernels — must be read CO-RE-relocatably, not by fixed offset.
  Requires `CAP_BPF`/`CAP_SYS_ADMIN`; fall back to "absent" gracefully (catalog requirement).
- *Windows:* DMA-remapping fault events via ETW (DeviceGuard / `Microsoft-Windows-Kernel-*`)
  where surfaced. **UNCERTAINTY FLAG:** exact ETW provider GUID + event ID for DMAR faults is
  not confirmed — flagged in §Risks.

**Server (`dma_forensics.rs`):** fully async on tokio (guardrail #8); `thiserror` error
enum (`DmaForensicsError`); **no `unwrap()` outside `#[cfg(test)]`** — all parse/lookup
paths return `Result`. The reference tables (VID/DID OUI map, BAR profiles, chipset ACS
allowlist) load async at startup; missing-VID lookups return `Unknown`, never panic. Scoring
combines structural signals; low-weight sig 132 contributes only as a tie-break.

---

## Build wiring

- **`dma_detect/CMakeLists.txt`:** extend the existing per-host backend selection. Today it
  picks one `*EnumX` TU; add the new forensic TUs to the same platform branch
  (`backends/win/*` under `if(WIN32)`, `backends/linux/*` under `elseif(UNIX AND NOT APPLE)`,
  `backends/macos/*.mm` under `elseif(APPLE)`), plus the platform-clean
  `src/forensics_report.cpp` always. New option `HORKOS_DMA_FORENSICS` (**default ON** on
  Win/Linux; macOS forensics **default ON** but degrade where IOKit calls are restricted).
  Windows already links `setupapi`/`cfgmgr32`; macOS branch adds `IOKit` + `CoreFoundation`
  frameworks; `*.mm` files compile as Objective-C++.
- **`kernel/linux/bpf/CMakeLists.txt`:** add `src/iommu_fault.bpf.c` to the eBPF object list,
  gated behind the existing `HORKOS_LINUX_EBPF` option (**default OFF**, CI-on; Steam Deck
  Game Mode path per locked-decision #3). Toolchain: clang-bpf + libbpf + bpftool (existing).
- **Toolchain:** WDK only if a kernel arm is ever added (none in this plan — userspace path);
  clang-19 not required for the C++ backends; libbpf for sig 135 Linux; Xcode for `.mm`.
- **Server:** add `dma_forensics` module to `server/telemetry/Cargo.toml` member; no new
  crate.

---

## Test strategy

### Unit tests (TDD, guardrail #14)
- `forensics_report` aggregator: feed synthetic per-device records, assert correct wire
  serialization and the structural-gate flags (`bus_master_enabled && !driver_bound`).
- BAR 64-bit reconstruction: golden vectors where high-dword combination changes the
  containment verdict (sig 129/131 shared FP source).
- DSN OUI matcher (sig 127): EUI-64 with matching vs mismatching OUI for a known VID.
- ext-cfg aliasing detector (sig 128): synthetic 4KB buffer where `0x100` mirrors `0x000`.
- `dma_forensics.rs` server scoring: table-driven cases asserting that sig 132 alone never
  produces a positive verdict; missing-VID lookup returns `Unknown` not panic (no-unwrap).

### Bypass tests (merge gate, guardrail #12 — required because this adds files under a
security folder; name + what each must demonstrate)
- `bypass_dsn_clone.cpp` — synthesize a device record that clones a NIC's VID/DID but omits
  DSN or presents a mismatched OUI; assert sig 127 flags it AND that plain DSN-absence alone
  on a whitelisted DSN-less VID does **not** flag (FP gate honored).
- `bypass_extcfg_alias.cpp` — FPGA-style shadow config that aliases low 256B into ext space;
  assert sig 128 detects aliasing and that a real quirk-listed bridge does not trip.
- `bypass_msix_overflow.cpp` — MSI-X table offset+size exceeding the referenced BAR; assert
  sig 129 hard-containment violation fires and that a valid 64-bit-BAR layout does not.
- `bypass_rom_identity.cpp` — option ROM whose PCIR VID/DID contradicts config IDs; assert
  sig 130 mismatch fires; ROM-absent device does not fire.
- `bypass_bar_geometry.cpp` — generic FPGA BAR0 (huge prefetchable) vs reference I210
  profile; assert server scores mismatch but never standalone-bans.
- `bypass_acs_p2p.cpp` — unbound+bus-master suspect sharing an oversized IOMMU group with a
  sensitive endpoint; assert sig 133 scores; a benign consumer-chipset big group does not.
- `bypass_hotplug_after_start.cpp` — post-AC-start arrival of an unbound bus-master device
  with an ID anomaly; assert sig 134 flags; a Thunderbolt-domain dock arrival does not.
- `bypass_iommu_fault_storm.cpp` — steady-state fault stream attributed to a flagged BDF
  (sig 135); assert it scores while init-window bursts and faults on clean BDFs do not.
- `bypass_latency_only.cpp` — high TLP jitter as the **only** signal; assert the server
  produces **no** verdict (low-weight, never-standalone gate is enforced).

---

## Sequencing

1. **Interface + aggregator + server mirror first.** Land `dma_forensics.h`,
   `forensics_report.cpp`, schema v3 bump, `dma_forensics.rs`, and the `data-categories.md`
   block (guardrail #11) — testable with synthetic records, no hardware.
2. **Linux structural backends** (127/128 → 129 → 130 → 131 → 133): sysfs is the simplest,
   most-documented surface; builds the reference-table contract the server consumes.
3. **Windows structural backends** (same signal order) once the config-access uncertainty
   (below) is resolved.
4. **macOS IOKit backends** (structural signals) — userspace IOKit, no entitlement gate.
5. **Hot-plug monitors (134)** — depends on structural flags from 1–4 for correlation.
6. **IOMMU-fault (135):** Linux eBPF behind `HORKOS_LINUX_EBPF` (depends on shared-ringbuf
   plumbing already present), then Windows ETW.
7. **TLP latency (132) last** — lowest value, highest noise; only useful once structural
   signals exist for it to corroborate.

Dependency notes: 129 and 131 share BAR-sizing code (build once). 127 and 128 share the
config-space reader. 133's IOMMU-group read reuses the existing `PcieEnumLinux` sysfs paths.

---

## Risks & UNCERTAINTY FLAGS

Per guardrail #13 — flagged, not papered over:

1. **UNCERTAIN — Windows userspace extended config-space access (sig 127/128/129/130/133).**
   Whether a userspace AC component can reliably read PCIe **extended** config (offset ≥256)
   via `BusInterfaceStandard.GetBusData` / `HalGetBusDataByOffset` without the Horkos kernel
   driver is **not confirmed**. `HalGetBusDataByOffset` is a kernel API. **STOP/FLAG:** before
   implementing the Windows arm, confirm whether ext config must route through the KMDF driver
   (a new IOCTL) or whether a documented userspace path exists. Do not guess the API surface.
2. **UNCERTAIN — Windows DMAR-fault ETW provider (sig 135).** The exact provider GUID and
   event ID for DMA-remapping faults on Windows is unverified; may not be surfaced on consumer
   SKUs. Treat the Windows sig-135 arm as best-effort/degrade-absent until confirmed.
3. **UNCERTAIN — `iommu:io_page_fault` tracepoint stability (sig 135 Linux).** Tracepoint
   name and field layout have changed across kernel versions; the `report_iommu_fault` kprobe
   fallback signature is also version-sensitive. Must be CO-RE-relocatable and feature-probed
   at load; do not hard-code offsets.
4. **Side-effect — option-ROM enable (sig 130).** Enabling ROM decode to read it is a small
   device-state change. Mitigation: skip when a driver owns the ROM region; restore decode
   state; treat as the only non-pure-read probe and document it. If any doubt about a device
   actively using the ROM, **skip rather than probe.**
5. **FP-heavy by design (sig 132, 133, 134, 128, 130, 127):** the catalog assigns these
   medium/high FP risk with explicit server-side gates (peer cohorts, quirk lists, chipset
   allowlists, structural co-requirements). The client must ship raw facts only; **any
   client-side verdict here is a spec violation.** Enforced by `bypass_latency_only.cpp` and
   the FP-negative assertions in every bypass test.
6. **Identifier sensitivity:** `bdf`/`vendor_id`/`subsys_vendor_id` are hardware-adjacent
   identifiers. Flag for DPO review whether they inherit category-4 account-lifetime retention
   vs the 90-day default proposed here.
