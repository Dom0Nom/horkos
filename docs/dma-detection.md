# DMA Detection - Design and Threat Model

Subsystem: `dma_detect/`  
Phase: 4, Step 4.6  
Interface: `dma_detect/include/horkos/dma_detect.h`

---

## What this subsystem does and does not do

`hk_dma_scan()` is a **detect-and-report** function.  It populates an
`hk_dma_report` struct and returns it to the caller.  It never:

- Issues a client-side ban or kicks the player.
- Modifies any kernel state.
- Terminates or suspends processes.

The **server** (Rust/axum) receives the report in a telemetry event and
decides whether to act.  The client is explicitly not trusted to make that
decision (guardrail: no business logic in the AC binary for a finding that
could be caused by legitimate hardware).

---

## Why firmware claims alone are insufficient

UEFI firmware writes the DMAR (Intel VT-d) or SMMU (ARM/AMD) ACPI table to
describe the IOMMU topology.  The kernel's IOMMU subsystem reads this table
at boot.  **Firmware can lie, misconfigure, or be patched.**

Known cases where firmware reports IOMMU "enabled" but protection is absent:

| Scenario | Firmware report | Kernel reality |
|---|---|---|
| BIOS "VT-d" toggle present but DMAR table has zero remapping scopes | Enabled | No groups created |
| IOMMU hardware fused-off (OEM cost reduction) but firmware stub present | Enabled | Driver fails to initialise |
| Hypervisor hides DMAR from guest VM | Enabled | Guest kernel sees 0 groups |
| FPGA DMA card replaces its own BDF after POST, post-DMAR-scan | Enabled | Device outside any IOMMU group |

The last case is particularly relevant to PCILeech-style FPGA DMA boards:
they can enumerate as a benign device during POST (captured in the DMAR
scope), then have the FPGA image reconfigure the PCIe endpoint BDF after the
IOMMU has finished its bus scan.  The firmware says "IOMMU on and this BDF is
mapped"; the IOMMU has no actual page table for the new BDF.

---

## Cross-check logic and `high_confidence_flag`

The backend cross-checks two independent sources:

1. **Firmware claim** - DMAR/SMMU table present in ACPI (`/proc/iomem` on
   Linux; Kernel DMA Protection registry key on Windows).
2. **Kernel corroboration** - OS-visible IOMMU groups (`/sys/kernel/iommu_groups/`
   on Linux; KDP `iommu_groups_present` proxy on Windows).

`high_confidence_flag` is set to 1 when **any** of the following are true:

- Firmware claims IOMMU enabled (`iommu_enabled == 1`) but the kernel sees
  zero IOMMU groups (`iommu_groups_present == 0`).  This is the canonical
  "firmware lies" detection.

- Suspicious devices present (`suspicious_device_count > 0`) and the kernel
  has no active IOMMU groups.  A DMA-capable device with no IOMMU protection
  and no bound driver is an open channel.

- IOMMU is OS-active but a DMA-capable device has no kernel driver.  The
  IOMMU group exists, but without a driver managing the device's IOVA space,
  the hardware is not actually constrained by the IOMMU page tables.  This
  is the post-POST BDF-swap case described above.

When `high_confidence_flag == 0` and `suspicious_device_count == 0`, the
system is in a normal state.  The server should still log the report but
take no punitive action.

When `high_confidence_flag == 1`, the server escalates to human review or
a soft-ban workflow - it does not hard-ban automatically, because legitimate
hardware (custom NICs, FPGA development boards, Thunderbolt docking stations)
can present as suspicious without malicious intent.

---

## Platform notes

### Windows

- IOMMU detection uses the **Kernel DMA Protection** (KDP) registry key:
  `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelDmaProtection\Enabled`
  Available since Windows 10 1803.  Absent on older versions → treated as disabled.

- PCIe enumeration uses `SetupDiGetClassDevsA(nullptr, "PCI", ...)` with
  `DIGCF_ALLCLASSES | DIGCF_PRESENT` to enumerate all present PCI-bus devices.

- A device is flagged suspicious if it is DMA-capable (by PCI base class) and
  has no driver bound (`DN_DRIVER_LOADED` not set in `CM_Get_DevNode_Status`).

- **Known limitation**: the exact DMAR remapping unit count is not exposed via
  a documented userspace API on Windows.  `iommu_groups_present` is reported as
  1 (not the real unit count) when KDP is enabled.  The cross-check still
  fires correctly because any non-zero value means the kernel accepted the
  firmware's claim.

### Linux

- Firmware claim: `/proc/iomem` lines containing "DMAR" (Intel VT-d) or
  "SMMU" (ARM SMMU).

- Kernel corroboration: directory entry count under
  `/sys/kernel/iommu_groups/` (primary) and `/sys/class/iommu/` (fallback
  when `iommu_groups` sysfs is not compiled in).

- Device enumeration: `/sys/bus/pci/devices/<BDF>/class` for the class code;
  `/sys/bus/pci/devices/<BDF>/driver` symlink for driver binding.

- Requires read access to `/sys` and `/proc/iomem`.  No `CAP_SYS_ADMIN` is
  needed for these paths; standard user-level read access suffices.

### macOS

macOS has no sysfs equivalent.  IOKit provides PCIe enumeration via
`IOServiceGetMatchingServices` with `IOPCIDevice`.  IOMMU state is not
directly inspectable from userspace.  The macOS backend is currently a stub
returning `scan_error = 1`; the IOKit implementation is deferred to a later
phase pending the System Extension entitlement path.

---

## Telemetry integration

The server receives DMA scan results as a JSON-serialisable payload within
the standard horkos telemetry event envelope (see `docs/event-schema.md`).
When this event type is added:

1. Add `HK_EVENT_DMA_SCAN` to `hk_event_type` in `sdk/include/horkos/event_schema.h`.
2. Define `hk_event_dma_scan` payload mirroring the `hk_dma_report` fields.
3. Bump `HK_EVENT_SCHEMA_VERSION`.
4. Add the Rust mirror struct in `server/telemetry/src/schema.rs`.
5. Update `server/api/data-categories.md` (guardrail #11).
