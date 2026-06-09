# Windows Build & Bring-up (Phase 3)

## 1. VM provisioning (mandatory)

- Windows 11 24H2 (or later) in a **snapshot-ready** VM (Hyper-V / VMware / Parallels).
- Take a snapshot **before the first driver load**. A broken boot-start driver
  bricks the boot path; the snapshot is the recovery path.
- Enable test-signing: `bcdedit /set testsigning on` then reboot.
- Optionally enable kernel debugging to a host debugger: `bcdedit /debug on`.

## 2. Toolchain

- **Visual Studio 2022** Build Tools with the **Spectre-mitigated MSVC** toolset.
- **WDK** matching the installed SDK (installs under
  `C:\Program Files (x86)\Windows Kits\10\`).
- KMDF runtime ships with the WDK (co-installer no longer required on 24H2).

## 3. Build

Two supported paths:

1. **MSBuild (canonical for signing).** Open/author `kernel/win/horkos.vcxproj`
   in the WDK environment and build the `Release|x64` driver configuration. This
   is the path that produces a `.cat` and feeds the signing pipeline.
2. **CMake (developer convenience).** From the repo root on a Windows host with
   the WDK installed:
   ```
   cmake -S . -B build
   cmake --build build --config Release
   ```
   `kernel/win/CMakeLists.txt` auto-detects the WDK and builds `horkos.sys`. If
   the WDK is not found it **skips** the driver target with a warning so the
   C++/test build still works.

### 3a. Driver/module-integrity sensor flags (win-kernel-driver-integrity)

Signals 28–36 are read-only kernel integrity sensors. Each is gated by a CMake
option that maps to a `target_compile_definition`; when OFF, the sensor `.c`
compiles to a no-op stub, so the driver links with any subset. `ModuleMap.c` and
`HkIntegrityScan.c` are always compiled (the shared scan substrate). The MSBuild
`horkos.vcxproj` carries the same defaults via `PreprocessorDefinitions`.

| Option | Signal | Default | Rationale |
|---|---|---|---|
| `HK_WIN_INTEGRITY_DEBUGSTATE` | 33 kernel-debug attach | **ON** | low FP, documented exports only |
| `HK_WIN_INTEGRITY_CISTATE` | 30 code-integrity/DSE/HVCI | **ON** | low FP, delta-only |
| `HK_WIN_INTEGRITY_SSDT` | 35 SSDT range (non-shadow) | **ON** | low FP; shadow half deferred |
| `HK_WIN_INTEGRITY_DRVOBJ` | 34 DRIVER_OBJECT divergence | **ON** | low FP |
| `HK_WIN_INTEGRITY_FLT` | 28 minifilter owner audit | OFF | Flt object lifetime unverified (Risk 2); links `fltMgr.lib` when ON |
| `HK_WIN_INTEGRITY_CALLBACKS` | 31 callback residency | OFF | self-sentinel half only; full table walk OUT (Risk 1) |
| `HK_WIN_INTEGRITY_IMAGEHASH` | 29 `.text` hash | OFF | reloc/IAT normalization unproven (Risk 4) |
| `HK_WIN_INTEGRITY_NONIMAGE` | 32 non-image exec scan | OFF | HIGH FP (Risk 6) |
| `HK_WIN_INTEGRITY_BOOTLOAD` | 36 boot/ELAM load order | OFF | ELAM callback timing unverified (Risk 5) |

`HK_INTEGRITY_TIMER_MS` (default `30000`) sets the periodic scan interval.
`HK_IOCTL_INTEGRITY_RESCAN` triggers a manual sweep; findings flow out through the
existing `HK_IOCTL_DRAIN_EVENTS` ring as `HK_EVENT_INTEGRITY_FINDING` records.

The default-OFF sensors carry `// HK-UNCERTAIN(...)` stubs at the exact risky
call (FltMgr deref contract, ELAM registration timing, reloc normalization, the
undocumented `PspCreateProcessNotifyRoutine`/`CmCallbackListHead` arrays, the
unexported `KeServiceDescriptorTableShadow`, and big-pool executability). **Do not
flip these ON until the flagged API contract is verified on-box** — a BSOD is
worse than a missing signal (guardrail #13).

### 3b. Syscall/ETW/PatchGuard surface-integrity sensor flags (win-kernel-syscall-etw-integrity)

Signals 208–216 are read-only kernel sensors that bounds-check the x64 syscall
dispatch surface (SSDT, LSTAR MSR, syscall prologue, IDT) and the kernel ETW
telemetry surface (ETW-TI liveness, logger-session census, infinity-hook probe)
against the ntoskrnl image range and a boot baseline. **No table/MSR/IDT writes,
no hooks installed** — purely read-and-report; the server scores and bans. They
register as additional fan-out targets of the same `HkIntegrityScan.c` PASSIVE
work item (no second timer). `KernelImageMap.c` is always compiled (the shared
ntoskrnl/hal range cache). The per-CPU reads (210 LSTAR, 214 IDT) run inside
`KeIpiGenericCall` and do nothing but a register/MSR read + store at IPI level.

| Option | Signal | Default | Rationale |
|---|---|---|---|
| `HK_WIN_SYSCALL_SSDT` | 208 entry bounds + 216 base-swap | **ON** | exported `KeServiceDescriptorTable` only; low FP; out-of-band `Limit` → UNVERIFIABLE |
| `HK_WIN_SYSCALL_LSTAR` | 210 IA32_LSTAR per-CPU | **ON** | off-hot-path IPI; per-CPU divergence half always safe |
| `HK_WIN_SYSCALL_IDT` | 214 IDT gate bounds | **ON** *(pending)* | off-hot-path `__sidt` IPI; **confirm the `__sidt` read path on-box (Risk 11)** |
| `HK_WIN_SYSCALL_SHADOW_SSDT` | 209 shadow SSDT / `W32pServiceTable` | OFF | unexported shadow table + `KeStackAttachProcess` pairing (Risk 1/4) |
| `HK_WIN_SYSCALL_PROLOGUE` | 213 `KiSystemCall64` prologue | OFF | boot self-patch stable-window unvalidated (Risk 5) |
| `HK_WIN_ETW_TI` | 212 ETW-TI liveness | **ON** | keepalive half only; raw-handle half offset-gated → UNVERIFIABLE (Risk 1/7) |
| `HK_WIN_ETW_SESSION` | 215 logger-session census | OFF | kernel `NtTraceControl`/`EtwQueryAllTraces` surface unconfirmed (Risk 6) |
| `HK_WIN_ETW_INFINITYHOOK` | 211 infinity-hook probe | OFF | undocumented `WMI_LOGGER_CONTEXT` layout (Risk 8) |

`HK_ETW_KEEPALIVE_MIN_DELTA` (default `0`) sets the per-interval ETW-TI keepalive
floor; `0` means any counter advance counts as liveness. Findings reuse the same
`HK_EVENT_INTEGRITY_FINDING` record (finding codes `0x20..0x2F`) — no new event
type, no ring resize, no `ioctl.h` size change.

Every uncertainty-gated sensor (and the ON-but-pending IDT path) carries a
`// HK-UNCERTAIN(...)` stub at the exact risky call: the unexported
`KiSystemCall64[Shadow]`/`EtwThreatIntProvRegHandle` resolves, the KVA-shadow
expected-LSTAR selection, the `__sidt` IPI IDT read, the kernel logger-table
query, the `WMI_LOGGER_CONTEXT` walk, the shadow-table `KeStackAttachProcess`
pairing, and the ETW-TI consumer location (ETW-TI is a **protected provider** — no
ordinary KMDF driver can consume it; the keepalive counter has no in-kernel
bumper under current signing). **Do not flip the OFF sensors ON, and do not enable
210/214's absolute-match halves, until the flagged contract is verified on-box.**

## 4. verifier.exe (mandatory before load)

Arm Driver Verifier against the driver **before** the first load:

```
verifier /standard /driver horkos.sys
```

Reboot, then load. Verifier catches IRQL violations, leaked allocations, and
spinlock misuse — the exact failure classes this driver risks.

## 5. Load / unload

Elevated PowerShell in the VM:

```
.\kernel\win\install\install.ps1            # demand-start (safe for bring-up)
.\kernel\win\install\install.ps1 -BootStart # boot-start (production layout)
.\kernel\win\install\uninstall.ps1
```

Bring-up uses **demand-start**. Switch to boot-start only after the driver is
known-clean under verifier across multiple reboots.

## 6. Smoke test

With the driver loaded, run the userspace smoke test (built by CMake on Windows):

```
build\tests\integration\win\hk_ioctl_smoke.exe
```

It opens `\\.\Horkos`, issues `GET_STATUS` / `DRAIN_EVENTS` / `PUSH_POLICY`, and
prints the status. Without the driver it prints `SKIP` and exits 0.

## 7. In-VM validation checklist

- `ObRegisterCallbacks` altitude `385201` must not collide with an installed
  product on the test box; pick an Allocated Altitude for production.
- `PsSetCreateProcessNotifyRoutineEx` requires the image be linked
  `/INTEGRITYCHECK` (set in CMake link options) and signed/test-signed; the
  load will fail with `STATUS_ACCESS_DENIED` if either condition is not met.
- The control device SDDL (`SDDL_DEVOBJ_SYS_ALL_ADM_ALL`) must allow the smoke
  test to open the device when run elevated.
- `KeQueryInterruptTime` usage and the spinlock IRQL contract must pass the
  `/standard` verifier ruleset.
