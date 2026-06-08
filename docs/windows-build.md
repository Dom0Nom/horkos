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
