<#
  kernel/win/install/install.ps1
  Role: Install and start the Horkos kernel service for in-VM bring-up. Defaults
        to demand-start (safe for iterative testing); pass -BootStart to register
        the production boot-start configuration from horkos.inf.
  Target platform: Windows 10/11 x64, elevated PowerShell, test-signing enabled.
  Safety: kernel bring-up happens only in a snapshot-ready VM with verifier.exe
          armed (see docs/windows-build.md). Boot-start a broken driver and the
          VM will not boot — keep a snapshot.
#>
[CmdletBinding()]
param(
    [string]$SysPath = "$PSScriptRoot\..\..\..\build\kernel\win\horkos.sys",
    [switch]$BootStart
)

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    throw "Run this script from an elevated (Administrator) PowerShell."
}

if (-not (Test-Path $SysPath)) {
    throw "Driver binary not found at $SysPath. Build horkos.sys first."
}

$svc   = 'horkos'
$start = if ($BootStart) { 'boot' } else { 'demand' }

# Remove any prior registration so this is idempotent.
sc.exe stop   $svc | Out-Null
sc.exe delete $svc | Out-Null

Write-Host "Creating service '$svc' (start=$start) from $SysPath"
sc.exe create $svc type= kernel start= $start binPath= $SysPath
if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed ($LASTEXITCODE)." }

Write-Host "Starting service '$svc'"
sc.exe start $svc
if ($LASTEXITCODE -ne 0) {
    throw "sc.exe start failed ($LASTEXITCODE). Check test-signing and verifier."
}

Write-Host "Horkos driver loaded. Control device: \\.\Horkos"
