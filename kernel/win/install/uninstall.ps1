<#
  kernel/win/install/uninstall.ps1
  Role: Stop and remove the Horkos kernel service. Used between bring-up
        iterations in the VM.
  Target platform: Windows 10/11 x64, elevated PowerShell.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'

if (-not ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    throw "Run this script from an elevated (Administrator) PowerShell."
}

$svc = 'horkos'

Write-Host "Stopping service '$svc'"
sc.exe stop $svc | Out-Null

Write-Host "Deleting service '$svc'"
sc.exe delete $svc | Out-Null

Write-Host "Horkos driver service removed. A reboot clears any boot-start entry."
