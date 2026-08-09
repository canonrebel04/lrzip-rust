# lrzip-rust Windows installer - install.ps1
# Runs from the IExpress extraction dir. Installs lrzip-rust.exe per-user.
$ErrorActionPreference = 'Stop'

$AppName    = 'lrzip-rust'
$Version    = '__VERSION__'   # stamped by build-installer.ps1
$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\$AppName"
$ExeSource  = Join-Path $PSScriptRoot 'lrzip-rust.exe'

if (-not (Test-Path $ExeSource)) {
    Write-Error "lrzip-rust.exe not found next to installer: $ExeSource"
    exit 1
}

# 1. Copy the binary
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Force -Path $ExeSource -Destination (Join-Path $InstallDir 'lrzip-rust.exe')

# 2. Ship the uninstaller alongside
Copy-Item -Force -Path (Join-Path $PSScriptRoot 'uninstall.ps1') -Destination $InstallDir
$uninstallCmd = Join-Path $InstallDir 'uninstall.cmd'
@"
@echo off
cd /d "%TEMP%"
powershell -NoProfile -ExecutionPolicy Bypass -File "%LOCALAPPDATA%\Programs\lrzip-rust\uninstall.ps1"
"@ | Set-Content -Path $uninstallCmd -Encoding ASCII

# 3. Add/Remove Programs entry (HKCU, no admin needed)
$unreg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$AppName"
New-Item -Path $unreg -Force | Out-Null
New-ItemProperty -Path $unreg -Name 'DisplayName'       -Value "$AppName (lrzip-next compatible compressor)" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $unreg -Name 'DisplayVersion'    -Value $Version -PropertyType String -Force | Out-Null
New-ItemProperty -Path $unreg -Name 'Publisher'         -Value 'canonrebel04' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $unreg -Name 'InstallLocation'   -Value $InstallDir -PropertyType String -Force | Out-Null
New-ItemProperty -Path $unreg -Name 'UninstallString'   -Value "`"$uninstallCmd`"" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $unreg -Name 'DisplayIcon'       -Value (Join-Path $InstallDir 'lrzip-rust.exe') -PropertyType String -Force | Out-Null
New-ItemProperty -Path $unreg -Name 'NoModify'          -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $unreg -Name 'NoRepair'          -Value 1 -PropertyType DWord -Force | Out-Null

# 4. Add to user PATH (idempotent)
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath -notlike "*$InstallDir*") {
    $newPath = if ([string]::IsNullOrEmpty($userPath)) { $InstallDir } else { $userPath.TrimEnd(';') + ';' + $InstallDir }
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
}

Write-Host "Installed $AppName $Version to $InstallDir"
Write-Host "Added to user PATH. Open a new terminal to use it."
