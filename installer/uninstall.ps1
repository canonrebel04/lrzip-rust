# lrzip-rust Windows uninstaller - uninstall.ps1
# Runs from the install dir via uninstall.cmd. Removes PATH entry, registry key, files.
$ErrorActionPreference = 'Continue'

$AppName    = 'lrzip-rust'
$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\$AppName"

# 1. Remove from user PATH
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath) {
    $parts = $userPath -split ';' | Where-Object { $_ -and ($_.TrimEnd('\') -ne $InstallDir.TrimEnd('\')) }
    [Environment]::SetEnvironmentVariable('Path', ($parts -join ';'), 'User')
}

# 2. Remove Add/Remove Programs key
Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$AppName" -Recurse -Force -ErrorAction SilentlyContinue

# 3. Schedule a detached cleanup of the install dir (2s delay: lets uninstall.cmd
#    and this ps1 fully exit first, so no file-lock conflicts). This is the only
#    removal path — an immediate Remove-Item here would race the running cmd.exe
#    that is executing uninstall.cmd from inside that dir and emit spurious
#    "cannot find path" errors + a non-zero exit for Add/Remove Programs.
$cleanup = Join-Path $env:TEMP 'lrzip-rust-cleanup.cmd'
("@echo off`r`ntimeout /t 2 /nobreak >nul`r`nrmdir /s /q `"$InstallDir`" 2>nul`r`ndel /q /f `"$cleanup`" 2>nul`r`n" |
    Set-Content -Path $cleanup -Encoding ASCII)
Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', "`"$cleanup`"" -WindowStyle Hidden

Write-Host "Uninstalled $AppName. PATH cleaned."
