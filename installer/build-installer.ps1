# build-installer.ps1 - builds lrzip-rust-setup.exe via IExpress (built into Windows)
# Usage: powershell -File build-installer.ps1 -ExePath ..\target\release\lrzip-rust.exe [-Version 0.26.0] [-OutDir .]
param(
    [Parameter(Mandatory = $true)][string]$ExePath,
    [string]$Version = '0.0.0',
    [string]$OutDir  = '.'
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
# CI passes github.ref_name like "v0.26.0" - strip the leading v for DisplayVersion
$Version = $Version.TrimStart('v')
$stage = Join-Path $env:TEMP 'lrzip-rust-installer-stage'
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force -Path $stage | Out-Null

# Stage payload (stamp version into install.ps1 so it survives to install time)
Copy-Item $ExePath (Join-Path $stage 'lrzip-rust.exe')
(Get-Content (Join-Path $root 'install.ps1') -Raw) -replace '__VERSION__', $Version |
    Set-Content -Path (Join-Path $stage 'install.ps1') -Encoding UTF8
Copy-Item (Join-Path $root 'uninstall.ps1') (Join-Path $stage 'uninstall.ps1')
Copy-Item (Join-Path $root 'install.cmd')   (Join-Path $stage 'install.cmd')

$outExe = Join-Path (Resolve-Path $OutDir) 'lrzip-rust-setup.exe'
$sed = Join-Path $stage 'setup.sed'

$sedContent = @"
[Version]
Class=IEXPRESS
SEDVersion=3
[Options]
PackagePurpose=InstallApp
ShowInstallProgramWindow=0
HideExtractAnimation=1
UseLongFileName=1
InsideCompressed=0
CAB_FixedSize=0
CAB_ResvCodeSigning=0
RebootMode=N
InstallPrompt=%InstallPrompt%
DisplayLicense=%DisplayLicense%
FinishMessage=%FinishMessage%
TargetName=%TargetName%
FriendlyName=%FriendlyName%
AppLaunched=%AppLaunched%
PostInstallCmd=%PostInstallCmd%
AdminQuietInstCmd=%AdminQuietInstCmd%
UserQuietInstCmd=%UserQuietInstCmd%
SourceFiles=SourceFiles
[Strings]
InstallPrompt=
DisplayLicense=
FinishMessage=
TargetName=$outExe
FriendlyName=lrzip-rust Setup
AppLaunched=cmd.exe /c install.cmd
PostInstallCmd=<None>
AdminQuietInstCmd=
UserQuietInstCmd=
FILE0=lrzip-rust.exe
FILE1=install.ps1
FILE2=uninstall.ps1
FILE3=install.cmd
[SourceFiles]
SourceFiles0=$stage
[SourceFiles0]
%FILE0%=
%FILE1%=
%FILE2%=
%FILE3%=
"@

# IExpress wants CRLF line endings in the .sed
$sedContent -replace "`n", "`r`n" | Set-Content -Path $sed -Encoding ASCII -NoNewline

$env:LRZIP_INSTALLER_VERSION = $Version
$p = Start-Process -FilePath "$env:WINDIR\system32\iexpress.exe" `
                   -ArgumentList '/N', $sed `
                   -Wait -PassThru
if ($p.ExitCode -ne 0) { throw "iexpress failed with exit code $($p.ExitCode)" }
if (-not (Test-Path $outExe)) { throw "installer not produced: $outExe" }

Write-Host "Installer built: $outExe ($([math]::Round((Get-Item $outExe).Length/1MB,2)) MB)"
