<#
.SYNOPSIS
    Set up YEMU on Windows 10/11: QEMU (via winget), Windows Hypervisor Platform,
    a Python virtualenv with YEMU installed, then `yemu doctor`.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\setup_windows.ps1
    powershell -ExecutionPolicy Bypass -File scripts\setup_windows.ps1 -CreateVM ubuntu-clean
#>
param(
    [string]$VenvDir = ".venv",
    [string]$CreateVM = "",
    [switch]$SkipQemu
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

function Step($msg) { Write-Host "[+] $msg" -ForegroundColor Green }
function Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }

# --- Python ---
$py = Get-Command py -ErrorAction SilentlyContinue
$pythonCmd = if ($py) { @("py", "-3") } else { @("python") }
$version = & $pythonCmd[0] $pythonCmd[1..9] -c "import sys; print('%d.%d' % sys.version_info[:2])"
if ([version]$version -lt [version]"3.10") { throw "Python 3.10+ is required (found $version)." }
Step "Python $version"

# --- QEMU ---
$qemuDirs = @("$env:ProgramFiles\qemu", "${env:ProgramFiles(x86)}\qemu", "$env:USERPROFILE\scoop\apps\qemu\current")
$qemu = (Get-Command qemu-system-x86_64 -ErrorAction SilentlyContinue).Source
if (-not $qemu) { $qemu = $qemuDirs | ForEach-Object { Join-Path $_ "qemu-system-x86_64.exe" } | Where-Object { Test-Path $_ } | Select-Object -First 1 }
if (-not $qemu -and -not $SkipQemu) {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Step "Installing QEMU with winget..."
        winget install --id SoftwareFreedomConservancy.QEMU -e --accept-package-agreements --accept-source-agreements
    } else {
        Warn "QEMU not found and winget is unavailable. Install QEMU from https://qemu.weilnetz.de/w64/ and re-run."
    }
} elseif ($qemu) {
    Step "QEMU found: $qemu"
}

# --- Windows Hypervisor Platform (WHPX acceleration) ---
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    $whp = Get-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform
    if ($whp.State -ne "Enabled") {
        Step "Enabling Windows Hypervisor Platform (a reboot will be required)..."
        Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -All -NoRestart | Out-Null
        Warn "Reboot Windows, then re-run this script."
    } else {
        Step "Windows Hypervisor Platform is enabled"
    }
} else {
    Warn "Not elevated: skipping the Windows Hypervisor Platform check. 'yemu doctor' will report whether WHPX works."
    Warn "To enable it, run in an admin PowerShell: Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -All"
}

# --- Virtualenv + YEMU ---
if (-not (Test-Path $VenvDir)) {
    Step "Creating virtualenv in $VenvDir"
    & $pythonCmd[0] $pythonCmd[1..9] -m venv $VenvDir
}
$venvPy = Join-Path $VenvDir "Scripts\python.exe"
Step "Installing YEMU and dependencies..."
& $venvPy -m pip install --upgrade pip | Out-Null
& $venvPy -m pip install -e ".[gui,dev]"

$yemu = Join-Path $VenvDir "Scripts\yemu.exe"
Step "Running yemu doctor"
& $yemu doctor

if ($CreateVM) {
    Step "Creating analysis VM '$CreateVM' (downloads an Ubuntu cloud image, ~600 MB)..."
    & $yemu vm create $CreateVM
}

Write-Host ""
Step "Done. Activate with:  $VenvDir\Scripts\Activate.ps1"
Write-Host "    yemu gui                         # desktop app"
Write-Host "    yemu vm create ubuntu-clean      # build an isolated analysis VM"
Write-Host "    yemu analyze C:\path\to\sample   # detonate a sample"
