# install_offline.ps1
# Run on the OFFLINE Windows machine after unzipping dbcap_offline.zip.
# This installs Python dependencies from the bundled vendor/ wheels.

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "=== dbcap Offline Installer ===" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check Python
Write-Host "[1/4] Checking Python..." -ForegroundColor Yellow
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Host "  ERROR: Python 3.10+ is not installed." -ForegroundColor Red
    Write-Host "  Download the Python offline installer from another machine:"
    Write-Host "    https://www.python.org/downloads/windows/"
    Write-Host "  During install, check 'Add Python to PATH'."
    exit 1
}
$pyVer = python --version 2>&1
Write-Host "  $pyVer" -ForegroundColor Green

# Step 2: Install bundled wheels
Write-Host "[2/4] Installing Python dependencies (offline)..." -ForegroundColor Yellow
$vendorDir = Join-Path $ScriptDir "vendor"
if (-not (Test-Path $vendorDir)) {
    Write-Host "  ERROR: vendor/ directory not found. Make sure you unzipped the full package." -ForegroundColor Red
    exit 1
}

$wheels = Get-ChildItem "$vendorDir\*.whl"
if ($wheels.Count -eq 0) {
    Write-Host "  ERROR: No wheel files in vendor/" -ForegroundColor Red
    exit 1
}

pip install --no-index --find-links="$vendorDir" -r (Join-Path $ScriptDir "requirements.txt")
Write-Host "  Dependencies installed." -ForegroundColor Green

# Step 3: Check tshark
Write-Host "[3/4] Checking tshark..." -ForegroundColor Yellow
$tsharkCmd = Get-Command tshark -ErrorAction SilentlyContinue
if (-not $tsharkCmd) {
    # Check common install paths
    $tsharkPaths = @(
        "D:\Wireshark\tshark.exe",
        "C:\Program Files\Wireshark\tshark.exe",
        "C:\Program Files (x86)\Wireshark\tshark.exe"
    )
    $found = $false
    foreach ($p in $tsharkPaths) {
        if (Test-Path $p) {
            Write-Host "  Found: $p" -ForegroundColor Green
            Write-Host "  Adding to PATH for this session..."
            $env:Path = "$(Split-Path $p);$env:Path"
            $found = $true
            break
        }
    }
    if (-not $found) {
        Write-Host "  WARNING: tshark not found!" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  You need Wireshark with TShark on this machine."
        Write-Host "  On an online machine, download from: https://www.wireshark.org/download.html"
        Write-Host "  Look for 'Windows Installer (64-bit)' — copy it here and install."
        Write-Host "  During install, make sure 'TShark' component is selected."
        Write-Host ""
        Write-Host "  After installing, add the Wireshark directory to PATH:"
        Write-Host '    setx PATH "%PATH%;C:\Program Files\Wireshark"'
        Write-Host "  Or re-run: .\install_offline.ps1"
    }
} else {
    Write-Host "  tshark found: $($tsharkCmd.Source)" -ForegroundColor Green
}

# Step 4: Test
Write-Host "[4/4] Testing dbcap..." -ForegroundColor Yellow
try {
    $result = python -m dbcap --version 2>&1
    Write-Host "  $result" -ForegroundColor Green
} catch {
    Write-Host "  WARNING: dbcap test failed: $_" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Usage:"
Write-Host "  python -m dbcap -f <pcap_file> -d dameng"
Write-Host "  python -m dbcap -f <pcap_file> -d mysql"
Write-Host "  python -m dbcap --help"
