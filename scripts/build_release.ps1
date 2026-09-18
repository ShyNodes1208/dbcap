# build_release.ps1 — whitelist clean build for DBCAP V1 offline package
param(
    [string]$WiresharkDir = "C:\Program Files\Wireshark",
    [switch]$SkipTShark
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $Root "dbcap\__init__.py"))) {
    if (Test-Path ".\dbcap\__init__.py") { $Root = (Resolve-Path ".").Path }
}
$Version = (Get-Content (Join-Path $Root "VERSION") -Raw).Trim()
$DistRoot = Join-Path $Root "dist"
$PkgName = "dbcap-v$Version"
$PkgDir = Join-Path $DistRoot $PkgName
$ZipPath = Join-Path $DistRoot "$PkgName-windows-x64.zip"
$ZipSha = Join-Path $DistRoot "$PkgName-windows-x64.zip.sha256"

Write-Host "=== DBCAP Clean Release Builder ===" -ForegroundColor Cyan
Write-Host "Root=$Root Version=$Version"

# Wipe previous package completely
if (Test-Path $PkgDir) { Remove-Item $PkgDir -Recurse -Force }
if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }
if (Test-Path $ZipSha) { Remove-Item $ZipSha -Force }
New-Item -ItemType Directory -Path $PkgDir -Force | Out-Null

function Ensure-Dir($p) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
function Copy-Ascii($src, $dst) {
    $text = [System.IO.File]::ReadAllText($src)
    $enc = New-Object System.Text.ASCIIEncoding
    [System.IO.File]::WriteAllText($dst, $text, $enc)
}

foreach ($d in @("app\dbcap","runtime\python","tools\tshark","config","input","output","samples","docs")) {
    Ensure-Dir (Join-Path $PkgDir $d)
}

# --- Whitelist: app sources only (.py), no caches ---
Write-Host "[1/9] Copy app (whitelist .py)..." -ForegroundColor Yellow
$AppSrc = Join-Path $Root "dbcap"
Get-ChildItem $AppSrc -Recurse -File -Filter "*.py" | ForEach-Object {
    $rel = $_.FullName.Substring($AppSrc.Length).TrimStart('\','/')
    $dst = Join-Path $PkgDir "app\dbcap\$rel"
    Ensure-Dir (Split-Path $dst -Parent)
    Copy-Item $_.FullName $dst -Force
}
# protocols package marker already included via *.py

# --- Embeddable Python ---
Write-Host "[2/9] Embeddable Python + runtime wheels..." -ForegroundColor Yellow
$EmbedZip = Join-Path $Root "python-3.12.9-embed-amd64.zip"
if (-not (Test-Path $EmbedZip)) { throw "Missing $EmbedZip" }
$PyDir = Join-Path $PkgDir "runtime\python"
Expand-Archive -Path $EmbedZip -DestinationPath $PyDir -Force
$Pth = Get-ChildItem $PyDir -Filter "python*._pth" | Select-Object -First 1
$PyZip = Get-ChildItem $PyDir -Filter "python*.zip" | Select-Object -First 1
# NO "import site" — prevents user site / usercustomize (R04)
$PthContent = @"
$($PyZip.Name)
.
Lib\site-packages
..\..\app
"@
$encA = New-Object System.Text.ASCIIEncoding
[System.IO.File]::WriteAllText($Pth.FullName, $PthContent, $encA)

$Site = Join-Path $PyDir "Lib\site-packages"
Ensure-Dir $Site
Add-Type -AssemblyName System.IO.Compression.FileSystem
# Runtime wheels whitelist only
$runtimeWheels = @(
    "rich-15.0.0-py3-none-any.whl",
    "markdown_it_py-4.2.0-py3-none-any.whl",
    "mdurl-0.1.2-py3-none-any.whl",
    "pygments-2.20.0-py3-none-any.whl"
)
foreach ($w in $runtimeWheels) {
    $wp = Join-Path $Root "vendor\$w"
    if (-not (Test-Path $wp)) { throw "Missing runtime wheel: $wp" }
    Write-Host "  Extract $w"
    [System.IO.Compression.ZipFile]::ExtractToDirectory($wp, $Site)
}
# Remove any .pyc created during extract (should be none) and __pycache__
Get-ChildItem $PkgDir -Recurse -Include "__pycache__","*.pyc" -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

# --- Config / version / baseline ---
Write-Host "[3/9] Config, VERSION, TCP baseline..." -ForegroundColor Yellow
Copy-Item (Join-Path $Root "config\thresholds.json") (Join-Path $PkgDir "config\thresholds.json") -Force
Copy-Item (Join-Path $Root "VERSION") (Join-Path $PkgDir "VERSION") -Force
$BaselineSrc = Join-Path $Root "TCP_CORE_BASELINE_SHA256.txt"
if (-not (Test-Path $BaselineSrc)) { throw "Missing $BaselineSrc — generate baseline before build" }
Copy-Item $BaselineSrc (Join-Path $PkgDir "TCP_CORE_BASELINE_SHA256.txt") -Force

# Verify package TCP core hashes match baseline
function Get-Sha256Hex([string]$FilePath) {
    $hash = Get-FileHash -Algorithm SHA256 -Path $FilePath
    return $hash.Hash.ToLowerInvariant()
}
$baselineMap = @{}
Get-Content $BaselineSrc | ForEach-Object {
    $line = $_.Trim()
    if (-not $line -or $line.StartsWith("#")) { return }
    $parts = $line -split "\s+", 2
    if ($parts.Count -eq 2) { $baselineMap[$parts[1].Replace("/","\")] = $parts[0].ToLowerInvariant() }
}
foreach ($rel in $baselineMap.Keys) {
    $f = Join-Path $PkgDir "app\$rel"
    if (-not (Test-Path $f)) { throw "Baseline file missing in package: $rel" }
    $h = Get-Sha256Hex $f
    if ($h -ne $baselineMap[$rel]) {
        throw "TCP Core hash mismatch for $rel`n expected $($baselineMap[$rel])`n got      $h"
    }
}
Write-Host "  TCP Core baseline: PASS"

# --- TShark Mode A/B ---
Write-Host "[4/9] TShark runtime..." -ForegroundColor Yellow
$TsharkDst = Join-Path $PkgDir "tools\tshark"
$TsharkMode = "B"
if (-not $SkipTShark -and (Test-Path (Join-Path $WiresharkDir "tshark.exe"))) {
    $TsharkMode = "A"
    Copy-Item (Join-Path $WiresharkDir "tshark.exe") $TsharkDst -Force
    if (Test-Path (Join-Path $WiresharkDir "capinfos.exe")) {
        Copy-Item (Join-Path $WiresharkDir "capinfos.exe") $TsharkDst -Force
    }
    if (Test-Path (Join-Path $WiresharkDir "COPYING.txt")) {
        Copy-Item (Join-Path $WiresharkDir "COPYING.txt") (Join-Path $TsharkDst "COPYING.txt") -Force
    }
    Get-ChildItem $WiresharkDir -Filter "*.dll" | ForEach-Object { Copy-Item $_.FullName $TsharkDst -Force }
    foreach ($name in @("cfilters","dfilters","colorfilters","manuf","services","smi.conf","pdml2html.xsl")) {
        $src = Join-Path $WiresharkDir $name
        if (Test-Path $src) { Copy-Item $src $TsharkDst -Force }
    }
    foreach ($subdir in @("plugins","diameter","dtds","radius","snmp","tls","profiles","wimaxasncp","tpncp","protobuf")) {
        $src = Join-Path $WiresharkDir $subdir
        if (Test-Path $src) {
            robocopy $src (Join-Path $TsharkDst $subdir) /E /NFL /NDL /NJH /NJS /nc /ns /np | Out-Null
            if ($LASTEXITCODE -ge 8) { throw "robocopy failed $subdir" }
        }
    }
    @"
Bundled TShark for offline PCAP reading only (no dumpcap/Npc).
Source: $WiresharkDir
See LICENSES.txt and COPYING.txt (GPL). LEGAL/LICENSING REVIEW REQUIRED.
"@ | Set-Content (Join-Path $TsharkDst "README.txt") -Encoding ASCII
} else {
    @"
TShark NOT bundled (Mode B).
No Wireshark binary is distributed in this package.

DBCAP looks for tshark.exe in this order:
  1. <DBCAP_HOME>\tools\tshark\tshark.exe   (drop a copy here to make it self-contained)
  2. the DBCAP_TSHARK environment variable
  3. PATH
  4. C:\Program Files\Wireshark\tshark.exe and similar standard install paths

Obtain TShark from the Wireshark project: https://www.wireshark.org/download.html
The installer offers a TShark-only component; the GUI and Npcap are not required.
Wireshark is licensed GPL-2.0-or-later; its license and notices are in that install.

See ..\..\README.txt section 4 and ..\..\LICENSES.txt.
"@ | Set-Content (Join-Path $TsharkDst "README.txt") -Encoding ASCII
}

# --- Launchers / docs (whitelist) ---
Write-Host "[5/9] Launchers and docs..." -ForegroundColor Yellow
Copy-Ascii (Join-Path $Root "release_assets\run.bat") (Join-Path $PkgDir "run.bat")
Copy-Ascii (Join-Path $Root "release_assets\doctor.bat") (Join-Path $PkgDir "doctor.bat")
Copy-Item (Join-Path $Root "release_assets\README.txt") (Join-Path $PkgDir "README.txt") -Force
Copy-Item (Join-Path $Root "release_assets\LICENSES.txt") (Join-Path $PkgDir "LICENSES.txt") -Force
# License texts referenced by LICENSES.txt:
#   Apache-2.0.txt  -> DBCAP itself AND OpenSSL (Apache-2.0 requires recipients get a copy)
#   libffi-MIT.txt  -> libffi (MIT requires the notice be retained)
$LicSrc = Join-Path $Root "release_assets\licenses"
if (-not (Test-Path $LicSrc)) { throw "Missing $LicSrc" }
$LicDst = Join-Path $PkgDir "licenses"
Ensure-Dir $LicDst
Copy-Item (Join-Path $LicSrc "*.txt") $LicDst -Force
if (-not (Test-Path (Join-Path $Root "NOTICE"))) { throw "Missing NOTICE at repo root" }
Copy-Item (Join-Path $Root "NOTICE") (Join-Path $PkgDir "NOTICE") -Force
Copy-Item (Join-Path $Root "release_assets\samples_README.txt") (Join-Path $PkgDir "samples\README.txt") -Force
Ensure-Dir (Join-Path $PkgDir "examples\case-template")
if (Test-Path (Join-Path $Root "examples\case-template\README.txt")) {
    Copy-Item (Join-Path $Root "examples\case-template\README.txt") (Join-Path $PkgDir "examples\case-template\README.txt") -Force
}
@"
DBCAP
$Version

Platform:
Windows x64
"@ | Set-Content (Join-Path $PkgDir "VERSION.txt") -Encoding ASCII
foreach ($doc in @("USER_GUIDE.md","OFFLINE_DEPLOYMENT.md","TROUBLESHOOTING.md")) {
    Copy-Item (Join-Path $Root "docs\$doc") (Join-Path $PkgDir "docs\$doc") -Force
}
# Do NOT ship failed review reports or historical acceptance with old version claims unless updated
Copy-Item (Join-Path $Root "docs\DBCAP_V1_ACCEPTANCE.md") (Join-Path $PkgDir "docs\DBCAP_V1_ACCEPTANCE.md") -Force -ErrorAction SilentlyContinue
if (-not (Test-Path (Join-Path $PkgDir "docs\DBCAP_V1_ACCEPTANCE.md"))) {
    Copy-Item (Join-Path $Root "DBCAP_V1_ACCEPTANCE.md") (Join-Path $PkgDir "docs\DBCAP_V1_ACCEPTANCE.md") -Force
}

# Empty placeholders only — never copy historical output/payload
"Place PCAP files here for analysis." | Set-Content (Join-Path $PkgDir "input\README.txt") -Encoding ASCII
"Analysis reports are written here." | Set-Content (Join-Path $PkgDir "output\README.txt") -Encoding ASCII

# --- Strip caches again after any import ---
Write-Host "[6/9] Strip caches / contamination..." -ForegroundColor Yellow
Get-ChildItem $PkgDir -Recurse -Include "__pycache__","*.pyc",".pytest_cache" -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
# Forbid shipping report artifacts
$banned = @("*.pcap","*.pcapng","evidence.csv","flows.csv","anomalies.json","report.md")
foreach ($pat in $banned) {
    Get-ChildItem (Join-Path $PkgDir "output") -Recurse -Filter $pat -ErrorAction SilentlyContinue |
        Remove-Item -Force -ErrorAction SilentlyContinue
}
if (Test-Path (Join-Path $PkgDir "output\payload")) {
    Remove-Item (Join-Path $PkgDir "output\payload") -Recurse -Force
}

# --- Internal SHA256SUMS (package files, not the zip) ---
Write-Host "[7/9] SHA256SUMS.txt ..." -ForegroundColor Yellow
$sums = New-Object System.Collections.Generic.List[string]
Get-ChildItem $PkgDir -Recurse -File | ForEach-Object {
    $rel = $_.FullName.Substring($PkgDir.Length).TrimStart('\','/').Replace('\','/')
    if ($rel -eq "SHA256SUMS.txt") { return }
    $h = Get-Sha256Hex $_.FullName
    $sums.Add("$h  $rel")
}
$sums | Sort-Object | Set-Content (Join-Path $PkgDir "SHA256SUMS.txt") -Encoding ASCII

# --- Smoke without contaminating package with pyc in app ---
Write-Host "[8/9] Smoke test (isolated)..." -ForegroundColor Yellow
$env:DBCAP_HOME = $PkgDir
$env:PYTHONNOUSERSITE = "1"
$env:PYTHONDONTWRITEBYTECODE = "1"
Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
$PyExe = Join-Path $PyDir "python.exe"
& $PyExe -I -c "import sys,site; import dbcap,rich; print(dbcap.__version__); print('USER_SITE', site.ENABLE_USER_SITE); print('ok')"
if ($LASTEXITCODE -ne 0) { throw "Smoke failed" }
# Remove any pyc created by smoke (app + runtime)
Get-ChildItem $PkgDir -Recurse -Directory -Filter "__pycache__" -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem $PkgDir -Recurse -Include "*.pyc","*.pyo" -File -ErrorAction SilentlyContinue |
    Remove-Item -Force -ErrorAction SilentlyContinue

# Contamination gate
$contam = @()
Get-ChildItem $PkgDir -Recurse -File | ForEach-Object {
    $n = $_.Name.ToLowerInvariant()
    $rel = $_.FullName.Substring($PkgDir.Length)
    if ($n.EndsWith(".pyc") -or $n.EndsWith(".pyo")) { $contam += $rel }
    if ($n -eq "report.md" -and $rel -match "output") { $contam += $rel }
    if ($n -eq "evidence.csv") { $contam += $rel }
    if ($n.EndsWith(".pcap") -or $n.EndsWith(".pcapng")) { $contam += $rel }
    if ($rel -match "payload\\") { $contam += $rel }
    if ($rel -match "review_work") { $contam += $rel }
}
if ($contam.Count -gt 0) {
    throw ("Contamination files found:`n" + ($contam -join "`n"))
}

# Regenerate SHA256SUMS after smoke cleanup so checksums match shipped tree
Write-Host "[7b/9] Refresh SHA256SUMS.txt ..." -ForegroundColor Yellow
$sums = New-Object System.Collections.Generic.List[string]
Get-ChildItem $PkgDir -Recurse -File | ForEach-Object {
    $rel = $_.FullName.Substring($PkgDir.Length).TrimStart('\','/').Replace('\','/')
    if ($rel -eq "SHA256SUMS.txt") { return }
    $h = Get-Sha256Hex $_.FullName
    $sums.Add("$h  $rel")
}
$sums | Sort-Object | Set-Content (Join-Path $PkgDir "SHA256SUMS.txt") -Encoding ASCII

# --- Zip + external sha256 ---
Write-Host "[9/9] Zip + external SHA256..." -ForegroundColor Yellow
Compress-Archive -Path $PkgDir -DestinationPath $ZipPath -Force
$zh = Get-Sha256Hex $ZipPath
"$zh  $PkgName-windows-x64.zip" | Set-Content $ZipSha -Encoding ASCII

Write-Host ""
Write-Host "=== DONE ===" -ForegroundColor Green
Write-Host "Package : $PkgDir"
Write-Host "Zip     : $ZipPath"
Write-Host "SHA256  : $zh"
Write-Host "TShark  : Mode $TsharkMode"
if ($TsharkMode -eq "A") {
    Write-Host "NOTE    : LEGAL/LICENSING REVIEW REQUIRED for Mode A GPL redistribution." -ForegroundColor Yellow
} else {
    Write-Host "NOTE    : Mode B - no Wireshark binaries redistributed, no GPL source obligation." -ForegroundColor Green
}
