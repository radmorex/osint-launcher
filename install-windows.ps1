#Requires -Version 5.1
<#
  OSINT toolkit installer for Windows 10/11 (x64 / ARM64).
  Installs the tools behind the `osint` launcher and the launcher itself.

  Run from the repository folder (it must contain osint.py and requirements.txt):
      git clone https://github.com/radmorex/osint-launcher $HOME\tools\osint-launcher
      cd $HOME\tools\osint-launcher
      powershell -ExecutionPolicy Bypass -File .\install-windows.ps1
  Optional:  -WithSherloq   (image forensics GUI, ~1.5 GB of dependencies)
#>
param([switch]$WithSherloq)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'   # Invoke-WebRequest is 10x faster without the progress bar

$ToolsDir    = Join-Path $HOME 'tools'
$BinDir      = Join-Path $ToolsDir 'bin'
$LauncherDir = Join-Path $ToolsDir 'osint-launcher'
$Arch        = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
$Failed      = New-Object System.Collections.Generic.List[string]

New-Item -ItemType Directory -Force $ToolsDir, $BinDir | Out-Null

function Say($msg)  { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Refresh-Path {
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
                [Environment]::GetEnvironmentVariable('Path', 'User')
    foreach ($p in @("$HOME\.local\bin", "$HOME\go\bin", $BinDir)) {
        if ($env:Path -notlike "*$p*") { $env:Path += ";$p" }
    }
}
function Exec([string]$File) {
    & $File @args
    if ($LASTEXITCODE -ne 0) { throw "$File $($args -join ' ') -> exit code $LASTEXITCODE" }
}
function Step([string]$Name, [scriptblock]$Body) {
    Say $Name
    try { & $Body; Write-Host "    OK" -ForegroundColor Green }
    catch { Write-Host "    FAIL: $($_.Exception.Message)" -ForegroundColor Red; $Failed.Add($Name) }
}
function Add-UserPath([string]$Dir) {
    $user = [string][Environment]::GetEnvironmentVariable('Path', 'User')
    if (($user -split ';') -notcontains $Dir) {
        [Environment]::SetEnvironmentVariable('Path', ($user.TrimEnd(';') + ";$Dir"), 'User')
    }
}
function Install-GhRelease([string]$Repo, [string]$Pattern, [string]$ExeName) {
    $rel   = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ 'User-Agent' = 'osint-setup' }
    $asset = $rel.assets | Where-Object { $_.name -match $Pattern } | Select-Object -First 1
    if (-not $asset) { throw "no release asset matching '$Pattern' in $Repo $($rel.tag_name)" }
    $tmp = Join-Path $env:TEMP ("osint-" + [guid]::NewGuid())
    New-Item -ItemType Directory $tmp | Out-Null
    try {
        $file = Join-Path $tmp $asset.name
        Invoke-WebRequest $asset.browser_download_url -OutFile $file -UseBasicParsing
        Exec tar -xf $file -C $tmp
        $exe = Get-ChildItem $tmp -Recurse -Filter $ExeName | Select-Object -First 1
        if (-not $exe) { throw "$ExeName not found inside $($asset.name)" }
        Copy-Item $exe.FullName (Join-Path $BinDir $ExeName) -Force
        Write-Host "    $ExeName $($rel.tag_name)"
    } finally { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}
function New-RepoVenv([string]$Dir, [string]$Requirements) {
    if (-not (Test-Path "$Dir\.venv")) { Exec $Py312 -m venv "$Dir\.venv" }
    Exec "$Dir\.venv\Scripts\python.exe" -m pip install -q --upgrade pip setuptools wheel
    Exec "$Dir\.venv\Scripts\python.exe" -m pip install -q -r $Requirements
}
function Clone([string]$Repo, [string]$Dir) {
    if (-not (Test-Path $Dir)) { Exec git clone --depth 1 "https://github.com/$Repo" $Dir }
}

# --- 0. Preconditions ----------------------------------------------------------
foreach ($f in 'osint.py', 'requirements.txt') {
    if (-not (Test-Path (Join-Path $PSScriptRoot $f))) { throw "$f must be in the same folder as this script ($PSScriptRoot)" }
}
if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { throw "winget not found. Install 'App Installer' from Microsoft Store." }

# --- 1. Base runtimes ----------------------------------------------------------
Say "Base runtimes via winget (Python 3.12 + 3.14, Git, Go, ExifTool)"
foreach ($id in 'Python.Python.3.12', 'Python.Python.3.14', 'Git.Git', 'GoLang.Go', 'OliverBetz.ExifTool') {
    Write-Host "    winget $id"
    winget install -e --id $id --silent --accept-package-agreements --accept-source-agreements | Out-Null
    # non-zero here usually means "already installed"; presence is verified below
}
Refresh-Path

function Find-Python([string]$Ver) {
    try { $exe = & py "-$Ver" -c "import sys; print(sys.executable)" 2>$null } catch { $exe = $null }
    if (-not $exe -or $LASTEXITCODE -ne 0) { throw "Python $Ver not found after winget install. Open a new terminal and re-run." }
    return $exe.Trim()
}
$Py312 = Find-Python '3.12'
$Py314 = Find-Python '3.14'
foreach ($cmd in 'git', 'go') {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { throw "$cmd not found after winget install. Open a new terminal and re-run." }
}

Step "pipx" {
    Exec $Py312 -m pip install -q --user --upgrade pipx
    Exec $Py312 -m pipx ensurepath
}

# --- 2. Python tools (pipx, isolated venvs) -----------------------------------
$pipx312 = @(
    'maigret', 'holehe', 'ghunt', 'sherlock-project', 'social-analyzer', 'crosslinked', 'instaloader',
    'git+https://github.com/megadose/ignorant',
    'git+https://github.com/thewhiteh4t/nexfil'
)
foreach ($pkg in $pipx312) {
    Step "pipx: $pkg" { Exec $Py312 -m pipx install --force --python $Py312 $pkg }
}
Step "pipx: theHarvester (Python 3.14)" {
    Exec $Py312 -m pipx install --force --python $Py314 'git+https://github.com/laramies/theHarvester'
}

# --- 3. Go tools ---------------------------------------------------------------
Step "go: mosint"      { Exec go install github.com/alpkeskin/mosint/v3/cmd/mosint@latest }
Step "go: waybackurls" { Exec go install github.com/tomnomnom/waybackurls@latest }
Step "mosint config (~/.mosint.yaml, no API keys)" {
    $cfg = Join-Path $HOME '.mosint.yaml'
    if (-not (Test-Path $cfg)) {
        Invoke-WebRequest 'https://raw.githubusercontent.com/alpkeskin/mosint/master/example-config.yaml' -OutFile $cfg -UseBasicParsing
    }
}

# --- 4. Prebuilt binaries from GitHub releases --------------------------------
$piArch = if ($Arch -eq 'arm64') { 'arm64' } else { 'x86_64' }
Step "subfinder"   { Install-GhRelease 'projectdiscovery/subfinder' "windows_$Arch\.zip$"          'subfinder.exe' }
Step "amass"       { Install-GhRelease 'owasp-amass/amass'          'amass_windows_amd64'            'amass.exe' }
Step "phoneinfoga" { Install-GhRelease 'sundowndev/phoneinfoga'     "Windows_$piArch\.tar\.gz$"      'phoneinfoga.exe' }
Step "add $BinDir to user PATH" { Add-UserPath $BinDir }

# --- 5. Git-based tools with their own venv -----------------------------------
Step "Snoop" {
    Clone 'snooppr/snoop' "$ToolsDir\snoop"
    New-RepoVenv "$ToolsDir\snoop" "$ToolsDir\snoop\requirements.txt"
}
Step "SpiderFoot" {
    Clone 'smicallef/spiderfoot' "$ToolsDir\spiderfoot"
    New-RepoVenv "$ToolsDir\spiderfoot" "$ToolsDir\spiderfoot\requirements.txt"
}
if ($WithSherloq) {
    Step "Sherloq (large download)" {
        Clone 'GuidoBartoli/sherloq' "$ToolsDir\sherloq"
        $req = "$ToolsDir\sherloq\.requirements-py312.txt"
        # upstream pins pandas 1.5, which has no Python 3.12 build
        (Get-Content "$ToolsDir\sherloq\gui\requirements.txt") -replace '^pandas==1\.5\.\*', 'pandas==2.1.*' |
            Set-Content $req -Encoding ascii
        New-RepoVenv "$ToolsDir\sherloq" $req
    }
}

# --- 6. Launcher --------------------------------------------------------------
Step "osint launcher" {
    New-Item -ItemType Directory -Force $LauncherDir | Out-Null
    if ((Resolve-Path $PSScriptRoot).Path.TrimEnd('\') -ne $LauncherDir.TrimEnd('\')) {
        foreach ($f in 'osint.py', 'requirements.txt') {
            Copy-Item (Join-Path $PSScriptRoot $f) (Join-Path $LauncherDir $f) -Force
        }
    }
    if (-not (Test-Path "$LauncherDir\.venv")) { Exec $Py312 -m venv "$LauncherDir\.venv" }
    Exec "$LauncherDir\.venv\Scripts\python.exe" -m pip install -q -r "$LauncherDir\requirements.txt"
    # .cmd shim on PATH: works in cmd and PowerShell, no profile / execution-policy changes needed
    Set-Content (Join-Path $BinDir 'osint.cmd') -Encoding ascii -Value `
        "@echo off`r`n`"%USERPROFILE%\tools\osint-launcher\.venv\Scripts\python.exe`" `"%USERPROFILE%\tools\osint-launcher\osint.py`" %*"
}

# --- 7. Summary ---------------------------------------------------------------
Refresh-Path
Say "Status"
& "$LauncherDir\.venv\Scripts\python.exe" "$LauncherDir\osint.py" --check

if ($Failed.Count) {
    Write-Host "`nFailed steps:" -ForegroundColor Yellow
    $Failed | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    Write-Host "Logs are above. Re-running the script is safe: finished steps are skipped or reinstalled."
} else {
    Write-Host "`nAll steps OK." -ForegroundColor Green
}
Write-Host "`nOpen a NEW terminal (Windows Terminal recommended) and run:  osint" -ForegroundColor Cyan
Write-Host "BBOT is Linux/macOS-only: use it via WSL (wsl --install -d kali-linux) if you need it."
