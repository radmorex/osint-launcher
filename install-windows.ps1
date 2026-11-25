#Requires -Version 5.1
<#
  OSINT toolkit installer for Windows 10/11 (x64 / ARM64).
  Installs the tools behind the `osint` launcher and the launcher itself.

  Run from the repository folder (it must contain osint.py, repo_setup.py and requirements.txt):
      git clone https://github.com/radmorex/osint-launcher $HOME\tools\osint-launcher
      cd $HOME\tools\osint-launcher
      powershell -ExecutionPolicy Bypass -File .\install-windows.ps1

  Options (combine freely):
      -WithSherloq      image-forensics GUI (~1.5 GB of dependencies)
      -WithReverse      Ghidra (~500 MB) + MobSF Docker image
      -WithFrameworks   all-in-one OSINT frameworks (some need Docker)
      -WithDocker       Docker Desktop; needed by MobSF, Scrummage, Legion, osint-analyser, IntellyWeave.
                        The first install may ask for a reboot: reboot, start Docker Desktop once,
                        then re-run the script with the same options.
  Safe to re-run: finished steps are skipped.
#>
param([switch]$WithSherloq, [switch]$WithReverse, [switch]$WithFrameworks, [switch]$WithDocker)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'   # Invoke-WebRequest is 10x faster without the progress bar

$ToolsDir    = Join-Path $HOME 'tools'
$BinDir      = Join-Path $ToolsDir 'bin'
$LauncherDir = Join-Path $ToolsDir 'osint-launcher'
$Helper      = Join-Path $PSScriptRoot 'repo_setup.py'
$Arch        = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
$Failed      = New-Object System.Collections.Generic.List[string]

New-Item -ItemType Directory -Force $ToolsDir, $BinDir | Out-Null

function Say($msg)  { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Skip($msg) { Write-Host "    skip: $msg" -ForegroundColor DarkGray }
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
function Write-Shim([string]$Name, [string]$Line) {
    # .cmd on PATH: works in cmd and PowerShell, no execution-policy changes needed
    Set-Content (Join-Path $BinDir "$Name.cmd") -Encoding ascii -Value "@echo off`r`n$Line"
}
function Get-GhAsset([string]$Repo, [string]$Pattern, [string]$Dir) {
    # downloads the newest release asset matching $Pattern into $Dir, returns its full path
    $rel   = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ 'User-Agent' = 'osint-setup' }
    $asset = $rel.assets | Where-Object { $_.name -match $Pattern } | Select-Object -First 1
    if (-not $asset) { throw "no release asset matching '$Pattern' in $Repo $($rel.tag_name)" }
    $file = Join-Path $Dir $asset.name
    Invoke-WebRequest $asset.browser_download_url -OutFile $file -UseBasicParsing
    Write-Host "    $($asset.name)"
    return $file
}
function New-TempDir {
    $d = Join-Path $env:TEMP ("osint-" + [guid]::NewGuid())
    New-Item -ItemType Directory $d | Out-Null
    return $d
}
function Install-GhRelease([string]$Repo, [string]$Pattern, [string]$ExeName) {
    $tmp = New-TempDir
    try {
        $file = Get-GhAsset $Repo $Pattern $tmp
        Exec tar -xf $file -C $tmp
        $exe = Get-ChildItem $tmp -Recurse -Filter $ExeName | Select-Object -First 1
        if (-not $exe) { throw "$ExeName not found inside $(Split-Path $file -Leaf)" }
        Copy-Item $exe.FullName (Join-Path $BinDir $ExeName) -Force
    } finally { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}
function Install-GhArchive([string]$Repo, [string]$Pattern, [string]$Dest) {
    # whole archive unpacked into $Dest (replaced if it exists)
    $tmp = New-TempDir
    try {
        $file = Get-GhAsset $Repo $Pattern $tmp
        if (Test-Path $Dest) { Remove-Item $Dest -Recurse -Force }
        New-Item -ItemType Directory -Force $Dest | Out-Null
        Exec tar -xf $file -C $Dest
    } finally { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}
function Clone([string]$Repo, [string]$Dir) {
    if (-not (Test-Path $Dir)) { Exec git clone --depth 1 "https://github.com/$Repo" $Dir }
}
function Test-Ready([string]$Dir) { return (Test-Path "$Dir\.venv\.osint-ready") }
function New-Venv([string]$Dir) {
    if (-not (Test-Path "$Dir\.venv\Scripts\python.exe")) { Exec $Py312 -m venv "$Dir\.venv" | Out-Null }
    # setuptools stays below 81: old libraries still import pkg_resources, which 81 removed
    Exec "$Dir\.venv\Scripts\python.exe" -m pip install -q --upgrade pip wheel 'setuptools<81' | Out-Null
    return "$Dir\.venv\Scripts\python.exe"
}
function Repo-Req([string]$Repo, [string]$Dir, [string]$Req = 'requirements.txt') {
    # clone + own venv; requirements cleaned of stdlib names and denied packages, retried
    # without version pins if those don't build; forgotten imports installed afterwards
    Clone $Repo $Dir
    if (Test-Ready $Dir) { Skip "$(Split-Path $Dir -Leaf) ready"; return }
    $py = New-Venv $Dir
    if ($Req -ne '-' -and (Test-Path "$Dir\$Req")) {
        $cleaned = "$Dir\.venv\osint-requirements.txt"
        Exec $py -I $Helper clean-reqs "$Dir\$Req" $cleaned
        try { Exec $py -m pip install -q -r $cleaned }
        catch {
            Write-Host "    pinned versions failed, retrying without pins" -ForegroundColor Yellow
            Exec $py -I $Helper clean-reqs "$Dir\$Req" $cleaned --strip
            Exec $py -m pip install -q -r $cleaned
        }
    }
    Exec $py -I $Helper fill-imports $Dir
    New-Item -ItemType File -Force "$Dir\.venv\.osint-ready" | Out-Null   # the launcher shows the tool only after this
}
function Test-Docker {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { return $false }
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { & docker info *> $null } catch { }
    $ErrorActionPreference = $old
    return ($LASTEXITCODE -eq 0)
}
function Start-Docker {
    if (Test-Docker) { return $true }
    $exe = Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'
    if (-not (Test-Path $exe)) { return $false }
    Write-Host "    starting Docker Desktop (up to 2 minutes)..."
    Start-Process $exe | Out-Null
    for ($i = 0; $i -lt 40; $i++) { Start-Sleep 3; if (Test-Docker) { return $true } }
    return $false
}
function Docker-Build([string]$Repo, [string]$Dir, [string]$Tag) {
    Clone $Repo $Dir
    if (Test-Path "$Dir\.docker-built") { Skip "$(Split-Path $Dir -Leaf) image ready"; return }
    if (-not $DockerOk) { throw "Docker is not running (start Docker Desktop, then re-run with -WithDocker)" }
    Exec docker build -t $Tag $Dir
    New-Item -ItemType File -Force "$Dir\.docker-built" | Out-Null
}

# --- 0. Preconditions ----------------------------------------------------------
foreach ($f in 'osint.py', 'requirements.txt', 'repo_setup.py', 'collector\__main__.py') {
    if (-not (Test-Path (Join-Path $PSScriptRoot $f))) { throw "$f must be in the same folder as this script ($PSScriptRoot)" }
}
if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { throw "winget not found. Install 'App Installer' from Microsoft Store." }

# --- 1. Base runtimes ----------------------------------------------------------
Say "Base runtimes via winget (Python 3.12 + 3.14, Git, Go, Java 21, ExifTool)"
$winget = @('Python.Python.3.12', 'Python.Python.3.14', 'Git.Git', 'GoLang.Go', 'EclipseAdoptium.Temurin.21.JDK', 'OliverBetz.ExifTool')
if ($WithDocker) { $winget += 'Docker.DockerDesktop' }
foreach ($id in $winget) {
    Write-Host "    winget $id"
    winget install -e --id $id --silent --accept-package-agreements --accept-source-agreements | Out-Null
    # non-zero here usually means "already installed"; presence is verified below
}
Refresh-Path
# the ExifTool installer does not always put itself on PATH
if (-not (Get-Command exiftool -ErrorAction SilentlyContinue)) {
    $et = Get-ChildItem "$env:ProgramFiles\ExifTool", "$env:LOCALAPPDATA\Programs\ExifTool" -Filter exiftool.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($et) { Add-UserPath $et.DirectoryName; Refresh-Path }
}

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
if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
    Write-Host "    java is not on PATH in this window yet: jadx / apktool / Ghidra work in a NEW terminal" -ForegroundColor Yellow
}

Step "pipx" {
    Exec $Py312 -m pip install -q --user --upgrade pipx
    Exec $Py312 -m pipx ensurepath
}

# --- 2. Python tools (pipx, isolated venvs) -----------------------------------
$pipx312 = @(
    'maigret', 'user-scanner', 'socid-extractor', 'holehe', 'ghunt', 'sherlock-project', 'social-analyzer', 'crosslinked', 'instaloader', 'osintgraph',
    'git+https://github.com/megadose/ignorant',
    'git+https://github.com/thewhiteh4t/nexfil',
    # file analysis / reverse
    'pdfx', 'oletools', 'mutagen', 'iocextract', 'xortool', 'apkleaks',
    # frameworks
    'openosint'
)
foreach ($pkg in $pipx312) {
    Step "pipx: $pkg" { Exec $Py312 -m pipx install --force --python $Py312 $pkg }
}
# iocextract imports requests without declaring it
Step "pipx: iocextract needs requests" { Exec $Py312 -m pipx inject iocextract requests }
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
# amass ships x64 only; Windows on ARM runs it through x64 emulation
Step "amass"       { Install-GhRelease 'owasp-amass/amass'          'amass_windows_amd64'            'amass.exe' }
Step "phoneinfoga" { Install-GhRelease 'sundowndev/phoneinfoga'     "Windows_$piArch\.tar\.gz$"      'phoneinfoga.exe' }
Step "add $BinDir to user PATH" { Add-UserPath $BinDir }

# --- 5. Java tools: jadx, apktool ----------------------------------------------
Step "jadx" {
    $d = "$ToolsDir\jadx"
    if (Test-Path "$d\bin\jadx-gui.bat") { Skip "jadx ready" }
    else { Install-GhArchive 'skylot/jadx' '^jadx-[\d.]+\.zip$' $d }
    Write-Shim 'jadx-gui' "call `"%USERPROFILE%\tools\jadx\bin\jadx-gui.bat`" %*"
    Write-Shim 'jadx'     "call `"%USERPROFILE%\tools\jadx\bin\jadx.bat`" %*"
}
Step "apktool" {
    $d = "$ToolsDir\apktool"
    New-Item -ItemType Directory -Force $d | Out-Null
    if (Test-Path "$d\apktool.jar") { Skip "apktool ready" }
    else {
        $jar = Get-GhAsset 'iBotPeaches/Apktool' '^apktool_[\d.]+\.jar$' $d
        Move-Item $jar "$d\apktool.jar" -Force
    }
    Write-Shim 'apktool' "java -jar `"%USERPROFILE%\tools\apktool\apktool.jar`" %*"
}

# --- 6. Git-based tools with their own venv -----------------------------------
Step "Snoop"      { Repo-Req 'snooppr/snoop'        "$ToolsDir\snoop" }
Step "SpiderFoot" { Repo-Req 'smicallef/spiderfoot' "$ToolsDir\spiderfoot" }
foreach ($r in @('l4rm4nd/LinkedInDumper', 'l4rm4nd/XingDumper', 'eth0izzle/the-endorser')) {
    $d = Join-Path $ToolsDir ($r.Split('/')[1])
    Step "$r" { Repo-Req $r $d }
}
# Maryam: upstream lists a non-existent "umap" package plus ~3 GB of ML libraries used only by
# its four NLP ("iris") modules. Install the core; Maryam switches those four off by itself.
Step "Maryam (core, without the ML modules)" {
    $d = "$ToolsDir\maryam"
    Clone 'saeeddhqan/Maryam' $d
    if (Test-Ready $d) { Skip "maryam ready"; return }
    $py = New-Venv $d
    Exec $py -m pip install -q beautifulsoup4 certifi cloudscraper Flask lxml numpy packaging pandas requests typing-extensions vaderSentiment matplotlib
    Exec $py -m pip install -q --no-deps $d
    New-Item -ItemType File -Force "$d\.venv\.osint-ready" | Out-Null
}
if ($WithSherloq) {
    Step "Sherloq (large download)" {
        $d = "$ToolsDir\sherloq"
        Clone 'GuidoBartoli/sherloq' $d
        # upstream pins pandas 1.5, which has no Python 3.12 build
        (Get-Content "$d\gui\requirements.txt") -replace '^pandas==1\.5\.\*', 'pandas==2.1.*' |
            Set-Content "$d\.requirements-py312.txt" -Encoding ascii
        Repo-Req 'GuidoBartoli/sherloq' $d '.requirements-py312.txt'
    }
} else { Skip "Sherloq (run with -WithSherloq)" }

# --- 7. Docker -----------------------------------------------------------------
$DockerOk = $false
if ($WithDocker) {
    Say "Docker Desktop"
    Refresh-Path
    $DockerOk = Start-Docker
    if ($DockerOk) { Write-Host "    OK" -ForegroundColor Green }
    else {
        Write-Host "    Docker is installed but not running yet. Reboot if Windows asked for it, start Docker Desktop once," -ForegroundColor Yellow
        Write-Host "    then re-run this script with the same options to build the Docker tools." -ForegroundColor Yellow
        $Failed.Add("Docker Desktop (not running yet)")
    }
} elseif (Test-Docker) { $DockerOk = $true }

# --- 8. Reverse engineering ----------------------------------------------------
if ($WithReverse) {
    Step "Ghidra" {
        $d = "$ToolsDir\ghidra"
        $run = Get-ChildItem $d -Recurse -Filter ghidraRun.bat -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($run) { Skip "Ghidra ready" }
        else {
            Install-GhArchive 'NationalSecurityAgency/ghidra' '^ghidra_[\d.]+_PUBLIC_\d+\.zip$' $d
            $run = Get-ChildItem $d -Recurse -Filter ghidraRun.bat | Select-Object -First 1
            if (-not $run) { throw "ghidraRun.bat not found in the Ghidra archive" }
        }
        Write-Shim 'ghidraRun' "call `"$($run.FullName)`" %*"
    }
    Step "MobSF (Docker image)" {
        $d = "$ToolsDir\mobsf"
        New-Item -ItemType Directory -Force $d | Out-Null
        if (Test-Path "$d\.docker-built") { Skip "MobSF image ready"; return }
        if (-not $DockerOk) { throw "Docker is not running (re-run with -WithDocker)" }
        Exec docker pull opensecurity/mobile-security-framework-mobsf:latest
        New-Item -ItemType File -Force "$d\.docker-built" | Out-Null
    }
} else { Skip "Ghidra / MobSF (run with -WithReverse)" }

# --- 9. Frameworks -------------------------------------------------------------
if ($WithFrameworks) {
    # ReconSpider: its setup.py imports pip, writes a third party's API keys into the config
    # and pulls h8mail. Install only what its code imports; keys come from your environment.
    Step "ReconSpider" {
        $d = "$ToolsDir\reconspider"
        Clone 'bhavsec/reconspider' $d
        if (Test-Ready $d) { Skip "reconspider ready"; return }
        $py = New-Venv $d
        Exec $py -m pip install -q requests beautifulsoup4 lxml prompt_toolkit pillow shodan tweepy paramiko python-nmap gmplot IP2Proxy click wget
        Set-Content "$d\core\config.py" -Encoding ascii -Value "import os`r`nshodan_api = os.environ.get('SHODAN_API_KEY', '')"
        Set-Content "$d\plugins\api.py" -Encoding ascii -Value (
            "import os`r`n" +
            "def phoneapis():`r`n    return os.environ.get('NUMVERIFY_API_KEY', '')`r`n" +
            "def ipstack():`r`n    return os.environ.get('IPSTACK_API_KEY', '')`r`n" +
            "def gmap():`r`n    return os.environ.get('GOOGLE_MAPS_API_KEY', '')")
        Exec $py -I $Helper fill-imports $d
        New-Item -ItemType File -Force "$d\.venv\.osint-ready" | Out-Null
    }
    Step "TensSens" { Repo-Req 'thenurhabib/tenssens'   "$ToolsDir\tenssens" }
    Step "Ashok"    { Repo-Req 'powerexploit/Ashok'     "$ToolsDir\Ashok" }
    Step "OSINTEye" { Repo-Req 'ritchiemwewa/osinteye'  "$ToolsDir\osinteye" }
    Step "X-osint"  { Repo-Req 'TermuxHackz/X-osint'    "$ToolsDir\X-osint" }
    Step "Scrummage (Docker)" { Docker-Build 'matamorphosis/Scrummage' "$ToolsDir\Scrummage" 'osint/scrummage' }
    Step "Legion (Docker)"    { Docker-Build 'carlospolop/legion'      "$ToolsDir\legion"    'osint/legion' }
    Step "osint-analyser (Docker compose)" { Clone 'joestanding/osint-analyser' "$ToolsDir\osint-analyser" }
    Step "IntellyWeave (Docker compose)"   { Clone 'vericle/intellyweave'       "$ToolsDir\intellyweave" }
    # Not installed on purpose: DaProfiler and Phone OSINT Framework pull leaked passwords /
    # breach-database records about a person, the same category as h8mail and dehashed.
} else { Skip "Frameworks (run with -WithFrameworks)" }

# --- 10. Launcher -------------------------------------------------------------
Step "osint launcher" {
    New-Item -ItemType Directory -Force $LauncherDir | Out-Null
    if ((Resolve-Path $PSScriptRoot).Path.TrimEnd('\') -ne $LauncherDir.TrimEnd('\')) {
        foreach ($f in 'osint.py', 'requirements.txt', 'repo_setup.py') {
            Copy-Item (Join-Path $PSScriptRoot $f) (Join-Path $LauncherDir $f) -Force
        }
        $col = Join-Path $LauncherDir 'collector'
        if (Test-Path $col) { Remove-Item $col -Recurse -Force }
        Copy-Item (Join-Path $PSScriptRoot 'collector') $col -Recurse -Force
    }
    if (-not (Test-Path "$LauncherDir\.venv")) { Exec $Py312 -m venv "$LauncherDir\.venv" }
    Exec "$LauncherDir\.venv\Scripts\python.exe" -m pip install -q -r "$LauncherDir\requirements.txt"
    Write-Shim 'osint' "`"%USERPROFILE%\tools\osint-launcher\.venv\Scripts\python.exe`" `"%USERPROFILE%\tools\osint-launcher\osint.py`" %*"
}

# --- 11. Summary --------------------------------------------------------------
Refresh-Path
Say "Status"
& "$LauncherDir\.venv\Scripts\python.exe" "$LauncherDir\osint.py" --check

if ($Failed.Count) {
    Write-Host "`nFailed steps:" -ForegroundColor Yellow
    $Failed | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    Write-Host "Logs are above. Re-running the script is safe: finished steps are skipped."
} else {
    Write-Host "`nAll steps OK." -ForegroundColor Green
}
Write-Host "`nOpen a NEW terminal (Windows Terminal recommended) and run:  osint" -ForegroundColor Cyan
Write-Host "BBOT is Linux/macOS-only: use it via WSL (wsl --install -d kali-linux) if you need it."
