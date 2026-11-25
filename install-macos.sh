#!/usr/bin/env bash
# OSINT toolkit installer for macOS (Apple Silicon / Intel).
# Installs the tools behind the `osint` launcher and the launcher itself.
#
#   git clone https://github.com/radmorex/osint-launcher ~/tools/osint-launcher
#   cd ~/tools/osint-launcher && ./install-macos.sh
#
# Options (all optional, combine freely):
#   --with-sherloq      image-forensics GUI (~1.5 GB)
#   --with-reverse      Ghidra (~600 MB with Java) + MobSF Docker image
#   --with-frameworks   all-in-one OSINT frameworks (some need Docker)
#   --with-docker       Docker runtime via Colima (no Docker Desktop, no licence prompt);
#                       needed by MobSF, Scrummage, Legion, osint-analyser, IntellyWeave
#
# Safe to re-run: anything already installed is skipped.
set -uo pipefail

WITH_SHERLOQ=0; WITH_REVERSE=0; WITH_FRAMEWORKS=0; WITH_DOCKER=0
for arg in "$@"; do
  case "$arg" in
    --with-sherloq) WITH_SHERLOQ=1 ;;
    --with-reverse) WITH_REVERSE=1 ;;
    --with-frameworks) WITH_FRAMEWORKS=1 ;;
    --with-docker) WITH_DOCKER=1 ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg"; exit 2 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOLS_DIR="${OSINT_TOOLS_DIR:-$HOME/tools}"
LAUNCHER_DIR="$TOOLS_DIR/osint-launcher"
FAILED=()

c_cyan=$'\033[36m'; c_green=$'\033[32m'; c_red=$'\033[31m'; c_yellow=$'\033[33m'; c_dim=$'\033[2m'; c_off=$'\033[0m'
say()  { printf '\n%s==> %s%s\n' "$c_cyan" "$1" "$c_off"; }
skip() { printf '    %sskip: %s%s\n' "$c_dim" "$1" "$c_off"; }
step() {  # step "<name>" <command...>
  local name="$1"; shift
  say "$name"
  if "$@"; then printf '    %sOK%s\n' "$c_green" "$c_off"
  else printf '    %sFAIL%s\n' "$c_red" "$c_off"; FAILED+=("$name"); fi
}

# ─── 0. Preconditions ─────────────────────────────────────────────────────────
[[ "$(uname -s)" == "Darwin" ]] || { echo "This installer is for macOS. On Windows use install-windows.ps1."; exit 1; }
for f in osint.py requirements.txt collector/__main__.py; do
  [[ -f "$SCRIPT_DIR/$f" ]] || { echo "$f must be next to this script ($SCRIPT_DIR)"; exit 1; }
done
if ! command -v brew >/dev/null 2>&1; then
  for b in /opt/homebrew/bin/brew /usr/local/bin/brew "$HOME/.homebrew/bin/brew"; do
    [[ -x "$b" ]] && eval "$("$b" shellenv)" && break
  done
fi
command -v brew >/dev/null 2>&1 || {
  echo "Homebrew is required: https://brew.sh"
  echo '  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
  exit 1
}
BREW_PREFIX="$(brew --prefix)"
export PATH="$BREW_PREFIX/bin:$HOME/.local/bin:$HOME/go/bin:$PATH"
mkdir -p "$TOOLS_DIR"

# ─── 1. Homebrew packages ─────────────────────────────────────────────────────
brew_pkgs() {
  local missing=()
  for p in python@3.12 python@3.14 pipx git go amass subfinder phoneinfoga exiftool jadx apktool c2patool poppler python-tk@3.12; do
    brew list --formula "$p" >/dev/null 2>&1 || missing+=("$p")
  done
  if ((${#missing[@]} == 0)); then skip "all brew packages present"; return 0; fi
  brew install "${missing[@]}"
}
step "Homebrew: python, pipx, git, go, amass, subfinder, phoneinfoga, exiftool, jadx, apktool, c2patool, poppler, tkinter" brew_pkgs

PY312="$BREW_PREFIX/bin/python3.12"
PY314="$BREW_PREFIX/bin/python3.14"
pipx ensurepath >/dev/null 2>&1 || true

# ─── 2. Python tools via pipx ─────────────────────────────────────────────────
# command | pipx spec | python
PIPX_TOOLS=(
  "maigret|maigret|$PY312"
  "user-scanner|user-scanner|$PY312"
  "socid_extractor|socid-extractor|$PY312"   # profile pages → names, dates, links, e-mail hashes
  "holehe|holehe|$PY312"
  "ghunt|ghunt|$PY312"
  "ignorant|git+https://github.com/megadose/ignorant|$PY312"
  "sherlock|sherlock-project|$PY312"
  "social-analyzer|social-analyzer|$PY312"
  "nexfil|git+https://github.com/thewhiteh4t/nexfil|$PY312"
  "crosslinked|crosslinked|$PY312"
  "instaloader|instaloader|$PY312"
  "theHarvester|git+https://github.com/laramies/theHarvester|$PY314"   # needs Python >= 3.14
  "bbot|bbot<3|$PY312"   # 3.x needs a Rust extension that fails to build on macOS
  "osintgraph|osintgraph|$PY312"   # pinned deps don't build on Python 3.15
  # file analysis / reverse
  "pdfx|pdfx|$PY312"
  "olevba|oletools|$PY312"
  "mutagen-inspect|mutagen|$PY312"
  "iocextract|iocextract|$PY312"
  "xortool|xortool|$PY312"
  "apkleaks|apkleaks|$PY312"
  # frameworks that install cleanly with pipx
  "openosint|openosint|$PY312"
)
pipx_tool() {
  local cmd="$1" spec="$2" py="$3"
  if command -v "$cmd" >/dev/null 2>&1; then skip "$cmd already installed"; return 0; fi
  pipx install --python "$py" "$spec"
}
for entry in "${PIPX_TOOLS[@]}"; do
  IFS='|' read -r cmd spec py <<<"$entry"
  step "pipx: $cmd" pipx_tool "$cmd" "$spec" "$py"
done
# Packages some tools import but forget to declare.
pipx_fixups() {
  if command -v iocextract >/dev/null 2>&1 && ! iocextract --help >/dev/null 2>&1; then
    pipx inject iocextract requests || return 1
  fi
  return 0
}
step "pipx: missing dependencies (iocextract → requests)" pipx_fixups

# ─── 3. Go tools ──────────────────────────────────────────────────────────────
go_tool() {
  local cmd="$1" pkg="$2"
  if command -v "$cmd" >/dev/null 2>&1; then skip "$cmd already installed"; return 0; fi
  go install "$pkg"
}
step "go: mosint"      go_tool mosint      github.com/alpkeskin/mosint/v3/cmd/mosint@latest
step "go: waybackurls" go_tool waybackurls github.com/tomnomnom/waybackurls@latest

mosint_cfg() {
  if [[ -f "$HOME/.mosint.yaml" ]]; then skip "mosint config exists"; return 0; fi
  curl -fsSL https://raw.githubusercontent.com/alpkeskin/mosint/master/example-config.yaml -o "$HOME/.mosint.yaml"
}
step "mosint config (~/.mosint.yaml, no API keys)" mosint_cfg

# ─── 4. Git-based tools with their own venv ──────────────────────────────────
repo_venv() {  # repo_venv <github/repo> <dir> <requirements-file relative to dir> <probe module>
  local repo="$1" dir="$2" req="$3" probe="$4"
  [[ -d "$dir" ]] || git clone --depth 1 "https://github.com/$repo" "$dir" || return 1
  if [[ -x "$dir/.venv/bin/python" ]] && "$dir/.venv/bin/python" -c "import $probe" 2>/dev/null; then
    skip "$(basename "$dir") venv ready"; return 0
  fi
  "$PY312" -m venv "$dir/.venv" &&
    "$dir/.venv/bin/pip" install -q --upgrade pip wheel "setuptools<81" &&
    "$dir/.venv/bin/pip" install -q -r "$dir/$req"
}
step "Snoop"      repo_venv snooppr/snoop        "$TOOLS_DIR/snoop"      requirements.txt requests
step "SpiderFoot" repo_venv smicallef/spiderfoot "$TOOLS_DIR/spiderfoot" requirements.txt cherrypy

sherloq() {
  local dir="$TOOLS_DIR/sherloq"
  [[ -d "$dir" ]] || git clone --depth 1 https://github.com/GuidoBartoli/sherloq "$dir" || return 1
  # upstream pins pandas 1.5, which has no Python 3.12 build
  sed 's/^pandas==1\.5\.\*/pandas==2.1.*/' "$dir/gui/requirements.txt" > "$dir/.requirements-py312.txt"
  repo_venv GuidoBartoli/sherloq "$dir" .requirements-py312.txt PySide6
}
if ((WITH_SHERLOQ)); then step "Sherloq (large download, ~1.5 GB)" sherloq
else skip "Sherloq (run with --with-sherloq to install)"; fi

# Docker runtime: Colima runs a small Linux VM with the Docker engine, all from the CLI.
docker_runtime() {
  local missing=()
  for p in colima docker docker-compose; do brew list --formula "$p" >/dev/null 2>&1 || missing+=("$p"); done
  ((${#missing[@]})) && { brew install "${missing[@]}" || return 1; }
  mkdir -p "$HOME/.docker/cli-plugins"
  ln -sfn "$BREW_PREFIX/opt/docker-compose/bin/docker-compose" "$HOME/.docker/cli-plugins/docker-compose"
  if ! docker info >/dev/null 2>&1; then colima start --cpu 2 --memory 4 --disk 40 || return 1; fi
  docker info >/dev/null 2>&1
}
if ((WITH_DOCKER)); then step "Docker runtime (Colima)" docker_runtime
else skip "Docker (run with --with-docker for MobSF, Scrummage, Legion, osint-analyser, IntellyWeave)"; fi

# Git-based tools: clone + own venv. The marker makes re-runs skip finished installs.
# setuptools stays below 81: old libraries still import pkg_resources, which 81 removed.
# Requirements are cleaned first: standard-library names (json, hashlib…) that some
# repos list by mistake are dropped, and so is anything on the deny list. If pinned
# versions don't build on this Python, the install is retried without the pins.
# The list of denied packages (h8mail: password-dump lookups) lives in repo_setup.py.
clean_reqs() {  # clean_reqs <venv-python> <in> <out> [strip]
  "$1" -I "$SCRIPT_DIR/repo_setup.py" clean-reqs "$2" "$3" ${4:+--strip}
}
# Unmaintained repos often import packages their requirements forget, or stdlib
# modules removed in Python 3.12 (imp, distutils, asyncore…). Scan the code and
# install what is missing, mapping import names to package names.
fill_imports() {  # fill_imports <dir>
  "$1/.venv/bin/python" -I "$SCRIPT_DIR/repo_setup.py" fill-imports "$1"
}
repo_req() {  # repo_req <github/repo> <dir> [requirements file | - (no deps)]
  local repo="$1" dir="$2" req="${3:-requirements.txt}"
  [[ -d "$dir" ]] || git clone --depth 1 "https://github.com/$repo" "$dir" || return 1
  if [[ -f "$dir/.venv/.osint-ready" ]]; then skip "$(basename "$dir") ready"; return 0; fi
  "$PY312" -m venv "$dir/.venv" && "$dir/.venv/bin/pip" install -q --upgrade pip wheel "setuptools<81" || return 1
  if [[ "$req" != "-" ]]; then
    local py="$dir/.venv/bin/python" cleaned="$dir/.venv/osint-requirements.txt"
    clean_reqs "$py" "$dir/$req" "$cleaned" || return 1
    if ! "$dir/.venv/bin/pip" install -q -r "$cleaned"; then
      printf '    %spinned versions failed, retrying without pins%s\n' "$c_yellow" "$c_off"
      clean_reqs "$py" "$dir/$req" "$cleaned" strip && "$dir/.venv/bin/pip" install -q -r "$cleaned" || return 1
    fi
  fi
  fill_imports "$dir"
  touch "$dir/.venv/.osint-ready"
}
docker_build() {  # docker_build <github/repo> <dir> <image-tag>
  command -v docker >/dev/null 2>&1 || { skip "Docker not installed: $(basename "$2")"; return 0; }
  [[ -d "$2" ]] || git clone --depth 1 "https://github.com/$1" "$2" || return 1
  if [[ -f "$2/.docker-built" ]]; then skip "$(basename "$2") image ready"; return 0; fi
  docker build -t "$3" "$2" && touch "$2/.docker-built"
}
clone_only() {  # clone_only <github/repo> <dir>
  [[ -d "$2" ]] && { skip "$(basename "$2") already cloned"; return 0; }
  git clone --depth 1 "https://github.com/$1" "$2"
}

# LinkedIn / XING (company employees; need your session cookie at run time)
step "LinkedInDumper" repo_req l4rm4nd/LinkedInDumper "$TOOLS_DIR/LinkedInDumper"
step "XingDumper"     repo_req l4rm4nd/XingDumper     "$TOOLS_DIR/XingDumper"
step "the-endorser"   repo_req eth0izzle/the-endorser "$TOOLS_DIR/the-endorser"

reverse_tools() {
  brew list --formula ghidra >/dev/null 2>&1 || brew install ghidra || return 1
  if command -v docker >/dev/null 2>&1; then
    mkdir -p "$TOOLS_DIR/mobsf"
    [[ -f "$TOOLS_DIR/mobsf/.docker-built" ]] ||
      { docker pull opensecurity/mobile-security-framework-mobsf:latest && touch "$TOOLS_DIR/mobsf/.docker-built"; }
  else
    skip "MobSF needs Docker"
  fi
}
if ((WITH_REVERSE)); then step "Reverse: Ghidra (+ MobSF via Docker)" reverse_tools
else skip "Ghidra / MobSF (run with --with-reverse)"; fi

# Maryam: upstream lists a non-existent "umap" package and ~3 GB of ML libraries used
# only by its four "iris" NLP modules. Install the core without them; those four are
# switched off by Maryam itself, every search / OSINT module works.
maryam_lite() {
  local dir="$TOOLS_DIR/maryam"
  [[ -d "$dir" ]] || git clone --depth 1 https://github.com/saeeddhqan/Maryam "$dir" || return 1
  if [[ -f "$dir/.venv/.osint-ready" ]]; then skip "maryam ready"; return 0; fi
  "$PY312" -m venv "$dir/.venv" && "$dir/.venv/bin/pip" install -q --upgrade pip wheel "setuptools<81" &&
    "$dir/.venv/bin/pip" install -q beautifulsoup4 certifi cloudscraper Flask lxml numpy packaging pandas \
      requests typing-extensions vaderSentiment matplotlib &&
    "$dir/.venv/bin/pip" install -q --no-deps "$dir" 2>/dev/null &&
    touch "$dir/.venv/.osint-ready"
}

# ReconSpider: its setup.py imports pip (breaks modern builds), writes a third party's
# API keys into the config and pulls h8mail. Install only what its code imports, and
# make it read your own keys from the environment instead.
reconspider() {
  local dir="$TOOLS_DIR/reconspider"
  [[ -d "$dir" ]] || git clone --depth 1 https://github.com/bhavsec/reconspider "$dir" || return 1
  if [[ -f "$dir/.venv/.osint-ready" ]]; then skip "reconspider ready"; return 0; fi
  "$PY312" -m venv "$dir/.venv" && "$dir/.venv/bin/pip" install -q --upgrade pip wheel "setuptools<81" &&
    "$dir/.venv/bin/pip" install -q requests beautifulsoup4 lxml prompt_toolkit pillow shodan tweepy paramiko \
      python-nmap gmplot IP2Proxy click wget || return 1
  cat > "$dir/core/config.py" <<'PY'
import os
shodan_api = os.environ.get("SHODAN_API_KEY", "")
PY
  cat > "$dir/plugins/api.py" <<'PY'
import os
def phoneapis():
    return os.environ.get("NUMVERIFY_API_KEY", "")
def ipstack():
    return os.environ.get("IPSTACK_API_KEY", "")
def gmap():
    return os.environ.get("GOOGLE_MAPS_API_KEY", "")
PY
  fill_imports "$dir"
  touch "$dir/.venv/.osint-ready"
}

if ((WITH_FRAMEWORKS)); then
  step "Maryam (core, without the ML modules)" maryam_lite
  step "ReconSpider"           reconspider
  step "TensSens"              repo_req thenurhabib/tenssens           "$TOOLS_DIR/tenssens"
  step "Ashok"                 repo_req powerexploit/Ashok             "$TOOLS_DIR/Ashok"
  step "OSINTEye"              repo_req ritchiemwewa/osinteye          "$TOOLS_DIR/osinteye"
  step "X-osint"               repo_req TermuxHackz/X-osint            "$TOOLS_DIR/X-osint"
  step "Scrummage (Docker)"    docker_build matamorphosis/Scrummage    "$TOOLS_DIR/Scrummage" osint/scrummage
  step "Legion (Docker)"       docker_build carlospolop/legion         "$TOOLS_DIR/legion"    osint/legion
  step "osint-analyser (Docker compose)" clone_only joestanding/osint-analyser "$TOOLS_DIR/osint-analyser"
  step "IntellyWeave (Docker compose)"   clone_only vericle/intellyweave       "$TOOLS_DIR/intellyweave"
  # discover and Pip-Intel are Kali/Ubuntu scripts: the launcher offers them on Linux only.
  # Not installed on purpose: DaProfiler and Phone OSINT Framework pull leaked passwords /
  # breach-database records about a person, the same category as h8mail and dehashed.
else
  skip "Frameworks (run with --with-frameworks)"
fi

# ─── 5. Launcher ──────────────────────────────────────────────────────────────
launcher() {
  mkdir -p "$LAUNCHER_DIR"
  if [[ "$SCRIPT_DIR" != "$LAUNCHER_DIR" ]]; then
    cp "$SCRIPT_DIR/osint.py" "$SCRIPT_DIR/requirements.txt" "$LAUNCHER_DIR/" || return 1
    rm -rf "$LAUNCHER_DIR/collector" && cp -R "$SCRIPT_DIR/collector" "$LAUNCHER_DIR/" || return 1
  fi
  [[ -x "$LAUNCHER_DIR/.venv/bin/python" ]] || "$PY312" -m venv "$LAUNCHER_DIR/.venv" || return 1
  "$LAUNCHER_DIR/.venv/bin/pip" install -q -r "$LAUNCHER_DIR/requirements.txt" || return 1
  local line="alias osint='$LAUNCHER_DIR/.venv/bin/python $LAUNCHER_DIR/osint.py'"
  for rc in "$HOME/.zshrc" "$HOME/.bashrc"; do
    [[ -f "$rc" || "$rc" == "$HOME/.zshrc" ]] || continue
    grep -q "alias osint=" "$rc" 2>/dev/null || echo "$line" >> "$rc"
  done
}
step "osint launcher + alias" launcher

# ─── 6. Summary ───────────────────────────────────────────────────────────────
say "Status"
"$LAUNCHER_DIR/.venv/bin/python" "$LAUNCHER_DIR/osint.py" --check

if ((${#FAILED[@]})); then
  printf '\n%sFailed steps:%s\n' "$c_yellow" "$c_off"
  printf '  - %s\n' "${FAILED[@]}"
  echo "Re-running this script is safe: finished steps are skipped."
else
  printf '\n%sAll steps OK.%s\n' "$c_green" "$c_off"
fi
printf '\n%sOpen a new terminal (or run: exec zsh) and type:  osint%s\n' "$c_cyan" "$c_off"
