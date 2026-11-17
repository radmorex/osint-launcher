#!/usr/bin/env bash
# OSINT toolkit installer for macOS (Apple Silicon / Intel).
# Installs the tools behind the `osint` launcher and the launcher itself.
#
#   git clone https://github.com/radmorex/osint-launcher ~/tools/osint-launcher
#   cd ~/tools/osint-launcher && ./install-macos.sh            # add --with-sherloq for the image-forensics GUI
#
# Safe to re-run: anything already installed is skipped.
set -uo pipefail

WITH_SHERLOQ=0
for arg in "$@"; do
  case "$arg" in
    --with-sherloq) WITH_SHERLOQ=1 ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg"; exit 2 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOLS_DIR="$HOME/tools"
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
for f in osint.py requirements.txt; do
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
  for p in python@3.12 python@3.14 pipx git go amass subfinder phoneinfoga exiftool; do
    brew list --formula "$p" >/dev/null 2>&1 || missing+=("$p")
  done
  if ((${#missing[@]} == 0)); then skip "all brew packages present"; return 0; fi
  brew install "${missing[@]}"
}
step "Homebrew: python 3.12/3.14, pipx, git, go, amass, subfinder, phoneinfoga, exiftool" brew_pkgs

PY312="$BREW_PREFIX/bin/python3.12"
PY314="$BREW_PREFIX/bin/python3.14"
pipx ensurepath >/dev/null 2>&1 || true

# ─── 2. Python tools via pipx ─────────────────────────────────────────────────
# command | pipx spec | python
PIPX_TOOLS=(
  "maigret|maigret|$PY312"
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
    "$dir/.venv/bin/pip" install -q --upgrade pip setuptools wheel &&
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

# ─── 5. Launcher ──────────────────────────────────────────────────────────────
launcher() {
  mkdir -p "$LAUNCHER_DIR"
  if [[ "$SCRIPT_DIR" != "$LAUNCHER_DIR" ]]; then
    cp "$SCRIPT_DIR/osint.py" "$SCRIPT_DIR/requirements.txt" "$LAUNCHER_DIR/" || return 1
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
