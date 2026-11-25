"""Installer helper for git-cloned tools, shared by install-macos.sh and install-windows.ps1.

  python -I repo_setup.py clean-reqs <in> <out> [--strip]   (run with the tool's venv python)
  python -I repo_setup.py fill-imports <repo-dir>            (run with the tool's venv python)

clean-reqs   drops standard-library names some repos list by mistake (json, hashlib…) and
             anything in DENY; --strip also drops version pins, for a retry when pinned
             versions don't build on this Python.
fill-imports scans the repo's code and pip-installs imports its requirements forgot,
             plus replacements for stdlib modules removed in Python 3.12 (imp, distutils…).
"""
from __future__ import annotations

import ast
import importlib.util
import pathlib
import re
import subprocess
import sys
import warnings

DENY = {"h8mail"}   # password-dump lookups: kept out of the toolkit on purpose

PKG = {"bs4": "beautifulsoup4", "yaml": "PyYAML", "PIL": "pillow", "cv2": "opencv-python",
       "dns": "dnspython", "nmap": "python-nmap", "Crypto": "pycryptodome", "dotenv": "python-dotenv",
       "googlesearch": "googlesearch-python", "magic": "python-magic", "jwt": "PyJWT", "OpenSSL": "pyOpenSSL",
       "serial": "pyserial", "sklearn": "scikit-learn", "docx": "python-docx", "socks": "PySocks",
       "Levenshtein": "python-Levenshtein", "telegram": "python-telegram-bot", "whois": "python-whois",
       "imp": "zombie-imp", "distutils": "setuptools", "asyncore": "pyasyncore", "asynchat": "pyasynchat",
       "IP2Proxy": "IP2Proxy", "fake_useragent": "fake-useragent", "Wappalyzer": "python-Wappalyzer",
       "pkg_resources": "setuptools<81", "termcolor": "termcolor", "colorama": "colorama"}
REMOVED = {"imp", "distutils", "asyncore", "asynchat"}
# stdlib modules that Windows Python lacks but a pip package replaces
WIN_SUBST = {"readline": "pyreadline3", "curses": "windows-curses"} if sys.platform == "win32" else {}


def _read(path: pathlib.Path) -> str:
    """Text of a file saved by any editor: UTF-8, UTF-8 with BOM or UTF-16 (Windows Notepad)."""
    raw = path.read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


def clean_reqs(src: str, dst: str, strip: bool) -> None:
    out = []
    for line in _read(pathlib.Path(src)).splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        name = re.split(r"[<>=!~\[; ]", line, maxsplit=1)[0].strip()
        if name.lower() in DENY or name in sys.stdlib_module_names:
            continue
        out.append(name if strip else line)
    pathlib.Path(dst).write_text("\n".join(out) + "\n", encoding="utf-8")


def fill_imports(root: pathlib.Path) -> None:
    warnings.simplefilter("ignore", SyntaxWarning)   # old code with "\." in plain strings
    local = {p.stem for p in root.rglob("*.py")} | {p.name for p in root.rglob("*") if p.is_dir()}
    wanted: set[str] = set()
    for f in root.rglob("*.py"):
        if ".venv" in f.parts or "test" in f.name.lower():
            continue
        try:
            tree = ast.parse(_read(f))
        except (SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                names = [node.module]
            else:
                continue
            for n in names:
                top = n.split(".")[0]
                if top in WIN_SUBST:
                    wanted.add(top)
                    continue
                if top in local or (top in sys.stdlib_module_names and top not in REMOVED):
                    continue
                wanted.add(top)
    missing = sorted(t for t in wanted
                     if t in WIN_SUBST   # curses is found but its C part is missing on Windows: always install
                     or (importlib.util.find_spec(t) is None and PKG.get(t, t).lower() not in DENY))
    for t in missing:
        pkg = WIN_SUBST.get(t) or PKG.get(t, t)
        ok = subprocess.run([sys.executable, "-m", "pip", "install", "-q", pkg],
                            capture_output=True).returncode == 0
        print(f"    + {pkg}" if ok else f"    ? {t}: no package found")


def main(argv: list[str]) -> int:
    if len(argv) >= 3 and argv[0] == "clean-reqs":
        clean_reqs(argv[1], argv[2], "--strip" in argv[3:])
        return 0
    if len(argv) == 2 and argv[0] == "fill-imports":
        fill_imports(pathlib.Path(argv[1]))
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
