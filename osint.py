#!/usr/bin/env python3
"""OSINT launcher — TUI menu + multi-search over local open-source OSINT tools."""
from __future__ import annotations

import argparse
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

try:
    import questionary
    from questionary import Choice, Separator
    from rich.align import Align
    from rich.box import HEAVY, HEAVY_HEAD
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
except ImportError:
    print("Не вистачає пакетів. Встанови: pip install rich questionary")
    sys.exit(1)

__version__ = "2.7.0"

# ─── Config (override via environment) ────────────────────────────────────────
IS_WIN = os.name == "nt"
HOME = Path.home()
TOOLS_DIR = Path(os.environ.get("OSINT_TOOLS_DIR", HOME / "tools"))
REPORTS_DIR = Path(os.environ.get("OSINT_REPORTS_DIR", HOME / "osint-reports"))
SPIDERFOOT_ADDR = os.environ.get("OSINT_SPIDERFOOT_ADDR", "127.0.0.1:5001")


def setup_hint(*opts: str) -> str:
    """Installer command that adds the given optional parts, in this platform's syntax."""
    if IS_WIN:
        return "встановіть: .\\install-windows.ps1 " + " ".join("-With" + o.title() for o in opts)
    return "встановіть: ./install-macos.sh " + " ".join("--with-" + o for o in opts)


DOCKER_HINT = setup_hint("docker")

# Extra bin dirs that may be missing from PATH when launched from a fresh shell.
for extra in (HOME / ".local" / "bin", HOME / "go" / "bin", TOOLS_DIR / "bin", Path("/opt/homebrew/bin")):
    if extra.is_dir() and str(extra) not in os.environ.get("PATH", ""):
        os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + str(extra)

console = Console()

BANNER = [
    " ██████╗ ███████╗██╗███╗   ██╗████████╗",
    "██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝",
    "██║   ██║███████╗██║██╔██╗ ██║   ██║   ",
    "██║   ██║╚════██║██║██║╚██╗██║   ██║   ",
    "╚██████╔╝███████║██║██║ ╚████║   ██║   ",
    " ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   ",
]
GRADIENT = ["#5f0000", "#870000", "#af0000", "#d70000", "#ff0000", "#ff5f5f"]  # dark → blood red

STYLE = questionary.Style([
    ("qmark", "fg:#ff0000 bold"),
    ("question", "fg:#eeeeee bold"),
    ("pointer", "fg:#ff0000 bold"),
    ("highlighted", "fg:#ffffff bg:#870000 bold"),
    ("selected", "fg:#ff5f5f"),
    ("answer", "fg:#ff5f5f bold"),
    ("separator", "fg:#870000"),
    ("disabled", "fg:#4e4e4e italic"),
    ("instruction", "fg:#626262"),
])

USER_RE = re.compile(r"[\w.\-]{1,64}")
EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
DOMAIN_RE = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")

CATEGORIES = [
    ("username", "USERNAME"),
    ("email", "EMAIL"),
    ("phone", "ТЕЛЕФОН"),
    ("domain", "ДОМЕН / КОМПАНІЯ"),
    ("media", "ФОТО / МЕДІА"),
    ("files", "ФАЙЛИ / АНАЛІЗ"),
    ("reverse", "РЕВЕРС / ЗАСТОСУНКИ"),
    ("framework", "ФРЕЙМВОРКИ"),
]


# ─── Locators ─────────────────────────────────────────────────────────────────
def _which(name: str) -> Callable[[], list[str] | None]:
    def locate() -> list[str] | None:
        path = shutil.which(name)
        return [path] if path else None
    return locate


def _repo(dirname: str, script: str) -> Callable[[], list[str] | None]:
    """Tool cloned into TOOLS_DIR/<dirname> with its own .venv."""
    def locate() -> list[str] | None:
        root = TOOLS_DIR / dirname
        entry = root / script
        if not entry.is_file():
            return None
        venv_py = root / ".venv" / ("Scripts/python.exe" if IS_WIN else "bin/python")
        return [str(venv_py if venv_py.is_file() else sys.executable), str(entry)]
    return locate


def _repo_ok(dirname: str, script: str) -> Callable[[], list[str] | None]:
    """Like _repo, but only once the installer finished it (it leaves .venv/.osint-ready)."""
    def locate() -> list[str] | None:
        if not (TOOLS_DIR / dirname / ".venv" / ".osint-ready").is_file():
            return None
        return _repo(dirname, script)()
    return locate


def _venv_bin(dirname: str, name: str) -> Callable[[], list[str] | None]:
    """Console script inside TOOLS_DIR/<dirname>/.venv, falling back to PATH."""
    def locate() -> list[str] | None:
        venv = TOOLS_DIR / dirname / ".venv"
        if (venv / ".osint-ready").is_file():
            exe = venv / ("Scripts" if IS_WIN else "bin") / (name + ".exe" if IS_WIN else name)
            if exe.is_file():
                return [str(exe)]
        found = shutil.which(name)
        return [found] if found else None
    return locate


def _repo_any(dirname: str, *scripts: str) -> Callable[[], list[str] | None]:
    """Like _repo, for repos whose entry point name differs between versions."""
    def locate() -> list[str] | None:
        for sc in scripts:
            found = _repo(dirname, sc)()
            if found:
                return found
        return None
    return locate


def _docker_compose(dirname: str) -> Callable[[], list[str] | None]:
    """Server app started with `docker compose up` from its cloned repo."""
    def locate() -> list[str] | None:
        docker = shutil.which("docker")
        root = TOOLS_DIR / dirname
        if not docker or not root.is_dir():
            return None
        if not any((root / f).is_file() for f in ("docker-compose.yml", "docker-compose.yaml", "compose.yaml",
                                                   "Dockerfile")):
            return None
        return [docker]
    return locate


def _docker_image(dirname: str) -> Callable[[], list[str] | None]:
    """Image built or pulled by the installer; it leaves TOOLS_DIR/<dirname>/.docker-built."""
    def locate() -> list[str] | None:
        docker = shutil.which("docker")
        return [docker] if docker and (TOOLS_DIR / dirname / ".docker-built").is_file() else None
    return locate


def _linux_repo(dirname: str, script: str) -> Callable[[], list[str] | None]:
    """Bash tool written for Kali/Ubuntu: offered on Linux only."""
    def locate() -> list[str] | None:
        entry = TOOLS_DIR / dirname / script
        return ["bash", str(entry)] if sys.platform.startswith("linux") and entry.is_file() else None
    return locate


def _never() -> list[str] | None:
    return None


def _in(dirname: str) -> Callable[[dict], Path]:
    return lambda t: TOOLS_DIR / dirname


def _report_dir(target: str, tool: str) -> Path:
    slug = re.sub(r"[^\w.\-@]", "_", target)[:80]
    out = REPORTS_DIR / f"{datetime.now():%Y%m%d-%H%M%S}_{tool}_{slug}"
    out.mkdir(parents=True, exist_ok=True)
    return out


def _argfile(*args: str) -> str:
    """UTF-8 argument file for tools that can't take non-ASCII paths on the Windows command line."""
    fd, name = tempfile.mkstemp(prefix="osint-args-", suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(args) + "\n")
    return name


@dataclass
class Tool:
    key: str
    name: str
    desc: str
    category: str
    kind: str                                   # username|email|phone|domain|company|file|instagram|none
    locate: Callable[[], list[str] | None]
    build: Callable[[dict], list[str]]
    cwd: Callable[[dict], Path | None] = field(default=lambda t: None)
    stdin: Callable[[dict], str] | None = None  # text fed to the tool's stdin
    tee: bool = False                           # duplicate stdout into a report file
    open_url: str | None = None                 # open in browser after start (web UIs)
    missing: str = "не встановлено"             # menu hint when locate() finds nothing
    only: str | None = None                     # "linux": shown only on that platform


HARVESTER_SOURCES = "crtsh,duckduckgo,hackertarget,rapiddns,urlscan,otx,certspotter,yahoo"

TOOLS: dict[str, Tool] = {t.key: t for t in [
    # USERNAME
    Tool("user_scanner_u", "user-scanner", "2500+ сайтів, без хибних збігів, JSON-звіт", "username", "username",
         _which("user-scanner"),
         lambda t: ["-u", t["username"], "-f", "json", "-o",
                    str(_report_dir(t["username"], "user-scanner") / "results.json")]),
    Tool("maigret", "Maigret", "3000+ сайтів, рекурсія, HTML-звіт", "username", "username",
         _which("maigret"),
         lambda t: [t["username"], "--html", "-fo", str(_report_dir(t["username"], "maigret"))]),
    Tool("snoop", "Snoop", "упор на RU/СНД-сегмент", "username", "username",
         _repo("snoop", "snoop.py"), lambda t: [t["username"]],
         cwd=lambda t: TOOLS_DIR / "snoop"),
    Tool("sherlock", "Sherlock", "класика пошуку по ніку", "username", "username",
         _which("sherlock"),
         lambda t: [t["username"], "--folderoutput", str(_report_dir(t["username"], "sherlock"))]),
    Tool("social_analyzer", "Social Analyzer", "1000+ сайтів з оцінкою впевненості", "username", "username",
         _which("social-analyzer"),
         lambda t: ["--username", t["username"], "--metadata", "--filter", "good", "--mode", "fast"]),
    Tool("nexfil", "Nexfil", "швидкий пошук по ніку", "username", "username",
         _which("nexfil"), lambda t: ["-u", t["username"]]),
    # EMAIL
    Tool("user_scanner_e", "user-scanner", "де зареєстрований email; без листів власнику", "email", "email",
         _which("user-scanner"),
         lambda t: ["-e", t["email"], "-f", "json", "-o",
                    str(_report_dir(t["email"], "user-scanner") / "results.json")]),
    Tool("holehe", "Holehe", "застарілий: більшість перевірок уже не працює", "email", "email",
         _which("holehe"), lambda t: [t["email"], "--only-used", "-NP"]),  # -NP: no reset emails to the owner
    Tool("ghunt", "GHunt", "розбір Google-акаунта", "email", "email",
         _which("ghunt"), lambda t: ["email", t["email"]]),
    Tool("mosint", "Mosint", "витоки, DNS, соцмережі (API-ключі)", "email", "email",
         _which("mosint"), lambda t: [t["email"]]),
    # PHONE
    Tool("ignorant", "Ignorant", "на яких сервісах зареєстрований", "phone", "phone",
         _which("ignorant"), lambda t: [t["cc"], t["number"]]),
    Tool("phoneinfoga", "PhoneInfoga", "оператор, країна, тип, дорки", "phone", "phone",
         _which("phoneinfoga"), lambda t: ["scan", "-n", f"+{t['cc']}{t['number']}"]),
    # DOMAIN / COMPANY
    Tool("subfinder", "Subfinder", "пасивний пошук субдоменів", "domain", "domain",
         _which("subfinder"), lambda t: ["-d", t["domain"], "-silent"], tee=True),
    Tool("amass", "Amass", "субдомени (OWASP), повільно, але глибоко", "domain", "domain",
         _which("amass"), lambda t: ["enum", "-passive", "-d", t["domain"]], tee=True),
    Tool("theharvester", "theHarvester", "пошти, хости, субдомени з відкритих джерел", "domain", "domain",
         _which("theHarvester"),
         lambda t: ["-d", t["domain"], "-b", HARVESTER_SOURCES, "-l", "300"], tee=True),
    Tool("waybackurls", "waybackurls", "усі URL домену з Wayback Machine", "domain", "domain",
         _which("waybackurls"), lambda t: [], stdin=lambda t: t["domain"] + "\n", tee=True),
    Tool("crosslinked", "CrossLinked", "співробітники з LinkedIn → ймовірні email", "domain", "company",
         _which("crosslinked"),
         lambda t: ["-f", f"{t['format']}@{t['domain']}", t["company"]],
         cwd=lambda t: _report_dir(t["company"], "crosslinked")),
    Tool("linkedindumper", "LinkedInDumper", "співробітники компанії з LinkedIn (cookie li_at)", "domain", "linkedin",
         _repo_ok("LinkedInDumper", "linkedindumper.py"),
         lambda t: ["--url", t["url"], "--cookie", t["cookie"], "--jitter",
                    *(["--email-format", t["fmt"]] if t.get("fmt") else []),
                    "--output-csv", str(_report_dir(t["url"].rstrip("/").split("/")[-1], "linkedindumper") / "employees.csv")],
         cwd=_in("LinkedInDumper")),
    Tool("xingdumper", "XingDumper", "співробітники компанії з XING (cookie login)", "domain", "xing",
         _repo_ok("XingDumper", "xingdumper.py"),
         lambda t: ["--url", t["url"], "--cookie", t["cookie"],
                    *(["--email-format", t["fmt"]] if t.get("fmt") else []),
                    "--output-csv", str(_report_dir(t["url"].rstrip("/").split("/")[-1], "xingdumper") / "employees.csv")],
         cwd=_in("XingDumper")),
    Tool("endorser", "the-endorser", "зв'язки між людьми через рекомендації LinkedIn", "domain", "args",
         _repo_ok("the-endorser", "the-endorser.py"), lambda t: t["args"] or ["-h"], cwd=_in("the-endorser")),
    # MEDIA
    Tool("exiftool", "ExifTool", "метадані фото/документів: GPS, камера, дата", "media", "file",
         _which("exiftool"), lambda t: ["-charset", "filename=utf8", "-a", "-G1", "-s", "-@", _argfile(t["file"])],
         tee=True),
    Tool("sherloq", "Sherloq", "форензика зображень (GUI)", "media", "none",
         _repo("sherloq", "sherloq.py"), lambda t: [],
         cwd=lambda t: TOOLS_DIR / "sherloq"),
    Tool("instaloader", "Instaloader", "публічний Instagram-профіль без логіну", "media", "instagram",
         _which("instaloader"),
         lambda t: ["--no-videos", "--no-video-thumbnails", "--no-compress-json", t["instagram"]],
         cwd=lambda t: _report_dir(t["instagram"], "instaloader")),
    # FILES / ANALYSIS
    Tool("linkfiles", "Зв'язки між файлами", "відбитки (EXIF, автор, XMP, камера) + стиль письма: папка → граф",
         "files", "dir", lambda: [sys.executable, "-m", "collector", "link"], lambda t: [t["dir"]],
         cwd=lambda t: Path(__file__).resolve().parent),
    Tool("pdfx", "pdfx", "метадані й усі посилання з PDF", "files", "file",
         _which("pdfx"), lambda t: [t["file"], "-v"], tee=True),
    Tool("olemeta", "olemeta", "автор, компанія, дати в документах Office", "files", "file",
         _which("olemeta"), lambda t: [t["file"]], tee=True),
    Tool("olevba", "olevba", "макроси й підозрілі виклики в документах Office", "files", "file",
         _which("olevba"), lambda t: [t["file"]], tee=True),
    Tool("mutagen", "mutagen-inspect", "теги аудіо: виконавець, програма, дати", "files", "file",
         _which("mutagen-inspect"), lambda t: [t["file"]], tee=True),
    Tool("c2patool", "c2patool", "Content Credentials: хто й чим створив або змінив файл", "files", "file",
         _which("c2patool"), lambda t: [t["file"]], tee=True),
    Tool("iocextract", "iocextract", "URL, IP, email і хеші з тексту чи файлу", "files", "file",
         _which("iocextract"), lambda t: ["--input", t["file"]], tee=True),
    # REVERSE
    Tool("ghidra", "Ghidra", "реверс бінарників (GUI)", "reverse", "none", _which("ghidraRun"), lambda t: [],
         missing=setup_hint("reverse")),
    Tool("jadx", "jadx-gui", "декомпіляція APK / DEX / JAR у Java", "reverse", "file",
         _which("jadx-gui"), lambda t: [t["file"]]),
    Tool("apktool", "apktool", "розпаковка APK: маніфест, ресурси, smali", "reverse", "file",
         _which("apktool"),
         lambda t: ["d", t["file"], "-f", "-o", str(_report_dir(Path(t["file"]).name, "apktool") / "out")]),
    Tool("apkleaks", "APKLeaks", "ключі, токени й URL всередині APK", "reverse", "file",
         _which("apkleaks"),
         lambda t: ["-f", t["file"], "-o", str(_report_dir(Path(t["file"]).name, "apkleaks") / "leaks.txt")]),
    Tool("xortool", "xortool", "XOR-аналіз: довжина ключа й підбір", "reverse", "file",
         _which("xortool"), lambda t: [t["file"]], tee=True),
    Tool("mobsf", "MobSF", "аналіз APK/IPA у браузері (Docker)", "reverse", "none",
         _docker_image("mobsf"),
         lambda t: ["run", "--rm", "-it", "-p", "127.0.0.1:8000:8000",
                    "opensecurity/mobile-security-framework-mobsf:latest"],
         open_url="http://127.0.0.1:8000", missing=setup_hint("docker", "reverse")),
    # FRAMEWORKS
    Tool("bbot", "BBOT", "рекурсивна розвідка домену: субдомени + пошти", "framework", "domain",
         _which("bbot"),
         lambda t: ["-t", t["domain"], "-p", "subdomain-enum", "email-enum", "-y",
                    "-o", str(_report_dir(t["domain"], "bbot"))]),
    Tool("spiderfoot", "SpiderFoot", f"веб-інтерфейс на {SPIDERFOOT_ADDR} (Ctrl+C — стоп)", "framework", "none",
         _repo("spiderfoot", "sf.py"), lambda t: ["-l", SPIDERFOOT_ADDR],
         cwd=lambda t: TOOLS_DIR / "spiderfoot", open_url=f"http://{SPIDERFOOT_ADDR}"),
    Tool("osintgraph", "Osintgraph", "Instagram-граф у Neo4j: підписники, пости, лайки", "framework", "instagram",
         _which("osintgraph"), lambda t: ["discover", t["instagram"]]),
    Tool("osintgraph_agent", "Osintgraph Agent", "AI-агент (Gemini) по зібраному графу", "framework", "none",
         _which("osintgraph"), lambda t: ["agent"]),
    Tool("openosint", "OpenOSINT", "агент: 21 джерело за одним запитом, веб-інтерфейс", "framework", "none",
         _which("openosint"), lambda t: ["web"]),
    Tool("maryam", "OWASP Maryam", "модульний фреймворк (архівований; без NLP-модулів iris)", "framework", "args",
         _venv_bin("maryam", "maryam"), lambda t: t["args"] or ["-e", "show", "modules"],
         cwd=_in("maryam"),
         missing=setup_hint("frameworks")),
    Tool("reconspider", "ReconSpider", "IP, домени, email, телефони; сканери портів і SSH лише для ваших цілей. Ключі: SHODAN_API_KEY та ін.", "framework", "none",
         _repo_ok("reconspider", "reconspider.py"), lambda t: [], cwd=_in("reconspider"),
         missing=setup_hint("frameworks")),
    Tool("tenssens", "TensSens", "збір інформації з безкоштовних сервісів", "framework", "none",
         _repo_ok("tenssens", "tenssens.py"), lambda t: [], cwd=_in("tenssens"),
         missing=setup_hint("frameworks")),
    Tool("ashok", "Ashok", "розвідка сайту: заголовки, CMS, дорки, whois", "framework", "args",
         _repo_ok("Ashok", "Ashok.py"), lambda t: t["args"] or ["-h"], cwd=_in("Ashok"),
         missing=setup_hint("frameworks")),
    Tool("osinteye", "OSINTEye", "нік на GitHub, PyPI, DockerHub, About.me (архівований)", "framework", "args",
         _repo_ok("osinteye", "osinteye"), lambda t: t["args"] or ["-h"], cwd=_in("osinteye"),
         missing=setup_hint("frameworks")),
    Tool("xosint", "X-osint", "інтерактивний фреймворк (зроблений під Linux/Termux)", "framework", "none",
         _repo_ok("X-osint", "xosint"), lambda t: [], cwd=_in("X-osint"),
         missing=setup_hint("frameworks")),
    Tool("scrummage", "Scrummage", "веб-платформа OSINT і threat hunting (Docker)", "framework", "none",
         _docker_image("Scrummage"), lambda t: ["run", "--rm", "-it", "-p", "127.0.0.1:5000:5000", "osint/scrummage"],
         open_url="https://127.0.0.1:5000", missing=setup_hint("docker", "frameworks")),
    Tool("osint_analyser", "osint-analyser", "збір, переклад і AI-аналіз джерел (Docker)", "framework", "none",
         _docker_compose("osint-analyser"), lambda t: ["compose", "up"], cwd=_in("osint-analyser"),
         missing=setup_hint("docker", "frameworks")),
    Tool("intellyweave", "IntellyWeave", "AI-аналіз OSINT з Weaviate (Docker)", "framework", "none",
         _docker_compose("intellyweave"), lambda t: ["compose", "up"], cwd=_in("intellyweave"),
         missing=setup_hint("docker", "frameworks")),
    Tool("legion", "Legion", "автоматична енумерація сервісів, лише ваші цілі (Docker)", "framework", "none",
         _docker_image("legion"), lambda t: ["run", "--rm", "-it", "osint/legion"],
         missing=setup_hint("docker", "frameworks")),
    Tool("discover", "discover", "пентест-скрипти, лише ваші цілі", "framework", "none",
         _linux_repo("discover", "discover.sh"), lambda t: [], cwd=_in("discover"), missing="лише Kali / Ubuntu",
         only="linux"),
    Tool("pip_intel", "Pip-Intel", "набір OSINT-тулів для Kali", "framework", "none",
         _linux_repo("Pip-Intel", "pip-intel.sh"), lambda t: [], cwd=_in("Pip-Intel"), missing="лише Kali Linux",
         only="linux"),
]}

def visible() -> list[Tool]:
    """Tools that can exist on this platform (Linux-only scripts are hidden on macOS/Windows)."""
    return [t for t in TOOLS.values() if not t.only or sys.platform.startswith(t.only)]


COMBOS: dict[str, tuple[str, str, list[str]]] = {
    "combo_username": ("⚡ Мульти: username → user-scanner + Maigret + Sherlock + Social Analyzer + Nexfil + Snoop",
                       "username", ["user_scanner_u", "maigret", "sherlock", "social_analyzer", "nexfil", "snoop"]),
    "combo_email": ("⚡ Мульти: email → user-scanner + GHunt + Mosint + нік з email через username-тулзи",
                    "email", ["user_scanner_e", "ghunt", "mosint", "@user_scanner_u", "@maigret"]),
    "combo_phone": ("⚡ Мульти: телефон → Ignorant + PhoneInfoga", "phone", ["ignorant", "phoneinfoga"]),
    "combo_domain": ("⚡ Мульти: домен → Subfinder + theHarvester + waybackurls + Amass",
                     "domain", ["subfinder", "theharvester", "waybackurls", "amass"]),
}
COMBO_CATEGORY = {"combo_username": "username", "combo_email": "email",
                  "combo_phone": "phone", "combo_domain": "domain"}


# ─── Input ────────────────────────────────────────────────────────────────────
def _clean_path(raw: str) -> str:
    s = raw.strip().strip("'\"")
    if not IS_WIN:
        s = s.replace("\\ ", " ")          # drag-and-drop into Terminal escapes spaces
    return str(Path(s).expanduser())


def _split_args(raw: str) -> list[str]:
    if not IS_WIN:
        return shlex.split(raw)
    # posix=False keeps C:\paths intact but leaves the quotes around "two words"
    return [a[1:-1] if len(a) > 1 and a[0] == a[-1] and a[0] in "\"'" else a
            for a in shlex.split(raw, posix=False)]


def _clean_domain(raw: str) -> str:
    s = raw.strip().lower()
    s = re.sub(r"^[a-z]+://", "", s)
    return s.split("/")[0].split(":")[0]


def _text(msg: str, check: Callable[[str], bool], err: str) -> str | None:
    return questionary.text(msg, style=STYLE, validate=lambda s: check(s) or err).ask()


def ask_target(kind: str) -> dict | None:
    if kind == "none":
        return {}
    if kind == "username":
        v = _text("Username:", lambda s: bool(USER_RE.fullmatch(s.strip())), "Лише літери, цифри, . _ -")
        return None if v is None else {"username": v.strip()}
    if kind == "instagram":
        v = _text("Instagram-профіль (нік):", lambda s: bool(USER_RE.fullmatch(s.strip().lstrip("@"))),
                  "Лише літери, цифри, . _")
        return None if v is None else {"instagram": v.strip().lstrip("@")}
    if kind == "email":
        v = _text("Email:", lambda s: bool(EMAIL_RE.fullmatch(s.strip())), "Невірний формат email")
        return None if v is None else {"email": v.strip()}
    if kind == "phone":
        cc = _text("Код країни (без +, напр. 380):", lambda s: bool(re.fullmatch(r"\d{1,3}", s.strip())),
                   "1–3 цифри")
        if cc is None:
            return None
        num = _text("Номер без коду країни:",
                    lambda s: bool(re.fullmatch(r"\d{4,14}", re.sub(r"[\s\-()]", "", s))), "4–14 цифр")
        return None if num is None else {"cc": cc.strip(), "number": re.sub(r"[\s\-()]", "", num)}
    if kind == "domain":
        v = _text("Домен (напр. example.com):", lambda s: bool(DOMAIN_RE.fullmatch(_clean_domain(s))),
                  "Невірний домен")
        return None if v is None else {"domain": _clean_domain(v)}
    if kind == "company":
        company = _text("Назва компанії (як у LinkedIn):", lambda s: len(s.strip()) >= 2, "Мінімум 2 символи")
        if company is None:
            return None
        dom = ask_target("domain")
        if dom is None:
            return None
        fmt = questionary.select(
            "Формат email у компанії:", style=STYLE,
            choices=["{first}.{last}", "{f}{last}", "{first}{last}", "{first}", "{first}_{last}", "{last}{f}"],
        ).ask()
        return None if fmt is None else {"company": company.strip(), "format": fmt, **dom}
    if kind == "file":
        v = _text("Шлях до файлу (можна перетягнути у вікно):",
                  lambda s: Path(_clean_path(s)).is_file(), "Файл не знайдено")
        return None if v is None else {"file": _clean_path(v)}
    if kind == "dir":
        v = _text("Папка або файл (можна перетягнути у вікно):",
                  lambda s: Path(_clean_path(s)).exists(), "Шлях не знайдено")
        return None if v is None else {"dir": _clean_path(v)}
    if kind == "args":
        v = questionary.text("Аргументи (порожньо — довідка тула):", style=STYLE).ask()
        return None if v is None else {"args": _split_args(v)}
    if kind in ("linkedin", "xing"):
        site = {"linkedin": ("https://www.linkedin.com/company/", "LINKEDIN_LI_AT", "li_at"),
                "xing": ("https://www.xing.com/pages/", "XING_LOGIN_COOKIE", "login")}[kind]
        url = _text(f"URL компанії ({site[0]}<назва>):",
                    lambda s: s.strip().startswith(site[0]) and len(s.strip()) > len(site[0]),
                    f"Має починатися з {site[0]}")
        if url is None:
            return None
        cookie = os.environ.get(site[1]) or questionary.password(
            f"Cookie '{site[2]}' (або задайте {site[1]}; краще з запасного акаунта):", style=STYLE,
            validate=lambda s: len(s.strip()) > 10 or "Порожній cookie").ask()
        if cookie is None:
            return None
        fmt = questionary.text("Формат email, напр. {0}.{1}@firma.ua (порожньо — без email):", style=STYLE).ask()
        return None if fmt is None else {"url": url.strip(), "cookie": cookie.strip(), "fmt": fmt.strip()}
    raise ValueError(kind)


def _docker_up() -> bool:
    """Docker engine reachable; start Colima if that is how Docker is installed here."""
    ok = lambda: subprocess.run(["docker", "info"], capture_output=True).returncode == 0
    if ok():
        return True
    desktop = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Docker" / "Docker" / "Docker Desktop.exe"
    if IS_WIN and desktop.is_file():
        console.print("[#ff5f5f]▓ Docker не запущено, стартую Docker Desktop (до 2 хвилин)…[/]")
        subprocess.Popen([str(desktop)])
        for _ in range(40):
            time.sleep(3)
            if ok():
                return True
    if shutil.which("colima"):
        console.print("[#ff5f5f]▓ Docker не запущено, стартую Colima (перший раз до хвилини)…[/]")
        subprocess.call(["colima", "start"])
        if ok():
            return True
    console.print(f"[red]✗ Docker не працює: {DOCKER_HINT}[/]")
    return False


# ─── Execution ────────────────────────────────────────────────────────────────
def run_tool(tool: Tool, target: dict) -> int:
    base = tool.locate()
    if base is None:
        console.print(f"[red]✗ {tool.name} не знайдено.[/]")
        return 127
    argv = base + tool.build(target)
    cwd = tool.cwd(target)
    console.rule(f"[bold #ff0000]▓▒░ {tool.name} ░▒▓[/]", style="#870000")
    console.print(f"[dim]$ {' '.join(argv)}{'  (cwd: ' + str(cwd) + ')' if cwd else ''}[/]\n")

    if Path(argv[0]).stem.lower() == "docker" and not _docker_up():
        return 125
    if tool.open_url:
        threading.Timer(4.0, lambda: webbrowser.open(tool.open_url)).start()

    report: Path | None = None
    try:
        if tool.tee or tool.stdin:
            target_name = next(iter(target.values()), "run") if target else "run"
            report = _report_dir(Path(str(target_name)).name, tool.key) / "output.txt"
            with subprocess.Popen(
                argv, cwd=str(cwd) if cwd else None,
                stdin=subprocess.PIPE if tool.stdin else None,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
                env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            ) as proc, report.open("w", encoding="utf-8") as fh:
                if tool.stdin:
                    proc.stdin.write(tool.stdin(target))
                    proc.stdin.close()
                for line in proc.stdout:
                    sys.stdout.write(line)
                    fh.write(line)
                rc = proc.wait()
        else:
            rc = subprocess.call(argv, cwd=str(cwd) if cwd else None)
    except KeyboardInterrupt:
        rc = 130
        console.print("\n[yellow]⏹ Перервано[/]")
    except OSError as exc:
        console.print(f"[red]✗ Не вдалося запустити: {exc}[/]")
        return 126

    color = "green" if rc == 0 else "yellow"
    console.print(f"\n[{color}]● {tool.name} завершено, код {rc}[/]")
    if report:
        console.print(f"[dim]  вивід збережено: {report}[/]")
    return rc


def run_combo(key: str) -> None:
    _, kind, members = COMBOS[key]
    target = ask_target(kind)
    if target is None:
        return
    for member in members:
        derived = member.startswith("@")
        tool = TOOLS[member.lstrip("@")]
        tgt = target
        if derived:  # email → local part as username
            local = target["email"].split("@")[0]
            if not USER_RE.fullmatch(local):
                continue
            tgt = {"username": local}
            console.print(f"\n[#ff5f5f]↳ нік з email: {local}[/]")
        if tool.locate():
            run_tool(tool, tgt)
        else:
            console.print(f"[dim]— {tool.name} пропущено (не встановлено)[/]")


# ─── UI ───────────────────────────────────────────────────────────────────────
def clear() -> None:
    os.system("cls" if IS_WIN else "clear")


def banner() -> None:
    art = Text()
    for line, color in zip(BANNER, GRADIENT):
        art.append(line + "\n", style=f"bold {color}")
    ready = sum(1 for t in visible() if t.locate())
    art.append("\n░▒▓█ open-source intelligence toolkit █▓▒░\n", style="bold #ff5f5f")
    art.append(f"root@osint:~$ ", style="#af0000")
    art.append(f"v{__version__} · {ready}/{len(visible())} armed", style="#eeeeee")
    art.append("_", style="blink bold #ff0000")
    console.print(Panel(Align.center(art), border_style="#af0000", box=HEAVY, padding=(1, 4)))


def status_table() -> Table:
    table = Table(border_style="#870000", header_style="bold #ff0000", show_lines=False, box=HEAVY_HEAD)
    table.add_column("Категорія", style="bold #ff5f5f")
    table.add_column("Інструменти")
    for cat, label in CATEGORIES:
        cells = [
            f"[#ff0000]●[/] [#eeeeee]{t.name}[/]" if t.locate() else f"[#3a3a3a]○[/] [#585858]{t.name}[/]"
            for t in visible() if t.category == cat
        ]
        table.add_row(label, "   ".join(cells))
    return table


def compact_status() -> Text:
    """Ready/total per category in one or two centred lines instead of the full table."""
    chips = []
    for cat, label in CATEGORIES:
        tools = [t for t in visible() if t.category == cat]
        if tools:
            ready = sum(1 for t in tools if t.locate())
            chips.append((label.split(" /")[0], ready, len(tools)))
    width = sum(len(n) + len(f" {r}/{t}") + 5 for n, r, t in chips)
    rows = [chips] if width < console.width - 4 else [chips[: (len(chips) + 1) // 2], chips[(len(chips) + 1) // 2:]]
    out = Text(justify="center")
    for ri, row in enumerate(rows):
        if ri:
            out.append("\n")
        for i, (name, ready, total) in enumerate(row):
            if i:
                out.append("  ▪  ", style="#5f0000")
            out.append(name, style="bold #ff5f5f")
            out.append(f" {ready}/{total}", style="#eeeeee" if ready == total else "bold #ff0000")
    missing = [t.name for t in visible() if not t.locate()]
    if missing:
        out.append("\n○ " + ", ".join(missing[:5]) + (f" +{len(missing) - 5}" if len(missing) > 5 else ""),
                   style="#6c6c6c")
        out.append("  · osint --check", style="#4e4e4e")
    return out


def build_menu() -> list:
    items: list = []
    for cat, label in CATEGORIES:
        items.append(Separator(f"──────── {label} " + "─" * max(2, 22 - len(label))))
        for tool in (t for t in visible() if t.category == cat):
            dot = "●" if tool.locate() else "○"
            items.append(Choice(f"{dot} {tool.name}", value=tool.key, description=tool.desc,
                                disabled=None if tool.locate() else tool.missing))
        for ckey, ccat in COMBO_CATEGORY.items():
            if ccat == cat:
                title, _, members = COMBOS[ckey]
                ready = any(TOOLS[m.lstrip("@")].locate() for m in members)
                chain = " + ".join(TOOLS[m.lstrip("@")].name for m in members)
                items.append(Choice(f"⚡ Мульти-пошук ({label.lower()})", value=ckey,
                                    description=f"по черзі: {chain}",
                                    disabled=None if ready else "немає інструментів"))
    items += [
        Separator("──────── АВТОМАТИЗАЦІЯ ──────────"),
        Choice("🧭 Збирач — автоматичний збір з дедуплікацією", value="collector",
               description="веб-інтерфейс: сіди → модулі → досьє, тріаж, експорт в OSINT Graph"),
        Separator("──────── СЕРВІС ────────────────"),
        Choice("🔑 GHunt — вхід у Google", value="ghunt_login",
               description="одноразовий ghunt login для пошти Google",
               disabled=None if TOOLS["ghunt"].locate() else "GHunt не встановлено"),
        Choice("⚙  Osintgraph — налаштування", value="osintgraph_setup",
               description="Instagram, Neo4j, Gemini (osintgraph setup)",
               disabled=None if TOOLS["osintgraph"].locate() else "Osintgraph не встановлено"),
        Choice("📁 Папка звітів", value="reports", description=str(REPORTS_DIR)),
        Choice("✖  Вихід", value="exit", description="закрити лаунчер"),
    ]
    return items


def open_reports() -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if IS_WIN:
        os.startfile(REPORTS_DIR)  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        subprocess.call(["open", str(REPORTS_DIR)])
    else:
        subprocess.call(["xdg-open", str(REPORTS_DIR)])


def pause() -> None:
    questionary.press_any_key_to_continue("Натисни будь-яку клавішу, щоб повернутися в меню…",
                                          style=STYLE).ask()


def main_loop() -> None:
    while True:
        clear()
        banner()
        console.print(compact_status())
        console.print()
        choice = questionary.select(
            "Що запускаємо?", choices=build_menu(), style=STYLE,
            instruction="↑↓ рух · друкуй назву, щоб знайти · Enter — запуск · Esc — вихід",
            qmark="❯", use_search_filter=True, use_jk_keys=False, show_description=True,
        ).ask()

        if choice in (None, "exit"):
            console.print("[dim]Бувай![/]")
            return
        if choice == "reports":
            open_reports()
            continue
        if choice == "collector":
            console.print("[dim]Збирач працює у браузері. Ctrl+C — зупинити й повернутися в меню.[/]")
            try:
                subprocess.call([sys.executable, "-m", "collector", "serve"], cwd=Path(__file__).resolve().parent)
            except KeyboardInterrupt:
                pass
            continue
        if choice == "ghunt_login":
            subprocess.call(TOOLS["ghunt"].locate() + ["login"])
        elif choice == "osintgraph_setup":
            subprocess.call(TOOLS["osintgraph"].locate() + ["setup"])
        elif choice in COMBOS:
            run_combo(choice)
        else:
            tool = TOOLS[choice]
            target = ask_target(tool.kind)
            if target is None:
                continue
            run_tool(tool, target)
        pause()


def main() -> int:
    # `osint collect …` forwards to the collector CLI (serve / run / modules / export).
    if sys.argv[1:2] == ["collect"]:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from collector.__main__ import main as collector_main
        return collector_main(sys.argv[2:] or ["serve"])
    parser = argparse.ArgumentParser(description="OSINT toolkit launcher")
    parser.add_argument("--check", action="store_true", help="показати статус інструментів і вийти")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args()

    if args.check:
        banner()
        console.print(Align.center(status_table()))
        missing = [t.name for t in visible() if not t.locate()]
        if missing:
            console.print(f"[yellow]Не знайдено: {', '.join(missing)}[/]")
        return 0
    if not sys.stdin.isatty():
        console.print("[red]Потрібен інтерактивний термінал. Для статусу: --check[/]")
        return 2
    try:
        main_loop()
    except KeyboardInterrupt:
        console.print("\n[dim]Бувай![/]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
