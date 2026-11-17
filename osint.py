#!/usr/bin/env python3
"""OSINT launcher — TUI menu + multi-search over local open-source OSINT tools."""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import threading
import webbrowser
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

try:
    import questionary
    from questionary import Choice, Separator
    from rich.align import Align
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
except ImportError:
    print("Не вистачає пакетів. Встанови: pip install rich questionary")
    sys.exit(1)

__version__ = "2.2.0"

# ─── Config (override via environment) ────────────────────────────────────────
IS_WIN = os.name == "nt"
HOME = Path.home()
TOOLS_DIR = Path(os.environ.get("OSINT_TOOLS_DIR", HOME / "tools"))
REPORTS_DIR = Path(os.environ.get("OSINT_REPORTS_DIR", HOME / "osint-reports"))
SPIDERFOOT_ADDR = os.environ.get("OSINT_SPIDERFOOT_ADDR", "127.0.0.1:5001")

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
GRADIENT = ["#00d7ff", "#00afff", "#5f87ff", "#875fff", "#af5fff", "#ff5fd7"]

STYLE = questionary.Style([
    ("qmark", "fg:#00d7ff bold"),
    ("question", "bold"),
    ("pointer", "fg:#ff5fd7 bold"),
    ("highlighted", "fg:#ff5fd7 bold"),
    ("selected", "fg:#00d7ff"),
    ("answer", "fg:#00d7ff bold"),
    ("separator", "fg:#5f87ff"),
    ("disabled", "fg:#6c6c6c italic"),
    ("instruction", "fg:#6c6c6c"),
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


def _report_dir(target: str, tool: str) -> Path:
    slug = re.sub(r"[^\w.\-@]", "_", target)[:80]
    out = REPORTS_DIR / f"{datetime.now():%Y%m%d-%H%M%S}_{tool}_{slug}"
    out.mkdir(parents=True, exist_ok=True)
    return out


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


HARVESTER_SOURCES = "crtsh,duckduckgo,hackertarget,rapiddns,urlscan,otx,certspotter,yahoo"

TOOLS: dict[str, Tool] = {t.key: t for t in [
    # USERNAME
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
    Tool("holehe", "Holehe", "на яких сервісах зареєстрований", "email", "email",
         _which("holehe"), lambda t: [t["email"], "--only-used"]),
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
    # MEDIA
    Tool("exiftool", "ExifTool", "метадані фото/документів: GPS, камера, дата", "media", "file",
         _which("exiftool"), lambda t: ["-a", "-G1", "-s", t["file"]], tee=True),
    Tool("sherloq", "Sherloq", "форензика зображень (GUI)", "media", "none",
         _repo("sherloq", "sherloq.py"), lambda t: [],
         cwd=lambda t: TOOLS_DIR / "sherloq"),
    Tool("instaloader", "Instaloader", "публічний Instagram-профіль без логіну", "media", "instagram",
         _which("instaloader"),
         lambda t: ["--no-videos", "--no-video-thumbnails", "--no-compress-json", t["instagram"]],
         cwd=lambda t: _report_dir(t["instagram"], "instaloader")),
    # FRAMEWORKS
    Tool("bbot", "BBOT", "рекурсивна розвідка домену: субдомени + пошти", "framework", "domain",
         _which("bbot"),
         lambda t: ["-t", t["domain"], "-p", "subdomain-enum", "email-enum", "-y",
                    "-o", str(_report_dir(t["domain"], "bbot"))]),
    Tool("spiderfoot", "SpiderFoot", f"веб-інтерфейс на {SPIDERFOOT_ADDR} (Ctrl+C — стоп)", "framework", "none",
         _repo("spiderfoot", "sf.py"), lambda t: ["-l", SPIDERFOOT_ADDR],
         cwd=lambda t: TOOLS_DIR / "spiderfoot", open_url=f"http://{SPIDERFOOT_ADDR}"),
]}

COMBOS: dict[str, tuple[str, str, list[str]]] = {
    "combo_username": ("⚡ Мульти: username → Maigret + Sherlock + Social Analyzer + Nexfil + Snoop",
                       "username", ["maigret", "sherlock", "social_analyzer", "nexfil", "snoop"]),
    "combo_email": ("⚡ Мульти: email → Holehe + GHunt + Mosint + нік з email через username-тулзи",
                    "email", ["holehe", "ghunt", "mosint", "@maigret", "@sherlock"]),
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
    raise ValueError(kind)


# ─── Execution ────────────────────────────────────────────────────────────────
def run_tool(tool: Tool, target: dict) -> int:
    base = tool.locate()
    if base is None:
        console.print(f"[red]✗ {tool.name} не знайдено.[/]")
        return 127
    argv = base + tool.build(target)
    cwd = tool.cwd(target)
    console.rule(f"[bold #ff5fd7]{tool.name}[/]", style="#5f87ff")
    console.print(f"[dim]$ {' '.join(argv)}{'  (cwd: ' + str(cwd) + ')' if cwd else ''}[/]\n")

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
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace",
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
            console.print(f"\n[#af5fff]↳ нік з email: {local}[/]")
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
    ready = sum(1 for t in TOOLS.values() if t.locate())
    art.append(f"\n  toolkit launcher v{__version__} · готово {ready}/{len(TOOLS)}", style="dim")
    console.print(Panel(Align.center(art), border_style="#5f87ff", padding=(1, 4)))


def status_table() -> Table:
    table = Table(border_style="#5f87ff", header_style="bold #00d7ff", show_lines=False)
    table.add_column("Категорія", style="bold #00d7ff")
    table.add_column("Інструменти")
    for cat, label in CATEGORIES:
        cells = [
            f"[green]●[/] {t.name}" if t.locate() else f"[red]○[/] [dim]{t.name}[/]"
            for t in TOOLS.values() if t.category == cat
        ]
        table.add_row(label, "   ".join(cells))
    return table


def build_menu() -> list:
    items: list = []
    for cat, label in CATEGORIES:
        items.append(Separator(f"──────── {label} " + "─" * max(2, 22 - len(label))))
        for tool in (t for t in TOOLS.values() if t.category == cat):
            items.append(Choice(f"{tool.name:<16} {tool.desc}", value=tool.key,
                                disabled=None if tool.locate() else "не встановлено"))
        for ckey, ccat in COMBO_CATEGORY.items():
            if ccat == cat:
                title, _, members = COMBOS[ckey]
                ready = any(TOOLS[m.lstrip("@")].locate() for m in members)
                items.append(Choice(title, value=ckey, disabled=None if ready else "немає інструментів"))
    items += [
        Separator("──────── СЕРВІС ────────────────"),
        Choice("🔑 GHunt: увійти в Google (ghunt login)", value="ghunt_login",
               disabled=None if TOOLS["ghunt"].locate() else "GHunt не встановлено"),
        Choice(f"📁 Відкрити папку звітів ({REPORTS_DIR})", value="reports"),
        Choice("✖  Вихід", value="exit"),
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
        console.print(Align.center(status_table()))
        console.print()
        choice = questionary.select(
            "Що запускаємо?", choices=build_menu(), style=STYLE,
            instruction="(↑↓ — вибір, Enter — запуск)", qmark="❯",
        ).ask()

        if choice in (None, "exit"):
            console.print("[dim]Бувай![/]")
            return
        if choice == "reports":
            open_reports()
            continue
        if choice == "ghunt_login":
            subprocess.call(TOOLS["ghunt"].locate() + ["login"])
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
    parser = argparse.ArgumentParser(description="OSINT toolkit launcher")
    parser.add_argument("--check", action="store_true", help="показати статус інструментів і вийти")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args()

    if args.check:
        banner()
        console.print(Align.center(status_table()))
        missing = [t.name for t in TOOLS.values() if not t.locate()]
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
