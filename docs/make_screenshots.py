"""Regenerate the README screenshots (docs/*.svg). Run: python docs/make_screenshots.py"""
import sys
from pathlib import Path
from rich.console import Console
from rich.align import Align
from rich.text import Text

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import osint  # noqa: E402

for t in osint.TOOLS.values():          # render every tool as installed
    t.locate = lambda: ["/bin/true"]

OUT = Path(__file__).resolve().parent
PINK, BLUE, DIM = "#ff5fd7", "#5f87ff", "#6c6c6c"


def menu_mock() -> Text:
    m = Text()
    m.append("❯ ", style="bold #00d7ff"); m.append("Що запускаємо? ", style="bold")
    m.append("(↑↓ — вибір, Enter — запуск)\n", style=DIM)
    rows = [("sep", "USERNAME"), ("item", "Maigret          3000+ сайтів, рекурсія, HTML-звіт"),
            ("item", "Snoop            упор на RU/СНД-сегмент"), ("item", "Sherlock         класика пошуку по ніку"),
            ("item", "Social Analyzer  1000+ сайтів з оцінкою впевненості"), ("item", "Nexfil           швидкий пошук по ніку"),
            ("sel", "⚡ Мульти: username → Maigret + Sherlock + Social Analyzer + Nexfil + Snoop"),
            ("sep", "EMAIL"), ("item", "Holehe           на яких сервісах зареєстрований"),
            ("item", "GHunt            розбір Google-акаунта"), ("dim", "…")]
    for kind, label in rows:
        if kind == "sep":
            m.append(f"   ──────── {label} " + "─" * (22 - len(label)) + "\n", style=BLUE)
        elif kind == "sel":
            m.append(" » " + label + "\n", style=f"bold {PINK}")
        elif kind == "dim":
            m.append("   " + label + "\n", style=DIM)
        else:
            m.append("   " + label + "\n")
    return m


c = Console(record=True, width=110, force_terminal=True, color_system="truecolor")
osint.console = c
osint.banner()
c.print(Align.center(osint.status_table()))
c.print()
c.print(menu_mock())
c.save_svg(str(OUT / "menu.svg"), title="osint")

c = Console(record=True, width=110, force_terminal=True, color_system="truecolor")
c.print(Text("❯ Email: ", style="bold #00d7ff") + Text("john.doe@example.com", style="bold #00d7ff"))
for name, lines in [
    ("Holehe", ["[+] github.com", "[+] spotify.com", "[+] twitter.com", "[x] instagram.com (rate limit)"]),
    ("GHunt", ["🙋 Google Account data", "Gaia ID : 1083…", "Last profile edit : 2026/03/02", "[+] 3 public reviews on Maps"]),
    ("Mosint", ["[*] DNS Lookup", "[+] MX aspmx.l.google.com.", "[*] IP Lookup", "[+] Country: US"]),
]:
    c.rule(f"[bold {PINK}]{name}[/]", style=BLUE)
    for ln in lines:
        c.print(ln, highlight=False, markup=False)
    c.print(f"[green]● {name} завершено, код 0[/]\n")
c.print("[#af5fff]↳ нік з email: john.doe[/]")
c.rule(f"[bold {PINK}]Maigret[/]", style=BLUE)
c.print("[*] Checking username john.doe on: 3112 sites …", highlight=False)
c.print("[green]● Maigret завершено, код 0[/]")
c.print(f"[dim]  звіт: ~/osint-reports/20261117-201455_maigret_john.doe/[/]")
c.save_svg(str(OUT / "multisearch.svg"), title="osint — мульти-пошук")
print("written:", *sorted(p.name for p in OUT.glob("*.svg")))
