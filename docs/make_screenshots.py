"""Regenerate the README terminal screenshots (docs/*.svg). Run: python docs/make_screenshots.py

Uses the launcher's own banner and status line, with every tool shown as installed.
No real targets: the examples use reserved names (example.com, night_owl).
"""
import sys
from pathlib import Path

from rich.box import HEAVY
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import osint  # noqa: E402

for t in osint.TOOLS.values():          # render every tool as installed
    t.locate = lambda: ["/bin/true"]

OUT = Path(__file__).resolve().parent
RED, DARK, SOFT, DIM, FG = "#ff0000", "#870000", "#ff5f5f", "#626262", "#eeeeee"


def menu_mock() -> Text:
    m = Text()
    m.append("❯ ", style=f"bold {RED}")
    m.append("Що запускаємо? ", style=f"bold {FG}")
    m.append("↑↓ рух · друкуй назву, щоб знайти · Enter — запуск\n", style=DIM)
    rows = [("sep", "USERNAME"),
            ("item", "● user-scanner       2500+ сайтів, без хибних збігів"),
            ("item", "● Maigret            3000+ сайтів, рекурсія, HTML-звіт"),
            ("item", "● Sherlock           класика пошуку по ніку"),
            ("sel", "⚡ Мульти-пошук (username)"),
            ("sep", "ФАЙЛИ / АНАЛІЗ"),
            ("item", "● Зв'язки між файлами  відбитки (EXIF, автор, XMP) + стиль письма"),
            ("item", "● pdfx               метадані й посилання з PDF"),
            ("sep", "АВТОМАТИЗАЦІЯ"),
            ("item", "🧭 Збирач — автоматичний збір з дедуплікацією"),
            ("dim", "…")]
    for kind, label in rows:
        if kind == "sep":
            m.append(f"   ──────── {label} " + "─" * max(2, 22 - len(label)) + "\n", style=DARK)
        elif kind == "sel":
            m.append(" » ", style=f"bold {RED}")
            m.append(f" {label} \n", style=f"bold #ffffff on {DARK}")
        elif kind == "dim":
            m.append("   " + label + "\n", style=DIM)
        else:
            dot, rest = label[:1], label[1:]
            m.append("   ")
            m.append(dot, style=RED if dot == "●" else FG)
            m.append(rest + "\n", style=FG)
    return m


c = Console(record=True, width=100, force_terminal=True, color_system="truecolor")
osint.console = c
head = Text(justify="center")
head.append("▓▒░ OSINT ░▒▓", style=f"bold {RED}")
head.append("   open-source intelligence toolkit\n", style=f"bold {SOFT}")
head.append("root@osint:~$ ", style="#af0000")
head.append(f"v{osint.__version__} · {len(osint.visible())}/{len(osint.visible())} armed", style=FG)
head.append("_", style=f"bold {RED}")
c.print(Panel(head, border_style="#af0000", box=HEAVY, padding=(0, 2)))
c.print(osint.compact_status())
c.print()
c.print(menu_mock())
c.save_svg(str(OUT / "terminal.svg"), title="osint")

print("written:", *sorted(p.name for p in OUT.glob("*.svg")))
