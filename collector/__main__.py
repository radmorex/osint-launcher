"""CLI.

  python -m collector serve                      # web UI on http://127.0.0.1:8765
  python -m collector run ivan@example.com night_owl --depth 2 --out case.osint.json
  python -m collector modules                    # what is installed / available
  python -m collector export 3 --out case.osint.json
  python -m collector link ~/Documents/leaked-folder  # file fingerprints + writing style
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .engine import DEFAULTS, Engine
from .export import build_tree, to_csv
from .modules import PROFILES, REGISTRY
from .store import Store

DATA_DIR = Path(os.environ.get("OSINT_REPORTS_DIR", Path.home() / "osint-reports")) / "collector"


def _open() -> tuple[Store, Engine]:
    store = Store(DATA_DIR / "collector.db")
    return store, Engine(store, DATA_DIR)


def cmd_modules(_: argparse.Namespace) -> int:
    for m in REGISTRY.values():
        d = m.describe()
        mark = "●" if d["available"] else "○"
        if not d["env_key"]:
            key = ""
        elif d["has_key"]:
            key = f"  [ключ {d['env_key']}: є]"
        else:
            need = d["key_required"] or not d["available"]
            key = f"  [ключ {d['env_key']}: {'немає, потрібен' if need else 'немає, працює без нього'}]"
        print(f"{mark} {d['name']:<13} {d['title']:<42} {','.join(d['consumes']):<16} "
              f"профілі: {','.join(d['profiles'])}{key}{'  — ' + d['reason'] if d['reason'] else ''}")
    print("\nПрофілі:", *(f"\n  {k}: {v}" for k, v in PROFILES.items()))
    return 0


def cmd_run(a: argparse.Namespace) -> int:
    store, engine = _open()
    settings = {**DEFAULTS, "profile": a.profile, "max_depth": a.depth, "budget": a.budget,
                "scope": a.scope or []}
    cid = store.create_case(a.case or " · ".join(a.seeds), a.purpose or "", settings)
    for s in a.seeds:
        kind, _, val = s.partition(":") if s.split(":", 1)[0] in (
            "username", "email", "phone", "domain", "ip", "url") else ("", "", s)
        try:
            e = engine.add_seed(cid, val or s, kind or None)
            print(f"сід: {e['type']} {e['value']}")
        except ValueError as err:
            print(f"пропущено: {err}", file=sys.stderr)

    def tick(p: dict) -> None:
        if sys.stderr.isatty():
            print(f"\r  в черзі {p['queued']:>3} · виконується {p['running']:>2} · готово {p['done']:>3} "
                  f"· помилок {p['error']:>2} · бюджет {p['budget_used']}/{p['budget']}   ",
                  end="", file=sys.stderr, flush=True)

    p = engine.wait(cid, poll=0.5, on_tick=tick)
    print(file=sys.stderr)
    ents = store.entities(cid)
    by_type: dict[str, int] = {}
    for e in ents:
        by_type[e["type"]] = by_type.get(e["type"], 0) + 1
    print(f"Справа #{cid}: {len(ents)} сутностей — " + ", ".join(f"{k} {v}" for k, v in sorted(by_type.items())))
    suggested = [e for e in ents if e["pivot"] == "suggested"]
    if suggested:
        print(f"Запропоновано розгорнути вручну: {len(suggested)} (див. веб-інтерфейс, вкладка «Тріаж»)")
    for r in store.runs(cid):
        if r["state"] == "error":
            print(f"  помилка {r['module']} ({r['entity_value']}): {r['error']}", file=sys.stderr)
    if a.out:
        out = Path(a.out)
        if out.suffix == ".csv":
            out.write_text(to_csv(store, cid), encoding="utf-8-sig")
        else:
            out.write_text(json.dumps(build_tree(store, cid), ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"Збережено: {out}")
    engine.shutdown()
    return 0 if p["error"] == 0 else 1


def cmd_export(a: argparse.Namespace) -> int:
    store = Store(DATA_DIR / "collector.db")
    if a.csv:
        text = to_csv(store, a.case_id)
    else:
        text = json.dumps(build_tree(store, a.case_id, min_confidence=a.min), ensure_ascii=False, indent=1)
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
        print(f"Збережено: {a.out}")
    else:
        print(text)
    return 0


def cmd_link(a: argparse.Namespace) -> int:
    from datetime import datetime

    from .analysis import link_case
    store, engine = _open()
    target = Path(a.path).expanduser().resolve()
    settings = {**DEFAULTS, "profile": "quick", "max_depth": 1, "budget": 50}
    cid = store.create_case(a.case or f"Файли: {target.name}", "зв'язки між файлами", settings)
    seed = engine.add_seed(cid, str(target), "file")
    print(f"Файлів додано: {seed.get('count', 1)}")
    engine.wait(cid, poll=0.5)
    rep = link_case(store, cid, style_threshold=a.threshold)
    engine.shutdown()

    print(f"\nТекстів для порівняння стилю: {rep['texts']}"
          + (f" (замало слів: {', '.join(rep['too_short'][:5])}{' …' if len(rep['too_short']) > 5 else ''})"
             if rep["too_short"] else ""))
    for n in rep["notes"]:
        print("  ! " + n)
    print("\nСпільні відбитки в метаданих:" if rep["shared"] else "\nСпільних відбитків у метаданих немає.")
    for r in rep["shared"]:
        print(f"  • {r['what']}  →  {', '.join(r['files'])}")
    print("\nСхожий стиль письма (зачіпка, не доказ):" if rep["style"] else "\nЗбігів стилю вище порогу немає.")
    for r in rep["style"]:
        extra = f"; спільні звички: {', '.join(r['shared_habits'])}" if r["shared_habits"] else ""
        print(f"  • {r['a']} ↔ {r['b']}: {round(r['score'] * 100)}% "
              f"(символи {r['chars']}, слова {r['words']}, звички {r['habits']}{extra})")
    if rep["images"]:
        print("\nМайже однакові зображення:")
        for r in rep["images"]:
            print(f"  • {r['a']} ↔ {r['b']} (відстань {r['distance']})")

    out = Path(a.out) if a.out else DATA_DIR.parent / f"{datetime.now():%Y%m%d-%H%M%S}_links_{target.name}.osint.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(build_tree(store, cid), ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\nГраф для OSINT Graph: {out}\nСправа #{cid} також відкривається у веб-інтерфейсі (osint collect).")
    return 0


def cmd_serve(a: argparse.Namespace) -> int:
    from .server import serve
    store, engine = _open()
    serve(store, engine, port=a.port, open_browser=not a.no_browser)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="collector", description="OSINT collector: автоматизований збір")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="веб-інтерфейс")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--no-browser", action="store_true")
    s.set_defaults(fn=cmd_serve)

    r = sub.add_parser("run", help="зібрати по сідах і вийти")
    r.add_argument("seeds", nargs="+", help="значення; тип визначається сам або явно: email:x@y.z")
    r.add_argument("--case", help="назва справи")
    r.add_argument("--purpose", help="мета / правова підстава")
    r.add_argument("--profile", choices=list(PROFILES), default=DEFAULTS["profile"])
    r.add_argument("--depth", type=int, default=DEFAULTS["max_depth"])
    r.add_argument("--budget", type=int, default=DEFAULTS["budget"])
    r.add_argument("--scope", nargs="*", help="домени у скоупі")
    r.add_argument("--out", help="файл .osint.json або .csv")
    r.set_defaults(fn=cmd_run)

    lk = sub.add_parser("link", help="зв'язки між файлами: відбитки метаданих і стиль письма")
    lk.add_argument("path", help="папка або файл")
    lk.add_argument("--case", help="назва справи")
    lk.add_argument("--threshold", type=float, help="поріг схожості стилю 0..1 (типово 0.72, для 2 текстів 0.9)")
    lk.add_argument("--out", help="куди зберегти .osint.json")
    lk.set_defaults(fn=cmd_link)

    m = sub.add_parser("modules", help="список модулів і що встановлено")
    m.set_defaults(fn=cmd_modules)

    e = sub.add_parser("export", help="експорт справи")
    e.add_argument("case_id", type=int)
    e.add_argument("--out")
    e.add_argument("--csv", action="store_true")
    e.add_argument("--min", type=float, default=0.0, help="мінімальна впевненість")
    e.set_defaults(fn=cmd_export)

    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
