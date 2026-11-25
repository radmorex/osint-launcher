"""Module registry.

Built-in modules ship with the repo. Extra modules can be dropped as `*.py`
files (each exposing a `MODULES` list) into a local folder that git never sees:

  * `collector/local/`               — gitignored, next to the code
  * `~/.osint-collector/modules/`    — or `$OSINT_COLLECTOR_HOME/modules/`

They are loaded at start-up and merged into the registry, so they show up in
the UI and the CLI like any other module, but never get committed or pushed.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import traceback
from pathlib import Path

from .base import Context, Finding, Module, ModuleError, Result
from .company import MODULES as COMPANY
from .enrich import MODULES as ENRICH
from .files import MODULES as FILES
from .native import MODULES as NATIVE
from .tools import MODULES as TOOLS

REGISTRY: dict[str, type[Module]] = {m.name: m for m in [*NATIVE, *FILES, *TOOLS, *COMPANY, *ENRICH]}
PROFILES = {
    "quick": "лише вбудовані джерела (без зовнішніх тулів), хвилина-дві",
    "standard": "+ Maigret, Sherlock, user-scanner, профілі знайдених акаунтів (socid-extractor), Ignorant, Subfinder, PhoneInfoga, співробітники компаній (CrossLinked, LinkedIn, XING)",
    "deep": "+ theHarvester, Holehe (застарілий), Maigret по 1500 сайтах",
    "selfaudit": "перевірка власного сліду: усе зі standard + монітори активності, з порадами, як приховати",
}


def local_dirs() -> list[Path]:
    home = os.environ.get("OSINT_COLLECTOR_HOME")
    base = Path(home) if home else Path.home() / ".osint-collector"
    return [Path(__file__).resolve().parent.parent / "local", base / "modules"]


def load_local(registry: dict[str, type[Module]], dirs: list[Path] | None = None) -> list[str]:
    """Import every `*.py` in the local folders and register its MODULES."""
    loaded: list[str] = []
    for d in dirs if dirs is not None else local_dirs():
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.py")):
            if f.name.startswith("_"):
                continue
            try:
                spec = importlib.util.spec_from_file_location(f"collector_local_{f.stem}", f)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)  # type: ignore[union-attr]
                for m in getattr(mod, "MODULES", []):
                    registry[m.name] = m
                    loaded.append(m.name)
            except Exception:  # a broken local module must not stop the collector
                print(f"[collector] не вдалося завантажити локальний модуль {f}:", file=sys.stderr)
                traceback.print_exc()
    return loaded


LOCAL = load_local(REGISTRY)

__all__ = ["Context", "Finding", "Module", "ModuleError", "Result", "REGISTRY", "PROFILES",
           "LOCAL", "load_local", "local_dirs"]
