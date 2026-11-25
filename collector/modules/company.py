"""Company → employees: CrossLinked (search engines, no login), LinkedInDumper, XingDumper.

Seed an `org` with a company name (CrossLinked) or with the company page URL
(https://www.linkedin.com/company/<x>, https://www.xing.com/pages/<x>).
Employees become `person` entities with their profile as an `account`.
If the case has an e-mail format ("{first}.{last}@firma.ua"), likely addresses
are generated too, at low confidence: they land in triage, never get checked
automatically.

LinkedIn and XING forbid scraping in their terms and ban accounts for it: use
a spare account's cookie (LINKEDIN_LI_AT, XING_LOGIN_COOKIE).
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import unicodedata
from pathlib import Path

from .base import Context, Module, ModuleError, Result

TOOLS_DIR = Path(os.environ.get("OSINT_TOOLS_DIR", Path.home() / "tools"))
LINKEDIN_CO = re.compile(r"^https?://([a-z]{2,3}\.)?(www\.)?linkedin\.com/company/[^/?#]+", re.I)
XING_CO = re.compile(r"^https?://(www\.)?xing\.com/pages/[^/?#]+", re.I)


# Ukrainian national transliteration (2010), plus the Russian-only letters.
_TR = {"а": "a", "б": "b", "в": "v", "г": "h", "ґ": "g", "д": "d", "е": "e", "є": "ie", "ж": "zh", "з": "z",
       "и": "y", "і": "i", "ї": "i", "й": "i", "к": "k", "л": "l", "м": "m", "н": "n", "о": "o", "п": "p",
       "р": "r", "с": "s", "т": "t", "у": "u", "ф": "f", "х": "kh", "ц": "ts", "ч": "ch", "ш": "sh",
       "щ": "shch", "ь": "", "ю": "iu", "я": "ia", "'": "", "’": "", "ё": "e", "ы": "y", "э": "e", "ъ": ""}
_TR_START = {"є": "ye", "ї": "yi", "й": "y", "ю": "yu", "я": "ya"}


def translit(word: str) -> str:
    out = []
    for i, ch in enumerate(word.lower()):
        out.append(_TR_START.get(ch) if i == 0 and ch in _TR_START else _TR.get(ch, ch))
    return "".join(out)


def _ascii(s: str) -> str:
    s = unicodedata.normalize("NFKD", translit(s)).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z]", "", s.lower())


def email_candidates(first: str, last: str, fmt: str) -> str | None:
    """'{first}.{last}@firma.ua' → 'ivan.petrenko@firma.ua'. Also {f} and {l} for initials."""
    f, l = _ascii(first), _ascii(last)
    if not fmt or not f or not l or "@" not in fmt:
        return None
    try:
        return fmt.format(first=f, last=l, f=f[0], l=l[0])
    except (KeyError, IndexError, ValueError):
        return None


def split_name(full: str) -> tuple[str, str]:
    parts = [p for p in re.split(r"\s+", full.strip()) if p and not p.endswith(".")]
    if len(parts) < 2:
        return (parts[0] if parts else "", "")
    return parts[0], parts[-1]


def employees_result(rows: list[dict], fmt: str, site: str) -> Result:
    res = Result()
    for r in rows:
        first, last = (r.get("firstname") or "").strip(), (r.get("lastname") or "").strip()
        if not first or (first == "LinkedIn" and last == "Member"):
            continue
        name = f"{first} {last}".strip()
        meta = {k: r[k] for k in ("position", "location", "gender") if r.get(k) and r[k] != "N/A"}
        res.add("person", name, "employee", 0.75, data={"site": site, **meta}, attrs=meta)
        prof = r.get("profile_link") or r.get("profile")
        if prof and str(prof).startswith("http"):
            res.add("account", prof, "employee_profile", 0.8, attrs={"platform": site, **meta})
        mail = r.get("business_email") or email_candidates(first, last, fmt)
        if mail and mail != "N/A":
            res.add("email", mail, "email_pattern", 0.3, data={"from": name})
        if meta.get("location"):
            res.add("location", meta["location"], "employee_location", 0.3)
    return res


# ─── CrossLinked ──────────────────────────────────────────────────────────────
def parse_crosslinked(csv_text: str) -> list[dict]:
    """names.csv rows: runtime, engine, name, title, url, text."""
    out, seen = [], set()
    for row in csv.reader(io.StringIO(csv_text)):
        if len(row) < 5:
            continue
        name, title, url = row[2].strip(), row[3].strip(), row[4].strip()
        if not name or name.lower() in seen or "linkedin" in name.lower():
            continue
        seen.add(name.lower())
        first, last = split_name(name)
        out.append({"firstname": first, "lastname": last, "position": title,
                    "profile_link": url if "linkedin.com/in/" in url else ""})
    return out


class CrossLinked(Module):
    name, title = "crosslinked", "CrossLinked (співробітники через пошуковики)"
    consumes, produces = ("org",), ("person", "account", "email")
    reliability, cost, concurrency, timeout = 0.6, 5, 1, 600
    binary = "crosslinked"
    profiles = ("standard", "deep")

    def accepts(self, entity: dict) -> bool:
        return entity["type"] == "org" and not entity["value"].startswith("http")

    def run(self, entity: dict, ctx: Context) -> Result:
        out = Path(ctx.workdir) / "names"
        p = ctx.run_tool(["crosslinked", "-f", "{first} {last}", "-o", str(out), entity["value"]])
        csv_file = out.with_suffix(".csv")
        if not csv_file.exists():
            raise ModuleError("crosslinked нічого не зберіг: " + (p.stderr or p.stdout)[-300:].strip())
        text = csv_file.read_text(errors="replace")
        res = employees_result(parse_crosslinked(text), ctx.env.get("COLLECTOR_EMAIL_FORMAT", ""), "LinkedIn")
        res.raw, res.raw_ext = text.encode(), "csv"
        return res


# ─── LinkedInDumper / XingDumper ──────────────────────────────────────────────
class _Dumper(Module):
    key_required = True
    consumes, produces = ("org",), ("person", "account", "email", "location")
    reliability, cost, concurrency, timeout = 0.85, 6, 1, 900
    profiles = ("standard", "deep")
    repo: str = ""
    script: str = ""
    url_re: re.Pattern = LINKEDIN_CO
    site: str = ""
    extra: tuple[str, ...] = ()

    @classmethod
    def _entry(cls) -> list[str] | None:
        root = TOOLS_DIR / cls.repo
        if not (root / cls.script).is_file():
            return None
        py = root / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        return [str(py if py.is_file() else "python3"), str(root / cls.script)]

    @classmethod
    def available(cls) -> tuple[bool, str]:
        if not cls._entry():
            return False, f"не встановлено: {cls.repo} (інсталятор launcher'а)"
        if not os.environ.get(cls.env_key or ""):
            return False, f"задайте {cls.env_key} (cookie запасного акаунта)"
        return True, ""

    def accepts(self, entity: dict) -> bool:
        return entity["type"] == "org" and bool(self.url_re.match(entity["value"]))

    def run(self, entity: dict, ctx: Context) -> Result:
        entry = self._entry()
        cookie = ctx.env.get(self.env_key or "")
        if not entry or not cookie:
            raise ModuleError(self.available()[1])
        out = Path(ctx.workdir) / "employees.json"
        p = ctx.run_tool([*entry, "--url", self.url_re.match(entity["value"]).group(0), "--cookie", cookie,
                          *self.extra, "--output-json", str(out), "--quiet"], cwd=Path(entry[1]).parent)
        if not out.exists():
            raise ModuleError(f"{self.repo} не створив JSON (cookie прострочено?): "
                              + (p.stderr or p.stdout)[-300:].strip())
        raw = out.read_bytes()
        data = json.loads(raw or b"{}")
        res = employees_result(data.get("employees") or [], ctx.env.get("COLLECTOR_EMAIL_FORMAT", ""), self.site)
        res.attrs["employees_found"] = len(data.get("employees") or [])
        res.raw, res.raw_ext = raw, "json"
        return res


class LinkedInDumper(_Dumper):
    name, title = "linkedindumper", "LinkedInDumper (співробітники, cookie li_at)"
    repo, script, url_re, site, env_key = "LinkedInDumper", "linkedindumper.py", LINKEDIN_CO, "LinkedIn", "LINKEDIN_LI_AT"
    extra = ("--jitter",)


class XingDumper(_Dumper):
    name, title = "xingdumper", "XingDumper (співробітники, cookie login)"
    repo, script, url_re, site, env_key = "XingDumper", "xingdumper.py", XING_CO, "XING", "XING_LOGIN_COOKIE"


MODULES = [CrossLinked, LinkedInDumper, XingDumper]
