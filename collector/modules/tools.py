"""Wrappers around CLI tools the launcher already installs.

Each wrapper runs the tool with machine-readable output where it exists, keeps
the raw output as evidence and turns it into findings. Parsers are separate
functions so they can be tested on saved output without running the tool.
"""
from __future__ import annotations

import csv
import io
import json
import re
import shutil
from pathlib import Path
from urllib.parse import urlsplit

from .base import Context, Module, ModuleError, Result


def _tool(binary: str) -> str:
    path = shutil.which(binary)
    if not path:
        raise ModuleError(f"не встановлено: {binary}")
    return path


# ─── Usernames ────────────────────────────────────────────────────────────────
def parse_maigret(report: dict) -> Result:
    res = Result()
    for site, info in (report or {}).items():
        status = info.get("status") or {}
        url = status.get("url") or info.get("url_user")
        if not url or str(status.get("status", "")).lower() != "claimed":
            continue
        similar = bool(info.get("is_similar"))
        tags = status.get("tags") or (info.get("site") or {}).get("tags") or []
        res.add("account", url, "has_account", 0.35 if similar else 0.75,
                data={"site": site, "similar_search": similar, "rank": info.get("rank")},
                attrs={"platform": site, "tags": ", ".join(tags)})
        ids = status.get("ids") or {}
        if ids.get("fullname"):
            res.add("person", ids["fullname"], "profile_name", 0.45, data={"site": site})
        for k in ("location", "country"):
            if ids.get(k):
                res.add("location", ids[k], "profile_location", 0.4, data={"site": site})
        for k, v in ids.items():
            if k.endswith("username") or k in ("usernames",):
                for u in (v if isinstance(v, list) else str(v).split(",")):
                    if str(u).strip():
                        res.add("username", str(u).strip(), "linked_username", 0.55, data={"site": site})
            if k in ("links", "website") and v:
                for link in (v if isinstance(v, list) else [v]):
                    if str(link).startswith("http") and str(link).rstrip("/") != str(url).rstrip("/"):
                        res.add("url", str(link), "profile_link", 0.6, data={"site": site})
            if k == "email" and v:
                res.add("email", str(v), "profile_email", 0.7, data={"site": site})
    return res


def canary_name() -> str:
    """A username nobody has: sites that 'find' it answer yes to anything."""
    import secrets
    import string
    return "zq" + "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(12))


def drop_false_positives(report: dict, canary_report: dict, remembered: set | None = None) -> tuple[dict, list[str]]:
    bad = set(canary_report or {}) | set(remembered or ())
    return {k: v for k, v in (report or {}).items() if k not in bad}, sorted(bad & set(report or {}))


class FalsePositives:
    """Sites caught answering 'found' for a nonexistent canary nick, remembered for 30 days.

    Such sites lie only some of the time, so a single canary can miss them; memory
    across runs makes the filter stable.
    """
    TTL = 30 * 24 * 3600

    def __init__(self, ctx: Context, module: str):
        import os
        base = Path(ctx.env.get("COLLECTOR_DATA") or Path(os.path.expanduser("~")) / ".osint-collector")
        self.path, self.module = base / "false_positives.json", module

    def load(self) -> set[str]:
        import time
        try:
            data = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return set()
        now = time.time()
        return {site for site, ts in (data.get(self.module) or {}).items() if now - ts < self.TTL}

    def add(self, sites) -> None:
        import time
        if not sites:
            return
        try:
            data = json.loads(self.path.read_text())
        except (OSError, ValueError):
            data = {}
        mod = data.setdefault(self.module, {})
        for site in sites:
            mod[site] = time.time()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(data, ensure_ascii=False, indent=1))
        except OSError:
            pass


class Maigret(Module):
    name, title = "maigret", "Maigret (акаунти за ніком, з перевіркою на хибні збіги)"
    consumes, produces = ("username",), ("account", "person", "location", "username", "url")
    reliability, cost, concurrency, timeout = 0.8, 8, 1, 900
    binary = "maigret"
    profiles = ("standard", "deep")
    TOP = {"standard": 500, "deep": 1500}
    version = 3   # 2: canary filter, 3: remembered false positives

    def accepts(self, entity: dict) -> bool:
        return entity["type"] == "username" and "generic" not in (entity.get("flags") or [])

    def run(self, entity: dict, ctx: Context) -> Result:
        user, canary = entity["value"], canary_name()
        top = self.TOP.get(ctx.env.get("COLLECTOR_PROFILE", "standard"), 500)
        p = ctx.run_tool([_tool("maigret"), user, canary, "-J", "simple", "-fo", str(ctx.workdir),
                          "--no-color", "--no-progressbar", "--no-recursion", "--timeout", "15",
                          "--top-sites", str(top)])
        reports = {f.name: f for f in Path(ctx.workdir).glob("*_simple.json")}
        mine = next((f for n, f in reports.items() if n == f"report_{user.replace('/', '_')}_simple.json"), None)
        mine = mine or next((f for n, f in reports.items() if canary not in n), None)
        if not mine:
            raise ModuleError("maigret не створив звіт: " + (p.stderr or p.stdout)[-300:].strip())
        canary_file = next((f for n, f in reports.items() if canary in n), None)
        raw = mine.read_bytes()
        canary_report = json.loads(canary_file.read_bytes() or b"{}") if canary_file else {}
        memory = FalsePositives(ctx, "maigret")
        memory.add(canary_report)
        report, bad = drop_false_positives(json.loads(raw or b"{}"), canary_report, memory.load())
        res = parse_maigret(report)
        if bad:
            res.attrs["maigret_відкинуто"] = (f"{len(bad)} сайтів відповідають «є» на будь-який нік: "
                                               + ", ".join(bad))
        res.raw, res.raw_ext = raw, "json"
        return res


def parse_sherlock(text: str) -> Result:
    res = Result()
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"^(?:\[\+\]\s*([^:]+):\s*)?(https?://\S+)$", line)
        if m:
            url = m.group(2)
            site = (m.group(1) or urlsplit(url).hostname or "").strip()
            res.add("account", url, "has_account", 0.65, data={"site": site}, attrs={"platform": site})
    return res


def sherlock_sections(text: str) -> dict[str, str]:
    """Split Sherlock's stdout into one block per username ('[*] Checking username X on:')."""
    out: dict[str, list[str]] = {}
    cur = None
    for line in text.splitlines():
        m = re.match(r"^\[\*\]\s+Checking username\s+(\S+)\s+on:", line.strip())
        if m:
            cur = m.group(1)
            out[cur] = []
        elif cur is not None:
            out[cur].append(line)
    return {u: "\n".join(lines) for u, lines in out.items()}


class Sherlock(Module):
    name, title = "sherlock", "Sherlock (акаунти за ніком, з перевіркою на хибні збіги)"
    consumes, produces = ("username",), ("account",)
    reliability, cost, concurrency, timeout = 0.7, 6, 1, 600
    binary = "sherlock"
    profiles = ("standard", "deep")
    version = 3   # 2: canary filter, 3: remembered false positives

    def accepts(self, entity: dict) -> bool:
        return entity["type"] == "username" and "generic" not in (entity.get("flags") or [])

    def run(self, entity: dict, ctx: Context) -> Result:
        user, canary = entity["value"], canary_name()
        out = Path(ctx.workdir)
        p = ctx.run_tool([_tool("sherlock"), user, canary, "--print-found", "--no-color",
                          "--timeout", "15", "--folderoutput", str(out)])
        sections = sherlock_sections(p.stdout)
        text = sections.get(user, p.stdout if not sections else "")
        res = parse_sherlock(text)
        memory = FalsePositives(ctx, "sherlock")
        if canary in sections:
            memory.add({(urlsplit(f.value).hostname or "") for f in parse_sherlock(sections[canary]).findings})
        bad_hosts = memory.load()
        kept = [f for f in res.findings if (urlsplit(f.value).hostname or "") not in bad_hosts]
        dropped = sorted({(urlsplit(f.value).hostname or "").removeprefix("www.")
                          for f in res.findings if f not in kept})
        res.findings = kept
        if dropped:
            res.attrs["sherlock_відкинуто"] = (f"{len(dropped)} сайтів відповідають «є» на будь-який нік: "
                                                + ", ".join(dropped))
        res.raw = text.encode()
        return res


# ─── Email ────────────────────────────────────────────────────────────────────
def parse_holehe(csv_text: str, email: str) -> Result:
    res = Result()
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    broken = sum(1 for r in rows if str(r.get("rateLimit", "")).strip().lower() == "true")
    if rows and broken / len(rows) >= 0.8 and not any(str(r.get("exists", "")).lower() == "true" for r in rows):
        raise ModuleError(f"Holehe: {broken} з {len(rows)} перевірок не відпрацювали (сайти змінились або "
                          f"блокують). Результат недостовірний; дивіться user-scanner")
    if broken:
        res.attrs["holehe_не_перевірено"] = f"{broken} з {len(rows)} сайтів"
    for row in rows:
        if str(row.get("exists", "")).strip().lower() != "true":
            continue
        domain = (row.get("domain") or row.get("name") or "").strip()
        if not domain:
            continue
        data = {k: row[k] for k in ("emailrecovery", "phoneNumber", "others")
                if row.get(k) and row[k] not in ("None", "")}
        res.add("account", f"{domain} · {email}", "registered_on", 0.8, data=data,
                attrs={"platform": domain, **({"recovery_hint": data["emailrecovery"]}
                                              if "emailrecovery" in data else {}),
                       **({"phone_hint": data["phoneNumber"]} if "phoneNumber" in data else {})})
    return res


class Holehe(Module):
    # Upstream unmaintained since 2024: most checks broke as sites changed. user-scanner replaces it
    # in the standard profile; Holehe stays in deep and reports when its result can't be trusted.
    name, title = "holehe", "Holehe (застарілий; де зареєстровано email)"
    consumes, produces = ("email",), ("account",)
    reliability, cost, concurrency, timeout = 0.6, 4, 1, 400
    binary = "holehe"
    profiles = ("deep",)

    def accepts(self, entity: dict) -> bool:
        flags = entity.get("flags") or []
        return entity["type"] == "email" and "disposable" not in flags and "role" not in flags

    def run(self, entity: dict, ctx: Context) -> Result:
        # -NP: skip modules that use password recovery, so the target gets no reset emails.
        p = ctx.run_tool([_tool("holehe"), entity["value"], "--only-used", "--no-color",
                          "--no-clear", "-NP", "-C", "-T", "15"])
        files = sorted(Path(ctx.workdir).glob("holehe_*_results.csv"))
        if not files:
            raise ModuleError("holehe не створив CSV: " + (p.stderr or p.stdout)[-300:].strip())
        text = files[-1].read_text(errors="replace")
        res = parse_holehe(text, entity["value"])
        res.raw, res.raw_ext = text.encode(), "csv"
        return res


# ─── user-scanner (email + username, maintained) ─────────────────────────────
def parse_user_scanner(rows: list, kind: str, value: str) -> Result:
    res = Result()
    stats = {"found": 0, "not": 0, "error": 0, "skipped": 0}
    for r in rows or []:
        st = str(r.get("status", "")).lower()
        site = str(r.get("site_name", "")).strip()
        url = str(r.get("url", "")).strip()
        if st in ("registered", "found"):
            stats["found"] += 1
            meta = {k: v for k, v in (r.get("extra") or {}).items() if v not in ("", None)}
            if kind == "email" or not url.startswith("http"):
                host = (urlsplit(url).hostname or site.lower()).removeprefix("www.")
                res.add("account", f"{host} · {value}", "registered_on", 0.85, data=meta,
                        attrs={"platform": site, "category": r.get("category", "")})
            else:
                res.add("account", url, "has_account", 0.85, data=meta,
                        attrs={"platform": site, "category": r.get("category", ""),
                               **{k: str(v) for k, v in meta.items() if k in ("followers", "title", "name")}})
        elif st == "error":
            stats["error"] += 1
        elif st == "skipped":
            stats["skipped"] += 1
        else:
            stats["not"] += 1
    checked = stats["found"] + stats["not"] + stats["error"]
    res.attrs["user_scanner"] = (f"знайдено {stats['found']} · не знайдено {stats['not']} · помилок {stats['error']}"
                                 + (f" · пропущено {stats['skipped']} (сповістили б власника)" if stats["skipped"] else ""))
    if checked and stats["error"] / checked > 0.6:
        raise ModuleError(f"user-scanner: {stats['error']} з {checked} перевірок з помилкою, результат недостовірний")
    return res


class UserScanner(Module):
    name, title = "user_scanner", "user-scanner (де є email / нік; без сповіщень власнику)"
    consumes, produces = ("email", "username"), ("account",)
    reliability, cost, concurrency, timeout = 0.85, 5, 1, 900
    binary = "user-scanner"
    profiles = ("standard", "deep")

    def accepts(self, entity: dict) -> bool:
        flags = entity.get("flags") or []
        return entity["type"] in self.consumes and "generic" not in flags and "disposable" not in flags

    def run(self, entity: dict, ctx: Context) -> Result:
        out = Path(ctx.workdir) / "user_scanner.json"
        mode = "-e" if entity["type"] == "email" else "-u"
        # never --allow-loud: checks that would notify the account owner stay skipped
        p = ctx.run_tool([_tool("user-scanner"), mode, entity["value"], "-f", "json", "-o", str(out)])
        if not out.exists():
            raise ModuleError("user-scanner не створив JSON: " + (p.stderr or p.stdout)[-300:].strip())
        raw = out.read_bytes()
        res = parse_user_scanner(json.loads(raw or b"[]"), entity["type"], entity["value"])
        res.raw, res.raw_ext = raw, "json"
        return res


# ─── Phone ────────────────────────────────────────────────────────────────────
# ITU calling codes: 1 and 7 are one digit, these are two, everything else is three.
_CC2 = {"20", "27", "30", "31", "32", "33", "34", "36", "39", "40", "41", "43", "44", "45", "46", "47", "48",
        "49", "51", "52", "53", "54", "55", "56", "57", "58", "60", "61", "62", "63", "64", "65", "66", "81",
        "82", "84", "86", "90", "91", "92", "93", "94", "95", "98"}


def split_cc(e164: str) -> tuple[str, str]:
    """'+380000000000' → ('380', '000000000')."""
    d = e164.lstrip("+")
    n = 1 if d[:1] in ("1", "7") else 2 if d[:2] in _CC2 else 3
    return d[:n], d[n:]


def parse_ignorant(text: str, phone: str) -> Result:
    res = Result()
    for line in text.splitlines():
        m = re.match(r"^\s*\[\+\]\s+([a-z0-9.-]+\.[a-z]{2,})\s*$", re.sub(r"\x1b\[[0-9;]*m", "", line), re.I)
        if m:
            site = m.group(1).lower()
            res.add("account", f"{site} · {phone}", "registered_on", 0.8, attrs={"platform": site})
    return res


class Ignorant(Module):
    name, title = "ignorant", "Ignorant (де зареєстровано номер)"
    consumes, produces = ("phone",), ("account",)
    reliability, cost, concurrency, timeout = 0.75, 2, 1, 180
    binary = "ignorant"
    profiles = ("standard", "deep")

    def run(self, entity: dict, ctx: Context) -> Result:
        cc, num = split_cc(entity["value"])
        p = ctx.run_tool([_tool("ignorant"), cc, num, "--only-used", "--no-color", "--no-clear"])
        res = parse_ignorant(p.stdout, entity["value"])
        res.raw = (p.stdout + p.stderr).encode()
        return res


def parse_phoneinfoga(text: str) -> dict:
    attrs = {}
    for line in text.splitlines():
        m = re.match(r"^\s*(Country|Carrier|Line type|Local|International|Valid)\s*:\s*(.+)$", line)
        if m and m.group(2).strip():
            key = {"Line type": "line_type"}.get(m.group(1), m.group(1).lower())
            attrs.setdefault(key, m.group(2).strip())
    return attrs


class PhoneInfoga(Module):
    name, title = "phoneinfoga", "PhoneInfoga (країна, оператор)"
    consumes, produces = ("phone",), ()
    reliability, cost, concurrency, timeout = 0.85, 2, 2, 120
    binary = "phoneinfoga"
    profiles = ("standard", "deep")

    def run(self, entity: dict, ctx: Context) -> Result:
        p = ctx.run_tool([_tool("phoneinfoga"), "scan", "-n", entity["value"], "-D", "googlesearch"])
        res = Result(raw=(p.stdout + p.stderr).encode())
        res.attrs.update(parse_phoneinfoga(p.stdout))
        if not res.attrs and p.returncode != 0:
            raise ModuleError((p.stderr or p.stdout)[-300:].strip() or "phoneinfoga: помилка")
        return res


# ─── Domains ──────────────────────────────────────────────────────────────────
def parse_subfinder(jsonl: str, domain: str) -> Result:
    res = Result()
    hosts: dict[str, set[str]] = {}
    for line in jsonl.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        host = str(row.get("host", "")).lower().removeprefix("*.")
        if host.endswith("." + domain):
            hosts.setdefault(host, set()).update(row.get("sources") or [row.get("source", "")])
    for host, sources in sorted(hosts.items()):
        sources.discard("")
        # More independent passive sources → more likely real.
        conf = min(0.9, 0.55 + 0.1 * len(sources))
        res.add("domain", host, "subdomain", conf, data={"sources": sorted(sources)})
    return res


class Subfinder(Module):
    name, title = "subfinder", "Subfinder (піддомени, пасивно)"
    consumes, produces = ("domain",), ("domain",)
    reliability, cost, concurrency, timeout = 0.8, 4, 1, 300
    binary = "subfinder"
    profiles = ("standard", "deep")

    def accepts(self, entity: dict) -> bool:
        from ..normalize import registered_domain
        v = entity["value"]
        return entity["type"] == "domain" and v == registered_domain(v) \
            and "platform" not in (entity.get("flags") or [])

    def run(self, entity: dict, ctx: Context) -> Result:
        p = ctx.run_tool([_tool("subfinder"), "-d", entity["value"], "-silent", "-oJ", "-cs",
                          "-timeout", "20"])
        res = parse_subfinder(p.stdout, entity["value"])
        res.raw, res.raw_ext = p.stdout.encode(), "jsonl"
        return res


def parse_harvester(data: dict, domain: str) -> Result:
    res = Result()
    for mail in data.get("emails") or []:
        res.add("email", mail, "found_on_domain", 0.6)
    for h in data.get("hosts") or []:
        host, _, ip = str(h).partition(":")
        host = host.lower()
        if host.endswith("." + domain) or host == domain:
            res.add("domain", host, "subdomain", 0.6, data={"ip": ip} if ip else {})
    return res


class TheHarvester(Module):
    name, title = "theharvester", "theHarvester (пошти, хости)"
    consumes, produces = ("domain",), ("email", "domain")
    reliability, cost, concurrency, timeout = 0.65, 6, 1, 600
    binary = "theHarvester"
    profiles = ("deep",)
    SOURCES = "crtsh,duckduckgo,hackertarget,rapiddns,urlscan,otx,certspotter"

    def accepts(self, entity: dict) -> bool:
        from ..normalize import registered_domain
        v = entity["value"]
        return entity["type"] == "domain" and v == registered_domain(v) \
            and "platform" not in (entity.get("flags") or [])

    def run(self, entity: dict, ctx: Context) -> Result:
        base = Path(ctx.workdir) / "harvester"
        p = ctx.run_tool([_tool("theHarvester"), "-d", entity["value"], "-b", self.SOURCES,
                          "-l", "300", "-f", str(base)])
        out = base.with_suffix(".json")
        if not out.exists():
            raise ModuleError("theHarvester не створив JSON: " + (p.stderr or p.stdout)[-300:].strip())
        raw = out.read_bytes()
        res = parse_harvester(json.loads(raw or b"{}"), entity["value"])
        res.raw, res.raw_ext = raw, "json"
        return res


MODULES = [Maigret, UserScanner, Sherlock, Holehe, Ignorant, PhoneInfoga, Subfinder, TheHarvester]
