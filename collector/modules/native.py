"""Built-in modules: no external tools, public sources only, no API keys required."""
from __future__ import annotations

import hashlib
import json
import secrets
import socket
from urllib.parse import quote, urlsplit

from ..normalize import ROLE_LOCALPARTS, normalize, registered_domain
from .base import Context, Module, ModuleError, Result


def _vcard_name(entity: dict) -> str:
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if item and item[0] == "fn":
            return str(item[3])
    return ""


# ─── Offline derivations ──────────────────────────────────────────────────────
class EmailParts(Module):
    name, title = "email_parts", "Розбір email"
    consumes, produces = ("email",), ("username", "domain")
    reliability, cost = 1.0, 0

    def run(self, entity: dict, ctx: Context) -> Result:
        res = Result()
        local, _, host = entity["value"].rpartition("@")
        local = local.split("+", 1)[0]
        flags = set(entity.get("flags") or [])
        # Same nick ≠ same person: below the auto-pivot threshold on purpose.
        if local not in ROLE_LOCALPARTS and len(local) >= 4 and normalize("username", local):
            res.add("username", local, "local_part", 0.5)
        if "freemail" not in flags:
            res.add("domain", host, "email_domain", 0.95)
        return res


class UrlParts(Module):
    # Personal links (blog, site from a profile) only: the host of a profile URL is
    # the platform itself and would flood the case with platform domains.
    name, title = "url_parts", "Розбір URL"
    consumes, produces = ("url",), ("domain",)
    reliability, cost = 1.0, 0

    def accepts(self, entity: dict) -> bool:
        return entity["type"] in self.consumes and entity.get("url", "").startswith("http")

    def run(self, entity: dict, ctx: Context) -> Result:
        res = Result()
        host = urlsplit(entity["url"]).hostname or ""
        if host:
            res.add("domain", host, "hosted_on", 0.95)
        return res


# ─── DNS ──────────────────────────────────────────────────────────────────────
def _resolve(host: str) -> set[str]:
    try:
        return {ai[4][0] for ai in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)}
    except (socket.gaierror, UnicodeError, OSError):
        return set()


class DnsResolve(Module):
    name, title = "dns", "DNS (A/AAAA)"
    consumes, produces = ("domain",), ("ip",)
    reliability, cost, concurrency, timeout = 0.95, 1, 8, 15
    cache_ttl = 6 * 3600

    def run(self, entity: dict, ctx: Context) -> Result:
        host = entity["value"]
        ips = _resolve(host)
        res = Result(raw=json.dumps(sorted(ips)).encode(), raw_ext="json")
        if not ips:
            res.attrs["dns"] = "не резолвиться"
            return res
        # Wildcard zone: a random label resolving to the same IPs means this
        # subdomain proves nothing (it would "exist" under any name).
        reg = registered_domain(host)
        if host != reg:
            probe = _resolve(f"{secrets.token_hex(6)}.{reg}")
            if probe and ips <= probe:
                res.attrs["dns"] = "wildcard-зона: будь-яке ім'я резолвиться"
                res.flags.add("wildcard")
                return res
        for ip in sorted(ips):
            res.add("ip", ip, "resolves_to", 0.95)
        return res


# ─── Certificate transparency ─────────────────────────────────────────────────
class CrtSh(Module):
    name, title = "crtsh", "crt.sh (сертифікати)"
    consumes, produces = ("domain",), ("domain",)
    reliability, cost, concurrency, timeout = 0.9, 2, 2, 90
    MAX = 400

    def accepts(self, entity: dict) -> bool:
        v = entity["value"]
        return entity["type"] == "domain" and v == registered_domain(v) \
            and "platform" not in (entity.get("flags") or [])

    def run(self, entity: dict, ctx: Context) -> Result:
        dom = entity["value"]
        status, data, raw = ctx.http_json(f"https://crt.sh/?q={quote('%.' + dom)}&output=json",
                                          retries=3)
        res = Result(raw=raw, raw_ext="json")
        if status == 404 or not data:
            return res
        names: dict[str, str] = {}
        for row in data:
            for n in str(row.get("name_value", "")).splitlines():
                n = n.strip().lower().removeprefix("*.")
                if n.endswith("." + dom) and n not in names:
                    names[n] = row.get("not_before", "")
        res.attrs["ct_names"] = len(names)
        for n in sorted(names)[: self.MAX]:
            res.add("domain", n, "subdomain", 0.85, data={"cert_not_before": names[n]})
        if len(names) > self.MAX:
            res.attrs["ct_truncated"] = f"показано {self.MAX} з {len(names)}"
        return res


# ─── Registration data ────────────────────────────────────────────────────────
class RdapDomain(Module):
    name, title = "rdap_domain", "RDAP (реєстрація домену)"
    consumes, produces = ("domain",), ()
    reliability, cost, timeout = 0.95, 1, 30
    cache_ttl = 7 * 24 * 3600

    def accepts(self, entity: dict) -> bool:
        v = entity["value"]
        return entity["type"] == "domain" and v == registered_domain(v) \
            and "platform" not in (entity.get("flags") or [])

    def run(self, entity: dict, ctx: Context) -> Result:
        status, data, raw = ctx.http_json(f"https://rdap.org/domain/{entity['value']}")
        res = Result(raw=raw, raw_ext="json")
        if status == 404 or not isinstance(data, dict):
            res.attrs["rdap"] = "немає RDAP для цієї зони"
            return res
        for ev in data.get("events", []):
            action = ev.get("eventAction")
            if action in ("registration", "expiration", "last changed"):
                res.attrs[{"registration": "registered", "expiration": "expires",
                           "last changed": "updated"}[action]] = str(ev.get("eventDate", ""))[:10]
        for ent in data.get("entities", []):
            if "registrar" in (ent.get("roles") or []):
                res.attrs["registrar"] = _vcard_name(ent)
            if "registrant" in (ent.get("roles") or []):
                org = _vcard_name(ent)
                if org and "redacted" not in org.lower() and "privacy" not in org.lower():
                    res.add("org", org, "registrant", 0.7)
        ns = [n.get("ldhName", "").lower() for n in data.get("nameservers", []) if n.get("ldhName")]
        if ns:
            res.attrs["nameservers"] = ", ".join(sorted(ns))
        return res


class RipeStat(Module):
    name, title = "ripestat", "RIPEstat (ASN, мережа)"
    consumes, produces = ("ip",), ()
    reliability, cost, timeout = 0.95, 1, 30
    cache_ttl = 7 * 24 * 3600

    def run(self, entity: dict, ctx: Context) -> Result:
        ip = entity["value"]
        _, data, raw = ctx.http_json(
            f"https://stat.ripe.net/data/prefix-overview/data.json?resource={quote(ip)}&sourceapp=osint-collector")
        res = Result(raw=raw, raw_ext="json")
        d = (data or {}).get("data") or {}
        asns = d.get("asns") or []
        if asns:
            res.attrs["asn"] = ", ".join(f"AS{a.get('asn')} {a.get('holder', '')}".strip() for a in asns)
        if d.get("resource"):
            res.attrs["prefix"] = d["resource"]
        _, geo, _ = ctx.http_json(
            f"https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource={quote(ip)}&sourceapp=osint-collector")
        for loc in ((geo or {}).get("data") or {}).get("located_resources", [])[:1]:
            for l in loc.get("locations", [])[:1]:
                place = ", ".join(x for x in (l.get("city"), l.get("country")) if x)
                if place:
                    res.attrs["geo_ip"] = place + " (GeoIP, приблизно)"
        return res


# ─── Archives ─────────────────────────────────────────────────────────────────
class Wayback(Module):
    name, title = "wayback", "Wayback Machine (перший/останній знімок)"
    consumes, produces = ("domain",), ()
    reliability, cost, concurrency, timeout = 0.95, 1, 2, 45
    cache_ttl = 7 * 24 * 3600

    def accepts(self, entity: dict) -> bool:
        return entity["type"] == "domain" and "platform" not in (entity.get("flags") or [])

    def run(self, entity: dict, ctx: Context) -> Result:
        base = "https://web.archive.org/cdx/search/cdx?output=json&fl=timestamp,original&url="
        dom = quote(entity["value"])
        _, first, raw1 = ctx.http_json(base + dom + "&limit=1", retries=2)
        _, last, raw2 = ctx.http_json(base + dom + "&limit=-1", retries=2)
        res = Result(raw=raw1 + b"\n" + raw2, raw_ext="json")

        def ts(rows: object) -> str:
            if isinstance(rows, list) and len(rows) > 1:
                t = rows[1][0]
                return f"{t[:4]}-{t[4:6]}-{t[6:8]}"
            return ""

        if ts(first):
            res.attrs["archived_first"] = ts(first)
            res.attrs["archived_last"] = ts(last)
            res.attrs["archive_url"] = f"https://web.archive.org/web/*/{entity['value']}*"
        return res


# ─── Accounts with public APIs ────────────────────────────────────────────────
class GitHubUser(Module):
    name, title = "github", "GitHub (профіль і commit-email)"
    consumes, produces = ("username",), ("account", "email", "person", "location", "url", "org")
    reliability, cost, concurrency, timeout = 0.95, 1, 2, 30
    env_key = "GITHUB_TOKEN"

    def _h(self, ctx: Context) -> dict:
        tok = ctx.env.get("GITHUB_TOKEN")
        return {"Authorization": f"Bearer {tok}"} if tok else {}

    def run(self, entity: dict, ctx: Context) -> Result:
        user = entity["value"]
        status, prof, raw = ctx.http_json(f"https://api.github.com/users/{quote(user)}",
                                          headers=self._h(ctx))
        res = Result(raw=raw, raw_ext="json")
        if status == 404 or not isinstance(prof, dict) or not prof.get("html_url"):
            return res
        meta = {k: prof.get(k) for k in ("name", "company", "location", "bio", "created_at",
                                         "public_repos", "followers") if prof.get(k)}
        res.add("account", prof["html_url"], "has_account", 0.95, data=meta,
                attrs={"platform": "GitHub", **meta})
        if prof.get("email"):
            res.add("email", prof["email"], "profile_email", 0.9)
        if prof.get("name"):
            res.add("person", prof["name"], "profile_name", 0.5)
        if prof.get("location"):
            res.add("location", prof["location"], "profile_location", 0.5)
        if prof.get("blog"):
            res.add("url", prof["blog"], "profile_link", 0.8)
        if prof.get("twitter_username"):
            res.add("account", f"https://x.com/{prof['twitter_username']}", "linked_account", 0.85,
                    attrs={"platform": "X"})
        # Commit emails from recent public pushes (if GitHub still includes them).
        try:
            _, events, raw_ev = ctx.http_json(
                f"https://api.github.com/users/{quote(user)}/events/public?per_page=100",
                headers=self._h(ctx), retries=1)
            res.raw += b"\n" + raw_ev
            seen = set()
            for ev in events or []:
                for c in ((ev.get("payload") or {}).get("commits") or []):
                    mail = ((c.get("author") or {}).get("email") or "").lower()
                    if mail and "noreply" not in mail and mail not in seen:
                        seen.add(mail)
                        res.add("email", mail, "commit_email", 0.75,
                                data={"repo": (ev.get("repo") or {}).get("name", "")})
        except ModuleError:
            pass
        return res


class Gravatar(Module):
    name, title = "gravatar", "Gravatar (профіль за email)"
    consumes, produces = ("email",), ("username", "account", "person", "location")
    reliability, cost, timeout = 0.9, 1, 20
    env_key = "GRAVATAR_API_KEY"

    def run(self, entity: dict, ctx: Context) -> Result:
        h = hashlib.sha256(entity["value"].strip().lower().encode()).hexdigest()
        headers = {}
        if ctx.env.get("GRAVATAR_API_KEY"):
            headers["Authorization"] = f"Bearer {ctx.env['GRAVATAR_API_KEY']}"
        status, prof, raw = ctx.http_json(f"https://api.gravatar.com/v3/profiles/{h}", headers=headers)
        res = Result(raw=raw, raw_ext="json")
        if status == 404 or not isinstance(prof, dict) or not prof.get("profile_url"):
            return res
        res.add("account", prof["profile_url"], "has_account", 0.95, attrs={"platform": "Gravatar"})
        slug = urlsplit(prof["profile_url"]).path.strip("/")
        if slug and not slug.isdigit():
            res.add("username", slug, "gravatar_slug", 0.8)
        if prof.get("display_name"):
            res.add("person", prof["display_name"], "profile_name", 0.5)
        if prof.get("location"):
            res.add("location", prof["location"], "profile_location", 0.5)
        for acc in prof.get("verified_accounts") or []:
            if acc.get("url"):
                res.add("account", acc["url"], "verified_account", 0.9,
                        attrs={"platform": acc.get("service_label") or acc.get("service_type", "")})
        if prof.get("avatar_url"):
            res.attrs["avatar"] = prof["avatar_url"]
        return res


MODULES = [EmailParts, UrlParts, DnsResolve, CrtSh, RdapDomain, RipeStat, Wayback,
           GitHubUser, Gravatar]
