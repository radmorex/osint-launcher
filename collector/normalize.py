"""Canonical forms and junk flags for every entity type.

`normalize(type, value)` returns a `Norm` (display value, canonical key, flags) or
None when the value is not a valid instance of the type. The key is what
de-duplication runs on; the display value keeps what the source actually said.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

TYPES = ("username", "email", "phone", "domain", "ip", "url", "account",
         "person", "org", "location", "note", "file", "fingerprint")
COMPANY_PAGE = re.compile(r"^https?://(?:[a-z]{2,3}\.)?(?:www\.)?(linkedin\.com/company|xing\.com/pages)/([^/?#]+)",
                          re.I)

# ─── Reference lists ──────────────────────────────────────────────────────────
# Mail providers: the domain says nothing about the person, never pivot on it.
FREEMAIL = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
    "yahoo.com", "ymail.com", "icloud.com", "me.com", "mac.com", "aol.com", "proton.me",
    "protonmail.com", "pm.me", "gmx.com", "gmx.net", "gmx.de", "web.de", "mail.com",
    "zoho.com", "yandex.ru", "yandex.ua", "yandex.com", "ya.ru", "mail.ru", "bk.ru",
    "inbox.ru", "list.ru", "rambler.ru", "ukr.net", "i.ua", "meta.ua", "tutanota.com",
    "tuta.io", "fastmail.com", "qq.com", "163.com", "126.com", "seznam.cz", "wp.pl",
    "o2.pl", "interia.pl", "libero.it", "orange.fr", "free.fr", "t-online.de",
}
# Providers where "+tag" is an alias of the same mailbox.
PLUS_ALIAS = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
              "icloud.com", "me.com", "proton.me", "protonmail.com", "pm.me",
              "fastmail.com", "zoho.com", "yandex.ru", "yandex.com", "ya.ru"}
DISPOSABLE = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "temp-mail.org",
    "tempmail.com", "yopmail.com", "trashmail.com", "sharklasers.com", "getnada.com",
    "dispostable.com", "maildrop.cc", "throwawaymail.com", "fakeinbox.com", "mohmal.com",
    "emailondeck.com", "mintemail.com", "tempr.email", "discard.email", "moakt.com",
}
ROLE_LOCALPARTS = {
    "info", "admin", "administrator", "support", "help", "contact", "sales", "office",
    "hello", "mail", "webmaster", "postmaster", "hostmaster", "abuse", "noreply",
    "no-reply", "donotreply", "marketing", "press", "media", "jobs", "hr", "billing",
    "security", "privacy", "team", "service", "feedback", "root", "test", "example",
}
# Big platforms: an account/domain here is never a pivot point on its own.
PLATFORM_DOMAINS = FREEMAIL | {
    "google.com", "youtube.com", "facebook.com", "instagram.com", "twitter.com", "x.com",
    "t.me", "telegram.org", "github.com", "gitlab.com", "linkedin.com", "tiktok.com",
    "reddit.com", "vk.com", "ok.ru", "microsoft.com", "apple.com", "amazon.com",
    "wikipedia.org", "medium.com", "wordpress.com", "blogspot.com", "cloudflare.com",
    "amazonaws.com", "googleusercontent.com", "akamaihd.net", "fastly.net",
    "gravatar.com", "archive.org", "example.com", "example.org", "example.net",
}
# Usernames that collide with everyone.
GENERIC_USERNAMES = {"admin", "user", "test", "root", "info", "support", "null", "none",
                     "guest", "anonymous", "me", "official", "contact", "hello", "mail"}
# Two-level public suffixes most often met in our region and in general.
# A full Public Suffix List is better; this covers the common cases offline.
MULTI_SUFFIXES = {
    "com.ua", "org.ua", "net.ua", "gov.ua", "edu.ua", "in.ua", "kiev.ua", "kyiv.ua",
    "lviv.ua", "odessa.ua", "dp.ua", "kh.ua", "co.ua", "biz.ua", "pp.ua",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "co.nz", "co.jp", "ne.jp", "or.jp", "co.kr",
    "com.br", "com.ar", "com.mx", "com.tr", "com.pl", "net.pl", "org.pl", "com.cn",
    "com.hk", "com.tw", "com.sg", "co.in", "co.za", "co.il", "com.ru", "msk.ru",
    "spb.ru", "com.by", "com.kz", "github.io", "gitlab.io", "herokuapp.com",
    "blogspot.com", "netlify.app", "vercel.app", "pages.dev", "workers.dev",
}
TRACKING_PARAMS = re.compile(
    r"^(utm_\w+|fbclid|gclid|dclid|gbraid|wbraid|yclid|msclkid|mc_cid|mc_eid|igshid|"
    r"si|_hsenc|_hsmi|mkt_tok|ref_src|ref_url|spm|from|share_source|s)$", re.I)
# Major CDN / shared edge networks: an IP here is shared by thousands of sites.
CDN_NETS = [ipaddress.ip_network(n) for n in (
    # Cloudflare
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
    # Fastly
    "151.101.0.0/16", "199.232.0.0/16", "146.75.0.0/16", "2a04:4e40::/32",
    # Akamai (main edge blocks)
    "23.32.0.0/11", "23.192.0.0/11", "2.16.0.0/13", "104.64.0.0/10",
    # Amazon CloudFront (main blocks)
    "13.32.0.0/15", "13.224.0.0/14", "18.64.0.0/14", "54.230.0.0/16", "54.239.128.0/18",
    "99.84.0.0/16", "205.251.192.0/19", "143.204.0.0/16",
    # GitHub Pages
    "185.199.108.0/22",
)]

USERNAME_RE = re.compile(r"^[\w.\-]{2,64}$", re.UNICODE)
EMAIL_RE = re.compile(r"^[^@\s<>()\[\],;:\"]{1,64}@[^@\s<>()\[\],;:\"]{1,253}$")
LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


@dataclass
class Norm:
    type: str
    value: str                 # what we show
    key: str                   # what we de-duplicate on: "<type>:<canonical>"
    flags: set[str] = field(default_factory=set)
    url: str = ""              # clickable link, if the entity has one


# ─── Helpers ──────────────────────────────────────────────────────────────────
def _clean(s: str) -> str:
    s = unicodedata.normalize("NFKC", str(s)).strip()
    return re.sub(r"\s+", " ", s)


def _idna(host: str) -> str | None:
    host = host.strip().strip(".").lower()
    if not host:
        return None
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = host.split(".")
    if len(labels) < 2 or len(host) > 253 or not all(LABEL_RE.match(l) for l in labels):
        return None
    if not re.match(r"^(xn--[a-z0-9-]+|[a-z]{2,63})$", labels[-1]):
        return None
    return host


def registered_domain(host: str) -> str:
    """eTLD+1: mail.shop.example.com.ua → example.com.ua."""
    labels = host.lower().strip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def cdn_network(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in CDN_NETS if net.version == addr.version)


def canonical_url(raw: str) -> str | None:
    raw = _clean(raw)
    if not re.match(r"^[a-z][a-z0-9+.\-]*://", raw, re.I):
        raw = "https://" + raw
    try:
        p = urlsplit(raw)
    except ValueError:
        return None
    if p.scheme.lower() not in ("http", "https"):
        return None
    host = _idna(p.hostname or "")
    if not host:
        return None
    port = p.port if p.port and p.port not in (80, 443) else None
    netloc = host + (f":{port}" if port else "")
    query = urlencode(sorted((k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)
                             if not TRACKING_PARAMS.match(k)))
    path = re.sub(r"/{2,}", "/", p.path or "/")
    if len(path) > 1:
        path = path.rstrip("/")
    return urlunsplit(("https", netloc, path, query, ""))


# ─── Per-type normalisers ─────────────────────────────────────────────────────
def _username(v: str) -> Norm | None:
    v = _clean(v).lstrip("@")
    if not USERNAME_RE.match(v):
        return None
    flags = {"generic"} if v.casefold() in GENERIC_USERNAMES or len(v) < 3 else set()
    return Norm("username", v, "username:" + v.casefold(), flags)


def _email(v: str) -> Norm | None:
    v = _clean(v).lower().removeprefix("mailto:")
    if not EMAIL_RE.match(v):
        return None
    local, _, host = v.rpartition("@")
    host = _idna(host)
    if not host or not local or local.startswith(".") or local.endswith(".") or ".." in local:
        return None
    canon_local = local
    if host in PLUS_ALIAS:
        canon_local = canon_local.split("+", 1)[0]
    if host in ("gmail.com", "googlemail.com"):
        canon_local, host_key = canon_local.replace(".", ""), "gmail.com"
    else:
        host_key = host
    flags = set()
    if host in FREEMAIL:
        flags.add("freemail")
    if host in DISPOSABLE:
        flags.add("disposable")
    if local.split("+", 1)[0] in ROLE_LOCALPARTS:
        flags.add("role")
    return Norm("email", f"{local}@{host}", f"email:{canon_local}@{host_key}", flags,
                url=f"mailto:{local}@{host}")


def _phone(v: str) -> Norm | None:
    raw = _clean(v)
    if re.search(r"[a-zA-Z]", raw):
        return None
    digits = re.sub(r"\D", "", raw)
    if raw.startswith("00"):
        digits = digits[2:]
    elif not raw.startswith("+"):
        if len(digits) == 10 and digits.startswith("0"):   # local UA format 0XXXXXXXXX
            digits = "38" + digits
    if not 8 <= len(digits) <= 15 or digits.startswith("0"):
        return None
    try:  # optional, much stricter validation if the library is installed
        import phonenumbers  # type: ignore
        num = phonenumbers.parse("+" + digits)
        if not phonenumbers.is_possible_number(num):
            return None
    except ImportError:
        pass
    except Exception:
        return None
    e164 = "+" + digits
    return Norm("phone", e164, "phone:" + e164, set(), url=f"tel:{e164}")


def _domain(v: str) -> Norm | None:
    v = _clean(v)
    if "://" in v or "/" in v:
        v = urlsplit(v if "://" in v else "https://" + v).hostname or ""
    v = v.lower().removeprefix("*.")
    host = _idna(v)
    if not host:
        return None
    if host.startswith("www.") and host.count(".") >= 2:
        host = host[4:]
    flags = set()
    reg = registered_domain(host)
    if reg in PLATFORM_DOMAINS or host in PLATFORM_DOMAINS:
        flags.add("platform")
    if host != reg:
        flags.add("subdomain")
    return Norm("domain", host, "domain:" + host, flags, url="https://" + host)


def _ip(v: str) -> Norm | None:
    try:
        addr = ipaddress.ip_address(_clean(v).strip("[]"))
    except ValueError:
        return None
    if not addr.is_global:
        return None
    flags = {"cdn"} if cdn_network(str(addr)) else set()
    return Norm("ip", str(addr), f"ip:{addr.compressed}", flags)


def _url(v: str) -> Norm | None:
    canon = canonical_url(v)
    if not canon:
        return None
    flags = set()
    if registered_domain(urlsplit(canon).hostname or "") in PLATFORM_DOMAINS:
        flags.add("platform")
    return Norm("url", canon, "url:" + canon.removeprefix("https://"), flags, url=canon)


def _account(v: str) -> Norm | None:
    """An account is either a profile URL or a 'service · identifier' pair."""
    v = _clean(v)
    if re.match(r"^https?://", v, re.I):
        canon = canonical_url(v)
        if not canon:
            return None
        bare = canon.removeprefix("https://")
        host = urlsplit(canon).hostname or ""
        if host.startswith("www."):
            bare = bare[4:]
        # same profile, two URL shapes: user.deviantart.com == deviantart.com/user
        m = re.match(r"^([a-z0-9_-]+)\.(deviantart\.com|tumblr\.com|livejournal\.com)/?$", bare, re.I)
        if m and m.group(1).lower() != "www":
            bare = f"{m.group(2)}/{m.group(1)}"
        return Norm("account", canon, "account:" + bare.casefold(), set(), url=canon)
    if len(v) < 3:
        return None
    return Norm("account", v, "account:" + v.casefold(), set())


def _text(kind: str):
    def norm(v: str) -> Norm | None:
        v = _clean(v)
        if len(v) < 2 or len(v) > 500:
            return None
        return Norm(kind, v, f"{kind}:" + v.casefold(), set())
    return norm


def _org(v: str) -> Norm | None:
    """Company name, or its LinkedIn / XING page (then it keeps a canonical URL)."""
    v = _clean(v)
    m = COMPANY_PAGE.match(v)
    if m:
        url = f"https://www.{m.group(1).lower()}/{m.group(2)}"
        return Norm("org", url, "org:" + url.removeprefix("https://www.").casefold(), set(), url=url)
    return _text("org")(v)


def _file(v: str) -> Norm | None:
    """Local file: one entity per content (same bytes under two names = one file)."""
    from pathlib import Path
    p = Path(_clean(v).strip("'\"")).expanduser()
    try:
        p = p.resolve()
        if not p.is_file():
            return None
        h = hashlib.sha256()
        with p.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return None
    return Norm("file", str(p), "file:" + h.hexdigest(), set(), url=p.as_uri())


_NORMALISERS = {
    "username": _username, "email": _email, "phone": _phone, "domain": _domain,
    "ip": _ip, "url": _url, "account": _account,
    "person": _text("person"), "org": _org, "location": _text("location"),
    "note": _text("note"), "file": _file, "fingerprint": _text("fingerprint"),
}


def normalize(kind: str, value: str) -> Norm | None:
    fn = _NORMALISERS.get(kind)
    if fn is None or value is None:
        return None
    return fn(str(value))


def guess_type(value: str) -> str | None:
    """Best guess for a seed typed by a human."""
    v = _clean(value)
    if _email(v):
        return "email"
    if COMPANY_PAGE.match(v):
        return "org"
    if re.match(r"^https?://", v, re.I):
        return "url"
    if v.startswith(("/", "~", "./")) or re.match(r"^[A-Za-z]:[\\/]|^\\\\", v):
        from pathlib import Path
        if Path(v.strip("'\"")).expanduser().exists():
            return "file"
    if _ip(v):
        return "ip"
    if re.match(r"^\+?[\d\s()\-]{8,20}$", v) and _phone(v):
        return "phone"
    if "." in v and _domain(v):
        return "domain"
    if _username(v):
        return "username"
    return None


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
