"""Profile enrichment: open every found account and pull what the page says.

Finding *where* someone has an account is half the job; the profile page has
the rest: display name, country, creation date, bio, links to other accounts,
other usernames. socid-extractor (by the Maigret author) knows ~270 sites.

Email hashes are the strongest link a profile can leak: Gravatar avatars (used
by GitLab, WordPress, Stack Overflow, …) embed md5 / sha256 of the owner's
e-mail. `email_parts` emits the same hashes for every e-mail in the case, so a
profile whose avatar carries one joins that e-mail through a shared entity.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil

from .base import Context, Module, ModuleError, Result

HASH_IN_URL = re.compile(r"(?:gravatar\.com/(?:avatar/)?|avatar/)([0-9a-f]{64}|[0-9a-f]{32})\b", re.I)
SKIP_KEYS = {"_extractor", "image", "image_bg", "gravatar_url", "website", "url"}
NAME_KEYS = ("fullname", "full_name", "name", "display_name")
PLACE_KEYS = ("country", "location", "city")
LINK_KEYS = ("links", "website", "blog", "external_url")
USER_KEYS = ("username", "other_usernames", "usernames", "nickname")


def email_hashes(email: str) -> list[str]:
    e = email.strip().lower().encode()
    return [f"email-хеш sha256:{hashlib.sha256(e).hexdigest()}", f"email-хеш md5:{hashlib.md5(e).hexdigest()}"]


def _hash_fp(h: str) -> str:
    return f"email-хеш {'sha256' if len(h) == 64 else 'md5'}:{h.lower()}"


def parse_socid(blocks: list, account_url: str, known_user: str = "") -> Result:
    res = Result()
    info: dict = {}
    for b in blocks or []:
        for k, v in (b.get("info") or {}).items():
            if v not in (None, "", [], {}) and k not in info:
                info[k] = v
    if not info:
        return res
    res.attrs["профіль"] = info.get("_extractor", "")
    for k, v in info.items():
        if k in SKIP_KEYS or isinstance(v, (dict, list)):
            continue
        sv = str(v)
        if len(sv) <= 200 and not sv.startswith("data:"):
            res.attrs[k] = sv
    for k in NAME_KEYS:
        name = str(info.get(k, "")).strip()
        if len(name) >= 3:
            res.add("person", name, "profile_name", 0.55)
            break
    for k in PLACE_KEYS:
        if info.get(k):
            res.add("location", str(info[k]), "profile_location", 0.5)
            break
    for k in LINK_KEYS:
        v = info.get(k)
        for link in (v if isinstance(v, list) else [v] if v else []):
            if str(link).startswith("http") and str(link).rstrip("/") != account_url.rstrip("/"):
                res.add("url", str(link), "profile_link", 0.65)
    for k in USER_KEYS:
        v = info.get(k)
        for u in (v if isinstance(v, list) else [v] if v else []):
            u = str(u).strip().lstrip("@")
            if u and u.lower() != known_user.lower():
                res.add("username", u, "profile_username", 0.6)
    for k in ("email", "emails", "public_email"):
        v = info.get(k)
        for mail in (v if isinstance(v, list) else [v] if v else []):
            if "@" in str(mail):
                res.add("email", str(mail), "profile_email", 0.85)
    hashes = {str(info[k]).lower() for k in ("gravatar_email_sha256_hash", "gravatar_email_hash", "gravatar_hash")
              if info.get(k)}
    for v in info.values():
        for m in HASH_IN_URL.finditer(str(v)):
            hashes.add(m.group(1).lower())
    for h in sorted(hashes):
        res.add("fingerprint", _hash_fp(h), "avatar_email_hash", 0.95)
    return res


class ProfileEnrich(Module):
    name, title = "profile", "Профіль акаунта (ім'я, країна, дати, посилання, хеш пошти)"
    consumes, produces = ("account",), ("person", "location", "url", "username", "email", "fingerprint")
    reliability, cost, concurrency, timeout = 0.85, 1, 3, 90
    binary = "socid_extractor"
    profiles = ("standard", "deep")
    version = 1

    def accepts(self, entity: dict) -> bool:
        return entity["type"] == "account" and entity.get("url", "").startswith("http")

    def run(self, entity: dict, ctx: Context) -> Result:
        exe = shutil.which("socid_extractor") or shutil.which("socid-extractor")
        if not exe:
            raise ModuleError("не встановлено: socid-extractor")
        p = ctx.run_tool([exe, "--url", entity["url"], "--json"], timeout=self.timeout)
        text = p.stdout.strip()
        start = text.find("[")
        try:
            blocks = json.loads(text[start:]) if start >= 0 else []
        except ValueError:
            blocks = []
        known = entity["url"].rstrip("/").rsplit("/", 1)[-1].lstrip("@")
        res = parse_socid(blocks, entity["url"], known)
        res.raw, res.raw_ext = (text or p.stderr).encode(), "json"
        return res


MODULES = [ProfileEnrich]
