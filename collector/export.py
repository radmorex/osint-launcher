"""Exports: OSINT Graph tree (.osint.json, format v2, readable by v1) and CSV.

Tree layout = how things were found: case → seed → what the seed led to, grouped
by type when a node has many children. Edges that do not fit the tree (the same
email found from two accounts) go to `refs` and are spelled out in the note, so
OSINT Graph v1, which ignores unknown fields, still shows them.
"""
from __future__ import annotations

import csv
import io
import time
from collections import defaultdict
from datetime import datetime, timezone

from .store import Store

GRAPH_TYPE = {"username": "username", "email": "email", "phone": "phone", "domain": "domain",
              "ip": "ip", "url": "link", "account": "social", "person": "person", "org": "org",
              "location": "location", "note": "note", "fingerprint": "note", "file": "document"}
GROUP_LABEL = {"account": "Акаунти", "username": "Нікнейми", "email": "Email", "phone": "Телефони",
               "domain": "Домени", "ip": "IP-адреси", "url": "Посилання", "person": "Імена",
               "org": "Організації", "location": "Локації", "note": "Нотатки", "file": "Файли",
               "fingerprint": "Відбитки"}
TYPE_ORDER = ["account", "username", "email", "phone", "person", "location", "org", "fingerprint",
              "file", "domain", "ip", "url", "note"]
STATUS = {"ok": "ok", "maybe": "maybe", "no": "no", "new": ""}
FLAG_LABEL = {"freemail": "поштовий сервіс", "disposable": "одноразова пошта", "role": "службова адреса",
              "platform": "платформа", "cdn": "CDN", "generic": "загальний нік", "supernode": "суперновузол",
              "wildcard": "wildcard DNS", "subdomain": "піддомен"}
ATTR_SKIP = {"platform", "tags"}


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _label(e: dict) -> str:
    if e["type"] == "file":
        return e["value"].replace("\\", "/").rsplit("/", 1)[-1]
    platform = (e.get("attrs") or {}).get("platform")
    if e["type"] == "account" and platform and not e["value"].lower().startswith(str(platform).lower()):
        shown = e["value"].removeprefix("https://").removeprefix("www.")
        return f"{platform} · {shown}"
    return e["value"]


def _note(e: dict, sources: list[dict], refs: list[str]) -> str:
    parts = []
    if not e["is_seed"]:
        mods = sorted({s["module"] for s in sources})
        parts.append(f"впевненість {round(e['confidence'] * 100)}% · джерела: {', '.join(mods) or '—'}")
    attrs = {k: v for k, v in (e.get("attrs") or {}).items() if k not in ATTR_SKIP and v not in ("", None)}
    for k, v in attrs.items():
        parts.append(f"{k}: {v}")
    flags = [FLAG_LABEL.get(f, f) for f in e.get("flags") or [] if f != "subdomain"]
    if flags:
        parts.append("позначки: " + ", ".join(flags))
    if refs:
        parts.append("також пов'язано з: " + "; ".join(refs[:8]) + (" …" if len(refs) > 8 else ""))
    if e["pivot"] == "suggested":
        parts.append("не розгорнуто: " + e["pivot_reason"])
    return " | ".join(parts)


def build_tree(store: Store, case_id: int, include_rejected: bool = False,
               min_confidence: float = 0.0, group_over: int = 3, collapse_over: int = 12) -> dict:
    case = store.case(case_id)
    if not case:
        raise KeyError(case_id)
    ents = {e["id"]: e for e in store.entities(case_id)}
    keep = {i for i, e in ents.items()
            if e["is_seed"] or ((include_rejected or e["status"] != "no")
                                and (e["confidence"] >= min_confidence or e["status"] == "ok"))}
    sources: dict[int, list[dict]] = defaultdict(list)
    for c in store.case_claims(case_id):
        sources[c["entity_id"]].append(c)

    # Re-parent entities whose discovery parent was filtered out to the nearest kept ancestor.
    def parent_of(e: dict) -> int | None:
        p = e["parent_id"]
        while p is not None and p not in keep:
            p = ents[p]["parent_id"] if p in ents else None
        return p

    children: dict[int | None, list[int]] = defaultdict(list)
    for i in keep:
        children[None if ents[i]["is_seed"] else parent_of(ents[i])].append(i)

    def node_id(i: int) -> str:
        return f"e{i}"

    refs: dict[int, list[str]] = defaultdict(list)
    ref_ids: dict[int, list[dict]] = defaultdict(list)
    for ed in store.edges(case_id):
        s, d = ed["src"], ed["dst"]
        if s in keep and d in keep and parent_of(ents[d]) != s:
            refs[d].append(f"{_label(ents[s])} ({ed['rel']})")
            ref_ids[d].append({"id": node_id(s), "rel": ed["rel"]})

    def node(i: int) -> dict:
        e = ents[i]
        gtype = GRAPH_TYPE.get(e["type"], "note")
        if e["type"] == "file" and e["value"].lower().rsplit(".", 1)[-1] in ("jpg", "jpeg", "png", "heic", "webp",
                                                                              "gif", "tif", "tiff", "bmp"):
            gtype = "photo"
        n = {
            "id": node_id(i), "name": _label(e), "type": gtype,
            "url": e["url"] if e["url"].startswith("http") else "",
            "note": _note(e, sources[i], refs[i]), "status": STATUS.get(e["status"], ""),
            "collapsed": False, "children": [],
            # v2 fields (ignored by OSINT Graph 1.x)
            "key": e["key"], "confidence": e["confidence"], "flags": e["flags"],
            "attrs": e["attrs"], "seen": _iso(e["first_seen"]), "review": e["status"],
            "sources": [{"module": s["module"], "at": _iso(s["observed"]), "sha256": s["raw_sha256"],
                         "evidence": s["raw_path"]} for s in sources[i]],
            "refs": ref_ids[i],
        }
        n["children"] = kids(i)
        return n

    def kids(i: int | None) -> list[dict]:
        ids = sorted(children.get(i, []), key=lambda k: (-ents[k]["confidence"], ents[k]["value"]))
        by_type: dict[str, list[int]] = defaultdict(list)
        for k in ids:
            by_type[ents[k]["type"]].append(k)
        if len(ids) <= group_over or len(by_type) == 1 and len(ids) <= collapse_over:
            return [node(k) for k in ids]
        out = []
        for t in sorted(by_type, key=lambda t: TYPE_ORDER.index(t) if t in TYPE_ORDER else 99):
            members = by_type[t]
            if len(members) == 1:
                out.append(node(members[0]))
                continue
            out.append({"id": f"g{i}-{t}", "name": f"{GROUP_LABEL.get(t, t)} ({len(members)})",
                        "type": "group", "url": "", "note": "", "status": "",
                        "collapsed": len(members) > collapse_over,
                        "children": [node(k) for k in members]})
        return out

    root = {"id": f"case{case_id}", "name": case["name"], "type": "group", "url": "",
            "note": " | ".join(x for x in (
                f"мета: {case['purpose']}" if case["purpose"] else "",
                f"зібрано osint-collector {datetime.now():%Y-%m-%d %H:%M}",
                f"профіль: {(case['settings'] or {}).get('profile', 'standard')}") if x),
            "status": "", "collapsed": False, "children": kids(None)}
    return {"format": "osint-graph", "version": 2, "exported": _iso(time.time()),
            "generator": "osint-collector", "root": root}


def to_csv(store: Store, case_id: int) -> str:
    ents = store.entities(case_id)
    by_ent: dict[int, list[dict]] = defaultdict(list)
    for c in store.case_claims(case_id):
        by_ent[c["entity_id"]].append(c)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["type", "value", "status", "confidence", "depth", "found_via", "sources",
                "flags", "url", "first_seen", "attrs"])
    names = {e["id"]: e["value"] for e in ents}
    for e in sorted(ents, key=lambda e: (e["type"], -e["confidence"])):
        w.writerow([e["type"], e["value"], e["status"], e["confidence"], e["depth"],
                    names.get(e["parent_id"], ""), ", ".join(sorted({c["module"] for c in by_ent[e["id"]]})),
                    ", ".join(e["flags"]), e["url"], _iso(e["first_seen"]),
                    "; ".join(f"{k}={v}" for k, v in (e["attrs"] or {}).items())])
    return buf.getvalue()
