"""The collection loop: plan → run modules → normalise → merge → score → decide pivots.

Pivot rules (why the result is not a pile of junk):
  * a finding becomes an entity only after normalisation; same key = same entity;
  * confidence = 1 − Π(1 − c) over *distinct* modules, so corroboration counts
    and one noisy tool repeating itself does not;
  * an entity is expanded automatically only if it is confident enough, within
    the depth limit, in scope, not a shared/platform/supernode value and the
    case still has budget; otherwise it lands in "suggested" for the analyst;
  * a suggested entity that later gets corroborated is expanded then.
"""
from __future__ import annotations

import os
import shutil
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

from .modules import REGISTRY, Context, Module, ModuleError, Result
from .modules.base import Finding, evidence
from .normalize import guess_type, normalize, registered_domain
from .store import Store

DEFAULTS = {
    "profile": "standard",
    "max_depth": 2,           # hops from a seed that are expanded automatically
    "budget": 150,            # max non-offline module runs per case
    "auto_threshold": 0.6,    # min confidence for automatic expansion
    "supernode": 25,          # in-degree at which a value is treated as shared
    "scope": [],              # registered domains in scope; empty = no restriction
    "modules_off": [],
    "email_format": "",       # e.g. "{first}.{last}@firma.ua": likely addresses for employees
}
# Flags that stop automatic expansion (the entity is kept, not pivoted on).
BLOCKING_FLAGS = {
    "platform": "спільна платформа",
    "cdn": "IP CDN / спільної інфраструктури",
    "generic": "загальний нік",
    "supernode": "суперновузол: пов'язаний з багатьма сутностями",
    "wildcard": "wildcard DNS",
    "disposable": "одноразова пошта",
}


def combine(confidences: dict[str, float]) -> float:
    p = 1.0
    for c in confidences.values():
        p *= 1 - max(0.0, min(c, 0.99))
    return round(min(0.99, 1 - p), 3)


class Engine:
    def __init__(self, store: Store, data_dir: Path, registry: dict[str, type[Module]] | None = None,
                 workers: int = 6):
        self.store = store
        self.data_dir = Path(data_dir)
        self.registry = registry if registry is not None else REGISTRY
        self.pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="collector")
        self.sems: dict[str, threading.Semaphore] = {
            name: threading.Semaphore(max(1, m.concurrency)) for name, m in self.registry.items()}
        self.lock = threading.RLock()
        self.listeners: list[Callable[[int], None]] = []
        self._recover()

    # ─── settings ───────────────────────────────────────────────────────────
    def settings(self, case_id: int) -> dict:
        case = self.store.case(case_id) or {}
        return {**DEFAULTS, **(case.get("settings") or {})}

    def _recover(self) -> None:
        """Runs left queued/running by a previous process are re-queued."""
        for r in self.store.q("SELECT id, case_id, module, entity_id FROM runs WHERE state IN ('queued','running')"):
            if r["module"] in self.registry:
                self.store.set_run(r["id"], state="queued")
                self.pool.submit(self._execute, r["case_id"], r["id"], r["module"], r["entity_id"])
            else:
                self.store.set_run(r["id"], state="skipped", error="модуль недоступний")

    # ─── public API ─────────────────────────────────────────────────────────
    def add_seed(self, case_id: int, value: str, kind: str | None = None) -> dict:
        path = Path(str(value).strip().strip("'\"")).expanduser()
        if kind in (None, "", "file") and path.is_dir():
            added = self.add_folder(case_id, path)
            return {"type": "folder", "value": str(path), "count": len(added), "id": None}
        kind = kind or guess_type(value)
        if not kind:
            raise ValueError(f"не вдалося визначити тип: {value!r}")
        n = normalize(kind, value)
        if not n:
            raise ValueError(f"некоректне значення для типу {kind}: {value!r}")
        with self.lock:
            e = self.store.entity_by_key(case_id, n.key)
            if e:
                self.store.x("UPDATE entities SET is_seed=1, status='ok', depth=0, confidence=1 WHERE id=?",
                             (e["id"],))
            else:
                eid = self.store.insert_entity(case_id, type=n.type, key=n.key, value=n.value, url=n.url,
                                               depth=0, parent_id=None, flags=n.flags, is_seed=True)
                self.store.set_entity(eid, confidence=1.0)
                e = self.store.entity(eid)
            e = self.store.entity(e["id"])
            self._plan(case_id, e, force=True)
        return self.store.entity(e["id"])

    SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".idea", ".DS_Store"}

    def add_folder(self, case_id: int, folder: Path, limit: int = 1000,
                   max_bytes: int = 200 * 1024 * 1024) -> list[int]:
        """Every regular file under `folder` becomes a seed (hidden and tool folders skipped)."""
        added: list[int] = []
        for p in sorted(folder.rglob("*")):
            if len(added) >= limit:
                break
            if any(part in self.SKIP_DIRS or part.startswith(".") for part in p.relative_to(folder).parts):
                continue
            try:
                if not p.is_file() or p.stat().st_size > max_bytes:
                    continue
            except OSError:
                continue
            try:
                added.append(self.add_seed(case_id, str(p), "file")["id"])
            except ValueError:
                continue
        return added

    def set_status(self, entity_id: int, status: str) -> dict:
        if status not in ("new", "ok", "maybe", "no"):
            raise ValueError(status)
        e = self.store.entity(entity_id)
        if not e:
            raise KeyError(entity_id)
        with self.lock:
            self.store.set_entity(entity_id, status=status)
            if status == "no":
                self.store.set_entity(entity_id, pivot="blocked", pivot_reason="хибний слід (аналітик)")
                self.store.x("UPDATE runs SET state='skipped', error='скасовано: хибний слід' "
                             "WHERE entity_id=? AND state='queued'", (entity_id,))
            elif status == "ok" and e["pivot"] == "suggested":
                self._plan(e["case_id"], self.store.entity(entity_id), analyst_ok=True)
        self._notify(e["case_id"])
        return self.store.entity(entity_id)

    def delete_entities(self, case_id: int, ids: list[int]) -> dict:
        """Remove entities from the case, with what was found only through them.

        A descendant that another, surviving entity also points at stays (it was
        corroborated elsewhere) and moves under that entity. Files on disk are
        never touched: only the case records go.
        """
        with self.lock:
            ents = {e["id"]: e for e in self.store.entities(case_id)}
            roots = {i for i in ids if i in ents}
            children: dict[int, list[int]] = {}
            for e in ents.values():
                if e["parent_id"] is not None:
                    children.setdefault(e["parent_id"], []).append(e["id"])
            doomed, stack = set(), list(roots)
            while stack:
                i = stack.pop()
                if i in doomed:
                    continue
                doomed.add(i)
                stack.extend(children.get(i, []))
            kept = 0
            incoming: dict[int, set[int]] = {}
            for ed in self.store.edges(case_id):
                incoming.setdefault(ed["dst"], set()).add(ed["src"])
            changed = True
            while changed:                       # keep descendants still reachable from outside
                changed = False
                for i in sorted(doomed - roots):
                    outside = incoming.get(i, set()) - doomed
                    if outside:
                        doomed.discard(i)
                        self.store.set_entity(i, parent_id=min(outside))
                        kept += 1
                        changed = True
            for i in doomed:
                self.store.x("DELETE FROM entities WHERE id=?", (i,))
        self._notify(case_id)
        return {"deleted": len(doomed), "kept": kept}

    def delete_case(self, case_id: int) -> None:
        import shutil as _sh
        self.store.delete_case(case_id)
        # the collector's own copies of evidence for this case; user files are never here
        _sh.rmtree(self.data_dir / "cases" / str(case_id), ignore_errors=True)
        self._notify(case_id)

    def expand(self, entity_id: int) -> dict:
        e = self.store.entity(entity_id)
        if not e:
            raise KeyError(entity_id)
        with self.lock:
            self._plan(e["case_id"], e, force=True)
        return self.store.entity(entity_id)

    def progress(self, case_id: int) -> dict:
        counts = self.store.run_counts(case_id)
        s = self.settings(case_id)
        return {"queued": counts.get("queued", 0), "running": counts.get("running", 0),
                "done": counts.get("done", 0), "error": counts.get("error", 0),
                "skipped": counts.get("skipped", 0), "budget": s["budget"],
                "budget_used": self._budget_used(case_id),
                "busy": bool(counts.get("queued") or counts.get("running"))}

    def wait(self, case_id: int, poll: float = 0.5, timeout: float | None = None,
             on_tick: Callable[[dict], None] | None = None) -> dict:
        start = time.time()
        while True:
            p = self.progress(case_id)
            if on_tick:
                on_tick(p)
            if not p["busy"]:
                return p
            if timeout and time.time() - start > timeout:
                return p
            time.sleep(poll)

    def shutdown(self) -> None:
        self.pool.shutdown(wait=False, cancel_futures=True)

    # ─── planning ───────────────────────────────────────────────────────────
    def _budget_used(self, case_id: int) -> int:
        offline = [n for n, m in self.registry.items() if m.cost == 0] or ["-"]
        marks = ",".join("?" * len(offline))
        r = self.store.one(f"SELECT COUNT(*) AS n FROM runs WHERE case_id=? AND module NOT IN ({marks}) "
                           f"AND state != 'skipped'", (case_id, *offline))
        return r["n"] if r else 0

    def _modules_for(self, settings: dict, entity: dict) -> list[type[Module]]:
        out = []
        prof = settings["profile"]
        for name, m in self.registry.items():
            # Self-audit = everything from "standard" plus modules that opt into it.
            in_profile = prof in m.profiles or (prof == "selfaudit" and "standard" in m.profiles)
            if name in settings["modules_off"] or not in_profile:
                continue
            if not m.available()[0] or not m().accepts(entity):
                continue
            out.append(m)
        return out

    def _in_scope(self, settings: dict, entity: dict) -> bool:
        scope = {s.lower().strip() for s in settings.get("scope") or [] if s.strip()}
        if not scope:
            return True
        host = ""
        if entity["type"] == "domain":
            host = entity["value"]
        elif entity["type"] == "email":
            host = entity["value"].rpartition("@")[2]
        else:
            return True       # scope restricts infrastructure, not people/accounts
        return registered_domain(host) in scope

    def _plan(self, case_id: int, entity: dict, force: bool = False, analyst_ok: bool = False) -> None:
        s = self.settings(case_id)
        mods = self._modules_for(s, entity)
        if not mods:
            if entity["pivot"] in ("none", "suggested"):
                self.store.set_entity(entity["id"], pivot="none", pivot_reason="немає модулів для цього типу")
            return
        reason = ""
        if not force:
            flags = set(entity.get("flags") or [])
            blocking = [BLOCKING_FLAGS[f] for f in flags if f in BLOCKING_FLAGS]
            if entity["status"] == "no":
                self.store.set_entity(entity["id"], pivot="blocked", pivot_reason="хибний слід")
                return
            if blocking:
                self.store.set_entity(entity["id"], pivot="blocked", pivot_reason="; ".join(blocking))
                return
            # Offline derivations (email → domain, link → host) cost nothing and touch
            # nobody: always run them, the limits apply to what they produce.
            offline = [m for m in mods if m.cost == 0]
            if offline:
                self._enqueue(case_id, entity, offline)
                mods = [m for m in mods if m.cost > 0]
                if not mods:
                    self.store.set_entity(entity["id"], pivot="done",
                                          pivot_reason=", ".join(m.name for m in offline))
                    return
            if entity["depth"] >= s["max_depth"]:
                reason = f"глибина {entity['depth']} ≥ {s['max_depth']}"
            elif entity["confidence"] < s["auto_threshold"] and not analyst_ok and not entity["is_seed"]:
                reason = f"впевненість {entity['confidence']:.0%} < {s['auto_threshold']:.0%}"
            elif not self._in_scope(s, entity):
                reason = "поза скоупом кейсу"
            elif self._budget_used(case_id) >= s["budget"] and any(m.cost > 0 for m in mods):
                reason = "вичерпано бюджет запитів"
        if reason:
            cost = sum(m.cost for m in mods)
            self.store.set_entity(entity["id"], pivot="suggested",
                                  pivot_reason=f"{reason} · {len(mods)} модулів, вартість ≈{cost}")
            return
        self.store.set_entity(entity["id"], pivot="done", pivot_reason=", ".join(m.name for m in mods))
        self._enqueue(case_id, entity, mods)

    def _enqueue(self, case_id: int, entity: dict, mods: list[type[Module]]) -> None:
        for m in mods:
            run_id = self.store.add_run(case_id, m.name, entity["id"])
            if run_id is not None:
                self.pool.submit(self._execute, case_id, run_id, m.name, entity["id"])
        self._notify(case_id)

    # ─── execution ──────────────────────────────────────────────────────────
    def _execute(self, case_id: int, run_id: int, module_name: str, entity_id: int) -> None:
        mcls = self.registry[module_name]
        with self.sems[module_name]:
            run = self.store.one("SELECT state FROM runs WHERE id=?", (run_id,))
            entity = self.store.entity(entity_id)
            if not run or run["state"] != "queued" or not entity:
                return
            self.store.set_run(run_id, state="running", started=time.time())
            self._notify(case_id)
            s = self.settings(case_id)
            cache_key = f"v{getattr(mcls, 'version', 1)}|{s['profile']}|{entity['key']}"
            try:
                cached = self.store.cache_get(module_name, cache_key, mcls.cache_ttl)
                if cached is not None:
                    result = self._result_from_cache(cached)
                    raw_path, raw_sha = cached.get("raw_path", ""), cached.get("raw_sha256", "")
                    self.store.set_run(run_id, cached=1)
                else:
                    result, raw_path, raw_sha = self._run_module(case_id, run_id, mcls, entity, s)
                    self.store.cache_put(module_name, cache_key, self._result_to_cache(result, raw_path, raw_sha))
                self.store.set_run(run_id, raw_path=raw_path, raw_sha256=raw_sha)
                found = self._ingest(case_id, run_id, mcls, entity, result)
                self.store.set_run(run_id, state="done", finished=time.time(), found=found)
            except ModuleError as e:
                self.store.set_run(run_id, state="error", finished=time.time(), error=str(e)[:500])
            except Exception as e:  # a bug in one module must not stop the case
                self.store.set_run(run_id, state="error", finished=time.time(),
                                   error=f"{type(e).__name__}: {e}"[:500])
                if os.environ.get("COLLECTOR_DEBUG"):
                    traceback.print_exc()
        self._notify(case_id)

    def _run_module(self, case_id: int, run_id: int, mcls: type[Module], entity: dict,
                    settings: dict) -> tuple[Result, str, str]:
        case_dir = self.data_dir / "cases" / str(case_id)
        work = case_dir / "work" / str(run_id)
        ev_dir = case_dir / "evidence"
        work.mkdir(parents=True, exist_ok=True)
        ev_dir.mkdir(parents=True, exist_ok=True)
        env = {**os.environ, "COLLECTOR_PROFILE": settings["profile"],
               "COLLECTOR_EMAIL_FORMAT": settings.get("email_format") or "",
               "COLLECTOR_DATA": str(self.data_dir),
               "PYTHONIOENCODING": "utf-8", "NO_COLOR": "1"}
        try:
            result = mcls().run(entity, Context(work, timeout=mcls.timeout, env=env))
        except BaseException:
            shutil.rmtree(work, ignore_errors=True)
            raise
        raw_path = raw_sha = ""
        if result.raw:
            raw_path, raw_sha = evidence(result.raw, ev_dir, result.raw_ext)
        shutil.rmtree(work, ignore_errors=True)
        return result, raw_path, raw_sha

    @staticmethod
    def _result_to_cache(r: Result, raw_path: str, raw_sha: str) -> dict:
        return {"findings": [f.__dict__ for f in r.findings], "attrs": r.attrs,
                "flags": sorted(r.flags), "raw_path": raw_path, "raw_sha256": raw_sha}

    @staticmethod
    def _result_from_cache(d: dict) -> Result:
        return Result(findings=[Finding(**f) for f in d.get("findings", [])], attrs=d.get("attrs", {}),
                      flags=set(d.get("flags", [])))

    # ─── merging ────────────────────────────────────────────────────────────
    def _ingest(self, case_id: int, run_id: int, mcls: type[Module], parent: dict, result: Result) -> int:
        s = self.settings(case_id)
        found = 0
        with self.lock:
            if result.attrs:
                self.store.merge_attrs(parent["id"], result.attrs)
            if result.flags:
                cur = self.store.entity(parent["id"])
                self.store.set_entity(parent["id"], flags=set(cur["flags"]) | set(result.flags))
                self._rescore(parent["id"], s)
            touched: list[tuple[int, bool]] = []
            for f in result.findings:
                n = normalize(f.type, f.value)
                if not n:
                    continue
                conf = round(max(0.0, min(1.0, f.confidence)) * mcls.reliability, 3)
                e = self.store.entity_by_key(case_id, n.key)
                is_new = e is None
                if is_new:
                    eid = self.store.insert_entity(case_id, type=n.type, key=n.key, value=n.value,
                                                   url=n.url, depth=parent["depth"] + 1,
                                                   parent_id=parent["id"], flags=n.flags, is_seed=False)
                else:
                    eid = e["id"]
                    if e["status"] == "no":
                        # Analyst said false lead: record the claim, never resurrect it.
                        self.store.add_claim(eid, run_id, mcls.name, conf, f.value, f.data)
                        continue
                self.store.add_claim(eid, run_id, mcls.name, conf, f.value, {**f.data, "rel": f.rel})
                self.store.add_edge(case_id, parent["id"], eid, f.rel, mcls.name)
                if f.attrs:
                    self.store.merge_attrs(eid, f.attrs)
                self.store.set_entity(eid, last_seen=time.time())
                touched.append((eid, is_new))
                found += 1
            self._link_email_hashes(case_id, [eid for eid, _ in touched])
            for eid, is_new in touched:
                e = self._rescore(eid, s)
                if e["status"] == "no":
                    continue
                if is_new:
                    self._plan(case_id, e)
                elif e["pivot"] == "suggested" and e["confidence"] >= s["auto_threshold"]:
                    self._plan(case_id, e)          # corroboration unlocked it
        return found

    def _link_email_hashes(self, case_id: int, entity_ids: list[int]) -> None:
        """A profile leaked an e-mail hash (Gravatar avatar): join it to the case's e-mail it belongs to."""
        import hashlib
        fps = [self.store.entity(i) for i in entity_ids]
        fps = [e for e in fps if e and e["type"] == "fingerprint" and e["value"].startswith("email-хеш ")]
        if not fps:
            return
        emails = self.store.q("SELECT id, value FROM entities WHERE case_id=? AND type='email'", (case_id,))
        for fp in fps:
            h = fp["value"].split(":", 1)[-1].strip().lower()
            for em in emails:
                v = em["value"].strip().lower().encode()
                if h in (hashlib.sha256(v).hexdigest(), hashlib.md5(v).hexdigest()):
                    self.store.add_edge(case_id, em["id"], fp["id"], "same_email_hash", "email_hash")
                    self.store.merge_attrs(fp["id"], {"збіг_з_поштою": em["value"]})

    def _rescore(self, entity_id: int, settings: dict) -> dict:
        e = self.store.entity(entity_id)
        per_module: dict[str, float] = {}
        for c in self.store.claims(entity_id):
            per_module[c["module"]] = max(per_module.get(c["module"], 0), c["confidence"])
        conf = 1.0 if e["is_seed"] else combine(per_module)
        flags = set(e["flags"])
        if "wildcard" in flags and not e["is_seed"]:
            conf = round(conf * 0.5, 3)     # under a wildcard zone "exists" proves little
        if not e["is_seed"] and self.store.in_degree(entity_id) >= settings["supernode"]:
            flags.add("supernode")
            self.store.set_entity(entity_id, pivot="blocked", pivot_reason=BLOCKING_FLAGS["supernode"])
        self.store.set_entity(entity_id, confidence=conf, flags=flags)
        return self.store.entity(entity_id)

    # ─── events ─────────────────────────────────────────────────────────────
    def _notify(self, case_id: int) -> None:
        for fn in list(self.listeners):
            try:
                fn(case_id)
            except Exception:
                pass
