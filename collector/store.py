"""SQLite storage: cases, entities, claims (who said what, with evidence), edges, runs.

An entity owns no data by itself: everything known about it is a claim from a
module run, and every run points at the raw evidence file it produced.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS cases (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  purpose TEXT NOT NULL DEFAULT '',          -- legal basis / task, shown in exports
  settings TEXT NOT NULL DEFAULT '{}',
  created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS entities (
  id INTEGER PRIMARY KEY,
  case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  key TEXT NOT NULL,
  value TEXT NOT NULL,
  url TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'new',        -- new | ok | maybe | no  (analyst verdict)
  confidence REAL NOT NULL DEFAULT 0,
  depth INTEGER NOT NULL DEFAULT 0,
  parent_id INTEGER REFERENCES entities(id) ON DELETE SET NULL,   -- discovery tree
  pivot TEXT NOT NULL DEFAULT 'none',        -- none | auto | suggested | done | blocked
  pivot_reason TEXT NOT NULL DEFAULT '',
  flags TEXT NOT NULL DEFAULT '[]',
  attrs TEXT NOT NULL DEFAULT '{}',
  is_seed INTEGER NOT NULL DEFAULT 0,
  first_seen REAL NOT NULL,
  last_seen REAL NOT NULL,
  UNIQUE(case_id, key)
);
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY,
  case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  module TEXT NOT NULL,
  entity_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
  state TEXT NOT NULL DEFAULT 'queued',      -- queued | running | done | error | skipped
  started REAL, finished REAL,
  found INTEGER NOT NULL DEFAULT 0,
  error TEXT NOT NULL DEFAULT '',
  raw_path TEXT NOT NULL DEFAULT '',
  raw_sha256 TEXT NOT NULL DEFAULT '',
  cached INTEGER NOT NULL DEFAULT 0,
  UNIQUE(case_id, module, entity_id)
);
CREATE TABLE IF NOT EXISTS claims (
  id INTEGER PRIMARY KEY,
  entity_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
  run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  module TEXT NOT NULL,
  confidence REAL NOT NULL,
  observed REAL NOT NULL,
  raw_value TEXT NOT NULL,
  data TEXT NOT NULL DEFAULT '{}',
  UNIQUE(entity_id, run_id)
);
CREATE TABLE IF NOT EXISTS edges (
  id INTEGER PRIMARY KEY,
  case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  src INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
  dst INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
  rel TEXT NOT NULL,
  module TEXT NOT NULL,
  UNIQUE(src, dst, rel)
);
CREATE TABLE IF NOT EXISTS cache (
  module TEXT NOT NULL,
  key TEXT NOT NULL,
  stored REAL NOT NULL,
  payload TEXT NOT NULL,
  PRIMARY KEY(module, key)
);
CREATE INDEX IF NOT EXISTS ix_entities_case ON entities(case_id);
CREATE INDEX IF NOT EXISTS ix_runs_case ON runs(case_id, state);
CREATE INDEX IF NOT EXISTS ix_edges_dst ON edges(dst);
"""

JSON_COLS = {"flags": list, "attrs": dict, "settings": dict, "data": dict}


def _row(r: sqlite3.Row | None) -> dict | None:
    if r is None:
        return None
    d = dict(r)
    for col, typ in JSON_COLS.items():
        if col in d and isinstance(d[col], str):
            try:
                d[col] = json.loads(d[col])
            except ValueError:
                d[col] = typ()
    return d


class Store:
    """Thread-safe: one connection, one lock. Plenty for a single analyst box."""

    def __init__(self, path: Path | str):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self.db.executescript(SCHEMA)

    # ─── generic ────────────────────────────────────────────────────────────
    def q(self, sql: str, args: tuple = ()) -> list[dict]:
        with self.lock:
            return [_row(r) for r in self.db.execute(sql, args).fetchall()]

    def one(self, sql: str, args: tuple = ()) -> dict | None:
        with self.lock:
            return _row(self.db.execute(sql, args).fetchone())

    def x(self, sql: str, args: tuple = ()) -> int:
        with self.lock:
            cur = self.db.execute(sql, args)
            return cur.lastrowid or cur.rowcount

    # ─── cases ──────────────────────────────────────────────────────────────
    def create_case(self, name: str, purpose: str = "", settings: dict | None = None) -> int:
        return self.x("INSERT INTO cases(name, purpose, settings, created) VALUES (?,?,?,?)",
                      (name, purpose, json.dumps(settings or {}), time.time()))

    def case(self, case_id: int) -> dict | None:
        return self.one("SELECT * FROM cases WHERE id=?", (case_id,))

    def cases(self) -> list[dict]:
        return self.q("""SELECT c.*, (SELECT COUNT(*) FROM entities e WHERE e.case_id=c.id) AS n_entities
                         FROM cases c ORDER BY c.id DESC""")

    def update_case(self, case_id: int, **fields: Any) -> None:
        for k, v in fields.items():
            if k in ("name", "purpose"):
                self.x(f"UPDATE cases SET {k}=? WHERE id=?", (v, case_id))
            elif k == "settings":
                self.x("UPDATE cases SET settings=? WHERE id=?", (json.dumps(v), case_id))

    def delete_case(self, case_id: int) -> None:
        self.x("DELETE FROM cases WHERE id=?", (case_id,))

    # ─── entities ───────────────────────────────────────────────────────────
    def entity(self, entity_id: int) -> dict | None:
        return self.one("SELECT * FROM entities WHERE id=?", (entity_id,))

    def entity_by_key(self, case_id: int, key: str) -> dict | None:
        return self.one("SELECT * FROM entities WHERE case_id=? AND key=?", (case_id, key))

    def entities(self, case_id: int) -> list[dict]:
        return self.q("SELECT * FROM entities WHERE case_id=? ORDER BY depth, type, id", (case_id,))

    def insert_entity(self, case_id: int, *, type: str, key: str, value: str, url: str,
                      depth: int, parent_id: int | None, flags: set[str], is_seed: bool) -> int:
        now = time.time()
        return self.x("""INSERT INTO entities(case_id,type,key,value,url,status,depth,parent_id,flags,
                                              is_seed,first_seen,last_seen)
                         VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                      (case_id, type, key, value, url, "ok" if is_seed else "new", depth, parent_id,
                       json.dumps(sorted(flags)), int(is_seed), now, now))

    def set_entity(self, entity_id: int, **fields: Any) -> None:
        allowed = {"status", "confidence", "pivot", "pivot_reason", "url", "depth", "parent_id",
                   "last_seen", "flags", "attrs"}
        for k, v in fields.items():
            if k not in allowed:
                raise KeyError(k)
            if k == "flags":
                v = json.dumps(sorted(v))
            elif k == "attrs":
                v = json.dumps(v, ensure_ascii=False)
            self.x(f"UPDATE entities SET {k}=? WHERE id=?", (v, entity_id))

    def merge_attrs(self, entity_id: int, attrs: dict) -> None:
        with self.lock:
            e = self.entity(entity_id)
            if not e:
                return
            merged = {**e["attrs"], **{k: v for k, v in attrs.items() if v not in (None, "", [], {})}}
            self.set_entity(entity_id, attrs=merged)

    # ─── runs / claims / edges ──────────────────────────────────────────────
    def add_run(self, case_id: int, module: str, entity_id: int) -> int | None:
        """None when this module already ran (or is queued) for this entity."""
        with self.lock:
            try:
                return self.x("INSERT INTO runs(case_id,module,entity_id) VALUES (?,?,?)",
                              (case_id, module, entity_id))
            except sqlite3.IntegrityError:
                return None

    def set_run(self, run_id: int, **fields: Any) -> None:
        for k, v in fields.items():
            self.x(f"UPDATE runs SET {k}=? WHERE id=?", (v, run_id))

    def runs(self, case_id: int) -> list[dict]:
        return self.q("""SELECT r.*, e.value AS entity_value, e.type AS entity_type
                         FROM runs r JOIN entities e ON e.id=r.entity_id
                         WHERE r.case_id=? ORDER BY r.id DESC""", (case_id,))

    def add_claim(self, entity_id: int, run_id: int, module: str, confidence: float,
                  raw_value: str, data: dict) -> None:
        with self.lock:
            self.db.execute("""INSERT OR IGNORE INTO claims(entity_id,run_id,module,confidence,observed,
                                                           raw_value,data) VALUES (?,?,?,?,?,?,?)""",
                            (entity_id, run_id, module, confidence, time.time(), raw_value,
                             json.dumps(data, ensure_ascii=False, default=str)))

    def claims(self, entity_id: int) -> list[dict]:
        return self.q("""SELECT c.*, r.raw_path, r.raw_sha256 FROM claims c JOIN runs r ON r.id=c.run_id
                         WHERE c.entity_id=? ORDER BY c.observed""", (entity_id,))

    def case_claims(self, case_id: int) -> list[dict]:
        return self.q("""SELECT c.entity_id, c.module, c.confidence, c.observed, c.data,
                                r.raw_path, r.raw_sha256
                         FROM claims c JOIN runs r ON r.id=c.run_id WHERE r.case_id=?""", (case_id,))

    def add_edge(self, case_id: int, src: int, dst: int, rel: str, module: str) -> None:
        if src == dst:
            return
        self.x("INSERT OR IGNORE INTO edges(case_id,src,dst,rel,module) VALUES (?,?,?,?,?)",
               (case_id, src, dst, rel, module))

    def edges(self, case_id: int) -> list[dict]:
        return self.q("SELECT * FROM edges WHERE case_id=?", (case_id,))

    def in_degree(self, entity_id: int) -> int:
        """How many distinct entities point at this one (supernode detection)."""
        r = self.one("SELECT COUNT(DISTINCT src) AS n FROM edges WHERE dst=?", (entity_id,))
        return r["n"] if r else 0

    def run_counts(self, case_id: int) -> dict[str, int]:
        rows = self.q("SELECT state, COUNT(*) AS n FROM runs WHERE case_id=? GROUP BY state", (case_id,))
        return {r["state"]: r["n"] for r in rows}

    # ─── cache (shared across cases) ────────────────────────────────────────
    def cache_get(self, module: str, key: str, ttl: float) -> Any | None:
        r = self.one("SELECT stored, payload FROM cache WHERE module=? AND key=?", (module, key))
        if r and time.time() - r["stored"] < ttl:
            return json.loads(r["payload"])
        return None

    def cache_put(self, module: str, key: str, payload: Any) -> None:
        self.x("INSERT OR REPLACE INTO cache(module,key,stored,payload) VALUES (?,?,?,?)",
               (module, key, time.time(), json.dumps(payload, ensure_ascii=False, default=str)))
