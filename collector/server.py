"""Local web UI + JSON API. Binds to 127.0.0.1 only: case data never leaves the box."""
from __future__ import annotations

import json
import re
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import __version__
from .engine import DEFAULTS, Engine
from .export import build_tree, to_csv
from .modules import PROFILES, REGISTRY
from .store import Store

UI = Path(__file__).with_name("ui.html")


def _slug(s: str) -> str:
    return re.sub(r"[^\w.\-]+", "_", s, flags=re.UNICODE)[:60] or "case"


class App:
    def __init__(self, store: Store, engine: Engine):
        self.store, self.engine = store, engine

    # Each handler returns (status, body, content_type, extra_headers)
    def route(self, method: str, path: str, query: dict, body: dict):
        parts = [p for p in path.split("/") if p]
        if method == "GET" and parts == []:
            return 200, UI.read_bytes(), "text/html; charset=utf-8", {}
        if parts[:1] != ["api"]:
            return 404, {"error": "not found"}, None, {}
        p = parts[1:]

        if method == "GET" and p == ["meta"]:
            return 200, {"version": __version__, "profiles": PROFILES, "defaults": DEFAULTS,
                         "modules": [m.describe() for m in REGISTRY.values()]}, None, {}
        if method == "GET" and p == ["cases"]:
            return 200, self.store.cases(), None, {}
        if method == "POST" and p == ["cases"]:
            name = str(body.get("name", "")).strip() or "Нова справа"
            settings = {**DEFAULTS, **{k: v for k, v in (body.get("settings") or {}).items() if k in DEFAULTS}}
            cid = self.store.create_case(name, str(body.get("purpose", "")).strip(), settings)
            return 201, self.store.case(cid), None, {}

        if len(p) >= 2 and p[0] == "cases":
            cid = int(p[1])
            case = self.store.case(cid)
            if not case:
                return 404, {"error": "справу не знайдено"}, None, {}
            if method == "GET" and len(p) == 2:
                return 200, self.case_view(cid), None, {}
            if method == "PATCH" and len(p) == 2:
                fields = {k: body[k] for k in ("name", "purpose") if k in body}
                if "settings" in body:
                    fields["settings"] = {**self.engine.settings(cid),
                                          **{k: v for k, v in body["settings"].items() if k in DEFAULTS}}
                self.store.update_case(cid, **fields)
                return 200, self.store.case(cid), None, {}
            if method == "DELETE" and len(p) == 2:
                self.engine.delete_case(cid)
                return 200, {"ok": True}, None, {}
            if method == "POST" and p[2:] == ["delete-entities"]:
                ids = [int(i) for i in body.get("ids") or []]
                return 200, self.engine.delete_entities(cid, ids), None, {}
            if method == "POST" and p[2:] == ["seeds"]:
                try:
                    e = self.engine.add_seed(cid, str(body.get("value", "")), body.get("type") or None)
                except ValueError as err:
                    return 400, {"error": str(err)}, None, {}
                return 201, e, None, {}
            if method == "POST" and p[2:] == ["link"]:
                from .analysis import link_case
                return 200, link_case(self.store, cid), None, {}
            if method == "GET" and p[2:] == ["export.osint.json"]:
                doc = build_tree(self.store, cid, include_rejected=query.get("rejected") == ["1"],
                                 min_confidence=float((query.get("min") or ["0"])[0]))
                fname = f"{_slug(case['name'])}.osint.json"
                return 200, json.dumps(doc, ensure_ascii=False, indent=1).encode(), \
                    "application/json; charset=utf-8", {"Content-Disposition": f'attachment; filename="{fname}"'}
            if method == "GET" and p[2:] == ["export.csv"]:
                fname = f"{_slug(case['name'])}.csv"
                return 200, ("﻿" + to_csv(self.store, cid)).encode(), "text/csv; charset=utf-8", \
                    {"Content-Disposition": f'attachment; filename="{fname}"'}

        if len(p) >= 2 and p[0] == "entities":
            eid = int(p[1])
            e = self.store.entity(eid)
            if not e:
                return 404, {"error": "сутність не знайдено"}, None, {}
            if method == "GET" and len(p) == 2:
                return 200, {**e, "claims": self.store.claims(eid)}, None, {}
            if method == "POST" and p[2:] == ["status"]:
                return 200, self.engine.set_status(eid, str(body.get("status"))), None, {}
            if method == "POST" and p[2:] == ["expand"]:
                return 200, self.engine.expand(eid), None, {}
            if method == "DELETE" and len(p) == 2:
                return 200, self.engine.delete_entities(e["case_id"], [eid]), None, {}
        return 404, {"error": "not found"}, None, {}

    def case_view(self, cid: int) -> dict:
        claims: dict[int, set[str]] = {}
        for c in self.store.case_claims(cid):
            claims.setdefault(c["entity_id"], set()).add(c["module"])
        ents = self.store.entities(cid)
        for e in ents:
            e["sources"] = sorted(claims.get(e["id"], ()))
        runs = self.store.runs(cid)[:300]
        return {"case": self.store.case(cid), "settings": self.engine.settings(cid),
                "progress": self.engine.progress(cid), "entities": ents, "runs": runs}


def make_handler(app: App):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"osint-collector/{__version__}"

        def log_message(self, *a):  # quiet
            pass

        def _send(self, status, payload, ctype, headers):
            if ctype is None:
                payload = json.dumps(payload, ensure_ascii=False, default=str).encode()
                ctype = "application/json; charset=utf-8"
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                             "script-src 'self' 'unsafe-inline'; img-src 'self' data: https:")
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(payload)

        def _handle(self, method: str):
            # Only same-origin browser calls: blocks other sites from driving the API.
            if method != "GET":
                origin = self.headers.get("Origin")
                host = self.headers.get("Host", "")
                if origin and urlsplit(origin).netloc != host:
                    return self._send(403, {"error": "cross-origin"}, None, {})
            u = urlsplit(self.path)
            body = {}
            n = int(self.headers.get("Content-Length") or 0)
            if n:
                try:
                    body = json.loads(self.rfile.read(n) or b"{}")
                except ValueError:
                    return self._send(400, {"error": "bad json"}, None, {})
            try:
                status, payload, ctype, headers = app.route(method, u.path, parse_qs(u.query), body)
            except (ValueError, KeyError) as e:
                status, payload, ctype, headers = 400, {"error": str(e)}, None, {}
            except Exception as e:  # never kill the server thread
                status, payload, ctype, headers = 500, {"error": f"{type(e).__name__}: {e}"}, None, {}
            self._send(status, payload, ctype, headers)

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

        def do_PATCH(self):
            self._handle("PATCH")

        def do_DELETE(self):
            self._handle("DELETE")

    return Handler


def serve(store: Store, engine: Engine, port: int = 8765, open_browser: bool = True) -> None:
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(App(store, engine)))
    url = f"http://127.0.0.1:{httpd.server_port}/"
    print(f"OSINT collector {__version__}: {url}  (Ctrl+C — зупинити)")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nЗупинено.")
    finally:
        httpd.server_close()
        engine.shutdown()

