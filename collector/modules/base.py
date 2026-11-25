"""Module contract. Every source (native HTTP call or wrapped CLI tool) implements it.

A module takes one entity and returns a Result: new findings (other entities it
points to) plus attrs that enrich the input entity itself. It never writes to the
store: the engine does normalisation, de-duplication and scoring.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

from ..normalize import sha256

UA = "osint-collector/0.1 (+https://github.com/radmorex/osint-launcher)"


@dataclass
class Finding:
    type: str                  # entity type the value should normalise to
    value: str
    rel: str                   # how it relates to the input entity: "registered_on", "resolves_to"…
    confidence: float          # how sure THIS module is, 0..1
    data: dict = field(default_factory=dict)
    attrs: dict = field(default_factory=dict)   # attributes for the found entity


@dataclass
class Result:
    findings: list[Finding] = field(default_factory=list)
    attrs: dict = field(default_factory=dict)   # attributes for the input entity
    flags: set = field(default_factory=set)     # junk flags for the input entity ("wildcard")
    raw: bytes = b""                            # evidence: exact bytes the source returned
    raw_ext: str = "txt"

    def add(self, *a: Any, **kw: Any) -> None:
        self.findings.append(Finding(*a, **kw))


class ModuleError(RuntimeError):
    pass


class Context:
    """What a module may touch: HTTP, a scratch dir for tool output, timeouts."""

    def __init__(self, workdir: Path, timeout: float = 60, env: dict | None = None):
        self.workdir = workdir
        self.timeout = timeout
        self.env = env if env is not None else dict(os.environ)

    # HTTP ------------------------------------------------------------------
    def http(self, url: str, *, headers: dict | None = None, timeout: float | None = None,
             accept_404: bool = True, retries: int = 2) -> tuple[int, bytes]:
        h = {"User-Agent": UA, "Accept": "application/json, text/plain, */*"}
        h.update(headers or {})
        last: Exception | None = None
        for attempt in range(retries + 1):
            try:
                req = urllib.request.Request(url, headers=h)
                with urllib.request.urlopen(req, timeout=timeout or self.timeout) as r:
                    return r.status, r.read()
            except urllib.error.HTTPError as e:
                if e.code == 404 and accept_404:
                    return 404, e.read() if e.fp else b""
                if e.code in (429, 500, 502, 503, 504) and attempt < retries:
                    time.sleep(2 * (attempt + 1))
                    last = e
                    continue
                raise ModuleError(f"HTTP {e.code} від {url.split('?')[0]}") from e
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                last = e
                if attempt < retries:
                    time.sleep(1.5 * (attempt + 1))
                    continue
        raise ModuleError(f"мережа недоступна: {last}")

    def http_json(self, url: str, **kw: Any) -> tuple[int, Any, bytes]:
        status, body = self.http(url, **kw)
        if status == 404:
            return 404, None, body
        try:
            return status, json.loads(body or b"null"), body
        except ValueError as e:
            raise ModuleError(f"не JSON від {url.split('?')[0]}") from e

    # CLI tools -------------------------------------------------------------
    def run_tool(self, argv: list[str], *, cwd: Path | None = None, timeout: float | None = None,
                 stdin: str | None = None) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(argv, cwd=cwd or self.workdir, input=stdin, capture_output=True,
                                  text=True, encoding="utf-8", errors="replace",
                                  timeout=timeout or self.timeout, env=self.env)
        except subprocess.TimeoutExpired as e:
            raise ModuleError(f"{Path(argv[0]).name}: перевищено час ({int(e.timeout)} с)") from e
        except FileNotFoundError as e:
            raise ModuleError(f"{argv[0]} не знайдено") from e


class Module:
    name: ClassVar[str] = ""
    title: ClassVar[str] = ""
    consumes: ClassVar[tuple[str, ...]] = ()
    produces: ClassVar[tuple[str, ...]] = ()
    reliability: ClassVar[float] = 0.7     # how often this source is right, scales its claims
    passive: ClassVar[bool] = True         # False = touches the target's own infrastructure
    cost: ClassVar[int] = 1                # relative: 0 offline, 1 one API call, 5+ heavy tool
    concurrency: ClassVar[int] = 4         # parallel runs of this module
    timeout: ClassVar[float] = 60
    cache_ttl: ClassVar[float] = 24 * 3600
    version: ClassVar[int] = 1             # bump when parsing changes: cached results of older versions are ignored
    binary: ClassVar[str | None] = None    # CLI tool it wraps
    env_key: ClassVar[str | None] = None   # API key / cookie the module reads from the environment
    key_required: ClassVar[bool] = False   # True: without env_key the module returns nothing useful
    profiles: ClassVar[tuple[str, ...]] = ("quick", "standard", "deep")

    def accepts(self, entity: dict) -> bool:
        """Finer filter than `consumes` (e.g. only registered domains)."""
        return entity["type"] in self.consumes

    @classmethod
    def available(cls) -> tuple[bool, str]:
        if cls.binary and not shutil.which(cls.binary):
            return False, f"не встановлено: {cls.binary}"
        return True, ""

    def run(self, entity: dict, ctx: Context) -> Result:  # pragma: no cover - interface
        raise NotImplementedError

    @classmethod
    def describe(cls) -> dict:
        ok, why = cls.available()
        return {"name": cls.name, "title": cls.title, "consumes": list(cls.consumes),
                "produces": list(cls.produces), "passive": cls.passive, "cost": cls.cost,
                "reliability": cls.reliability, "profiles": list(cls.profiles),
                "available": ok, "reason": why, "env_key": cls.env_key, "key_required": cls.key_required,
                "has_key": bool(cls.env_key and os.environ.get(cls.env_key))}


def evidence(raw: bytes, workdir: Path, ext: str) -> tuple[str, str]:
    digest = sha256(raw)
    path = workdir / f"{digest[:16]}.{ext}"
    path.write_bytes(raw)
    return str(path), digest
