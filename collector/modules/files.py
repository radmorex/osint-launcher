"""File fingerprints: what metadata ties a file to a device, a person or other files.

Runs offline on local files only (nothing is uploaded). Strong links become
entities that several files can share: a camera serial number, a lens serial,
an XMP DocumentID (survives edits and exports), the document author and
company, GPS coordinates. Weak, widely shared values (camera model, plain
program name) stay attributes so they do not glue unrelated files together.
"""
from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path

from ..analysis import IMAGE_EXT, dhash, extract_text, profile
from .base import Context, Module, Result

GENERIC_AUTHORS = {"user", "admin", "administrator", "author", "owner", "windows user", "microsoft office user",
                   "unknown", "пользователь", "користувач", "admin1", "home", "pc", "test", "none", "-"}


def _val(meta: dict, *keys: str) -> str:
    for k in keys:
        v = meta.get(k)
        if isinstance(v, list):
            v = ", ".join(str(x) for x in v if str(x).strip())
        if v not in (None, "", 0) and str(v).strip() and str(v).strip().lower() not in ("unknown", "n/a"):
            return str(v).strip()
    return ""


def fingerprints(meta: dict) -> Result:
    """exiftool -j -n output for one file → findings + attrs. Pure, testable."""
    res = Result()
    make, model = _val(meta, "Make"), _val(meta, "Model")
    camera = model if make and model.lower().startswith(make.lower()) else " ".join(x for x in (make, model) if x)
    serial = _val(meta, "SerialNumber", "BodySerialNumber", "InternalSerialNumber", "CameraSerialNumber")
    if serial:
        res.add("fingerprint", f"камера {camera or '?'} · серійний {serial}", "meta_camera_serial", 0.95)
    elif camera:
        res.attrs["камера"] = camera
    lens = _val(meta, "LensSerialNumber")
    if lens:
        res.add("fingerprint", f"об'єктив · серійний {lens}", "meta_lens_serial", 0.9)
    if _val(meta, "LensModel", "LensID"):
        res.attrs["об'єктив"] = _val(meta, "LensModel", "LensID")
    owner = _val(meta, "OwnerName", "CameraOwnerName", "Artist")
    if owner and owner.lower() not in GENERIC_AUTHORS:
        res.add("person", owner, "meta_owner", 0.8)

    for key, rel in (("Author", "meta_author"), ("Creator", "meta_author"), ("LastModifiedBy", "meta_modified_by")):
        v = _val(meta, key)
        if v and v.lower() not in GENERIC_AUTHORS and not any(t in v.lower() for t in ("adobe", "microsoft", "word")):
            res.add("person", v, rel, 0.7)
    company = _val(meta, "Company")
    if company:
        res.add("org", company, "meta_company", 0.7)
    rights = _val(meta, "Copyright", "Rights")
    if rights:
        res.attrs["copyright"] = rights

    for key in ("DocumentID", "OriginalDocumentID", "DerivedFromDocumentID"):
        v = _val(meta, key)
        if v:
            res.add("fingerprint", f"XMP-документ {v.removeprefix('xmp.did:').removeprefix('uuid:')}",
                    "meta_document_id", 0.9)

    lat, lon = meta.get("GPSLatitude"), meta.get("GPSLongitude")
    if isinstance(lat, (int, float)) and isinstance(lon, (int, float)) and (lat or lon):
        place = f"{lat:.5f}, {lon:.5f}"
        res.add("location", place, "meta_gps", 0.9,
                attrs={"карта": f"https://www.openstreetmap.org/?mlat={lat:.5f}&mlon={lon:.5f}#map=17/{lat:.5f}/{lon:.5f}"})

    software = _val(meta, "Software", "CreatorTool", "Producer", "Application")
    if software:
        res.attrs["програма"] = software
        if any(ch.isdigit() for ch in software) and len(software) > 12:
            # an exact build string is a weak but real link between files
            res.add("fingerprint", f"програма {software}", "meta_software", 0.3)
    for k_out, keys in (("знято", ("DateTimeOriginal",)), ("створено", ("CreateDate",)),
                        ("змінено", ("ModifyDate", "FileModifyDate"))):
        v = _val(meta, *keys)
        if v:
            res.attrs[k_out] = v
    host = _val(meta, "HostComputer", "DeviceManufacturer")
    if host:
        res.attrs["пристрій"] = host
    return res


class FileFingerprint(Module):
    name, title = "file_fingerprint", "Відбитки файлу (EXIF, автор, XMP, GPS)"
    consumes, produces = ("file",), ("fingerprint", "person", "org", "location")
    reliability, cost, concurrency, timeout = 0.95, 0, 4, 120
    cache_ttl = 30 * 24 * 3600   # keyed by content hash: same bytes, same answer

    def run(self, entity: dict, ctx: Context) -> Result:
        path = Path(entity["value"])
        meta: dict = {}
        raw = b""
        if shutil.which("exiftool"):
            # path goes through a UTF-8 argument file: on Windows ExifTool can't read
            # non-ASCII (e.g. Cyrillic) file names straight from the command line
            argfile = ctx.workdir / "exiftool-args.txt"
            argfile.write_text(str(path) + "\n", encoding="utf-8")
            p = ctx.run_tool(["exiftool", "-charset", "filename=utf8", "-j", "-n", "-a", "-struct",
                              "-@", str(argfile)], timeout=60)
            raw = p.stdout.encode()
            try:
                meta = (json.loads(p.stdout or "[]") or [{}])[0]
            except ValueError:
                meta = {}
        res = fingerprints(meta)
        if not shutil.which("exiftool"):
            res.attrs["метадані"] = "exiftool не встановлено: лише текст і хеш зображення"
        res.attrs["розмір"] = f"{path.stat().st_size:,} байт".replace(",", " ")
        res.attrs.setdefault("змінено", datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M"))
        if path.suffix.lower() in IMAGE_EXT:
            h = dhash(path)
            if h:
                res.attrs["dhash"] = h
        text = extract_text(path)
        if text.strip():
            res.attrs["слів"] = profile(text)["n_words"]
        res.raw, res.raw_ext = raw or b"{}", "json"
        return res


MODULES = [FileFingerprint]
