"""Linking files by what people leave behind without noticing.

Two independent signals:

* Fingerprints in metadata (extracted per file by the `file_fingerprint` module):
  camera and lens serial numbers, document author / company, XMP DocumentID that
  survives edits, GPS. Files sharing one become linked through the same entity,
  so the normal merge logic does the work.

* Writing style (stylometry, case-level, here): character trigrams, the most
  frequent words and typing habits (dashes, ellipses, double spaces, emoji…).
  With three or more texts the features are z-scored across the set
  ("Cosine Delta"), which cancels what is just the language and keeps what is the
  author. With two texts that baseline is missing and the score is inflated.

Stylometry is a lead, not proof: it needs a few hundred words per text, is
language dependent and fails on edited or co-written text.
"""
from __future__ import annotations

import math
import re
import shutil
import subprocess
import zipfile
from collections import Counter
from html import unescape
from itertools import combinations
from pathlib import Path

MIN_WORDS = 150
MAX_CHARS = 400_000
TEXT_EXT = {".txt", ".md", ".rst", ".log", ".csv", ".srt", ".json"}
HTML_EXT = {".html", ".htm", ".xhtml"}
ZIP_XML = {".docx": "word/document.xml", ".odt": "content.xml", ".pptx": None, ".xlsx": None}
IMAGE_EXT = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".tif", ".tiff", ".heic"}

WORD = re.compile(r"[^\W\d_]+(?:['’][^\W\d_]+)?", re.UNICODE)
SENT = re.compile(r"[.!?…]+[\s\n]+")
EMOJI = re.compile("[\U0001F000-\U0001FAFF\u2600-\u27BF]")
HABITS = {  # pattern → what it says about the writer
    "em_dash": "—", "en_dash": "–", "spaced_hyphen": " - ", "ellipsis_char": "…",
    "three_dots": "...", "double_bang": "!!", "interrobang": "?!", "space_before_comma": " ,",
    "double_space": "  ", "bracket_smile": ")", "colon_smile": ":)", "guillemets": "«",
    "straight_quotes": '"', "curly_quotes": "“", "semicolon": ";",
}


# ─── Text extraction ──────────────────────────────────────────────────────────
def extract_text(path: Path) -> str:
    ext = path.suffix.lower()
    try:
        if ext in TEXT_EXT:
            return path.read_text(errors="replace")[:MAX_CHARS]
        if ext in HTML_EXT:
            html = path.read_text(errors="replace")
            html = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", html)
            return unescape(re.sub(r"<[^>]+>", " ", html))[:MAX_CHARS]
        if ext in (".docx", ".odt"):
            with zipfile.ZipFile(path) as z:
                xml = z.read(ZIP_XML[ext]).decode("utf-8", "replace")
            xml = re.sub(r"</(w:p|text:p|text:h)>", "\n", xml)
            return unescape(re.sub(r"<[^>]+>", "", xml))[:MAX_CHARS]
        if ext == ".pdf" and shutil.which("pdftotext"):
            p = subprocess.run(["pdftotext", "-q", "-enc", "UTF-8", str(path), "-"],
                               capture_output=True, text=True, timeout=60, errors="replace")
            return p.stdout[:MAX_CHARS]
        if ext == ".rtf":
            raw = path.read_text(errors="replace")
            return re.sub(r"\\[a-z]+-?\d* ?|[{}]", "", raw)[:MAX_CHARS]
    except (OSError, KeyError, zipfile.BadZipFile, subprocess.SubprocessError, UnicodeError):
        return ""
    return ""


# ─── Style profile ────────────────────────────────────────────────────────────
def profile(text: str) -> dict:
    flat = re.sub(r"\s+", " ", text).strip()
    low = flat.lower()
    words = [w.lower() for w in WORD.findall(text)]
    n_chars = max(1, len(flat))
    sentences = [s for s in SENT.split(text) if WORD.search(s)]
    habits = {k: text.count(pat) * 1000 / n_chars for k, pat in HABITS.items()}
    habits["emoji"] = len(EMOJI.findall(text)) * 1000 / n_chars
    habits["caps_words"] = sum(1 for w in WORD.findall(text) if len(w) > 2 and w.isupper()) * 1000 / max(1, len(words))
    habits["comma"] = text.count(",") * 1000 / n_chars
    habits["newline"] = text.count("\n") * 1000 / n_chars
    habits["sentence_len"] = (len(words) / len(sentences)) if sentences else 0
    habits["word_len"] = (sum(map(len, words)) / len(words)) if words else 0
    habits["lowercase_start"] = (sum(1 for s in sentences if s.strip()[:1].islower()) / len(sentences)
                                 if sentences else 0)
    return {"words": Counter(words), "n_words": len(words),
            "chars": Counter(low[i:i + 3] for i in range(len(low) - 2)), "habits": habits}


def _rel(c: Counter, keys: list[str]) -> list[float]:
    total = sum(c.values()) or 1
    return [c.get(k, 0) / total for k in keys]


def _cos(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na, nb = math.sqrt(sum(x * x for x in a)), math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def _zscore(rows: list[list[float]]) -> list[list[float]]:
    cols = list(zip(*rows))
    out_cols = []
    for col in cols:
        m = sum(col) / len(col)
        sd = math.sqrt(sum((x - m) ** 2 for x in col) / len(col)) or 1.0
        out_cols.append([(x - m) / sd for x in col])
    return [list(r) for r in zip(*out_cols)]


def _habit_sim(a: dict, b: dict) -> float:
    diffs = [abs(a[k] - b[k]) / (a[k] + b[k]) for k in a if (a[k] + b[k]) > 1e-9]
    return 1 - sum(diffs) / len(diffs) if diffs else 0.0


def style_matrix(profiles: dict[str, dict], mfw: int = 150, top_chars: int = 600) -> dict[tuple[str, str], dict]:
    """Pairwise similarity, 0..1, for every pair of documents."""
    names = list(profiles)
    if len(names) < 2:
        return {}
    words_all, chars_all = Counter(), Counter()
    for p in profiles.values():
        words_all.update(p["words"])
        chars_all.update(p["chars"])
    wkeys = [w for w, _ in words_all.most_common(mfw)]
    ckeys = [c for c, _ in chars_all.most_common(top_chars)]
    wv = [_rel(profiles[n]["words"], wkeys) for n in names]
    cv = [_rel(profiles[n]["chars"], ckeys) for n in names]
    relative = len(names) >= 3
    if relative:          # Cosine Delta: remove what all texts share (the language)
        wv, cv = _zscore(wv), _zscore(cv)
    out = {}
    for i, j in combinations(range(len(names)), 2):
        w, c = _cos(wv[i], wv[j]), _cos(cv[i], cv[j])
        if relative:
            w, c = (w + 1) / 2, (c + 1) / 2
        h = _habit_sim(profiles[names[i]]["habits"], profiles[names[j]]["habits"])
        out[(names[i], names[j])] = {"score": round(0.4 * c + 0.35 * w + 0.25 * h, 3),
                                     "chars": round(c, 3), "words": round(w, 3), "habits": round(h, 3),
                                     "relative": relative}
    return out


HABIT_LABEL = {"em_dash": "довге тире —", "en_dash": "коротке тире –", "spaced_hyphen": "дефіс як тире ( - )",
               "ellipsis_char": "знак …", "three_dots": "три крапки ...", "double_bang": "!!",
               "interrobang": "?!", "space_before_comma": "пробіл перед комою", "double_space": "подвійний пробіл",
               "bracket_smile": "дужки-смайли )", "colon_smile": ":)", "guillemets": "лапки «»",
               "straight_quotes": 'прямі лапки "', "curly_quotes": "лапки “”", "semicolon": "крапка з комою"}


def shared_habits(a: dict, b: dict, top: int = 4) -> list[str]:
    """Habits both writers use noticeably, for the human-readable explanation."""
    keys = [k for k in HABITS if a["habits"][k] > 0.3 and b["habits"][k] > 0.3]
    return [HABIT_LABEL.get(k, k) for k in sorted(keys, key=lambda k: -(a["habits"][k] + b["habits"][k]))[:top]]


# ─── Images ───────────────────────────────────────────────────────────────────
def dhash(path: Path) -> str | None:
    """64-bit difference hash; survives resizing and recompression. Needs Pillow."""
    try:
        from PIL import Image  # type: ignore
    except ImportError:
        return None
    try:
        with Image.open(path) as im:
            g = im.convert("L").resize((9, 8))
            px = list(g.getdata())
    except Exception:
        return None
    bits = 0
    for row in range(8):
        for col in range(8):
            bits = (bits << 1) | (px[row * 9 + col] > px[row * 9 + col + 1])
    return f"{bits:016x}"


def hamming(a: str, b: str) -> int:
    return bin(int(a, 16) ^ int(b, 16)).count("1")


# ─── Case-level linking ───────────────────────────────────────────────────────
def link_case(store, case_id: int, style_threshold: float | None = None, image_distance: int = 6) -> dict:
    """Compare every file in a case: style for texts, dHash for images. Adds edges."""
    files = [e for e in store.entities(case_id) if e["type"] == "file" and e["status"] != "no"]
    report: dict = {"files": len(files), "texts": 0, "too_short": [], "style": [], "images": [],
                    "shared": [], "notes": []}

    # 1. writing style
    profiles: dict[str, dict] = {}
    by_name = {}
    for e in files:
        text = extract_text(Path(e["value"]))
        if not text.strip():
            continue
        p = profile(text)
        if p["n_words"] < MIN_WORDS:
            report["too_short"].append(Path(e["value"]).name)
            continue
        profiles[e["value"]] = p
        by_name[e["value"]] = e
    report["texts"] = len(profiles)
    if len(profiles) == 2:
        report["notes"].append("Лише два тексти: фон мови не відсікається, оцінка завищена. "
                               "Додайте ще тексти (ідеально кілька різних авторів для порівняння).")
    matrix = style_matrix(profiles)
    if matrix:
        thr = style_threshold if style_threshold is not None else (0.72 if len(profiles) >= 3 else 0.9)
        for (a, b), s in sorted(matrix.items(), key=lambda kv: -kv[1]["score"]):
            if s["score"] < thr:
                continue
            ea, eb = by_name[a], by_name[b]
            store.add_edge(case_id, ea["id"], eb["id"], "similar_style", "stylometry")
            habits = shared_habits(profiles[a], profiles[b])
            report["style"].append({"a": Path(a).name, "b": Path(b).name, **s, "shared_habits": habits})
            for me, other in ((ea, eb), (eb, ea)):
                cur = store.entity(me["id"])["attrs"].get("схожий_стиль", "")
                item = f"{Path(other['value']).name} ({round(s['score'] * 100)}%)"
                if item not in cur:
                    store.merge_attrs(me["id"], {"схожий_стиль": ", ".join(x for x in (cur, item) if x)})

    # 2. near-duplicate images
    hashes = {e["id"]: e["attrs"].get("dhash") for e in files if e["attrs"].get("dhash")}
    for (ia, ha), (ib, hb) in combinations(hashes.items(), 2):
        d = hamming(ha, hb)
        if d <= image_distance:
            store.add_edge(case_id, ia, ib, "similar_image", "dhash")
            na, nb = Path(store.entity(ia)["value"]).name, Path(store.entity(ib)["value"]).name
            report["images"].append({"a": na, "b": nb, "distance": d})
    if files and not hashes and any(Path(e["value"]).suffix.lower() in IMAGE_EXT for e in files):
        report["notes"].append("Порівняння схожих фото недоступне: встановіть Pillow (pip install pillow).")

    # 3. metadata fingerprints shared by 2+ files (already linked through one entity)
    file_ids = {e["id"] for e in files}
    names = {e["id"]: Path(e["value"]).name for e in files}
    by_dst: dict[int, set[int]] = {}
    for ed in store.edges(case_id):
        if ed["src"] in file_ids and ed["rel"].startswith("meta_"):
            by_dst.setdefault(ed["dst"], set()).add(ed["src"])
    for dst, srcs in by_dst.items():
        if len(srcs) >= 2:
            ent = store.entity(dst)
            report["shared"].append({"what": ent["value"], "type": ent["type"],
                                     "files": sorted(names[s] for s in srcs)})
    report["shared"].sort(key=lambda r: -len(r["files"]))
    return report
