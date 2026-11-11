"""
Local knowledge-base corpus — plan 5.1 (docs/plan-5.1-local-kb-retrieval.md).

Three corpus tiers behind one doc model, shared by report(action='recall')
(tiers A/B/C) and scripts/build_kb.py (tier A builder):

    Tier A  kb/sources/<name>/  + kb/index.db   static security KB (GTFOBins,
            LOLBAS, WSTG, ExploitDB, NVD, nuclei templates, our skill refs)
    Tier B  kb/sessions/<sid>/                 per-engagement attached docs
            (client PDFs, API docs, documents found on the target)
    Tier C  engagements/<name>/                prior-engagement stores (digest
            builder output; gathered by report_tools/recall.py, not here)

Doc shape (a plain dict — recall scores (source, text) pairs as before):

    {source, kind, title, tags, text, untrusted}

Retrieval: SQLite FTS5 (bm25() ranking + snippet()) when kb/index.db exists,
deterministic flat-scan scoring otherwise — recall never hard-fails on a
missing/unreadable index. Pure stdlib; PyYAML is optional (build_kb degrades
to raw-text ingestion without it).

Untrusted-content fence: tier-B docs fetched FROM a target are attacker
influenceable input. They carry untrusted=1 (meta.json in the session dir),
render with an UNTRUSTED label prefix in recall output, and are data — never
instructions.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

# Root is cwd-relative (like engagements/) so a checkout is self-contained;
# SMITH_KB_ROOT overrides for machine-global installs (plan §10.4).
KB_ROOT = Path(os.environ.get("SMITH_KB_ROOT", "kb"))
SOURCES_DIR = KB_ROOT / "sources"
RAW_DIR = KB_ROOT / "sources" / "_raw"          # upstream clones/downloads
SESSIONS_DIR = KB_ROOT / "sessions"
INDEX_DB = KB_ROOT / "index.db"
MANIFEST = KB_ROOT / "MANIFEST.json"

# Registry of static-KB source names (build_kb.py implements the fetchers).
KB_KINDS = {
    "skill_refs": "skill_ref",
    "gtfobins": "gtfobins",
    "lolbas": "lolbas",
    "wstg": "wstg",
    "exploitdb": "exploit",
    "nvd": "cve",
    "nuclei": "nuclei",
}

_TOKEN = re.compile(r"[a-zA-Z0-9_.:/-]{2,}")
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_MAX_DOC_BYTES = 200_000          # cap per flat-scan file read
_MAX_CHUNK = 6_000                # build-side chunk ceiling for long bodies


def tokens(text: str) -> list[str]:
    return [t.lower() for t in _TOKEN.findall(text or "")]


def read_text(path: str | Path, cap: int = _MAX_DOC_BYTES) -> str:
    try:
        with open(path, "r", errors="replace") as fh:
            return _ANSI.sub("", fh.read(cap))
    except Exception:
        return ""


# ── FTS5 index ────────────────────────────────────────────────────────────
_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS kb_docs USING fts5(
    source UNINDEXED, kind UNINDEXED, title, tags UNINDEXED, body, untrusted UNINDEXED);
CREATE TABLE IF NOT EXISTS kb_meta(
    source TEXT PRIMARY KEY, docs INT, built_at TEXT, upstream_ref TEXT, license TEXT);
"""


def fts5_available() -> bool:
    """True when the stdlib sqlite3 was compiled with FTS5."""
    try:
        con = sqlite3.connect(":memory:")
        con.execute("CREATE VIRTUAL TABLE _probe USING fts5(x)")
        con.close()
        return True
    except Exception:
        return False


def open_index(path: Path | None = None, create: bool = False) -> sqlite3.Connection | None:
    """Open kb/index.db read-only-ish; None when missing (or FTS5 absent and !create)."""
    db = Path(path) if path else INDEX_DB
    if not create and not db.exists():
        return None
    if not fts5_available():
        return None
    if create:
        db.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(db))
    if create:
        con.executescript(_SCHEMA)
    return con


def replace_source(con: sqlite3.Connection, source_prefix: str, docs: list[dict]) -> int:
    """Atomically re-index one KB source: delete its rows, insert `docs`."""
    with con:
        con.execute("DELETE FROM kb_docs WHERE source LIKE ?", (source_prefix + "/%",))
        con.executemany(
            "INSERT INTO kb_docs (source, kind, title, tags, body, untrusted) "
            "VALUES (?,?,?,?,?,?)",
            [(d["source"], d["kind"], d.get("title", ""), " ".join(d.get("tags", [])),
              d["text"], 1 if d.get("untrusted") else 0) for d in docs])
        n = con.execute("SELECT changes()").fetchone()[0]
    return len(docs)


def record_meta(con: sqlite3.Connection, source: str, docs: int,
                upstream_ref: str = "", license_note: str = "") -> None:
    with con:
        con.execute(
            "INSERT INTO kb_meta (source, docs, built_at, upstream_ref, license) "
            "VALUES (?,?,?,?,?) ON CONFLICT(source) DO UPDATE SET "
            "docs=excluded.docs, built_at=excluded.built_at, "
            "upstream_ref=excluded.upstream_ref, license=excluded.license",
            (source, docs, datetime.now(timezone.utc).isoformat(timespec="seconds"),
             upstream_ref, license_note))


def fts_match_expr(query: str) -> str:
    """OR-join query tokens into a safe FTS5 MATCH expression (quoted terms)."""
    seen, terms = set(), []
    for tok in tokens(query):
        t = tok.strip('"')
        if len(t) >= 2 and t not in seen:
            seen.add(t)
            terms.append(f'"{t}"')
    return " OR ".join(terms)


def query_index(con: sqlite3.Connection, query: str, kinds: list[str] | None = None,
                limit: int = 8) -> list[dict]:
    """BM25-ranked hits from kb/index.db with highlighted snippets.
    AND-first (all query terms must match) with an OR fallback when that
    yields nothing — precision matters once the corpus holds 300k+ docs."""
    terms = [f'"{t}"' for t in dict.fromkeys(tokens(query)) if len(t) >= 2]
    if not terms:
        return []
    sql = ("SELECT source, kind, title, snippet(kb_docs, 4, '»', '«', '…', 14) AS snip, "
           "untrusted, bm25(kb_docs) AS rank FROM kb_docs WHERE kb_docs MATCH ?")
    args_extra: list = []
    if kinds:
        sql += " AND kind IN (%s)" % ",".join("?" * len(kinds))
        args_extra += kinds
    sql += " ORDER BY rank LIMIT ?"
    rows: list = []
    try:
        for expr in (" AND ".join(terms), " OR ".join(terms)):
            rows = con.execute(sql, [expr] + args_extra + [limit]).fetchall()
            if rows:
                break
    except sqlite3.OperationalError:
        return []
    return [{"source": r[0], "kind": r[1], "title": r[2], "snippet": r[3],
             "untrusted": bool(r[4]), "bm25": r[5]} for r in rows]


def index_stats(con: sqlite3.Connection) -> dict:
    """{source_kind: docs} + built_at for the recall provenance line."""
    try:
        rows = con.execute("SELECT kind, COUNT(*) FROM kb_docs GROUP BY kind").fetchall()
        meta = dict(con.execute("SELECT source, built_at FROM kb_meta").fetchall())
        return {"kinds": dict(rows), "meta": meta,
                "built_at": max(meta.values()) if meta else None}
    except sqlite3.OperationalError:
        return {"kinds": {}, "meta": {}, "built_at": None}


def kb_status() -> dict:
    """Which corpus tiers are actually populated — the presence gate for the recall
    reflex. Cheap + fail-soft. A user who never built the KB and never attached a doc
    gets ``any=False``, so the recall nudges/norm stay dormant and the feature is
    invisible + zero-cost (no empty-result noise, especially for small local models).

    Returns {kb_index, kb_sources, docs, engagements, kb, any, summary}.
    """
    index_docs = 0
    try:
        con = open_index()
        if con is not None:
            try:
                index_docs = sum(int(v) for v in index_stats(con).get("kinds", {}).values())
            finally:
                con.close()
    except Exception:
        index_docs = 0
    try:
        sources = KB_ROOT / "sources"
        kb_sources = sources.is_dir() and any(p.is_dir() for p in sources.iterdir())
    except Exception:
        kb_sources = False
    try:
        docs = len(iter_session_docs())
    except Exception:
        docs = 0
    try:
        import glob as _glob
        engagements = len(_glob.glob("engagements/*/resume.json"))
    except Exception:
        engagements = 0

    kb_present = bool(index_docs) or bool(kb_sources)
    bits: list[str] = []
    if index_docs:
        bits.append(f"{index_docs} static-KB docs")
    elif kb_sources:
        bits.append("static-KB sources (unindexed — run build_kb.py)")
    if docs:
        bits.append(f"{docs} engagement doc(s)")
    if engagements:
        bits.append(f"{engagements} prior-engagement store(s)")
    return {
        "kb_index": index_docs, "kb_sources": kb_sources, "docs": docs,
        "engagements": engagements, "kb": kb_present,
        "any": kb_present or bool(docs) or bool(engagements),
        "summary": ", ".join(bits) if bits else "no KB or engagement docs configured",
    }


# ── Flat-scan providers (zero-index fallback + tier B) ────────────────────
_FLAT_EXTS = {".md", ".txt", ".json", ".yaml", ".yml", ".csv", ".log", ".http", ".html"}


def _chunk(text: str) -> list[str]:
    """Split very long text on paragraph/heading boundaries (flat-scan read cap
    already bounds size; this keeps single docs from dominating snippets)."""
    if len(text) <= _MAX_CHUNK:
        return [text]
    parts, cur = [], ""
    for block in re.split(r"\n\s*\n", text):
        if len(cur) + len(block) > _MAX_CHUNK and cur:
            parts.append(cur)
            cur = block
        else:
            cur = (cur + "\n\n" + block) if cur else block
    if cur:
        parts.append(cur)
    return parts


def iter_kb_sources(root: Path | None = None) -> list[dict]:
    """Tier A flat scan: every file under kb/sources/<name>/ (excluding _raw
    clones' .git noise) becomes 1+ docs. Used when no FTS index exists."""
    base = Path(root) if root else SOURCES_DIR
    if not base.is_dir():
        return []
    docs: list[dict] = []
    for path in sorted(base.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in _FLAT_EXTS:
            continue
        rel = path.relative_to(base)
        if rel.parts and rel.parts[0] == "_raw":
            continue
        src_name = rel.parts[0] if rel.parts else "misc"
        kind = KB_KINDS.get(src_name, src_name)
        text = read_text(path)
        if not text.strip():
            continue
        for i, chunk in enumerate(_chunk(text)):
            docs.append({"source": f"kb:{rel.as_posix()}" + (f"#chunk-{i}" if i else ""),
                         "kind": kind, "title": rel.as_posix(), "tags": [],
                         "text": chunk, "untrusted": False})
    return docs


def iter_session_docs(root: Path | None = None) -> list[dict]:
    """Tier B flat scan: kb/sessions/<sid>/** — docs attached to engagements.
    Per-dir meta.json = {"untrusted": [names...], "notes": {...}} marks files
    that were fetched FROM the target (injection fence)."""
    base = Path(root) if root else SESSIONS_DIR
    if not base.is_dir():
        return []
    docs: list[dict] = []
    for sdir in sorted(p for p in base.iterdir() if p.is_dir()):
        meta = {}
        meta_path = sdir / "meta.json"
        if meta_path.is_file():
            try:
                meta = json.loads(meta_path.read_text(errors="replace"))
            except Exception:
                meta = {}
        untrusted = set(meta.get("untrusted") or [])
        for path in sorted(sdir.rglob("*")):
            if not path.is_file() or path.name == "meta.json":
                continue
            if path.suffix.lower() not in _FLAT_EXTS:
                continue
            rel = path.relative_to(sdir)
            text = read_text(path)
            if not text.strip():
                continue
            is_untrusted = rel.as_posix() in untrusted or path.name in untrusted
            for i, chunk in enumerate(_chunk(text)):
                docs.append({"source": f"docs:{sdir.name}/{rel.as_posix()}"
                                           + (f"#chunk-{i}" if i else ""),
                             "kind": "engagement_doc", "title": rel.as_posix(), "tags": [],
                             "text": chunk, "untrusted": is_untrusted})
    return docs


# ── Session-doc lifecycle (plan 5.1 §6.3 — ephemeral per-engagement data) ──
def purge_session_docs(session_id: str | None = None) -> int:
    """Delete per-engagement docs (kb/sessions/<sid>/ or every sid when None).

    Engagement docs are EPHEMERAL by design: client/target material lives only
    for the active scan and is purged when the scan completes (lifecycle) or a
    new scan starts (sweep) — data minimization. Only NAMES survive, inside
    session.json's known_assets.kb_docs audit trail. The static KB
    (kb/sources/ + kb/index.db) is NEVER touched by this purge.
    → number of docs removed."""
    import shutil as _sh
    if not SESSIONS_DIR.is_dir():
        return 0
    targets = [SESSIONS_DIR / session_id] if session_id else \
        [d for d in SESSIONS_DIR.iterdir() if d.is_dir()]
    removed = 0
    for d in targets:
        for f in d.rglob("*") if d.is_dir() else []:
            if f.is_file() and f.name != "meta.json" and not f.name.startswith("raw_"):
                removed += 1
        _sh.rmtree(d, ignore_errors=True)
    return removed


def load_manifest(path: Path | None = None) -> dict:
    p = Path(path) if path else MANIFEST
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(errors="replace"))
    except Exception:
        return {}


# ── Unindexed custom dirs (no-code KB extension, plan §5 README flow) ─────
def unindexed_source_dirs(con: sqlite3.Connection | None) -> list[Path]:
    """kb/sources/ subdirectories that are NOT built by build_kb.py (no kb_meta
    row). Files dropped there are always flat-scanned by recall — even when an
    FTS index exists — so a no-code `kb/sources/myorg-playbooks/*.md` drop works
    without touching the builder."""
    if not SOURCES_DIR.is_dir():
        return []
    indexed = set()
    if con is not None:
        try:
            indexed = {r[0] for r in con.execute("SELECT source FROM kb_meta").fetchall()}
        except sqlite3.OperationalError:
            indexed = set()
    out = []
    for d in sorted(SOURCES_DIR.iterdir()):
        if d.is_dir() and d.name != "_raw" and d.name not in indexed:
            out.append(d)
    return out


# ── Document parsers (session kb_add — plan §6.2) ─────────────────────────
_RAW_PARSE_EXTS = _FLAT_EXTS | {".pdf", ".docx", ".doc", ".xml"}


def _pdf_to_text(path: Path) -> tuple[str, str]:
    """pdftotext (poppler) → pypdf (if importable) → naive salvage. Fail-soft."""
    import shutil as _sh
    import subprocess as _sp
    if _sh.which("pdftotext"):
        try:
            r = _sp.run(["pdftotext", "-layout", str(path), "-"],
                        capture_output=True, timeout=120)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.decode("utf-8", errors="replace"), "pdftotext"
        except Exception:
            pass
    try:
        from pypdf import PdfReader                     # optional dep
        reader = PdfReader(str(path))
        text = "\n".join((page.extract_text() or "") for page in reader.pages)
        if text.strip():
            return text, "pypdf"
    except Exception:
        pass
    raw = path.read_bytes()[:200_000]
    # naive salvage: uncompressed text objects only — better than nothing
    import re as _re
    chunks = _re.findall(rb"\(([^()\\]{4,})\)", raw)
    return ("\n".join(c.decode("latin-1", errors="replace") for c in chunks),
            "naive-salvage (install poppler/pdftotext or pypdf for full text)")


def _docx_to_text(path: Path) -> tuple[str, str]:
    import shutil as _sh
    import subprocess as _sp
    if _sh.which("textutil"):                          # macOS
        try:
            r = _sp.run(["textutil", "-convert", "txt", "-stdout", str(path)],
                        capture_output=True, timeout=120)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.decode("utf-8", errors="replace"), "textutil"
        except Exception:
            pass
    if _sh.which("pandoc"):
        try:
            r = _sp.run(["pandoc", "-t", "plain", str(path)],
                        capture_output=True, timeout=120)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.decode("utf-8", errors="replace"), "pandoc"
        except Exception:
            pass
    return "", "no docx parser (install pandoc, or on macOS textutil)"


def _html_to_text(text: str) -> str:
    text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    import html as _html
    return _html.unescape(_html.unescape(text))


def _structured_to_text(text: str, fname: str) -> str:
    """JSON/YAML → searchable text. OpenAPI/GraphQL-aware (plan §6.2): one
    block per operation/endpoint — the highest-value doc type for coverage."""
    data, is_json = None, fname.endswith(".json") or fname.endswith(".graphql.json")
    try:
        data = json.loads(text) if is_json else None
    except Exception:
        data = None
    if data is None and fname.endswith((".yaml", ".yml")) and yaml_ok():
        try:
            data = yaml_load(text)
        except Exception:
            data = None
    if not isinstance(data, dict):
        return text
    spec = data.get("openapi") or data.get("swagger") or ""
    if spec:
        lines = [f"OpenAPI {spec}"]
        for path_, ops in (data.get("paths") or {}).items():
            for method, op in (ops or {}).items():
                if not isinstance(op, dict):
                    continue
                params = ", ".join(
                    f"{p.get('name')}({p.get('in')})" for p in op.get("parameters") or [])
                lines.append(f"{method.upper()} {path_} — {op.get('summary') or op.get('operationId') or ''}"
                             f" params[{params}]")
        if len(lines) > 1:
            return "\n".join(lines) + "\n\n" + text[:20_000]
    return json.dumps(data, indent=1, default=str)[:200_000]


def yaml_ok() -> bool:
    try:
        import yaml  # noqa: F401
        return True
    except Exception:
        return False


def yaml_load(text: str):
    import yaml
    return yaml.safe_load(text)


def parse_document(path: Path) -> tuple[str, str, str]:
    """→ (text, parser_note, status) — status ok|empty|skipped. Fail-soft chain."""
    suf = path.suffix.lower()
    try:
        if suf == ".pdf":
            text, note = _pdf_to_text(path)
        elif suf in (".docx", ".doc"):
            text, note = _docx_to_text(path)
            if not text:
                return "", note, "skipped"
        elif suf in (".html", ".htm"):
            text, note = _html_to_text(read_text(path)), "html-strip"
        elif suf in (".json", ".yaml", ".yml"):
            text, note = _structured_to_text(read_text(path), path.name), "structured"
        else:                                           # md/txt/csv/log/http/xml…
            text, note = read_text(path), "raw"
        text = text.strip()
        if not text:
            return "", note + " (no text extracted)", "empty"
        return text[:400_000], note, "ok"
    except Exception as exc:
        return "", f"parse error: {exc}", "skipped"


# ── Session-doc writer (plan §6.1/6.4) ────────────────────────────────────
def add_session_doc(session_id: str, name: str, text: str, untrusted: bool) -> Path:
    """Write one ingested doc under kb/sessions/<sid>/ + update meta.json."""
    sdir = SESSIONS_DIR / session_id
    sdir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^a-zA-Z0-9._()-]+", "_", name).strip("_") or "doc"
    dest = sdir / safe
    i = 1
    while dest.exists():                                # don't clobber distinct docs
        dest = sdir / f"{i}_{safe}"
        i += 1
    dest.write_text(text, encoding="utf-8", errors="replace")
    if untrusted:
        meta_path = sdir / "meta.json"
        meta = {}
        if meta_path.is_file():
            try:
                meta = json.loads(meta_path.read_text(errors="replace"))
            except Exception:
                meta = {}
        un = set(meta.get("untrusted") or [])
        un.add(dest.name)
        meta["untrusted"] = sorted(un)
        meta_path.write_text(json.dumps(meta, indent=1), encoding="utf-8")
    return dest
