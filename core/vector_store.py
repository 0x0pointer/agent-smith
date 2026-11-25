from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

_log = logging.getLogger(__name__)

VECTOR_ROOT = Path(os.environ.get("SMITH_VECTOR_ROOT", "vectors"))
KB_ROOT = Path(os.environ.get("SMITH_KB_ROOT", "kb"))
RAW_DIR = KB_ROOT / "sources" / "_raw"
MANIFEST = KB_ROOT / "MANIFEST.json"

STATIC_SECURITY_VAULT = "security"
ENGAGEMENT_VAULT_PREFIX = "engagement"
DEFAULT_DATASET = "docs"

_ID_RE = re.compile(r"[^a-zA-Z0-9._-]+")
_TOKEN_RE = re.compile(r"[a-zA-Z0-9_.:/-]{2,}")
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_MAX_DOC_BYTES = 200_000
_MAX_CHUNK = 6_000
_STORE_LOCK = threading.RLock()

_RAW_PARSE_EXTS = {
    ".md", ".txt", ".json", ".yaml", ".yml", ".csv", ".log", ".http",
    ".html", ".htm", ".xml", ".pdf", ".docx", ".doc",
}


def sanitize_id(value: str | None, default: str = "default") -> str:
    cleaned = _ID_RE.sub("_", str(value or "").strip()).strip("._-")
    return cleaned[:80] or default


def active_vault(session_id: str | None) -> str:
    return f"{ENGAGEMENT_VAULT_PREFIX}-{sanitize_id(session_id, 'manual')}"


def dataset_id(value: str | None) -> str:
    return sanitize_id(value, DEFAULT_DATASET)


def vault_dir(vault: str) -> Path:
    return VECTOR_ROOT / sanitize_id(vault)


def dataset_dir(vault: str, dataset: str) -> Path:
    return vault_dir(vault) / dataset_id(dataset)


def doc_path(vault: str, dataset: str, doc_name: str) -> Path:
    return dataset_dir(vault, dataset) / f"{sanitize_id(doc_name, 'doc')}.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _atomic_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def _load_doc(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        if isinstance(data, dict):
            return data
    except Exception:
        _log.warning("vector doc unreadable: %s", path, exc_info=True)
    return None


def read_text(path: str | Path, cap: int = _MAX_DOC_BYTES) -> str:
    try:
        with open(path, "r", errors="replace") as fh:
            return _ANSI_RE.sub("", fh.read(cap))
    except Exception:
        return ""


def tokens(text: str) -> list[str]:
    return [t.lower() for t in _TOKEN_RE.findall(text or "")]


def token_counts(text: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for tok in tokens(text):
        out[tok] = out.get(tok, 0) + 1
    return out


def _chunk(text: str) -> list[str]:
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


def _html_to_text(text: str) -> str:
    text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    import html as _html
    return _html.unescape(_html.unescape(text))


def yaml_ok() -> bool:
    try:
        import yaml  # noqa: F401
        return True
    except Exception:
        return False


def yaml_load(text: str):
    import yaml
    return yaml.safe_load(text)


def _structured_to_text(text: str, fname: str) -> str:
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
                    f"{p.get('name')}({p.get('in')})" for p in op.get("parameters") or []
                )
                lines.append(
                    f"{method.upper()} {path_} — {op.get('summary') or op.get('operationId') or ''}"
                    f" params[{params}]"
                )
        if len(lines) > 1:
            return "\n".join(lines) + "\n\n" + text[:20_000]
    return json.dumps(data, indent=1, default=str)[:200_000]


def _pdf_to_text(path: Path) -> tuple[str, str]:
    import shutil as _sh
    import subprocess as _sp
    if _sh.which("pdftotext"):
        try:
            r = _sp.run(["pdftotext", "-layout", str(path), "-"], capture_output=True, timeout=120)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.decode("utf-8", errors="replace"), "pdftotext"
        except Exception:
            pass
    try:
        from pypdf import PdfReader
        reader = PdfReader(str(path))
        text = "\n".join((page.extract_text() or "") for page in reader.pages)
        if text.strip():
            return text, "pypdf"
    except Exception:
        pass
    raw = path.read_bytes()[:200_000]
    chunks = re.findall(rb"\(([^()\\]{4,})\)", raw)
    return ("\n".join(c.decode("latin-1", errors="replace") for c in chunks),
            "naive-salvage (install poppler/pdftotext or pypdf for full text)")


def _docx_to_text(path: Path) -> tuple[str, str]:
    import shutil as _sh
    import subprocess as _sp
    if _sh.which("textutil"):
        try:
            r = _sp.run(["textutil", "-convert", "txt", "-stdout", str(path)], capture_output=True, timeout=120)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.decode("utf-8", errors="replace"), "textutil"
        except Exception:
            pass
    if _sh.which("pandoc"):
        try:
            r = _sp.run(["pandoc", "-t", "plain", str(path)], capture_output=True, timeout=120)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.decode("utf-8", errors="replace"), "pandoc"
        except Exception:
            pass
    return "", "no docx parser (install pandoc, or on macOS textutil)"


def parse_document(path: Path) -> tuple[str, str, str]:
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
        else:
            text, note = read_text(path), "raw"
        text = text.strip()
        if not text:
            return "", note + " (no text extracted)", "empty"
        return text[:400_000], note, "ok"
    except Exception:
        _log.warning("parse_document failed for %s", path, exc_info=True)
        return "", "parse error", "skipped"


def _safe_name(name: str | None) -> str:
    return sanitize_id(Path(name or "doc").stem, "doc") + (Path(name or "").suffix[:12])


def _content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def list_docs(vault: str | None = None, dataset: str | None = None) -> list[dict]:
    base = vault_dir(vault) if vault else VECTOR_ROOT
    if not base.exists():
        return []
    docs: list[dict] = []
    for path in sorted(base.rglob("*.json")):
        rel = path.relative_to(VECTOR_ROOT).parts
        if len(rel) != 3:
            continue
        if dataset and rel[1] != dataset_id(dataset):
            continue
        data = _load_doc(path)
        if data:
            docs.append(data)
    return docs


def list_vaults() -> list[dict]:
    out = []
    if not VECTOR_ROOT.exists():
        return out
    for vdir in sorted(p for p in VECTOR_ROOT.iterdir() if p.is_dir()):
        datasets = []
        for ddir in sorted(p for p in vdir.iterdir() if p.is_dir()):
            count = len(list(ddir.glob("*.json")))
            datasets.append({"name": ddir.name, "docs": count})
        out.append({"name": vdir.name, "datasets": datasets, "docs": sum(d["docs"] for d in datasets)})
    return out


def ingest_text(*, vault: str, dataset: str, name: str, text: str, untrusted: bool,
                kind: str | None = None, source: str | None = None, metadata: dict | None = None) -> dict:
    v_id = sanitize_id(vault)
    d_id = dataset_id(dataset)
    base_name = _safe_name(name)
    text = (text or "").strip()
    if not text:
        return {"status": "skipped", "reason": "empty"}
    content_sha = _content_hash(text)
    with _STORE_LOCK:
        existing = {d["name"]: d for d in list_docs(v_id, d_id)}
        if base_name in existing and existing[base_name].get("content_sha256") == content_sha:
            return {"status": "skipped", "reason": "duplicate", "name": base_name, "doc": existing[base_name]}
        final_name = base_name
        if base_name in existing:
            stem = Path(base_name).stem
            suffix = Path(base_name).suffix
            i = 2
            while True:
                candidate = f"{stem}-{i}{suffix}"
                if candidate not in existing:
                    final_name = candidate
                    break
                if existing[candidate].get("content_sha256") == content_sha:
                    return {"status": "skipped", "reason": "duplicate", "name": candidate, "doc": existing[candidate]}
                i += 1
        doc = {
            "id": sanitize_id(final_name, "doc"),
            "name": final_name,
            "vault": v_id,
            "dataset": d_id,
            "kind": kind or d_id,
            "source": source or f"{v_id}/{d_id}/{final_name}",
            "title": final_name,
            "text": text,
            "untrusted": bool(untrusted),
            "content_sha256": content_sha,
            "tokens": token_counts(text),
            "created_at": _now(),
            "metadata": metadata or {},
        }
        _atomic_write_json(doc_path(v_id, d_id, final_name), doc)
        return {"status": "ingested", "name": final_name, "doc": doc}


def delete_doc(vault: str, dataset: str, name: str) -> bool:
    safe = _safe_name(name)
    with _STORE_LOCK:
        for data in list_docs(vault, dataset):
            if data.get("name") != safe:
                continue
            try:
                doc_path(vault, dataset, safe).unlink()
                return True
            except Exception:
                _log.warning("vector delete failed: %s/%s/%s", vault, dataset, safe, exc_info=True)
                return False
    return False


def purge_vault(vault: str) -> int:
    import shutil
    count = len(list_docs(vault))
    with _STORE_LOCK:
        shutil.rmtree(vault_dir(vault), ignore_errors=True)
    return count


def purge_dataset(vault: str, dataset: str) -> int:
    import shutil
    ddir = dataset_dir(vault, dataset)
    count = len(list_docs(vault=vault, dataset=dataset))
    with _STORE_LOCK:
        shutil.rmtree(ddir, ignore_errors=True)
    return count


def purge_active_session(session_id: str | None) -> int:
    return purge_vault(active_vault(session_id))


def _score(query_counts: dict[str, int], doc_counts: dict[str, int]) -> tuple[int, int, float]:
    if not query_counts or not doc_counts:
        return (0, 0, 0.0)
    present = {tok: doc_counts.get(tok, 0) for tok in query_counts if doc_counts.get(tok, 0) > 0}
    if not present:
        return (0, 0, 0.0)
    distinct = len(present)
    total = sum(present.values())
    qnorm = sum(v * v for v in query_counts.values()) ** 0.5
    dnorm = sum(v * v for v in doc_counts.values()) ** 0.5
    dot = sum(query_counts[t] * doc_counts.get(t, 0) for t in query_counts)
    return distinct, total, (dot / (qnorm * dnorm)) if qnorm and dnorm else 0.0


def snippet(query: str, text: str) -> str:
    query_terms = set(tokens(query))
    lines = text.splitlines()
    best_i, best_hits = 0, -1
    for i, ln in enumerate(lines):
        hits = len(query_terms & set(tokens(ln)))
        if hits > best_hits:
            best_i, best_hits = i, hits
    if best_hits <= 0:
        return (text[:240] + "…") if len(text) > 240 else text
    lo = max(0, best_i - 1)
    hi = min(len(lines), best_i + 2)
    out = "\n".join(lines[lo:hi]).strip()
    return (out[:400] + "…") if len(out) > 400 else out


def search(query: str, *, vault: str | None = None, dataset: str | None = None,
           datasets: list[str] | None = None, source_filters: list[str] | None = None,
           limit: int = 8) -> list[dict]:
    q = (query or "").strip()
    q_counts = token_counts(q)
    if not q_counts:
        return []
    source_filters = [s for s in (source_filters or []) if s]
    dataset_filter = {dataset_id(d) for d in (datasets or [])}
    if dataset:
        dataset_filter.add(dataset_id(dataset))
    hits = []
    for doc in list_docs(vault=vault):
        if dataset_filter and doc.get("dataset") not in dataset_filter and doc.get("kind") not in dataset_filter:
            continue
        if dataset and doc.get("dataset") != dataset_id(dataset):
            continue
        if source_filters and not any(str(doc.get("source", "")).startswith(s) or doc.get("name") == s for s in source_filters):
            continue
        distinct, total, cosine = _score(q_counts, doc.get("tokens") or {})
        if not distinct:
            continue
        hits.append({
            **doc,
            "distinct": distinct,
            "hits": total,
            "score": cosine,
            "snippet": snippet(q, doc.get("text", "")),
        })
    hits.sort(key=lambda d: (d["distinct"], d["hits"], d["score"], d["name"]), reverse=True)
    return hits[:limit]


def vector_status() -> dict:
    static_docs = len(list_docs(STATIC_SECURITY_VAULT))
    engagement_docs = len([
        d for d in list_docs()
        if str(d.get("vault", "")).startswith(f"{ENGAGEMENT_VAULT_PREFIX}-")
    ])
    try:
        import glob as _glob
        prior = len(_glob.glob("engagements/*/resume.json"))
    except Exception:
        prior = 0
    bits = []
    if static_docs:
        bits.append(f"{static_docs} static security docs")
    if engagement_docs:
        bits.append(f"{engagement_docs} engagement doc(s)")
    if prior:
        bits.append(f"{prior} prior-engagement store(s)")
    return {
        "kb": bool(static_docs),
        "docs": engagement_docs,
        "engagements": prior,
        "any": bool(static_docs or engagement_docs or prior),
        "summary": ", ".join(bits) if bits else "no vector stores configured",
    }


def kb_status() -> dict:
    return vector_status()


def load_manifest(path: Path | None = None) -> dict:
    p = Path(path) if path else MANIFEST
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(errors="replace"))
    except Exception:
        return {}
