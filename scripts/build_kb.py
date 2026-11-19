#!/usr/bin/env python3
"""
build_kb.py — tier-A static security-KB builder (plan 5.1, docs/plan-5.1-local-kb-retrieval.md).

Fetches/parses the reference sources into normalized docs, indexes them into
kb/index.db (SQLite FTS5, bm25 + snippets for report(action='recall')) and
writes normalized text files under kb/sources/<name>/ so the zero-index flat-scan
fallback path also works.

    python3 scripts/build_kb.py --status              # manifest + staleness
    python3 scripts/build_kb.py --source skill_refs   # one source (offline source)
    python3 scripts/build_kb.py --all                 # light sources incl. network fetch
    python3 scripts/build_kb.py --source nvd          # bulk source, explicit
    python3 scripts/build_kb.py --source gtfobins --offline   # reuse last fetch
    python3 scripts/build_kb.py --selftest            # canned-query recall check

Sources (plan §5): skill_refs (local), gtfobins, lolbas, wstg, exploitdb
(metadata CSV — bodies stay opt-out; rows carry the path so Kali searchsploit
can fetch on demand), nuclei templates, nvd (JSON 1.1 feeds).

Pure stdlib + optional PyYAML (falls back to raw-text ingestion without it).
Nothing auto-fetches during a scan; the committed kb/MANIFEST.json records the
exact snapshot an engagement queried (license attribution for CC BY-SA sources).
"""
from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import kb as kb_mod  # noqa: E402

try:
    import yaml  # type: ignore
except Exception:
    yaml = None

# ── source registry ─────────────────────────────────────────────────────────
REPOS = {
    "gtfobins": "https://github.com/GTFOBins/GTFOBins.github.io",
    "lolbas": "https://github.com/LOLBAS-Project/LOLBAS.github.io",
    "wstg": "https://github.com/OWASP/wstg",          # renamed from www-web-security-testing-guide
    "nuclei": "https://github.com/projectdiscovery/nuclei-templates",
}
# ExploitDB's GitHub mirror is archived; primary is git.exploit-db.com (a GitLab
# raw URL), with the Kali package path as an offline fallback.
EXPLOITDB_CSV_URLS = [
    "https://git.exploit-db.com/exploit-db/-/raw/master/files_exploits.csv",
    "https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv",
]
EXPLOITDB_LOCAL = "/usr/share/exploitdb/files_exploits.csv"
# NVD retired its JSON 1.1 feeds (403) — the official bulk distribution is now the
# CVEProject/cvelistV5 repo (one JSON per CVE, published by CVE.org). Default year
# range keeps the raw clone sane (~1.3 GB for 2 recent years); override with
# SMITH_CVELIST_START_YEAR (e.g. 2002 for full history).
CVE_REPO = "https://github.com/CVEProject/cvelistV5"
CVELIST_START_YEAR = int(os.environ.get("SMITH_CVELIST_START_YEAR",
                                        str(datetime.now(timezone.utc).year - 5)))

LICENSE_NOTES = {
    "skill_refs": "agent-smith skills (project license)",
    "gtfobins": "GTFOBins — MIT (verify LICENSE in raw clone)",
    "lolbas": "LOLBAS — MIT (verify LICENSE in raw clone)",
    "wstg": "OWASP WSTG — CC BY-SA 4.0 (attribution retained)",
    "exploitdb": "ExploitDB — mixed per-submission; INTERNAL USE, no redistribution",
    "nuclei": "ProjectDiscovery nuclei-templates — MIT (verify LICENSE in raw clone)",
    "nvd": "NVD — US Government public domain",
}
LIGHT_SOURCES = ["skill_refs", "gtfobins", "lolbas", "wstg", "exploitdb"]   # --all
BULK_SOURCES = ["nuclei", "nvd"]                                           # explicit only
PER_DOC_SOURCES = {"skill_refs", "gtfobins", "lolbas", "wstg"}             # 1 file per doc
BULK_CHUNK = 500                                    # rows per normalized bulk file

# ── fetch helpers ───────────────────────────────────────────────────────────
def _sh(args: list[str], cwd: Path | None = None) -> str:
    r = subprocess.run(args, cwd=str(cwd) if cwd else None,
                       capture_output=True, text=True, timeout=900)
    if r.returncode != 0:
        raise RuntimeError(f"{' '.join(args[:3])}… failed: {r.stderr.strip()[:300]}")
    return r.stdout.strip()


def fetch_repo(name: str, refresh: bool) -> tuple[Path, str]:
    """Shallow clone (or update) into kb/sources/_raw/<name>/ → (dir, HEAD sha)."""
    raw = kb_mod.RAW_DIR / name
    if raw.exists() and refresh:
        shutil.rmtree(raw, ignore_errors=True)
    if not raw.exists():
        raw.parent.mkdir(parents=True, exist_ok=True)
        _sh(["git", "clone", "--depth", "1", REPOS[name], str(raw)])
    head = _sh(["git", "rev-parse", "HEAD"], cwd=raw)
    return raw, head


def fetch_url(name: str, url: str, refresh: bool, binary: bool = False) -> Path:
    """Download into kb/sources/_raw/<name>/ (reused unless --refresh)."""
    raw = kb_mod.RAW_DIR / name
    raw.mkdir(parents=True, exist_ok=True)
    dest = raw / url.rsplit("/", 1)[-1]
    if dest.exists() and not refresh:
        return dest
    with urllib.request.urlopen(url, timeout=300) as resp, open(dest, "wb") as fh:
        shutil.copyfileobj(resp, fh)
    return dest


def _license_sha(raw: Path) -> str:
    """Hash of the LICENSE file in a raw clone, for manifest provenance."""
    import hashlib
    for p in sorted(raw.glob("LICENSE*")) + sorted(raw.glob("license*")):
        if p.is_file():
            return hashlib.sha256(p.read_bytes()).hexdigest()[:16]
    return ""


def fetch_exploitdb_csv(refresh: bool) -> tuple[Path, str]:
    """Try the remote CSV mirrors, then the local Kali image, then a local file.
    The agent-smith Kali image ships the `exploitdb` package, so `docker run
    --rm --entrypoint cat pentest-agent/kali-mcp …` recovers the CSV offline.
    → (raw_dir, upstream_ref) — same contract as fetch_repo."""
    raw = kb_mod.RAW_DIR / "exploitdb"
    dest = raw / "files_exploits.csv"
    if dest.exists() and not refresh:
        return raw, "cached:" + dest.name
    for url in EXPLOITDB_CSV_URLS:
        try:
            fetch_url("exploitdb", url, refresh)
            return raw, url
        except Exception:
            continue
    import shutil as _sh
    import subprocess as _sp
    if _sh.which("docker"):
        try:
            _shutil_check = _sp.run(["docker", "image", "inspect", "pentest-agent/kali-mcp"],
                                    capture_output=True, timeout=60)
            if _shutil_check.returncode == 0:
                raw.mkdir(parents=True, exist_ok=True)
                r = _sp.run(["docker", "run", "--rm", "--entrypoint", "cat",
                             "pentest-agent/kali-mcp", EXPLOITDB_LOCAL],
                            capture_output=True, timeout=600)
                if r.returncode == 0 and r.stdout[:20].count(b",") >= 1:
                    dest.write_bytes(r.stdout)
                    print(f"  · exploitdb CSV recovered from local Kali image "
                          f"({len(r.stdout) // 1024} KB)")
                    return raw, "docker:pentest-agent/kali-mcp"
        except Exception:
            pass
    if os.path.exists(EXPLOITDB_LOCAL):
        raw.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(EXPLOITDB_LOCAL, dest)
        return raw, EXPLOITDB_LOCAL
    raise RuntimeError("exploitdb CSV unreachable (git.exploit-db.com + GitHub mirror) "
                       f"and no local {EXPLOITDB_LOCAL} — install the 'exploitdb' package, "
                       "build the agent-smith Kali image, or copy files_exploits.csv into "
                       "kb/sources/_raw/exploitdb/")


def _frontmatter_yaml(text: str):
    """Parse a `---`-fenced YAML frontmatter block (LOLBAS .md layout)."""
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n?", text, re.S)
    if not m or yaml is None:
        return None
    try:
        return yaml.safe_load(m.group(1))
    except Exception:
        return None


def fetch_cvelist_v5(_raw: Path, refresh: bool) -> tuple[Path, str]:
    """Sparse shallow clone of CVEProject/cvelistV5 limited to recent years
    (default: current year -5 .. now; SMITH_CVELIST_START_YEAR overrides).
    → (raw_dir, HEAD sha)."""
    raw = kb_mod.RAW_DIR / "nvd"
    years = [str(y) for y in range(CVELIST_START_YEAR, datetime.now(timezone.utc).year + 1)]
    if refresh and raw.exists():
        shutil.rmtree(raw, ignore_errors=True)
    if not raw.exists():
        raw.parent.mkdir(parents=True, exist_ok=True)
        _sh(["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse",
             CVE_REPO, str(raw)])
        _sh(["git", "sparse-checkout", "set"] + [f"cves/{y}" for y in years], cwd=raw)
    head = _sh(["git", "rev-parse", "HEAD"], cwd=raw)
    return raw, head


# ── ingesters → list[kb doc] ────────────────────────────────────────────────
def _doc(source: str, kind: str, title: str, text: str, tags=None) -> dict:
    return {"source": source, "kind": kind, "title": title,
            "tags": tags or [], "text": text.strip() or "(empty)", "untrusted": False}


def ingest_skill_refs(_raw: Path, out: Path) -> list[dict]:
    """Our skills tree: SKILL.md + refs/*.md — 1 doc per file."""
    skills_root = Path("skills")
    docs = []
    if not skills_root.is_dir():
        return docs
    for path in sorted(skills_root.rglob("*.md")):
        rel = path.relative_to(Path(".")).as_posix()
        text = kb_mod.read_text(path)
        if not text.strip():
            continue
        title = next((ln.lstrip("# ").strip() for ln in text.splitlines()
                      if ln.startswith("# ")), path.stem)
        docs.append(_doc(f"kb:skill_refs/{rel}", "skill_ref",
                         f"{title} ({rel})", text))
    return docs


def ingest_gtfobins(raw: Path, out: Path) -> list[dict]:
    """_gtfobins/<bin> → 1 doc per binary. Upstream restructured (2025): files
    now carry one base snippet per function with `contexts:` keys (sudo/suid/…)
    and `alias:` stubs pointing at a canonical binary — both are followed."""
    docs = []

    def _parse(text: str):
        """→ (functions_text, tags) from one YAML file, or None on parse failure."""
        if yaml is None:
            return text, []
        try:
            stripped = re.sub(r"^---\s*\n?|---\s*$", "", text).strip()
            data = yaml.safe_load(stripped) or {}
        except Exception:
            return None
        funcs, tags = [], []
        for fname, fval in (data.get("functions") or {}).items():
            tags.append(fname)
            for entry in fval if isinstance(fval, list) else []:
                code = (entry or {}).get("code", "")
                ctx = list(((entry or {}).get("contexts") or {}).keys())
                tags.extend(ctx)
                if code:
                    funcs.append(f"[{fname}]" + (f"[{','.join(ctx)}]" if ctx else "")
                                 + f" {code}")
        return (data.get("description") or "") + "\n" + "\n".join(funcs), tags

    for path in sorted((raw / "_gtfobins").iterdir()):
        if not path.is_file():
            continue
        name = path.name
        text = kb_mod.read_text(path)
        parsed = _parse(text)
        body, tags = parsed if parsed else (text, [])
        tags = ["linux", name] + [t for t in tags if t != name]
        if yaml is not None and re.search(r"^alias:\s*\S+", text, re.M):
            try:                                   # alias stub → merge canonical doc
                target = yaml.safe_load(re.sub(r"^---\s*\n?|---\s*$", "",
                                               text).strip()).get("alias")
                if target:
                    tags.append(str(target))
                    tp = raw / "_gtfobins" / str(target)
                    if tp.is_file():
                        tparse = _parse(kb_mod.read_text(tp))
                        if tparse:
                            body += f"\n(alias of {target})\n" + tparse[0]
                            tags.extend(tparse[1])
            except Exception:
                pass
        docs.append(_doc(f"kb:gtfobins/{name}", "gtfobins", f"{name} (GTFOBins)",
                         body, tags=sorted(set(tags))))
    return docs


def ingest_lolbas(raw: Path, out: Path) -> list[dict]:
    """_lolbas/<Category>/<Name>.md (YAML frontmatter) → 1 doc per binary/script."""
    docs = []
    for path in sorted((raw / "_lolbas").rglob("*.md")):
        name = path.stem
        text = kb_mod.read_text(path)
        title, body = name, text
        data = _frontmatter_yaml(text)
        if data:
            cmds = []
            for c in data.get("Commands") or []:
                if isinstance(c, dict):
                    cmds.append(f"[{c.get('Category', '')}] {c.get('Command', '')}  — "
                                f"{c.get('Description', '')} (MitreID: {c.get('MitreID', '')})")
            body = (f"{data.get('Name') or name}\n{data.get('Description') or ''}\n"
                    + "\n".join(cmds))
            title = f"{data.get('Name') or name} (LOLBAS)"
        docs.append(_doc(f"kb:lolbas/{name}", "lolbas", title, body,
                         tags=["windows", name]))
    return docs


def ingest_wstg(raw: Path, out: Path) -> list[dict]:
    """markdown test pages → 1 doc per WSTG test / appendix page."""
    docs = []
    for path in sorted(raw.rglob("*.md")):
        rel = path.relative_to(raw).as_posix()
        if "/images/" in rel or rel.startswith(".") or path.name.lower() in ("readme.md", "license.md"):
            continue
        text = kb_mod.read_text(path)
        if len(text.strip()) < 200:                 # skip stubs/index boilerplate
            continue
        m = re.search(r"WSTG-([A-Z]{4})-(\w+)", path.name + " " + text[:2000])
        title = next((ln.lstrip("# ").strip() for ln in text.splitlines()
                      if ln.startswith("# ")), path.stem)
        if m:
            title = f"{title} (WSTG-{m.group(1)}-{m.group(2)})"
        docs.append(_doc(f"kb:wstg/{rel}", "wstg", title, text,
                         tags=["wstg", m.group(1).lower()] if m else ["wstg"]))
    return docs


def ingest_exploitdb(raw: Path, out: Path) -> list[dict]:
    """files_exploits.csv → 1 doc per exploit (metadata; body stays opt-out —
    the file path is indexed so Kali searchsploit can fetch on demand)."""
    docs = []
    with open(raw / "files_exploits.csv", newline="", encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            eid, fpath = row.get("id", ""), row.get("file", "")
            desc = row.get("description", "")
            plat, etype = row.get("platform", ""), row.get("type", "")
            date_s, author = row.get("date", ""), row.get("author", "")
            cve = (row.get("codes") or "") if "codes" in row else ""
            text = (f"{desc}\nplatform: {plat}  type: {etype}  date: {date_s}  "
                    f"author: {author}\nfile: {fpath}"
                    + (f"\ncodes: {cve}" if cve else ""))
            docs.append(_doc(f"kb:exploitdb/{eid or fpath}", "exploit",
                             f"{desc[:120]}", text,
                             tags=[t for t in (plat.lower(), etype.lower(),
                                               cve.lower()) if t]))
    return docs


def ingest_nuclei(raw: Path, out: Path) -> list[dict]:
    """*.yaml templates → 1 doc per template (id, severity, tags, refs)."""
    docs = []
    for path in sorted(raw.rglob("*.yaml")):
        text = kb_mod.read_text(path, cap=20_000)
        if not text.lstrip().startswith("id:"):
            continue
        rel = path.relative_to(raw).as_posix()
        title, tags, body = rel, [], text
        if yaml is not None:
            try:
                data = yaml.safe_load(text) or {}
                tid = data.get("id") or rel
                title = f"{data.get('name') or tid} (nuclei:{tid})"
                tags = [str(t) for t in (data.get("tags") or [])][:12]
                refs = data.get("reference") or []
                sev = data.get("severity") or ""
                desc = re.sub(r"<[^>]+>", " ", str(data.get("description") or ""))[:600]
                info = data.get("info") or {}       # some layouts nest under info
                if not desc and isinstance(info, dict):
                    desc = re.sub(r"<[^>]+>", " ", str(info.get("description") or ""))[:600]
                    sev = sev or str(info.get("severity") or "")
                body = (f"{tid}\nseverity: {sev}\ntags: {' '.join(tags)}\n{desc}\n"
                        + "\n".join(f"ref: {r}" for r in (refs if isinstance(refs, list) else [refs]) if r))
            except Exception:
                pass
        docs.append(_doc(f"kb:nuclei/{rel}", "nuclei", title, body, tags=tags))
    return docs


def ingest_nvd(raw: Path, out: Path) -> list[dict]:
    """CVEProject/cvelistV5 (cves/<year>/<bucket>/CVE-*.json) → 1 doc per CVE.
    CVE 5.1 schema: cveMetadata.cveId, containers.cna.{descriptions,metrics,
    affected,references} (+ ADP container for CNA-SSVC rebases — ignored)."""
    docs = []
    for path in sorted((raw / "cves").rglob("CVE-*.json")):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
        except Exception:
            continue
        meta = data.get("cveMetadata") or {}
        cve_id = meta.get("cveId") or path.stem
        cna = ((data.get("containers") or {}).get("cna")) or {}
        descs = [d.get("value", "") for d in cna.get("descriptions") or []
                 if isinstance(d, dict) and d.get("lang") == "en"]
        cvss_bits = []
        for m in cna.get("metrics") or []:
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                v = (m or {}).get(key)
                if isinstance(v, dict):
                    cvss_bits.append(f"{key[-4:]} {v.get('baseScore', '?')} "
                                     f"{v.get('vectorString', '')}")
                    break
        affected = []
        for a in cna.get("affected") or []:
            if not isinstance(a, dict):
                continue
            versions = ",".join(str(v.get("version", "")) for v in (a.get("versions") or [])
                                if isinstance(v, dict))[:120]
            affected.append(f"{a.get('vendor', '')}/{a.get('product', '')} {versions}".strip())
        refs = [r.get("url") for r in cna.get("references") or []
                if isinstance(r, dict) and r.get("url")]
        body = ("\n".join(descs)
                + ("\nCVSS: " + " | ".join(cvss_bits) if cvss_bits else "")
                + ("\naffected: " + " ; ".join(affected[:8]) if affected else "")
                + ("\nrefs: " + " ".join(refs[:8]) if refs else ""))
        docs.append(_doc(f"kb:nvd/{cve_id}", "cve", cve_id, body,
                         tags=[cve_id.lower()]
                              + [str(a.get("product", "")).lower()
                                 for a in (cna.get("affected") or [])[:2]
                                 if isinstance(a, dict)]))
    return docs


INGESTERS = {
    "skill_refs": (None, ingest_skill_refs),
    "gtfobins": (lambda r, rf: fetch_repo("gtfobins", rf), ingest_gtfobins),
    "lolbas": (lambda r, rf: fetch_repo("lolbas", rf), ingest_lolbas),
    "wstg": (lambda r, rf: fetch_repo("wstg", rf), ingest_wstg),
    "exploitdb": (lambda r, rf: fetch_exploitdb_csv(rf), ingest_exploitdb),
    "nuclei": (lambda r, rf: fetch_repo("nuclei", rf), ingest_nuclei),
    "nvd": (fetch_cvelist_v5, ingest_nvd),
}


# ── normalized flat files (zero-index fallback) ─────────────────────────────
def write_flat(source: str, docs: list[dict]) -> int:
    """Per-doc files for small sources; chunked files for bulk ones."""
    out = kb_mod.SOURCES_DIR / source
    if out.exists():
        shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True, exist_ok=True)
    if source in PER_DOC_SOURCES:
        for d in docs:
            base = d["source"].split("/", 1)[-1]
            name = re.sub(r"[^a-zA-Z0-9._()-]+", "_", base)[:150].removesuffix(".md")
            (out / f"{name}.md").write_text(
                f"# {d['title']}\n\n{d['text']}\n", encoding="utf-8", errors="replace")
        return len(docs)
    lines_total = 0
    for i in range(0, len(docs), BULK_CHUNK):
        chunk = docs[i:i + BULK_CHUNK]
        body = "\n\n".join(f"## {d['title']}\n{d['text']}" for d in chunk)
        (out / f"{source}-{i // BULK_CHUNK:04d}.md").write_text(body, encoding="utf-8", errors="replace")
        lines_total += len(chunk)
    return lines_total


# ── build / status / selftest ───────────────────────────────────────────────
def build(sources: list[str], refresh: bool, offline: bool) -> int:
    if not kb_mod.fts5_available():
        print("⚠ sqlite3 lacks FTS5 — building flat files only (recall flat-scan path).")
    con = kb_mod.open_index(create=True) if kb_mod.fts5_available() else None
    manifest = kb_mod.load_manifest()
    total = 0
    for name in sources:
        raw = kb_mod.RAW_DIR / name
        fetcher, ingester = INGESTERS[name]
        try:
            if fetcher is not None:
                if offline:
                    if not raw.is_dir() and not raw.exists():
                        print(f"— {name}: no cached fetch under {raw}; skip (--offline). "
                              f"Run without --offline first.")
                        continue
                    upstream = (manifest.get(name) or {}).get("upstream_ref", "cached")
                else:
                    raw_res = fetcher(raw, refresh)
                    raw = raw_res if isinstance(raw_res, Path) else raw
                    upstream = raw_res[1] if isinstance(raw_res, tuple) else str(raw_res)
            else:
                upstream = "local"
            print(f"— {name}: ingesting…")
            docs = ingester(raw, kb_mod.SOURCES_DIR / name)
            n = write_flat(name, docs)
            if con is not None and docs:
                kb_mod.replace_source(con, f"kb:{name}", docs)
                kb_mod.record_meta(con, name, len(docs), upstream_ref=upstream,
                                   license_note=LICENSE_NOTES.get(name, ""))
            manifest[name] = {
                "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "upstream_ref": upstream,
                "docs": len(docs),
                "flat_files": n,
                "license": LICENSE_NOTES.get(name, ""),
                "license_sha": _license_sha(raw) if hasattr(raw, "glob") else "",
            }
            total += len(docs)
            print(f"  ✓ {name}: {len(docs)} docs indexed, {n} flat files")
        except Exception as exc:
            print(f"  ✗ {name}: FAILED ({exc}) — source skipped, rest continue")
    if con is not None:
        con.close()
    kb_mod.MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    kb_mod.MANIFEST.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"\nKB build complete: {total} docs across {len(sources)} source(s). "
          f"Index: {kb_mod.INDEX_DB} (exists={kb_mod.INDEX_DB.exists()})")
    return 0


def status() -> int:
    manifest = kb_mod.load_manifest()
    con = kb_mod.open_index()
    stats = kb_mod.index_stats(con) if con else {"kinds": {}, "built_at": None}
    if con:
        con.close()
    if not manifest:
        print("KB empty — nothing built yet. Run: python3 scripts/build_kb.py --all")
        return 0
    now = datetime.now(timezone.utc)
    print(f"{'source':<14}{'docs':>8}  {'age':>7}  upstream / license")
    for name, m in sorted(manifest.items()):
        age = "?"
        try:
            dt = datetime.fromisoformat(m["fetched_at"])
            age = f"{(now - dt).days}d"
        except Exception:
            pass
        print(f"{name:<14}{m.get('docs', 0):>8}  {age:>7}  {m.get('upstream_ref', '')[:12]}  {m.get('license', '')[:48]}")
    kinds = ", ".join(f"{k}:{v}" for k, v in sorted(stats.get("kinds", {}).items()))
    print(f"\nindex: {kb_mod.INDEX_DB} ({'present' if kb_mod.INDEX_DB.exists() else 'MISSING'}"
          f"{', built ' + str(stats.get('built_at')) if stats.get('built_at') else ''})")
    if kinds:
        print(f"kinds: {kinds}")
    return 0


SELFTEST = [  # (query, expected kind substring) — recall@k sanity (plan §9.1)
    ("gtfobins sudo suid shell", "gtfobins"),
    ("certutil download file windows", "lolbas"),
    ("testing for default credentials", "wstg"),
    ("prompt injection jailbreak system prompt", "skill_ref"),
]


def selftest() -> int:
    con = kb_mod.open_index()
    if con is None:
        print("selftest: no kb/index.db — run scripts/build_kb.py first.")
        return 1
    ok = 0
    for query, want in SELFTEST:
        hits = kb_mod.query_index(con, query, None, 8)
        kinds = [h["kind"] for h in hits]
        hit = want in kinds
        ok += hit
        top = f"{hits[0]['kind']}:{hits[0]['title'][:60]}" if hits else "—"
        print(f"{'✓' if hit else '✗'} '{query}' → top: {top}  (want kind {want})")
    con.close()
    print(f"\nselftest: {ok}/{len(SELFTEST)} passed")
    return 0 if ok == len(SELFTEST) else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--source", action="append", choices=list(INGESTERS),
                    help="build one source (repeatable)")
    ap.add_argument("--all", action="store_true", help=f"light sources: {', '.join(LIGHT_SOURCES)}")
    ap.add_argument("--refresh", action="store_true", help="re-fetch even if cached")
    ap.add_argument("--offline", action="store_true", help="never fetch; reuse kb/sources/_raw/")
    ap.add_argument("--status", action="store_true", help="manifest + staleness")
    ap.add_argument("--selftest", action="store_true", help="canned-query recall check")
    args = ap.parse_args()
    if args.status:
        return status()
    if args.selftest:
        return selftest()
    sources = args.source or (LIGHT_SOURCES if args.all else [])
    if not sources:
        ap.print_help()
        return 0
    return build(sources, args.refresh, args.offline)


if __name__ == "__main__":
    raise SystemExit(main())
