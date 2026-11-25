"""Compatibility shim for the old KB module.

The legacy SQLite/flat-file KB implementation has been replaced by the vault/
dataset vector store in ``core.vector_store``. Keep this module as a thin facade
for callers that still import ``core.kb`` for parser helpers, builder cache
paths, or status checks.
"""
from __future__ import annotations

from core.vector_store import (
    KB_ROOT,
    MANIFEST,
    RAW_DIR,
    STATIC_SECURITY_VAULT,
    VECTOR_ROOT,
    _RAW_PARSE_EXTS,
    _chunk,
    _docx_to_text,
    _html_to_text,
    _pdf_to_text,
    _structured_to_text,
    active_vault,
    dataset_id,
    delete_doc,
    ingest_text,
    kb_status,
    list_docs,
    list_vaults,
    load_manifest,
    parse_document,
    purge_active_session,
    purge_vault,
    read_text,
    sanitize_id,
    search,
    snippet,
    token_counts,
    tokens,
    vector_status,
    vault_dir,
    yaml_load,
    yaml_ok,
)

# Compatibility constant retained for scripts/build_kb.py's normalized output.
SOURCES_DIR = KB_ROOT / "sources"
