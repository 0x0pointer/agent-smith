from __future__ import annotations

from .vector_add import _collect_paths, _do_vector_add, _fetch_url, _name_from_url


async def _do_kb_add(opts):
    return await _do_vector_add(opts, alias="kb_add")
