# Obsolete plan — local KB / engagement-doc retrieval was removed

This file is kept only as historical context for issue and review archaeology.

The KB RAG feature described by the original plan is no longer part of agent-smith:
- there is no supported local/static KB builder or KB upload flow;
- `session(action="kb_add", ...)` is removed;
- `report(action="recall")` now searches prior engagement stores under `engagements/*` only.

Do not use this document as operational guidance for current installs or runs.
See the current README and tool help for supported behavior.
