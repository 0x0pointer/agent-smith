# Arcanum Prompt Injection Taxonomy (PITAX)

`arc_pi_taxonomy.json` is vendored from the **Arcanum Prompt Injection Taxonomy**
by Arcanum Security.

- Source: https://github.com/Arcanum-Sec/arc_pi_taxonomy (`docs/data/taxonomy.json`)
- Interactive: https://arcanum-sec.com/pitax
- License: **Creative Commons Attribution 4.0 International (CC BY 4.0)**

The taxonomy is redistributed unmodified under CC BY 4.0; attribution to Arcanum
Security is required. It maps 172 nodes across four pillars — Intents (PIT-I),
Techniques (PIT-T), Evasions (PIT-E), Inputs (PIT-N) — each cross-referenced to
OWASP LLM Top 10, MITRE ATLAS, NIST, MLCommons and garak.

Update: re-fetch the upstream `docs/data/taxonomy.json` and overwrite the vendored
copy; the loader (`mcp_server/redteam/taxonomy.py`) reads it as-is.
