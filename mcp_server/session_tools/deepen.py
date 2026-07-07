"""Thorough-depth iteration-gate briefs (live re-run passes)."""
from core import findings as findings_store
from core import session as scan_session

import mcp_server.session_tools as _st
from ._common import _THOROUGH_MIN_ITERATIONS
from .whitebox import _deepen_brief_condensed


def _deepen_steps_pass1(
    has_ai_ep: bool, skills_run: set, unchained: list
) -> list[str]:
    steps: list[str] = []
    steps.append(
        "Re-invoke /web-exploit (SECOND PASS) — reset all tested_clean cells to pending "
        "and re-test them with deeper payloads: sqlmap --level=4 --risk=3, "
        "XSS with CSP/filter bypass variants, SSTI with all engine templates, "
        "blind/OOB SQLi with out-of-band callbacks, second-order injection testing. "
        "Every endpoint that returned tested_clean in pass 1 is a candidate for a "
        "false negative — test again with a different technique."
    )
    steps.append(
        "Re-invoke /param-fuzz (SECOND PASS) — run with larger wordlists "
        "(burp-parameter-names.txt + raft-large-words.txt), test every parameter "
        "for HTTP verb tampering, auth header stripping, type confusion "
        "(string→int→array→null), and mass assignment on ALL endpoints including "
        "those that returned 4xx in pass 1 (try different HTTP methods)."
    )
    steps.append(
        "Re-invoke /business-logic (SECOND PASS) — run all 9 phases again: "
        "send concurrent requests (10 parallel) to every state-changing endpoint, "
        "test negative/zero/overflow values on EVERY numeric field found, "
        "replay all one-time tokens and confirmation codes, test BOLA on every "
        "resource ID found in the app, enumerate sequential IDs across all "
        "resource types."
    )
    if has_ai_ep or "ai-redteam" in skills_run:
        steps.append(
            "Re-invoke /ai-redteam (SECOND PASS) — run PyRIT crescendo (10 turns); "
            "Garak with the full probe set (dan,encoding,promptinject,leakreplay,xss,"
            "latentinjection,snowball,misleading,packagehallucination,malwaregen,gcg,"
            "glitch,grandma,goodside); promptfoo redteam (plugins prompt-injection,"
            "excessive-agency,pii,rag-poisoning,prompt-extraction; strategies jailbreak,"
            "crescendo); plus manual multi-objective authority-marker payloads on all AI "
            "endpoints. Close each OWASP LLM/MCP coverage cell with the run's artifact_id, "
            "and re-run every confirmed jailbreak/injection N times to record a k/N "
            "reproducibility rate (report(action='update_finding', adjudication=...)) before "
            "filing — LLM outputs are non-deterministic."
        )
    steps.append(
        "Re-run nuclei with ALL template categories: "
        "scan(tool='nuclei', templates='cve,exposure,misconfig,default-login,takeovers,"
        "technologies,token-spray,file-upload,xss,sqli,ssrf,lfi,rce,generic'). "
        "Also run scan(tool='ffuf') on every endpoint with raft-large-words.txt to "
        "discover hidden parameters and paths missed in pass 1."
    )
    if unchained:
        titles = ", ".join(f['title'][:40] for f in unchained[:3])
        steps.append(
            f"Chain {len(unchained)} unchained critical finding(s) to maximum impact "
            f"({titles}{'...' if len(unchained) > 3 else ''}): "
            "SQLi → dump all tables → crack hashes → use creds everywhere; "
            "SSRF → scan internal network → hit cloud metadata → exfil IAM keys; "
            "RCE → establish reverse shell → run LinPEAS → escalate to root. "
            "LOOK SIDEWAYS, not just forward: when a chain step is blocked on a missing "
            "primitive (file-read, a secret/PIN, internal reach), check whether ANOTHER "
            "confirmed finding already PROVIDES it — e.g. a Postgres SQLi's "
            "pg_read_server_file gives the file-read a PIN-locked Werkzeug console needs. "
            "Call report(action='chain', data={type:'suggest'}) for graph-derived bridges."
        )
    return steps


def _deepen_steps_pass2(
    criticals: list, has_ai_ep: bool, skills_run: set
) -> list[str]:
    steps: list[str] = []
    steps.append(
        "Re-invoke /web-exploit (THIRD PASS — MAXIMUM AGGRESSION) — "
        "sqlmap --level=5 --risk=3 --technique=BEUSTQ --tamper=space2comment,between,"
        "randomcase,charunicodeencode on every injection point; "
        "run commix on ALL parameter inputs for blind OS command injection; "
        "test HTTP request smuggling (CL.TE and TE.CL) on every HTTP/1.1 endpoint; "
        "probe all endpoints for CRLF injection and web cache poisoning; "
        "test deserialization on every cookie and binary parameter (pickle, Java, PHP)."
    )
    steps.append(
        "Re-invoke /param-fuzz (THIRD PASS) — fuzz with the full "
        "10-million-password-list as a parameter wordlist; test parameter pollution "
        "(duplicate params in query string + body simultaneously); inject into "
        "HTTP headers (X-Forwarded-For, X-Original-URL, X-Rewrite-URL, "
        "X-Custom-IP-Authorization) on every auth-gated endpoint; "
        "test GraphQL introspection and batching abuse if any /graphql endpoint exists."
    )
    steps.append(
        "Re-invoke /business-logic (THIRD PASS) — run Phase 5 (idempotency) with "
        "50 concurrent requests on every state-changing endpoint; "
        "test all time-based attacks (expired token reuse, cooldown bypass); "
        "perform full multi-tenant isolation testing across all user accounts; "
        "enumerate ALL resource IDs sequentially (orders, transfers, loans, cards, "
        "payments) across EVERY user to confirm or deny BOLA at scale."
    )
    if has_ai_ep or "ai-redteam" in skills_run:
        steps.append(
            "Re-invoke /ai-redteam (THIRD PASS) — run PyRIT with jailbreak + "
            "crescendo + multi-turn prompt injection (15 turns each); "
            "test excessive agency by attempting tool invocations with hidden params "
            "(include_internal=True, admin=True, debug=True, show_all=True); "
            "test indirect prompt injection via every data field the AI reads "
            "(usernames, transaction notes, profile fields, filenames)."
        )
    steps.append(
        "Run kali(command='nikto -h TARGET -C all -maxtime 300') for full server "
        "misconfiguration scan; run testssl.sh against every HTTPS endpoint; "
        "run enum4linux-ng if any SMB/LDAP ports are open; "
        "run wapiti with all modules against the full app."
    )
    steps.append(
        f"Produce one end-to-end chain PoC for EACH critical finding ({len(criticals)} total) "
        "that demonstrates the full kill chain from initial access to maximum impact. "
        "Each PoC must be a single executable curl/python script that requires zero "
        "manual steps. Save every PoC with http(action='save_poc') linked to its finding_id."
    )
    return steps


def _deepen_brief(iteration: int) -> str:
    """
    Generate a mandatory re-run brief for thorough-depth iteration gates.
    Each iteration re-executes ALL applicable skills and tools with escalating
    aggressiveness — not advisory hints, but concrete ordered commands.
    """
    if _st._condensed_directives():
        return _deepen_brief_condensed(iteration, whitebox=False)
    from core.coverage import get_matrix
    data      = findings_store._load()
    current   = scan_session.get() or {}
    findings  = data.get("findings", [])
    criticals = [f for f in findings if f.get("severity") == "critical"]
    highs     = [f for f in findings if f.get("severity") == "high"]
    cov       = get_matrix()

    pending_cells  = [c for c in cov.get("matrix", []) if c["status"] == "pending"]
    clean_cells    = [c for c in cov.get("matrix", []) if c["status"] == "tested_clean"]

    skills_run = {s["skill"] for s in current.get("skill_history", [])}
    endpoints  = current.get("known_assets", {}).get("endpoints", [])
    # Robust AI-surface detection: an AI scan rarely populates known_assets.endpoints
    # (the URL is passed straight to the scan tool, no spider). The old spider-only
    # substring check (`"ai" in ep`) was both a false-negative for that case and a
    # false-positive on paths like /detail, /email, /maintenance. Detect AI work by
    # the AI tools actually run, the ai-redteam skill, or any AI/MCP coverage cell.
    from core.coverage.classify import classify_endpoint
    _AI_TOOLS = {"fuzzyai", "garak", "pyrit", "promptfoo"}
    _AI_CELL_PREFIXES = (
        "prompt_injection", "jailbreak", "system_prompt_leak", "sensitive_info_disclosure",
        "improper_output_handling", "excessive_agency", "misinformation",
        "unbounded_consumption", "model_extraction", "content_bias",
        "membership_inference", "rag_poisoning", "embedding_manipulation", "mcp_",
    )
    has_ai_ep = (
        bool(_AI_TOOLS & _st._effective_tools())
        or "ai-redteam" in skills_run
        # Precise path classifier (chat/completions/mcp/...) — not the old naive
        # `"ai" in ep` substring that false-matched /detail, /email, /maintenance.
        or any(classify_endpoint(ep) == "ai-redteam" for ep in endpoints)
        or any(str(c.get("injection_type", "")).startswith(_AI_CELL_PREFIXES)
               for c in cov.get("matrix", []))
    )

    unchained  = [f for f in criticals if not f.get("escalation_leads")]
    finding_summary = (
        f"{len(findings)} findings ({len(criticals)} critical, {len(highs)} high)"
    )

    # ── Build the ordered mandatory re-run list ─────────────────────────────────
    if iteration == 1:
        steps = _deepen_steps_pass1(has_ai_ep, skills_run, unchained)
        intro = (
            f"⛔ ITERATION GATE: Pass 1/{_THOROUGH_MIN_ITERATIONS} done — "
            "thorough depth requires {_THOROUGH_MIN_ITERATIONS} full passes. "
            "RE-RUN ALL TOOLS NOW, harder than pass 1. "
            "Execute every step below before calling complete() again:"
        ).format(_THOROUGH_MIN_ITERATIONS=_THOROUGH_MIN_ITERATIONS)
    elif iteration == 2:
        steps = _deepen_steps_pass2(criticals, has_ai_ep, skills_run)
        intro = (
            f"⛔ ITERATION GATE: Pass 2/{_THOROUGH_MIN_ITERATIONS} done — "
            "one more full pass required at MAXIMUM aggression. "
            "Execute every step below before calling complete() again:"
        )
    else:
        steps = [
            f"Iteration {iteration}: re-run ALL skills at maximum depth again — "
            "the scan has not yet passed quality gates. "
            "Focus on any cells still pending or skipped, any findings without end-to-end PoCs, "
            "and any skill not invoked since the last iteration."
        ]
        intro = (
            f"⛔ ITERATION GATE: Pass {iteration}/{_THOROUGH_MIN_ITERATIONS} done — "
            "quality gates still blocking. "
            "Execute every step below before calling complete() again:"
        )

    steps.append(
        f"Current state: {finding_summary}, "
        f"{len(pending_cells)} cells pending, "
        f"{len(clean_cells)} cells marked clean (potential false negatives). "
        "After completing ALL steps above, call session(action='complete') again."
    )

    numbered = "\n".join(f"  {i + 1}. {step}" for i, step in enumerate(steps))
    return f"{intro}\n{numbered}"
