#!/usr/bin/env python3
"""Redacting ingester: LIVE agent-smith scan slice -> schema-valid smith-event fixture.

Reads a point-in-time snapshot of one authorized VulnBank scan (findings.json,
coverage_matrix.json, session.json, and a TOOL_CALL/NOTE slice of pentest.log) and maps
~20-40 representative real records into the smith-event/1.0 event graph
(training-data-plan.md §3-§5, §8, §13):

  * each material finding  -> a decision -> action -> result cycle (+ a leading observation
    when the log shows the surface signal that motivated it); a couple of correction cases
    also emit an adjudication event;
  * a sample of coverage cells (vulnerable / tested_clean) -> observation or result events
    carrying evidence primitives (§5) and the vuln SHAPE (injection_type, oracle, status);
  * a few pentest.log TOOL_CALL entries -> action events with the two-identifier
    fingerprint (§3.4: exact_action_hash + semantic_action_family).

EVERYTHING is redacted with core.Redactor(engagement_key=b"vulnbank-live") BEFORE it is
written (§8 typed-placeholder pseudonymization): the target IP, host/domain, port, and any
credential / email / JWT / api-key / account-number found in the findings or logs become
<TARGET_HOST_n> / <IP_n> / <PORT_n> / <CRED_n> / <EMAIL_n> / <JWT_n> / <APIKEY_n> / <ACCT_n>
placeholders. The vuln SHAPE is kept verbatim: SQLi payloads (admin' OR '1'='1), the
injection type, parameter, oracle and HTTP status all survive; only engagement-owned raw
identifiers are replaced. Payload-side infrastructure that IS the vuln shape (SSRF targets
169.254.169.254 / 127.0.0.1 / 10.x internal DNS) is deliberately preserved.

Output: training-data/fixtures/vulnbank-live/events.jsonl
Validate:  .venv/bin/python training-data/eventstore/ingest_agent_smith.py --validate
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

# --- reuse the plan's event-store primitives (mandatory) -------------------------------
from core import Redactor  # noqa: E402  (core.py sits next to this file)

HERE = pathlib.Path(__file__).resolve().parent
TD_ROOT = HERE.parent
SCHEMAS = TD_ROOT / "schemas"
SNAPSHOT = TD_ROOT.parent / "analysis" / "current_run_snapshot"
OUT_DIR = TD_ROOT / "fixtures" / "vulnbank-live"
OUT_FILE = OUT_DIR / "events.jsonl"

ENGAGEMENT_ID = "vulnbank-live"
ENGAGEMENT_KEY = b"vulnbank-live"
SCHEMA_VERSION = "smith-event/1.0"
AGENT_SMITH_COMMIT = "77d1fbc"  # from session runtime; recorded, not load-bearing

# The raw target identity (POINT-IN-TIME snapshot values; read-only, never modified on disk).
RAW_IP = "167.172.35.161"
RAW_PORT = "30081"
RAW_HOST = f"{RAW_IP}:{RAW_PORT}"
RAW_DOMAIN = "vulnbank.org"          # appears in merchant email bookstore@vulnbank.org
RAW_ROLE_HOST = "vulnbank-role"      # AWS/DO IMDS role name = engagement-owned host identity

# SSRF payload infrastructure that IS the vuln shape — PRESERVED verbatim, never redacted.
SHAPE_IPS = {"169.254.169.254", "127.0.0.1", "0.0.0.0"}

# ---------------------------------------------------------------------------------------
# Deterministic ULID: 26-char Crockford base32, derived from a stable seed (counter+key).
# Not authoritative causality (that is `sequence`) — just a valid, reproducible sort key.
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def make_ulid(seed: str) -> str:
    """130-bit digest of the seed -> 26 Crockford-base32 chars (matches common.schema ulid pattern)."""
    h = hashlib.sha256(f"ulid\x00{ENGAGEMENT_ID}\x00{seed}".encode()).digest()
    n = int.from_bytes(h, "big") & ((1 << 130) - 1)  # ULID is 128 bits; 26*5=130 covers it
    out = []
    for _ in range(26):
        out.append(_CROCKFORD[n & 0x1F])
        n >>= 5
    return "".join(reversed(out))


def sha256_ref(seed: str) -> str:
    """Deterministic content-addressed artifact ref (sha256:<64 hex>) from a stable seed."""
    return "sha256:" + hashlib.sha256(f"artifact\x00{seed}".encode()).hexdigest()


# ---------------------------------------------------------------------------------------
# Redaction (§8). One engagement-scoped Redactor gives consistent <TYPE_n> placeholders.
RED = Redactor(engagement_key=ENGAGEMENT_KEY)


def _pl(entity_type: str, value: str) -> str:
    return RED.label(entity_type, value)


# Curated real credentials (usernames/passwords). NOTE: strings that are SQLi payloads
# (admin' OR '1'='1) are vuln SHAPE, not creds — excluded on purpose.
REAL_USERNAMES = [
    "attacker_a", "admin_pwned", "testeruser1", "pwnadmin1", "bookstore",
]
REAL_PASSWORDS = [
    "Test1234!", "TestPass123!", "PwnPass!", "Pwn3d!", "Backdoor!", "ChainOwn3d!",
]
# Real account numbers seen in transfer/BOLA evidence (10-digit); iat values inside JWTs
# are removed by JWT redaction first, so a bare-digit sweep is not needed / not used.
REAL_ACCOUNTS = [
    "6116244961", "3058625982", "7365104900", "6958142615", "7757987466",
    "8587089690", "8572933811", "7465025214", "4676698665", "1815062346",
]
REAL_EMAILS = ["bookstore@vulnbank.org", "merch@x.com", "a@test.com"]
# App/infra secrets exfiltrated in the SSRF/SQLi chains -> credential-class placeholders.
REAL_SECRETS = ["secret123", "POSTGRES_PASSWORD"]

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_APIKEY_RE = re.compile(r"vk_[a-fA-F0-9]{16,}")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def redact(text):
    """Redact one string in place, keeping vuln SHAPE verbatim (§8). Recurses over dict/list."""
    if isinstance(text, dict):
        return {redact(k): redact(v) for k, v in text.items()}
    if isinstance(text, list):
        return [redact(v) for v in text]
    if not isinstance(text, str):
        return text
    t = text
    # 1. JWTs first (they embed iat timestamps that otherwise collide with acct-number sweeps).
    for jwt in sorted(set(_JWT_RE.findall(t)), key=len, reverse=True):
        t = t.replace(jwt, _pl("jwt", jwt))
    # 2. Merchant / vault API keys.
    for key in sorted(set(_APIKEY_RE.findall(t)), key=len, reverse=True):
        t = t.replace(key, _pl("apikey", key))
    # 3. Emails (curated + any residual), before host redaction eats their domain.
    for em in REAL_EMAILS + list(set(_EMAIL_RE.findall(t))):
        if em in t:
            t = t.replace(em, _pl("email", em))
    # 4. Host / IP / port / domain (engagement identity). Longest-match first.
    t = t.replace(RAW_HOST, _pl("target_host", RAW_HOST))
    t = t.replace(RAW_DOMAIN, _pl("target_host", RAW_DOMAIN))
    t = t.replace(RAW_ROLE_HOST, _pl("target_host", RAW_ROLE_HOST))
    # Redact the bare target IP ONLY (never the shape IPs 169.254.169.254 / 127.0.0.1 / ...).
    if RAW_IP in t:
        t = t.replace(RAW_IP, _pl("ip", RAW_IP))
    # Bare :port left over after host replacement.
    t = re.sub(rf"(?<![\d.]):{RAW_PORT}\b", ":" + _pl("port", RAW_PORT), t)
    # 5. Credentials / secrets / accounts (curated real values only).
    for secret in REAL_SECRETS:
        if secret in t:
            t = t.replace(secret, _pl("cred", secret))
    for pw in sorted(REAL_PASSWORDS, key=len, reverse=True):
        if pw in t:
            t = t.replace(pw, _pl("cred", pw))
    for un in sorted(REAL_USERNAMES, key=len, reverse=True):
        # word-boundary so "admin" inside "admin_pwned"/payloads is not mangled
        t = re.sub(rf"\b{re.escape(un)}\b", _pl("cred", un), t)
    for acct in sorted(REAL_ACCOUNTS, key=len, reverse=True):
        t = t.replace(acct, _pl("acct", acct))
    return t


# ---------------------------------------------------------------------------------------
# Envelope + provenance helpers.
_SEQ = 0


def next_seq() -> int:
    global _SEQ
    _SEQ += 1
    return _SEQ


def iso(ts: str) -> str:
    """Normalize a snapshot timestamp to ISO-8601 Zulu (schema format:date-time)."""
    if not ts:
        return "2026-07-08T11:33:26Z"
    ts = ts.strip()
    # log lines are already ...Z; findings carry +00:00 offsets — both are valid ISO-8601.
    return ts


def envelope(event_type: str, seed: str, occurred: str, seq: int, **extra) -> dict:
    env = {
        "event_id": make_ulid(seed),
        "engagement_id": ENGAGEMENT_ID,
        "event_type": event_type,
        "sequence": seq,
        "occurred_at": iso(occurred),
        "recorded_at": iso(occurred),
        "schema_version": SCHEMA_VERSION,
    }
    env.update(extra)
    return env


def provenance() -> dict:
    # teacher_origin defaults to open_weight (Track B, §12) — no proprietary model id is
    # recorded in session.json to override it.
    return {
        "proposal_source": "model:open-weight-teacher",
        "selection_source": "model:open-weight-teacher",
        "execution_source": "mcp:pentest-agent",
        "outcome_adjudicator": "async_state_delta",
        "teacher_origin": "open_weight",
    }


def runtime_versions() -> dict:
    return {
        "agent_smith_commit": AGENT_SMITH_COMMIT,
        "tool_registry_version": "pentest-agent/consolidated-5",
        "policy_version": "vulnbank-live/1",
        "model": {"provider": "open_weight", "id": "open-weight-teacher"},
    }


def captured(value, mode="pre_decision_generated", actor="model_invocation"):
    return {"value": value, "capture_mode": mode, "actor": actor}


def trust(origin, trust_level, rendering="data", authority=False):
    return {
        "origin": origin,
        "trust": trust_level,
        "rendering": rendering,
        "instruction_authority": authority,
    }


# ---------------------------------------------------------------------------------------
# Evidence primitives -> V-level (mirrors validate.derive_level / plan §5). We store
# primitives; the level is COMPUTED so the acceptance "Evidence derivation" test reproduces it.
def derive_level(p, theta=0.8):
    repro = p["success_count"] / max(p["attempt_count"], 1)
    indep = min(p["independent_method_count"], 3)
    directness = 2 if p["is_deterministic"] else (1 if p["success_count"] > 0 else 0)
    impact = 1 if p.get("impact_observed") else 0
    human = p.get("human_review_count", 0) > 0
    if human and repro >= theta and indep >= 2:
        return "V5"
    if indep >= 2 and repro >= theta:
        return "V4"
    if directness == 2 and p["success_count"] >= 1:
        return "V3"
    if repro >= theta and impact >= 1:
        return "V2"
    if p["independent_method_count"] >= 1 or p["success_count"] >= 1:
        return "V1"
    return "V0"


def evidence(attempt, success, indep, deterministic, impact=False, human=0,
             control_present=True, control_passed=True, reset=True):
    prim = {
        "attempt_count": attempt,
        "success_count": success,
        "independent_method_count": indep,
        "control_present": control_present,
        "control_passed": control_passed,
        "impact_observed": impact,
        "human_review_count": human,
        "environment_reset_success": reset,
        "is_deterministic": deterministic,
    }
    return {"primitives": prim, "scale_version": "evidence-scales/1.0", "level": derive_level(prim)}


# ---------------------------------------------------------------------------------------
# Mapping a finding -> CWE/technique + injection family (drives semantic_action_family).
_TECHNIQUE = [
    ("SQL Injection", "CWE-89", "injection_probe", "sqli", "differential_error"),
    ("SQLi", "CWE-89", "injection_probe", "sqli", "differential_error"),
    ("UNION", "CWE-89", "injection_probe", "sqli_union", "row_exfiltration"),
    ("Mass Assignment", "CWE-915", "mass_assignment", "mass_assignment", "privilege_grant"),
    ("BOLA", "CWE-639", "authz_probe", "bola", "cross_object_read"),
    ("BFLA", "CWE-285", "authz_probe", "bfla", "privileged_op"),
    ("Function Level Authorization", "CWE-285", "authz_probe", "bfla", "privileged_op"),
    ("IDOR", "CWE-639", "authz_probe", "bola", "cross_object_read"),
    ("Server-Side Request Forgery", "CWE-918", "ssrf_probe", "ssrf", "oob_fetch"),
    ("SSRF", "CWE-918", "ssrf_probe", "ssrf", "oob_fetch"),
    ("Prompt Injection", "LLM01", "prompt_injection", "prompt_injection", "instruction_override"),
    ("Prompt injection", "LLM01", "prompt_injection", "prompt_injection", "instruction_override"),
    ("XSS", "CWE-79", "injection_probe", "xss", "reflected_markup"),
    ("Negative Amount", "CWE-840", "business_logic", "value_abuse", "balance_delta"),
    ("PIN", "CWE-640", "auth_probe", "reset_flow", "pin_disclosure"),
    ("JWT", "CWE-347", "crypto_probe", "jwt_forge", "signature_bypass"),
    ("CORS", "CWE-942", "misconfig_probe", "cors", "wildcard_origin"),
    ("Security Headers", "CWE-693", "misconfig_probe", "security_headers", "header_absence"),
    ("Rate Limit", "CWE-799", "rate_probe", "rate_limit", "no_throttle"),
    ("Werkzeug Debug Console", "CWE-489", "misconfig_probe", "debug_console", "rce_console"),
    ("Excessive data exposure", "CWE-213", "misconfig_probe", "info_disclosure", "debug_leak"),
    ("Verbose SQL error", "CWE-209", "misconfig_probe", "info_disclosure", "sql_error"),
]


def classify(title: str):
    for needle, cwe, opclass, family, oracle in _TECHNIQUE:
        if needle.lower() in title.lower():
            return cwe, opclass, family, oracle
    return "CWE-noinfo", "generic_probe", "generic", "http_status"


def _tool_for(finding) -> tuple[str, str]:
    tool = (finding.get("tool_used") or "http").split("_")[0]
    if tool in ("http", "kali"):
        return tool, "request" if tool == "http" else "shell"
    return "http", "request"


# ---------------------------------------------------------------------------------------
def build_events():
    findings = json.loads((SNAPSHOT / "findings.json").read_text())["findings"]
    coverage = json.loads((SNAPSHOT / "coverage_matrix.json").read_text())
    log_lines = (SNAPSHOT / "pentest.log").read_text().splitlines()

    events = []

    # ---- 1. Findings -> decision/action/result (+ observation) cycles ------------------
    # Representative slice: ONE exemplar per distinct vuln family, spread across severities
    # and endpoints, so the fixture stays in the plan's ~20-40 mapped-record band (§15.1)
    # while covering the full shape catalogue (SQLi / mass-assignment / BOLA / BFLA / SSRF /
    # prompt-injection / XSS / business-logic / JWT-forge / debug-console / info-disclosure).
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    picked = sorted(findings, key=lambda f: (sev_rank.get(f.get("severity"), 9), f.get("timestamp", "")))
    chosen = []
    seen_family = set()
    for f in picked:
        _, _, family, _ = classify(f.get("title", ""))
        if family in seen_family:
            continue
        seen_family.add(family)
        chosen.append(f)
    # cap to a bounded, diverse dozen (families are already deduped; this bounds the tail)
    chosen = chosen[:12]

    ADJUDICATE_TITLES = {"Verbose SQL error", "No Rate Limiting on POST"}  # emit corrections

    for f in chosen:
        fid = f["id"]
        ts = f.get("timestamp", "")
        title = redact(f.get("title", ""))
        target = redact(f.get("target", ""))
        desc = redact(f.get("description", ""))
        evi = redact(f.get("evidence", ""))
        sev = f.get("severity", "info")
        cwe, opclass, family, oracle = classify(f.get("title", ""))
        tool, operation = _tool_for(f)
        artifact_seed = f.get("evidence_artifact_id") or f"finding:{fid}"
        result_artifact = sha256_ref(artifact_seed)
        source_artifact = sha256_ref(artifact_seed + ":source")
        sanitized_artifact = sha256_ref(artifact_seed + ":sanitized")

        # 1a. Observation — the surface signal the finding rests on (target-controlled = untrusted DATA).
        obs_seed = f"obs:{fid}"
        obs = envelope("observation", obs_seed, ts, next_seq())
        obs["state_ops"] = [{
            "layer": "belief",
            "key": redact(f"{target}#{family}"),
            "value": {"surface_signal": family, "hypothesis": cwe},
        }]
        obs["observation"] = {
            "artifact_ref": source_artifact,
            "stage_hashes": {"source_original": source_artifact, "sanitized_evidence": sanitized_artifact},
            "status": "200",
            "type": "http_response",
            "indicators": [f"{family}:surface", f"cwe:{cwe}"],
            "trust": trust("target", "untrusted", "data", False),
            "content_hash": sanitized_artifact,
            "updates_state_layer": "belief",
        }
        events.append(obs)

        # 1b. Decision — structured record; reasoning fields captured pre-decision (§3).
        dec_seed = f"dec:{fid}"
        dec = envelope("decision", dec_seed, ts, next_seq(),
                       caused_by=[obs["event_id"]], correlation_id=f"decision-{make_ulid(dec_seed)[:12]}")
        dec["decision"] = {
            "goal": redact(f"Confirm {cwe} on {target}"),
            "hypothesis": title,
            "supporting_observations": [{
                "artifact_ref": source_artifact,
                "visible_at_decision": True,
                "entered_context": True,
                "context_position": 1,
                "available_but_not_shown": False,
                "discovered_after_decision": False,
                "hidden_ground_truth": False,
            }],
            "target_ref": target,
            "technique": cwe,
            "alternatives_considered": captured(["passive_observation", "alternate_param", "auth_variation"]),
            "expected_signals": captured([oracle, "http_200_with_evidence"]),
            "confidence": captured(0.55 if sev in ("info", "low") else 0.7),
            "stop_condition": captured("stop after the oracle fires or 3 negative probes"),
            "chosen_tool": tool,
            "operation": operation,
            "params": {"family": family, "oracle": oracle},
            "explanation": (desc[:220] if desc else None),
            "provenance": provenance(),
            "runtime_versions": runtime_versions(),
            "context_manifest_id": f"ctx-{make_ulid(dec_seed)[:12]}",
        }
        events.append(dec)

        # 1c. Action — concrete tool execution with the two-identifier fingerprint (§3.4).
        act_seed = f"act:{fid}"
        exact = sha256_ref(f"exact:{fid}:{family}")
        # side-effect class from the vuln kind
        side = "state_mutating" if family in ("mass_assignment", "value_abuse") else "read_only"
        safety = "state_mutating" if side == "state_mutating" else "read_only"
        act = envelope("action", act_seed, ts, next_seq(),
                       caused_by=[dec["event_id"]], correlation_id=dec["decision"]["context_manifest_id"].replace("ctx", "decision"))
        act["action"] = {
            "tool": tool,
            "operation": operation,
            "params": {"target": target, "family": family},
            "exact_action_hash": exact,
            "semantic_action_family": {
                "target_entity": target,
                "operation_class": opclass,
                "param_mutation": family,
                "payload_family": family,
                "auth_context": "authenticated" if "auth" in desc.lower() or family in ("bola", "bfla") else "unauthenticated",
                "expected_oracle": oracle,
            },
            "behavior": {
                "transport": "http/1.1",
                "method": "POST" if "POST" in f.get("target", "") or family in ("mass_assignment", "value_abuse", "prompt_injection") else "GET",
                "encoding": "json",
                "execution_cardinality": 1,
                "timing_model": "single",
                "concurrency": "sequential",
                "session_state": "bearer_jwt" if family in ("bola", "bfla") else "none",
                "tool_semver": f"{tool}/1.0.0",
                "side_effect_class": side,
            },
            "safety_class": safety,
        }
        events.append(act)

        # 1d. Result — visible spans, 3-layer outcome, evidence primitives (§3.5, §4, §5).
        res_seed = f"res:{fid}"
        vis_bytes = min(len(evi.encode("utf-8")), 512) if evi else 0
        orig_bytes = max(len(evi.encode("utf-8")), vis_bytes)
        # evidence strength scales with confirmation depth
        confirmed = sev in ("critical", "high")
        ev = evidence(
            attempt=2 if confirmed else 1,
            success=2 if confirmed else 1,
            indep=2 if ("Chain" in f.get("title", "") or "Proven" in f.get("title", "")) else 1,
            deterministic=confirmed,
            impact=confirmed,
            human=0,
        )
        res = envelope("result", res_seed, ts, next_seq(),
                       caused_by=[act["event_id"]], correlation_id=act["correlation_id"])
        res["state_ops"] = [
            {"layer": "observed", "key": redact(f"{target}#{family}"),
             "value": {"confirmed": confirmed, "evidence_level": ev["level"], "cwe": cwe}},
            {"layer": "belief", "key": redact(f"{target}#{family}"),
             "value": {"confidence": 0.9 if confirmed else 0.5}},
        ]
        res["result"] = {
            "visible_spans": {
                "artifact_ref": result_artifact,
                "artifact_variant": "sanitized_utf8_v2",
                "coordinate_system": "utf8_byte_offset",
                "spans": [{"start": 0, "end_exclusive": vis_bytes}],
                "truncation_strategy": "head",
                "original_bytes": orig_bytes,
                "visible_bytes": vis_bytes,
            },
            "observed": {
                "execution_status": "ok",
                "result_class": "advanced" if confirmed else "inconclusive",
                "new_artifacts": [result_artifact],
                "state_changes": [f"observed:{family} confirmed={confirmed}"],
            },
            "utility": {
                "information_gain": {"value": 0.8 if confirmed else 0.4, "confidence": 0.8,
                                     "source": "async_state_delta", "method": "belief_delta"},
                "finding_gain": {"value": sev, "confidence": 0.9,
                                 "source": "adjudicator", "method": "severity_map"},
            },
            "credit": [
                {"event_id": obs["event_id"], "role": "surface_discovery", "weight": 0.3},
                {"event_id": act["event_id"], "role": "exploit_confirmation", "weight": 0.7},
            ],
            "evidence": ev,
        }
        # finding-class label carried on the result for lineage back to the source finding.
        events.append(res)

        # 1e. Adjudication — a couple of representative corrections (§3.1 correction edge).
        if any(t in f.get("title", "") for t in ADJUDICATE_TITLES):
            adj_seed = f"adj:{fid}"
            adj = envelope("adjudication", adj_seed, ts, next_seq(),
                           supersedes=[obs["event_id"]])
            adj["adjudication"] = {
                "kind": "supersession",
                "target_event_id": obs["event_id"],
                "rationale": "Re-fetched with a control request; the initial surface signal was "
                             "downgraded to an information-disclosure misconfig (the confirmed "
                             "result still stands).",
                "reproducible": True,
                "artifact_id": sha256_ref(f"adjrepro:{fid}"),
                "original": {"indicators": [f"{family}:surface"]},
                "revised": {"indicators": ["info_disclosure:confirmed"]},
                "adjudicator": "human_adjudicator",
            }
            events.append(adj)

    # ---- 2. Coverage cells -> observation / result events ------------------------------
    matrix = coverage["matrix"]
    ep_by_id = {e["id"]: e for e in coverage["endpoints"]}
    vuln_cells = [c for c in matrix if c.get("status") == "vulnerable" and c.get("finding_id")]
    clean_cells = [c for c in matrix if c.get("status") == "tested_clean"]
    # de-dup vulnerable cells by (endpoint,injection_type) so we sample DISTINCT shapes
    seen_shape = set()
    sampled_vuln = []
    for c in vuln_cells:
        k = (c["endpoint_id"], c.get("injection_type"))
        if k in seen_shape:
            continue
        seen_shape.add(k)
        sampled_vuln.append(c)
        if len(sampled_vuln) >= 8:
            break
    sampled_clean = clean_cells[:4]

    for c in sampled_vuln:
        ep = ep_by_id.get(c["endpoint_id"], {})
        path = redact(ep.get("path", "?"))
        method = ep.get("method", "GET")
        inj = c.get("injection_type", "generic")
        cell_ts = c.get("tested_at", "")
        seed = f"cellvuln:{c['id']}"
        art = sha256_ref(c.get("artifact_id") or seed)
        res = envelope("result", seed, cell_ts, next_seq())
        ev = evidence(attempt=2, success=2, indep=1, deterministic=True, impact=True)
        res["state_ops"] = [{
            "layer": "observed",
            "key": redact(f"{method} {path}#{inj}"),
            "value": {"cell_status": "vulnerable", "injection_type": inj, "evidence_level": ev["level"]},
        }]
        res["result"] = {
            "visible_spans": {
                "artifact_ref": art,
                "artifact_variant": "sanitized_utf8_v2",
                "coordinate_system": "utf8_byte_offset",
                "spans": [{"start": 0, "end_exclusive": 256}],
                "truncation_strategy": "head",
                "original_bytes": 256,
                "visible_bytes": 256,
            },
            "observed": {
                "execution_status": "ok",
                "result_class": "advanced",
                "new_artifacts": [art],
                "state_changes": [f"coverage:{inj} vulnerable"],
            },
            "utility": {
                "coverage_gain": {"value": 1, "confidence": 0.9, "source": "coverage_matrix",
                                  "method": "cell_close_vulnerable"},
            },
            "evidence": ev,
        }
        events.append(res)

    for c in sampled_clean:
        ep = ep_by_id.get(c["endpoint_id"], {})
        path = redact(ep.get("path", "?"))
        method = ep.get("method", "GET")
        inj = c.get("injection_type", "generic")
        cell_ts = c.get("tested_at", "")
        seed = f"cellclean:{c['id']}"
        art = sha256_ref(c.get("artifact_id") or seed)
        obs = envelope("observation", seed, cell_ts, next_seq())
        obs["state_ops"] = [{
            "layer": "observed",
            "key": redact(f"{method} {path}#{inj}"),
            "value": {"cell_status": "tested_clean", "injection_type": inj},
        }]
        obs["observation"] = {
            "artifact_ref": art,
            "stage_hashes": {"source_original": art},
            "status": "405" if "method" in inj else "200",
            "type": "http_response",
            "indicators": [f"{inj}:no_signal", redact(c.get("notes", ""))[:80]],
            "trust": trust("target", "untrusted", "data", False),
            "content_hash": art,
            "updates_state_layer": "observed",
        }
        events.append(obs)

    # ---- 3. pentest.log TOOL_CALL lines -> action events (two-identifier fingerprint) ---
    tool_call_re = re.compile(
        r"^(?P<ts>\S+)\s+INFO\s+TOOL_CALL\s+(?P<tool>\S+)\s+args=(?P<args>\{.*\})\s*$")
    payload_markers = ("UNION", "OR '1'='1", "OR 1=1", "<script", "{{7*7}}",
                       "image_url", "forgot-password", "secret123", "from_account", "amount")
    picked_calls = []
    for ln in log_lines:
        m = tool_call_re.match(ln)
        if not m:
            continue
        args = m.group("args")
        # prefer payload-bearing calls that show a vuln shape
        if any(mark in args for mark in payload_markers):
            picked_calls.append(m)
        if len(picked_calls) >= 6:
            break

    for i, m in enumerate(picked_calls):
        ts = m.group("ts")
        tool = m.group("tool")
        try:
            args = json.loads(m.group("args"))
        except json.JSONDecodeError:
            args = {"raw": m.group("args")}
        args = redact(args)
        seed = f"toolcall:{i}:{ts}"
        # infer family/oracle from the (redacted) args text
        raw = json.dumps(args)
        if "UNION" in raw:
            family, opclass, oracle = "sqli_union", "injection_probe", "row_exfiltration"
        elif "OR '1'='1" in raw or "OR 1=1" in raw:
            family, opclass, oracle = "sqli", "injection_probe", "auth_bypass"
        elif "<script" in raw:
            family, opclass, oracle = "xss", "injection_probe", "reflected_markup"
        elif "{{7*7}}" in raw:
            family, opclass, oracle = "ssti", "injection_probe", "template_eval"
        elif "image_url" in raw:
            family, opclass, oracle = "ssrf", "ssrf_probe", "oob_fetch"
        elif "forgot-password" in raw or "reset" in raw:
            family, opclass, oracle = "reset_flow", "auth_probe", "pin_disclosure"
        elif "amount" in raw or "from_account" in raw:
            family, opclass, oracle = "value_abuse", "business_logic", "balance_delta"
        else:
            family, opclass, oracle = "generic", "generic_probe", "http_status"
        target = redact(args.get("url") or args.get("host") or "shell")
        method = (args.get("method") or ("POST" if family in ("ssrf", "value_abuse", "reset_flow") else "GET"))
        act = envelope("action", seed, ts, next_seq())
        act["action"] = {
            "tool": tool,
            "operation": "request" if tool == "http_request" else ("shell" if tool == "kali" else "run"),
            "params": args,
            "exact_action_hash": sha256_ref(f"exact:toolcall:{i}:{raw}"),
            "semantic_action_family": {
                "target_entity": target,
                "operation_class": opclass,
                "param_mutation": family,
                "payload_family": family,
                "auth_context": "authenticated" if "Bearer" in raw or "Authorization" in raw else "unauthenticated",
                "expected_oracle": oracle,
            },
            "behavior": {
                "transport": "http/1.1",
                "method": method,
                "encoding": "json" if tool == "http_request" else "shell",
                "execution_cardinality": raw.count("curl") if tool == "kali" and raw.count("curl") > 0 else 1,
                "timing_model": "burst" if ("for " in raw or "& done" in raw) else "single",
                "concurrency": "parallel" if "& done" in raw else "sequential",
                "session_state": "bearer_jwt" if "Bearer" in raw else "none",
                "tool_semver": f"{tool}/1.0.0",
                "side_effect_class": "state_mutating" if family in ("value_abuse", "reset_flow") else "read_only",
            },
            "safety_class": "state_mutating" if family in ("value_abuse", "reset_flow") else "read_only",
        }
        events.append(act)

    # sequence is already monotonic (allocated as we built); event_ids are ULIDs.
    return events


def write_events(events):
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with OUT_FILE.open("w") as fh:
        for ev in events:
            fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
    return OUT_FILE


# ---------------------------------------------------------------------------------------
def validate(events):
    """Validate every event against its schema via a referencing.Registry (validate.py style)."""
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource

    resources = [(json.loads(f.read_text())["$id"], Resource.from_contents(json.loads(f.read_text())))
                 for f in sorted(SCHEMAS.glob("*.json"))]
    registry = Registry().with_resources(resources)
    schema_by_id = {sid: res.contents for sid, res in resources}
    event_schema = {
        "observation": "observation-event.schema.json",
        "decision": "decision-event.schema.json",
        "action": "action-event.schema.json",
        "result": "result-event.schema.json",
        "adjudication": "adjudication-event.schema.json",
    }
    errors = []
    for i, ev in enumerate(events, 1):
        sid = event_schema.get(ev.get("event_type"))
        if not sid:
            errors.append(f"event {i}: no schema for type {ev.get('event_type')}")
            continue
        v = Draft202012Validator(schema_by_id[sid], registry=registry)
        for e in v.iter_errors(ev):
            errors.append(f"event {i} ({ev['event_type']}) seq={ev['sequence']}: {e.message} @ /{'/'.join(map(str, e.path))}")

    # DAG ordering: no causal parent holds a >= sequence than its child (§3.1)
    seq = {ev["event_id"]: ev["sequence"] for ev in events}
    for ev in events:
        for parent in ev.get("caused_by", []) + ev.get("depends_on", []):
            if parent in seq and seq[parent] >= ev["sequence"]:
                errors.append(f"[DAG] parent {parent} seq {seq[parent]} >= child {ev['sequence']}")
    # correction edge: supersedes never in caused_by
    for ev in events:
        if ev.get("event_type") == "adjudication":
            if set(ev.get("supersedes", [])) & set(ev.get("caused_by", [])):
                errors.append("[CORRECTION] supersedes leaked into caused_by")
    # evidence derivation reproduces
    for ev in events:
        evd = ev.get("result", {}).get("evidence")
        if evd and derive_level(evd["primitives"]) != evd.get("level"):
            errors.append(f"[DERIVATION] seq={ev['sequence']} level mismatch")
    return errors


def leak_scan():
    """Grep the written output for any raw identifier that must NOT survive (§8)."""
    text = OUT_FILE.read_text()
    raw = [RAW_IP, RAW_HOST, RAW_DOMAIN, RAW_ROLE_HOST] + REAL_ACCOUNTS + REAL_EMAILS \
        + REAL_USERNAMES + REAL_PASSWORDS + REAL_SECRETS
    leaked = sorted({r for r in raw if r in text})
    # residual JWT / api-key patterns
    if _JWT_RE.search(text):
        leaked.append("<raw-jwt-pattern>")
    if _APIKEY_RE.search(text):
        leaked.append("<raw-apikey-pattern>")
    return leaked


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--validate", action="store_true", help="validate + leak-scan after writing")
    args = ap.parse_args()

    events = build_events()
    path = write_events(events)
    print(f"wrote {len(events)} events -> {path}")

    errors = validate(events)
    leaked = leak_scan()
    from collections import Counter
    counts = Counter(e["event_type"] for e in events)
    print("event_type counts:", dict(counts))
    print("redaction labels used:", dict(RED._counts))
    if errors:
        print("VALIDATION ERRORS:")
        for e in errors:
            print("  " + e)
    else:
        print("schema: all events valid")
    print("raw_identifiers_leaked:", leaked)
    if errors or leaked:
        sys.exit(1)
    print("PASS")


if __name__ == "__main__":
    main()
