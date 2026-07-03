"""Closure-integrity completion gates (no-artifact / suspect-N/A / skipped)."""
from core.taxonomy import BYPASS_REQUIRED_TYPES as _BYPASS_REQUIRED_TYPES


def _skipped_no_evidence_blocker(all_cells: list[dict]) -> str | None:
    _WAF_KEYWORDS = ("403", "429", "waf", "blocked", "rate limit", "firewall")
    skipped = [
        c for c in all_cells
        if c["status"] == "skipped"
        and not any(kw in c.get("notes", "").lower() for kw in _WAF_KEYWORDS)
    ]
    if not skipped:
        return None
    sample = ", ".join(c["id"] for c in skipped[:5])
    if len(skipped) > 5:
        sample += f" ... ({len(skipped) - 5} more)"
    return (
        f"INTEGRITY: {len(skipped)} cell(s) marked skipped without WAF block "
        f"evidence (403/429/WAF) in notes: {sample}. "
        f"'skipped' is only valid when a WAF blocked the request — add the response evidence or re-test."
    )

def _integrity_blockers(all_cells: list[dict], enforce_cov: bool, ctf_mode: bool) -> list[str]:
    """Closure-INTEGRITY gates — reject cells that LIE about being tested (no
    artifact, suspect-N/A, skipped-without-evidence, N/A-without-bypass). These run
    for EVERY profile (they prevent false data, they don't demand more work).
    Injection-breadth follows enforce_coverage (it demands MORE cells). Extracted
    from _coverage_blockers to keep that function under the cognitive-complexity cap."""
    out: list[str] = []
    from core.coverage import cell_has_test_evidence
    untooled = [c for c in all_cells
                if c["status"] in ("tested_clean", "vulnerable") and not cell_has_test_evidence(c)]
    if untooled:
        out.append(
            f"INTEGRITY: {len(untooled)} cell(s) marked tested/vulnerable but cite no "
            f"artifact_id. Re-test these cells and pass the artifact_id from the tool response."
        )
    suspect_na = _suspect_na_cells(all_cells, _BYPASS_REQUIRED_TYPES)
    if suspect_na:
        sample = ", ".join(suspect_na[:5]) + ("..." if len(suspect_na) > 5 else "")
        out.append(
            f"INTEGRITY: {len(suspect_na)} cell(s) marked N/A without testing bypass "
            f"techniques: {sample}. Test the bypass before marking N/A."
        )
    skipped_blocker = _skipped_no_evidence_blocker(all_cells)
    if skipped_blocker:
        out.append(skipped_blocker)
    na_blocker = _na_untooled_blocker(all_cells, _BYPASS_REQUIRED_TYPES)
    if na_blocker:
        out.append(na_blocker)
    # Injection-breadth is also a completeness gate (demands MORE cells registered/
    # tested), so it follows enforce_coverage too — advisory for local.
    breadth_blocker = _injection_breadth_blocker(all_cells, enforce_cov and not ctf_mode)
    if breadth_blocker:
        out.append(breadth_blocker)
    return out


def _na_untooled_blocker(cells: list[dict], bypass_types: dict) -> str | None:
    """Return a blocker string if any bypass-type N/A cells cite no test evidence."""
    from core.coverage import cell_has_test_evidence
    na_untooled = [
        c for c in cells
        if c["status"] == "not_applicable"
        and not cell_has_test_evidence(c)
        and c.get("injection_type") in bypass_types
    ]
    if not na_untooled:
        return None
    sample = ", ".join(f"{c['id']} ({c['injection_type']})" for c in na_untooled[:5])
    if len(na_untooled) > 5:
        sample += f" ... ({len(na_untooled) - 5} more)"
    return (
        f"INTEGRITY: {len(na_untooled)} injection-type N/A cell(s) cite no artifact_id "
        f"of a bypass attempt: {sample}. Run the bypass technique and pass its artifact_id before marking N/A."
    )


def _injection_breadth_blocker(cells: list[dict], coverage_enforced: bool) -> str | None:
    """Return a blocker if text params have sqli cells but no xss/ssti/ssrf/cmdi cells."""
    _BREADTH_REQUIRED = {"xss", "ssti", "ssrf", "cmdi"}
    _TEXT_PARAM_TYPES = {"query", "body_form", "body_json", "path", "header", "cookie"}
    from collections import defaultdict
    by_param: dict[tuple, set] = defaultdict(set)
    for c in cells:
        if c.get("param_type") in _TEXT_PARAM_TYPES and c.get("param") != "_endpoint":
            by_param[(c["endpoint_id"], c["param"])].add(c["injection_type"])
    breadth_gaps: list[str] = []
    for (_ep_id, param), inj_types in by_param.items():
        if "sqli" not in inj_types:
            continue
        missing = _BREADTH_REQUIRED - inj_types
        if missing:
            breadth_gaps.append(f"'{param}' (missing: {', '.join(sorted(missing))})")
    if not breadth_gaps or not coverage_enforced:
        return None
    sample = "; ".join(breadth_gaps[:5])
    more = f" (+{len(breadth_gaps) - 5} more)" if len(breadth_gaps) > 5 else ""
    return (
        f"INJECTION BREADTH: {len(breadth_gaps)} text param(s) have sqli cells but no "
        f"xss/ssti/ssrf/cmdi cells — these injection types were never registered for these params. "
        f"Re-register the endpoint(s) or add the missing cells with report(action='coverage'): "
        f"{sample}{more}"
    )


def _suspect_na_cells(cells: list[dict], bypass_types: dict) -> list[str]:
    """Return cell IDs/types marked N/A without bypass justification."""
    suspect = []
    for c in cells:
        if c["status"] != "not_applicable" or c["injection_type"] not in bypass_types:
            continue
        cell_notes = c.get("notes", "")
        bypass = bypass_types[c["injection_type"]]
        keywords = bypass.lower().split(", ")
        if not any(kw in cell_notes.lower() for kw in keywords) and len(cell_notes) < 40:
            suspect.append(f"{c['id']} ({c['injection_type']})")
    return suspect
