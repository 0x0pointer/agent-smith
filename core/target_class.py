"""
Deterministic target classifier
================================
Maps a raw target string to a coarse engagement *kind* plus the boot tool(s) and
skill that best fit it. Pure, regex-driven, no I/O — the same input always yields
the same classification.

This is advisory only. ``session(action='start')`` surfaces the result as a
"recommended first move" and stores it for the dashboard, but it never gates or
overrides the LLM's own skill choice — the agent stays free to route differently
based on what it actually finds. Its real value is in AUTONOMOUS / CI runs where
no human is there to notice that a codebase path, a cloud account, or an IP range
should not be greeted with an httpx web scan.

Borrowed (in spirit) from PiRanha's deterministic engagement router, adapted to
agent-smith's reactive, single-agent model: a prior, not a commitment.
"""
from __future__ import annotations

import re

# Bare IPv4, optional CIDR suffix, or a dashed range (1.2.3.4-1.2.3.20 / .20).
_IP_OR_CIDR = re.compile(
    r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?(?:\s*-\s*\d{1,3}(?:\.\d{1,3}){0,3})?$"
)
_CLOUD = re.compile(
    r"(?:^arn:aws:|amazonaws\.com|\.azure\.|azure\.com|azurewebsites|"
    r"googleapis\.com|\.gcp\.|cloud\.google\.com|blob\.core\.windows\.net)",
    re.IGNORECASE,
)
_API = re.compile(r"(?:/graphql\b|/graph\b|swagger|openapi|/api\b|/v\d+\b|\.wsdl\b)", re.IGNORECASE)
_PATH_PREFIX = ("/", "./", "../", "~", ".\\", "\\\\")
_WIN_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")


def classify_target(target: str) -> dict:
    """Classify a target string into {kind, boot_tools, skill_prior, reason}.

    kind ∈ {codebase, cloud, network, api, web}. ``web`` is the default and
    matches agent-smith's current behaviour, so nothing changes for plain URLs.
    """
    t = (target or "").strip()

    # Codebase: a local filesystem path, not a URL. Checked first because a path
    # must never be treated as a host.
    if "://" not in t and (t.startswith(_PATH_PREFIX) or _WIN_DRIVE.match(t)):
        return {
            "kind": "codebase",
            "boot_tools": ["semgrep", "trufflehog"],
            "skill_prior": "/codebase",
            "reason": "target is a local filesystem path — white-box source review, not a live scan",
        }

    # Cloud: ARN or a known provider host.
    if _CLOUD.search(t):
        return {
            "kind": "cloud",
            "boot_tools": [],
            "skill_prior": "/cloud-security",
            "reason": "target is a cloud account/resource (AWS/Azure/GCP) — IAM/storage/serverless posture",
        }

    # Network: a bare IP, CIDR, or IP range (strip any scheme/path first).
    host = re.sub(r"^\w+://", "", t).split("/")[0].split("?")[0]
    if _IP_OR_CIDR.match(t) or _IP_OR_CIDR.match(host):
        return {
            "kind": "network",
            "boot_tools": ["naabu", "nmap"],
            "skill_prior": "/network-assess",
            "reason": "target is an IP / CIDR / range — port-scan first; pivot to /ad-assessment if a domain controller appears",
        }

    # API: a URL whose path/shape signals a structured API surface.
    if _API.search(t):
        return {
            "kind": "api",
            "boot_tools": ["httpx"],
            "skill_prior": "/api-security",
            "reason": "target looks like a structured API (GraphQL/REST/swagger) — OWASP API Top 10",
        }

    # Default: treat as a web app (unchanged behaviour).
    return {
        "kind": "web",
        "boot_tools": ["httpx"],
        "skill_prior": "/web-exploit",
        "reason": "default web application target",
    }
