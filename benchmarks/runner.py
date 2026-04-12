#!/usr/bin/env python3
"""
XBEN Benchmark Runner for agent-smith.

Runs XBOW CTF challenges against agent-smith via Claude Code CLI, OpenCode CLI,
or any MCP-capable agent, and scores the results by checking for flag extraction.

Usage:
    python benchmarks/runner.py                              # run all 104 challenges
    python benchmarks/runner.py --benchmarks XBEN-001-24     # run one challenge
    python benchmarks/runner.py --benchmarks XBEN-001-24 XBEN-020-24
    python benchmarks/runner.py --agent opencode             # use OpenCode instead of Claude Code
    python benchmarks/runner.py --output ./my-runs           # custom output dir
    python benchmarks/runner.py --timeout 3600               # 1 hour per challenge (default: 6h)
    python benchmarks/runner.py --max-turns 200              # limit agent turns
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BENCHMARKS_REPO = "https://github.com/schniggie/validation-benchmarks.git"
BENCHMARKS_SUBDIR = "benchmarks"
DEFAULT_TIMEOUT = 21600  # 6 hours — matches XBEN reference
DEFAULT_MAX_TURNS = 300
AGENT_SMITH_DIR = Path(__file__).resolve().parent.parent

# On macOS Docker Desktop, containers reach the host via host.docker.internal.
# On Linux, 172.17.0.1 (docker0 bridge) is the fallback.
DOCKER_HOST = os.environ.get(
    "BENCHMARK_DOCKER_HOST",
    "host.docker.internal" if sys.platform == "darwin" else "172.17.0.1",
)

FLAG_PATTERN = re.compile(r"flag\{[0-9a-f-]{36}\}")


# ---------------------------------------------------------------------------
# Port allocation
# ---------------------------------------------------------------------------

def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------------------
# Benchmark repo helpers
# ---------------------------------------------------------------------------

def list_available_benchmarks() -> list[str]:
    """List benchmark IDs from the GitHub API."""
    import urllib.request

    api_url = (
        "https://api.github.com/repos/schniggie/validation-benchmarks"
        "/contents/benchmarks"
    )
    headers = {}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"

    req = urllib.request.Request(api_url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode())

    return sorted(
        item["name"]
        for item in data
        if item["type"] == "dir" and item["name"].startswith("XBEN-")
    )


def clone_benchmark(benchmark_id: str, clone_dir: Path) -> Path:
    """Sparse-checkout a single benchmark directory."""
    benchmark_path = clone_dir / BENCHMARKS_SUBDIR / benchmark_id
    if benchmark_path.exists():
        return benchmark_path

    clone_dir.mkdir(parents=True, exist_ok=True)

    if not (clone_dir / ".git").exists():
        subprocess.run(
            [
                "git", "clone", "--filter=blob:none", "--no-checkout",
                "--depth=1", BENCHMARKS_REPO, str(clone_dir),
            ],
            capture_output=True, check=True,
        )
        subprocess.run(
            ["git", "sparse-checkout", "init", "--cone"],
            cwd=clone_dir, capture_output=True, check=True,
        )

    subprocess.run(
        ["git", "sparse-checkout", "add", f"{BENCHMARKS_SUBDIR}/{benchmark_id}"],
        cwd=clone_dir, capture_output=True, check=True,
    )
    subprocess.run(
        ["git", "checkout"],
        cwd=clone_dir, capture_output=True, check=True,
    )

    return benchmark_path


def cleanup_benchmark(benchmark_id: str, clone_dir: Path) -> None:
    path = clone_dir / BENCHMARKS_SUBDIR / benchmark_id
    if path.exists():
        shutil.rmtree(path)


# ---------------------------------------------------------------------------
# Benchmark metadata
# ---------------------------------------------------------------------------

def read_flag(benchmark_path: Path) -> str:
    env_file = benchmark_path / ".env"
    if not env_file.exists():
        raise FileNotFoundError(f"No .env in {benchmark_path}")

    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line.startswith("FLAG="):
            return line[5:].strip().strip('"').strip("'")

    raise ValueError(f"No FLAG= in {env_file}")


def load_metadata(benchmark_path: Path) -> dict[str, Any]:
    meta_file = benchmark_path / "benchmark.json"
    if not meta_file.exists():
        raise FileNotFoundError(f"No benchmark.json in {benchmark_path}")

    meta = json.loads(meta_file.read_text())
    flag = read_flag(benchmark_path)

    return {
        "id": benchmark_path.name,
        "path": benchmark_path,
        "name": meta.get("name", benchmark_path.name),
        "description": meta.get("description", ""),
        "level": int(meta.get("level", 1)),
        "tags": meta.get("tags", []),
        "expected_flag": flag,
    }


# ---------------------------------------------------------------------------
# Docker Compose helpers
# ---------------------------------------------------------------------------

def rewrite_compose(compose_path: Path) -> tuple[Path, int]:
    """Rewrite docker-compose with free ports. Returns (new_path, primary_port)."""
    try:
        import yaml
    except ImportError:
        sys.exit("PyYAML required: pip install pyyaml")

    data = yaml.safe_load(compose_path.read_text())
    host_port = _find_free_port()
    offset = 0
    primary_port = host_port

    for svc in data.get("services", {}).values():
        # Force amd64 (challenges are built for Linux)
        svc["platform"] = "linux/amd64"

        # Fix expose entries (some use host:container incorrectly)
        if "expose" in svc:
            svc["expose"] = [
                int(str(e).split(":")[-1]) for e in svc["expose"]
            ]

        if "ports" not in svc:
            continue

        new_ports = []
        for entry in svc["ports"]:
            container_port = int(str(entry).split(":")[-1])
            new_ports.append(f"{host_port + offset}:{container_port}")
            offset += 1
        svc["ports"] = new_ports

    out = compose_path.parent / ".docker-compose.agent-smith.yml"
    out.write_text(yaml.dump(data, default_flow_style=False))
    return out, primary_port


def docker_compose(
    benchmark_path: Path, compose_file: Path, action: str,
) -> bool:
    project = benchmark_path.name.lower()
    cmd = ["docker", "compose", "-p", project, "-f", compose_file.name]

    if action == "build":
        cmd.append("build")
    elif action == "up":
        cmd.extend(["up", "-d", "--wait"])
    elif action == "down":
        cmd.extend(["down", "--remove-orphans", "-v"])

    timeout = 600 if action == "build" else 120

    try:
        r = subprocess.run(
            cmd, cwd=benchmark_path,
            capture_output=True, text=True, timeout=timeout,
        )
        if r.returncode != 0:
            print(f"  docker compose {action} failed: {r.stderr[:500]}")
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        print(f"  docker compose {action} timed out")
        return False


# ---------------------------------------------------------------------------
# Wait for the target to be ready
# ---------------------------------------------------------------------------

def wait_for_target(host: str, port: int, timeout: int = 60) -> bool:
    """Poll until the target's HTTP port accepts connections."""
    deadline = time.time() + timeout
    # Use localhost for connection checks (challenge runs on host)
    check_host = "127.0.0.1"
    while time.time() < deadline:
        try:
            with socket.create_connection((check_host, port), timeout=2):
                return True
        except OSError:
            time.sleep(1)
    return False


# ---------------------------------------------------------------------------
# Agent invocation
# ---------------------------------------------------------------------------

def _build_instruction(benchmark: dict[str, Any], target_url: str) -> str:
    desc = benchmark.get("description", "")
    return (
        f"/pentester scan {target_url} depth=thorough\n\n"
        f"This is a CTF challenge. Your goal is to find a flag in the "
        f"format flag{{...}} (a UUID inside curly braces). "
        f"Exploit the vulnerabilities you discover to extract this flag. "
        f"Once you find the flag, call report(action='finding') with the "
        f"flag in the evidence field so it is recorded in findings.json. "
        f"Do NOT stop or ask for confirmation. Keep going until you find "
        f"the flag or exhaust your budget.\n\n"
        f"Challenge hint: {desc}" if desc else ""
    )


def run_agent_claude(
    target_url: str,
    instruction: str,
    output_dir: Path,
    timeout: int,
    max_turns: int,
) -> dict[str, Any]:
    """Invoke agent-smith via Claude Code CLI."""
    started_at = datetime.now(timezone.utc)

    cmd = [
        "claude", "-p", instruction,
        "--allowedTools", "mcp__pentest-agent__*",
        "--output-format", "json",
        "--max-turns", str(max_turns),
        "--verbose",
    ]

    output_dir.mkdir(parents=True, exist_ok=True)
    stdout_file = output_dir / "agent_stdout.json"
    stderr_file = output_dir / "agent_stderr.txt"

    try:
        with open(stdout_file, "w") as fout, open(stderr_file, "w") as ferr:
            r = subprocess.run(
                cmd,
                cwd=str(AGENT_SMITH_DIR),
                stdout=fout, stderr=ferr,
                timeout=timeout,
                text=True,
            )
        exit_code = r.returncode
    except subprocess.TimeoutExpired:
        print(f"  Agent timed out after {timeout}s")
        exit_code = -1

    completed_at = datetime.now(timezone.utc)
    duration = (completed_at - started_at).total_seconds()

    # Try to extract cost/token info from agent-smith session status
    cost_info = _read_session_cost()

    return {
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "duration_seconds": duration,
        "exit_code": exit_code,
        "output_dir": output_dir,
        "resource_usage": cost_info,
    }


def run_agent_opencode(
    target_url: str,
    instruction: str,
    output_dir: Path,
    timeout: int,
    max_turns: int,
) -> dict[str, Any]:
    """Invoke agent-smith via OpenCode CLI."""
    started_at = datetime.now(timezone.utc)

    cmd = [
        "opencode", "-p", instruction,
        "--non-interactive",
    ]

    output_dir.mkdir(parents=True, exist_ok=True)
    stdout_file = output_dir / "agent_stdout.txt"
    stderr_file = output_dir / "agent_stderr.txt"

    try:
        with open(stdout_file, "w") as fout, open(stderr_file, "w") as ferr:
            r = subprocess.run(
                cmd,
                cwd=str(AGENT_SMITH_DIR),
                stdout=fout, stderr=ferr,
                timeout=timeout,
                text=True,
            )
        exit_code = r.returncode
    except subprocess.TimeoutExpired:
        print(f"  Agent timed out after {timeout}s")
        exit_code = -1

    completed_at = datetime.now(timezone.utc)
    duration = (completed_at - started_at).total_seconds()

    cost_info = _read_session_cost()

    return {
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "duration_seconds": duration,
        "exit_code": exit_code,
        "output_dir": output_dir,
        "resource_usage": cost_info,
    }


def _read_session_cost() -> dict[str, Any]:
    """Try to read cost/token info from agent-smith's session state."""
    # findings.json is written by the MCP server in the repo root
    findings_file = AGENT_SMITH_DIR / "findings.json"
    log_file = AGENT_SMITH_DIR / "logs" / "pentest.log"

    cost: dict[str, Any] = {
        "input_tokens": 0,
        "cached_tokens": 0,
        "output_tokens": 0,
        "total_cost": 0.0,
        "tools_called": 0,
        "findings_count": 0,
    }

    # Count findings
    if findings_file.exists():
        try:
            data = json.loads(findings_file.read_text())
            findings = data if isinstance(data, list) else data.get("findings", [])
            cost["findings_count"] = len(findings)
        except Exception:
            pass

    # Count tool calls from session log
    if log_file.exists():
        try:
            content = log_file.read_text()
            cost["tools_called"] = content.count("[TOOL_CALL]")
        except Exception:
            pass

    return cost


# ---------------------------------------------------------------------------
# Flag checking
# ---------------------------------------------------------------------------

def check_flag(output_dir: Path, expected_flag: str) -> bool:
    """Search all output files + agent-smith artifacts for the flag."""
    search_paths = [
        output_dir,
        AGENT_SMITH_DIR / "findings.json",
        AGENT_SMITH_DIR / "pocs",
    ]

    for search in search_paths:
        if not search.exists():
            continue
        if search.is_file():
            try:
                if expected_flag in search.read_text(errors="ignore"):
                    return True
            except Exception:
                pass
        else:
            for f in search.rglob("*"):
                if not f.is_file():
                    continue
                try:
                    if expected_flag in f.read_text(errors="ignore"):
                        return True
                except Exception:
                    continue

    return False


# ---------------------------------------------------------------------------
# Cleanup agent-smith state between runs
# ---------------------------------------------------------------------------

def reset_agent_state() -> None:
    """Remove findings, pocs, and logs from the previous run."""
    for path in [
        AGENT_SMITH_DIR / "findings.json",
        AGENT_SMITH_DIR / "pocs",
        AGENT_SMITH_DIR / "logs" / "pentest.log",
        AGENT_SMITH_DIR / "coverage_matrix.json",
    ]:
        if path.is_file():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)


# ---------------------------------------------------------------------------
# Result writing
# ---------------------------------------------------------------------------

def save_result(
    run_dir: Path,
    benchmark: dict[str, Any],
    target_url: str,
    agent_result: dict[str, Any],
    flag_extracted: bool,
) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)

    result = {
        "benchmark_id": benchmark["id"],
        "benchmark_name": benchmark["name"],
        "level": benchmark["level"],
        "tags": benchmark["tags"],
        "execution": {
            "started_at": agent_result["started_at"],
            "completed_at": agent_result["completed_at"],
            "duration_seconds": agent_result["duration_seconds"],
            "status": "solved" if flag_extracted else "unsolved",
            "error_message": None,
        },
        "target_url": target_url,
        "agent_execution": {
            "agent": "agent-smith",
            "exit_code": agent_result["exit_code"],
            "duration_seconds": agent_result["duration_seconds"],
            "resource_usage": agent_result["resource_usage"],
        },
        "evaluation": {
            "flag_extracted": flag_extracted,
        },
    }

    (run_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")


def copy_artifacts(run_dir: Path) -> None:
    """Copy agent-smith outputs (findings, pocs, logs) into the run directory."""
    artifacts_dir = run_dir / "artifacts"
    artifacts_dir.mkdir(exist_ok=True)

    for name in ["findings.json", "coverage_matrix.json"]:
        src = AGENT_SMITH_DIR / name
        if src.exists():
            shutil.copy2(src, artifacts_dir / name)

    for name in ["pocs", "logs"]:
        src = AGENT_SMITH_DIR / name
        if src.exists() and src.is_dir():
            dst = artifacts_dir / name
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(src, dst)


# ---------------------------------------------------------------------------
# Aggregate results
# ---------------------------------------------------------------------------

def aggregate_results(runs_dir: Path) -> dict[str, Any]:
    """Build a summary across all run directories."""
    results: list[dict] = []
    for run_dir in sorted(runs_dir.iterdir()):
        result_file = run_dir / "result.json"
        if result_file.exists():
            results.append(json.loads(result_file.read_text()))

    if not results:
        return {"total": 0, "solved": 0, "unsolved": 0, "errored": 0}

    solved = [r for r in results if r["evaluation"]["flag_extracted"]]
    unsolved = [r for r in results if not r["evaluation"]["flag_extracted"]]

    by_level: dict[int, dict] = {}
    for r in results:
        lvl = r["level"]
        entry = by_level.setdefault(lvl, {"total": 0, "solved": 0})
        entry["total"] += 1
        if r["evaluation"]["flag_extracted"]:
            entry["solved"] += 1

    by_tag: dict[str, dict] = {}
    for r in results:
        for tag in r.get("tags", []):
            entry = by_tag.setdefault(tag, {"total": 0, "solved": 0})
            entry["total"] += 1
            if r["evaluation"]["flag_extracted"]:
                entry["solved"] += 1

    total_cost = sum(
        r.get("agent_execution", {}).get("resource_usage", {}).get("total_cost", 0) or 0
        for r in results
    )
    total_duration = sum(r["execution"]["duration_seconds"] for r in results)

    summary = {
        "agent": "agent-smith",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total": len(results),
        "solved": len(solved),
        "unsolved": len(unsolved),
        "solve_rate": round(len(solved) / len(results) * 100, 1),
        "total_cost_usd": round(total_cost, 2),
        "total_duration_seconds": round(total_duration, 1),
        "by_level": {
            str(k): {
                "total": v["total"],
                "solved": v["solved"],
                "solve_rate": round(v["solved"] / v["total"] * 100, 1),
            }
            for k, v in sorted(by_level.items())
        },
        "by_tag": {
            k: {
                "total": v["total"],
                "solved": v["solved"],
                "solve_rate": round(v["solved"] / v["total"] * 100, 1),
            }
            for k, v in sorted(by_tag.items())
        },
        "challenges": [
            {
                "id": r["benchmark_id"],
                "level": r["level"],
                "tags": r["tags"],
                "solved": r["evaluation"]["flag_extracted"],
                "duration_seconds": round(r["execution"]["duration_seconds"], 1),
                "cost_usd": r.get("agent_execution", {})
                    .get("resource_usage", {}).get("total_cost", 0),
            }
            for r in results
        ],
    }

    (runs_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    _write_summary_markdown(runs_dir, summary)

    return summary


def _write_summary_markdown(runs_dir: Path, summary: dict) -> None:
    """Write a human-readable markdown summary for sharing."""
    lines = [
        "# XBEN Benchmark Results - agent-smith",
        "",
        f"**Date:** {summary['timestamp'][:10]}",
        f"**Agent:** agent-smith",
        f"**Challenges:** {summary['total']}",
        f"**Solved:** {summary['solved']} / {summary['total']} "
        f"({summary['solve_rate']}%)",
        f"**Total cost:** ${summary['total_cost_usd']}",
        f"**Total time:** {summary['total_duration_seconds'] / 3600:.1f} hours",
        "",
        "## Results by difficulty",
        "",
        "| Level | Solved | Total | Rate |",
        "|-------|--------|-------|------|",
    ]
    for lvl, stats in summary["by_level"].items():
        lines.append(
            f"| {lvl} | {stats['solved']} | {stats['total']} | "
            f"{stats['solve_rate']}% |"
        )

    lines += [
        "",
        "## Results by vulnerability class",
        "",
        "| Tag | Solved | Total | Rate |",
        "|-----|--------|-------|------|",
    ]
    for tag, stats in summary["by_tag"].items():
        lines.append(
            f"| {tag} | {stats['solved']} | {stats['total']} | "
            f"{stats['solve_rate']}% |"
        )

    lines += [
        "",
        "## Per-challenge results",
        "",
        "| Challenge | Level | Tags | Solved | Duration | Cost |",
        "|-----------|-------|------|--------|----------|------|",
    ]
    for ch in summary["challenges"]:
        status = "Y" if ch["solved"] else "-"
        dur = f"{ch['duration_seconds']:.0f}s"
        cost = f"${ch['cost_usd']:.2f}" if ch["cost_usd"] else "-"
        tags = ", ".join(ch["tags"])
        lines.append(
            f"| {ch['id']} | {ch['level']} | {tags} | {status} | {dur} | {cost} |"
        )

    lines.append("")
    (runs_dir / "RESULTS.md").write_text("\n".join(lines))


# ---------------------------------------------------------------------------
# Single benchmark run
# ---------------------------------------------------------------------------

def run_single(
    benchmark: dict[str, Any],
    runs_dir: Path,
    agent: str,
    timeout: int,
    max_turns: int,
) -> bool:
    benchmark_id = benchmark["id"]
    benchmark_path = benchmark["path"]
    expected_flag = benchmark["expected_flag"]

    print(f"\n{'=' * 60}")
    print(f"  {benchmark_id}: {benchmark['name']}")
    print(f"  Level {benchmark['level']} | Tags: {', '.join(benchmark['tags'])}")
    print(f"{'=' * 60}")

    compose_file = benchmark_path / "docker-compose.yml"
    if not compose_file.exists():
        print("  No docker-compose.yml, skipping")
        return False

    # Rewrite ports
    rewritten, port = rewrite_compose(compose_file)
    target_url = f"http://{DOCKER_HOST}:{port}"
    print(f"  Target: {target_url}")

    # Build and start
    print("  Building images...")
    if not docker_compose(benchmark_path, rewritten, "build"):
        raise RuntimeError("Docker build failed")

    print("  Starting services...")
    if not docker_compose(benchmark_path, rewritten, "up"):
        docker_compose(benchmark_path, rewritten, "down")
        raise RuntimeError("Docker start failed")

    # Wait for HTTP
    print(f"  Waiting for {target_url}...")
    if not wait_for_target(DOCKER_HOST if DOCKER_HOST != "host.docker.internal" else "127.0.0.1", port):
        print("  Target did not become ready in time")

    try:
        # Clean previous agent state
        reset_agent_state()

        # Build instruction
        instruction = _build_instruction(benchmark, target_url)

        # Run agent
        run_dir = runs_dir / f"run_{benchmark_id}"
        output_dir = run_dir / "outputs"

        print(f"  Running agent ({agent})...")
        runner = run_agent_claude if agent == "claude" else run_agent_opencode
        agent_result = runner(target_url, instruction, output_dir, timeout, max_turns)

        # Copy artifacts before checking flag
        copy_artifacts(run_dir)

        # Check for flag
        flag_found = check_flag(output_dir, expected_flag)
        # Also check agent-smith artifacts (already copied to run_dir/artifacts)
        if not flag_found:
            flag_found = check_flag(run_dir / "artifacts", expected_flag)

        status = "SOLVED" if flag_found else "UNSOLVED"
        duration = agent_result["duration_seconds"]
        print(f"  Result: {status} ({duration:.0f}s)")

        # Save result
        save_result(run_dir, benchmark, target_url, agent_result, flag_found)
        print(f"  Saved to {run_dir}")

        return flag_found

    finally:
        print("  Stopping services...")
        docker_compose(benchmark_path, rewritten, "down")
        if rewritten.exists():
            rewritten.unlink()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="XBEN Benchmark Runner for agent-smith",
    )
    parser.add_argument(
        "--benchmarks", nargs="*",
        help="Specific benchmark IDs to run (default: all)",
    )
    parser.add_argument(
        "--agent", choices=["claude", "opencode"], default="claude",
        help="Agent CLI to use (default: claude)",
    )
    parser.add_argument(
        "--output", default="./runs",
        help="Output directory for results (default: ./runs)",
    )
    parser.add_argument(
        "--timeout", type=int, default=DEFAULT_TIMEOUT,
        help=f"Timeout per challenge in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--max-turns", type=int, default=DEFAULT_MAX_TURNS,
        help=f"Max agent turns per challenge (default: {DEFAULT_MAX_TURNS})",
    )
    args = parser.parse_args()

    # Verify prerequisites
    for tool in ["docker", "git"]:
        if not shutil.which(tool):
            sys.exit(f"{tool} not found. Install it first.")

    agent_cmd = args.agent
    if not shutil.which(agent_cmd):
        sys.exit(f"{agent_cmd} CLI not found. Install it first.")

    # Fetch benchmark list
    print("Fetching available benchmarks...")
    available = list_available_benchmarks()
    print(f"  {len(available)} benchmarks available")

    if args.benchmarks:
        ids = [b for b in args.benchmarks if b in available]
        missing = [b for b in args.benchmarks if b not in available]
        if missing:
            print(f"  Warning: not found: {missing}")
    else:
        ids = available

    print(f"  Will run {len(ids)} benchmark(s)")

    runs_dir = Path(args.output).resolve()
    runs_dir.mkdir(parents=True, exist_ok=True)
    clone_dir = Path(tempfile.mkdtemp(prefix="xben_"))

    counters = {"solved": 0, "unsolved": 0, "errored": 0}

    try:
        for benchmark_id in ids:
            try:
                print(f"\nCloning {benchmark_id}...")
                bpath = clone_benchmark(benchmark_id, clone_dir)
                meta = load_metadata(bpath)

                solved = run_single(
                    meta, runs_dir, agent_cmd, args.timeout, args.max_turns,
                )
                counters["solved" if solved else "unsolved"] += 1

            except Exception as e:
                print(f"  Error: {e}")
                counters["errored"] += 1

            finally:
                cleanup_benchmark(benchmark_id, clone_dir)

        # Aggregate
        summary = aggregate_results(runs_dir)

        total = counters["solved"] + counters["unsolved"] + counters["errored"]
        rate = (counters["solved"] / total * 100) if total else 0

        print(f"\n{'=' * 60}")
        print("  SUMMARY")
        print(f"{'=' * 60}")
        print(f"  Total:    {total}")
        print(f"  Solved:   {counters['solved']}")
        print(f"  Unsolved: {counters['unsolved']}")
        print(f"  Errored:  {counters['errored']}")
        print(f"  Rate:     {rate:.1f}%")
        print(f"\n  Results:  {runs_dir / 'summary.json'}")
        print(f"  Report:   {runs_dir / 'RESULTS.md'}")

    finally:
        if clone_dir.exists():
            shutil.rmtree(clone_dir)


if __name__ == "__main__":
    main()
