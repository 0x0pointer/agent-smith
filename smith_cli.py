from __future__ import annotations

import argparse
import json

from control_plane import orchestrator


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="smith")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("start")
    sub.add_parser("stop")
    sub.add_parser("status")
    args = parser.parse_args(argv)

    if args.command == "start":
        print(json.dumps(orchestrator.start_control_plane()))
    elif args.command == "stop":
        print(json.dumps(orchestrator.stop_control_plane()))
    else:
        print(json.dumps(orchestrator.control_plane_status()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
