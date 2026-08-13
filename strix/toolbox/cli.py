"""strix-toolbox CLI — no LLM API key required."""

from __future__ import annotations

import argparse
import logging
import sys
from importlib import metadata


def _version() -> str:
    for name in ("strix-toolbox", "strix-agent"):
        try:
            return metadata.version(name)
        except metadata.PackageNotFoundError:
            continue
    return "dev"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="strix-toolbox",
        description=(
            "No-LLM security toolbox for Cursor MCP. Cursor provides reasoning; "
            "this process only executes tools. The original `strix` CLI still "
            "requires an LLM and is separate."
        ),
    )
    parser.add_argument("--version", action="store_true", help="print version and exit")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="verify runtime, MCP, Docker/browser (optional), HTTP, filesystem; no API keys",
    )
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("mcp", help="start the MCP stdio server (no API key)")
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(_version())
        return 0
    if args.self_test:
        from strix.toolbox.selftest import format_self_test, run_self_test

        report = run_self_test()
        print(format_self_test(report))
        return 0 if report["ok"] else 1
    if args.command == "mcp":
        from strix.toolbox.mcp_server import run_stdio

        run_stdio()
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
