#!/usr/bin/env python3
"""The stub must register the same tools as the production server.

This repo is registry metadata plus a sandbox stub. Directories like Glama
evaluate the stub, not production, and score the server on the tool descriptions
they find there. When the two drift, the score is computed against a server that
does not exist: on 2026-08-13 the stub carried eight tools while production
carried nine, missing fingerprint_population_tool, and nothing noticed.

MCP discovery is deliberately ungated on production (initialize, tools/list and
ping need no Bearer token, so registries can list the server), which is what lets
this run in CI with no credential at all.

Compares names only. Descriptions are prose and drift for good reasons; a missing
or extra tool is unambiguous.

    python scripts/check_stub_drift.py            # against production
    python scripts/check_stub_drift.py --url ...  # against another deploy
"""
from __future__ import annotations

import argparse
import ast
import json
import pathlib
import sys
import urllib.request

DEFAULT_URL = "https://mcp.honeylabs.net/mcp"
STUB = pathlib.Path(__file__).resolve().parent.parent / "glama" / "stub_server.py"


def stub_tools(path: pathlib.Path) -> set[str]:
    """Names of functions decorated with @mcp.tool, read without importing.

    Parsing rather than importing keeps this independent of whether the stub's
    dependencies are installed, and means a stub that fails to import produces a
    clear error here rather than an ImportError halfway through CI.
    """
    tree = ast.parse(path.read_text())
    names = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            attr = getattr(target, "attr", None)
            if attr == "tool":
                names.add(node.name)
    return names


def live_tools(url: str) -> set[str]:
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    ).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            # The server speaks streamable HTTP, so it may answer either shape.
            "Accept": "application/json, text/event-stream",
            "User-Agent": "honeylabs-stub-drift-check/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        raw = r.read().decode()

    # A text/event-stream reply wraps the JSON in `data: ` lines.
    if raw.lstrip().startswith("data:"):
        raw = "".join(
            line[len("data:"):].strip()
            for line in raw.splitlines()
            if line.startswith("data:")
        )
    body = json.loads(raw)
    if "error" in body:
        raise SystemExit(f"tools/list returned an error: {body['error']}")
    return {t["name"] for t in body["result"]["tools"]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=DEFAULT_URL)
    args = ap.parse_args()

    stub = stub_tools(STUB)
    live = live_tools(args.url)

    missing = sorted(live - stub)     # production has it, the stub does not
    extra = sorted(stub - live)       # the stub advertises something that does not exist

    print(f"stub  ({len(stub)}): {', '.join(sorted(stub))}")
    print(f"live  ({len(live)}): {', '.join(sorted(live))}")

    if not missing and not extra:
        print("\nOK: the stub mirrors production.")
        return 0

    if missing:
        print(f"\nMISSING from the stub: {', '.join(missing)}")
        print("  Registries score the stub, so a tool absent here is invisible to them.")
    if extra:
        print(f"\nEXTRA in the stub: {', '.join(extra)}")
        print("  The stub advertises a tool production does not serve.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
