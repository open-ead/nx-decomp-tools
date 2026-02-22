#!/usr/bin/env python3

import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
assert (PROJECT_ROOT / "tools" / "config.toml").exists(), f"config.toml not found; PROJECT_ROOT={PROJECT_ROOT}"

_ANSI_ESCAPE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

def _run(args: list[str], timeout: int) -> str:
    print(f"[nx-decomp-tools] {' '.join(args)}", file=sys.stderr, flush=True)
    result = subprocess.run(args, cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=timeout)
    output = _ANSI_ESCAPE.sub("", result.stdout + result.stderr)
    print(f"[nx-decomp-tools] exit {result.returncode}, {len(output)} chars", file=sys.stderr, flush=True)
    return output

mcp = FastMCP("nx-decomp-tools")


@mcp.tool()
def check(
    function: Optional[str] = None,
    functions: Optional[list[str]] = None,
    always_diff: bool = False,
    warnings_as_errors: bool = False,
    check_mismatch_comments: bool = False,
    check_placement: bool = False,
    context_lines: Optional[int] = None,
    show_source: bool = False,
) -> str:
    """
    Run tools/check to diff assembly for one or more functions, or all functions.

    Args:
        function: Single mangled or demangled symbol name to check.
        functions: List of symbol names to check (checked sequentially, output combined).
        always_diff: Pass --always-diff (show diff even for matching functions).
        warnings_as_errors: Pass --warnings-as-errors.
        check_mismatch_comments: Pass --check-mismatch-comments.
        check_placement: Pass --check-placement (verify functions are in correct objects).
        context_lines: Number of context lines for the diff (-U N). Single-function only.
        show_source: Show source alongside assembly (-c). Single-function only.
    """
    targets: list[Optional[str]] = list(functions) if functions else [function] if function else [None]

    base_flags = ["--no-pager", "--format=plain"]
    if always_diff: base_flags.append("--always-diff")
    if warnings_as_errors: base_flags.append("--warnings-as-errors")
    if check_mismatch_comments: base_flags.append("--check-mismatch-comments")
    if check_placement: base_flags.append("--check-placement")

    after_flags = (["-U", str(context_lines)] if context_lines is not None else []) + (["-c"] if show_source else [])

    results = []
    for target in targets:
        args = ["tools/check"] + base_flags + ([target] + after_flags if target else [])
        output = _run(args, timeout=60 if target else 600)
        if target is None and len(output) > 50_000:
            output = output[:50_000] + "\n\n[output truncated at 50,000 chars]"
        results.append(f"=== {target} ===\n{output}" if len(targets) > 1 else output)

    return "\n".join(results)


@mcp.tool()
def listsym(
    filter: Optional[str] = None,
    show_undefined: bool = False,
    show_data: bool = False,
    show_decompiled: bool = False,
) -> str:
    """
    Run tools/listsym to list symbols.

    Args:
        filter: Optional search string to filter symbol names.
        show_undefined: Pass -u (undefined / outgoing refs to unimplemented functions).
        show_data: Pass -d (include data symbols).
        show_decompiled: Pass -l (decompiled symbols that exist in the file list).
    """
    args = ["tools/listsym"]
    if show_undefined: args.append("-u")
    if show_data: args.append("-d")
    if show_decompiled: args.append("-l")
    if filter: args.append(filter)
    return _run(args, timeout=30)


@mcp.tool()
def build(clean: bool = False) -> str:
    """
    Run tools/build.py to compile the project.

    Args:
        clean: Pass --clean to do a clean build.
    """
    return _run(["tools/build.py"] + (["--clean"] if clean else []), timeout=300)


@mcp.tool()
def check_format() -> str:
    """
    Run tools/check-format.py to report formatting problems.
    Fix all reported issues before considering a class done.
    """
    return _run(["tools/check-format.py"], timeout=60)


if __name__ == "__main__":
    mcp.run()
