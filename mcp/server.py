#!/usr/bin/env python3

import re
import subprocess
import sys
from pathlib import Path
from typing import Optional
import time
from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
assert (PROJECT_ROOT / "tools" / "config.toml").exists(), f"config.toml not found; PROJECT_ROOT={PROJECT_ROOT}"

_ANSI_ESCAPE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

_AUTONOMY_CACHE = {
    "mtime": None,
    "text": ""
}

def _read_autonomy_message() -> str:
    path = Path.home() / "autonomy_message.txt"

    if not path.exists():
        return ""

    stat = path.stat()

    if _AUTONOMY_CACHE["mtime"] != stat.st_mtime:
        _AUTONOMY_CACHE["mtime"] = stat.st_mtime
        _AUTONOMY_CACHE["text"] = path.read_text()

    return _AUTONOMY_CACHE["text"]

def _build_autonomy_block() -> str:
    text = _read_autonomy_message().strip()
    if not text:
        return ""

    ts = datetime.now(timezone.utc).isoformat()

    return (
        "=== AUTONOMY MESSAGE BEGIN ===\n"
        "source: ~/autonomy_message.txt\n"
        f"timestamp: {ts}\n\n"
        f"{text}\n\n"
        "=== AUTONOMY MESSAGE END ===\n\n"
    )

def _run(args: list[str], timeout: int) -> str:
    print(f"[nx-decomp-tools] {' '.join(args)}", file=sys.stderr, flush=True)

    result = subprocess.run(
        args,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
    )

    tool_output = _ANSI_ESCAPE.sub("", result.stdout + result.stderr)

    autonomy_block = _build_autonomy_block()

    final_output = (
        f"{autonomy_block}"
        "=== TOOL OUTPUT BEGIN ===\n"
        f"{tool_output}\n"
        "=== TOOL OUTPUT END ===\n"
    )

    print(
        f"[nx-decomp-tools] exit {result.returncode}, {len(final_output)} chars",
        file=sys.stderr,
        flush=True,
    )

    return final_output

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
def check_status(
    function: Optional[str] = None,
    functions: Optional[list[str]] = None,
) -> str:
    """
    Check match status for one or more functions without showing the full diff.
    Returns OK/mismatch status plus diff statistics (matching lines, changed lines,
    added/deleted lines) so you can gauge how close a function is without the noise.

    Args:
        function: Single mangled or demangled symbol name to check.
        functions: List of symbol names to check (results combined).
    """
    targets: list[str] = list(functions) if functions else ([function] if function else [])
    if not targets:
        return "check_status requires at least one function name"

    # Markers used by asm-differ's plain format:
    #   (space) = matching
    #   s       = same opcode, different immediate/offset
    #   |       = different instruction
    #   r       = register-renamed
    #   <       = target-only (deleted from current)
    #   >       = current-only (added in current)
    _DIFF_LINE = re.compile(
        r"^[0-9a-f]+:\s+\S.*?([ s|r<>])\s+(?:[0-9a-f]+:\s+\S.*)?$"
    )

    results = []
    for target in targets:
        raw = _run(
            ["tools/check", "--no-pager", "--format=plain", "--always-diff", target],
            timeout=60,
        )

        if "mismatch" in raw and "OK" not in raw.split("mismatch")[0].split("\n")[-1]:
            verdict = "mismatch"
            m = re.search(r"mismatch at [0-9a-fx]+: (.+)", raw)
            reason = m.group(1).strip() if m else "unknown"
        else:
            verdict = "OK"
            reason = ""

        counts: dict[str, int] = {"match": 0, "s": 0, "|": 0, "r": 0, "<": 0, ">": 0}
        for line in raw.splitlines():
            m = _DIFF_LINE.match(line)
            if m:
                marker = m.group(1)
                if marker == " ":
                    counts["match"] += 1
                elif marker in counts:
                    counts[marker] += 1

        total = sum(counts.values())
        changed = counts["s"] + counts["|"] + counts["r"] + counts["<"] + counts[">"]
        effectively_matching = counts["match"] + counts["r"]

        if verdict == "OK":
            summary = f"{target}: OK ({effectively_matching} instructions, {counts['r']} regswap)"
        else:
            pct = int(100 * effectively_matching / total) if total > 0 else 0
            parts = []
            if counts["|"]: parts.append(f'{counts["|"]} changed')
            if counts["s"]: parts.append(f'{counts["s"]} imm/offset')
            if counts["r"]: parts.append(f'{counts["r"]} regswap')
            if counts["<"]: parts.append(f'{counts["<"]} deleted')
            if counts[">"]: parts.append(f'{counts[">"]} added')
            detail = ", ".join(parts) if parts else "no diff lines captured"
            summary = (
                f"{target}: mismatch ({reason})\n"
                f"  {effectively_matching}/{total} lines match ({pct}%), {changed} differ: {detail}"
            )

        results.append(summary)

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
def clangd_check(file: str) -> str:
    """
    Run clangd --check on a source file to get compiler diagnostics without a full build.
    Much faster than build() for catching type errors, missing includes, and syntax mistakes
    during first-pass implementation. Requires compile_commands.json to exist (from a prior build).

    Args:
        file: Path to the .cpp or .h file to check, relative to the project root.
    """
    _LOG_PREFIX = re.compile(r"^[IWE]\[\d{2}:\d{2}:\d{2}\.\d{3}\] ")
    _DIAG_LINE = re.compile(r"^E\[\d{2}:\d{2}:\d{2}\.\d{3}\] (?!.*tweak:)(?!.*==> )")
    _SUMMARY = re.compile(r"^I\[\d{2}:\d{2}:\d{2}\.\d{3}\] All checks completed")

    args = [
        "clangd",
        f"--check={file}",
        "--compile-commands-dir=build",
    ]
    print(f"[nx-decomp-tools] {' '.join(args)}", file=sys.stderr, flush=True)
    result = subprocess.run(
        args, cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=120
    )
    raw = _ANSI_ESCAPE.sub("", result.stderr)

    diags = []
    summary = None
    for line in raw.splitlines():
        if _DIAG_LINE.match(line):
            diags.append(_LOG_PREFIX.sub("", line))
        elif _SUMMARY.match(line):
            summary = _LOG_PREFIX.sub("", line)

    if summary is None:
        return f"clangd: no output (exit {result.returncode})"

    summary = re.sub(r"\d+ errors?", f"{len(diags)} error{'s' if len(diags) != 1 else ''}", summary)
    return "\n".join(diags + [summary])


@mcp.tool()
def check_format() -> str:
    """
    Run tools/check-format.py to report formatting problems.
    Fix all reported issues before considering a class done.
    """
    return _run(["tools/check-format.py"], timeout=60)


if __name__ == "__main__":
    mcp.run()
