#!/usr/bin/env python3
"""Render Opengrep JSON results without printing matched source code lines.

Opengrep's default CLI text formatter prints matched lines (`extra.lines`) to
stdout. In CI on public or shared repositories, printing matched lines can leak
hardcoded secrets into persistent GitHub Actions build logs. This formatter
emits file locations, rule IDs, severities, and diagnostic messages only.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


def format_report(json_path: Path) -> tuple[list[str], int]:
  """Return formatted diagnostic lines and exit status (0=clean, 1=findings, 2=error)."""
  if not json_path.is_file():
    return ([f"ERROR: Opengrep JSON report missing at {json_path}"], 2)

  data = json.loads(json_path.read_text(encoding="utf-8"))
  lines: list[str] = []

  errors = data.get("errors", [])
  for err in errors:
    if isinstance(err, dict):
      level = str(err.get("level", "error")).upper()
      err_type = err.get("type", "OpengrepError")
      msg = str(err.get("message", "")).splitlines()[0] if err.get("message") else ""
      path = err.get("path", "<unknown>")
      lines.append(f"[ENGINE-{level}] {path} ({err_type}): {msg}")

  results = data.get("results", [])
  active_findings = 0
  for item in results:
    if not isinstance(item, dict):
      continue
    extra = item.get("extra", {})
    if not isinstance(extra, dict):
      extra = {}
    if extra.get("is_ignored") is True:
      continue
    active_findings += 1
    path = item.get("path", "<unknown>")
    start = item.get("start", {}) if isinstance(item.get("start"), dict) else {}
    line_no = start.get("line", 0)
    col_no = start.get("col", 0)
    severity = extra.get("severity", "ERROR")
    check_id = item.get("check_id", "unknown-rule")
    message = " ".join(str(extra.get("message", "")).split())
    lines.append(
        f"{path}:{line_no}:{col_no} [{severity}] {check_id}: {message}"
    )

  if active_findings > 0:
    lines.append(
        f"Opengrep summary: {active_findings} finding(s) reported "
        "(source snippets suppressed to prevent CI log secret exposure)."
    )
    return (lines, 1)

  fatal_errors = [
      e for e in errors
      if isinstance(e, dict) and str(e.get("level", "")).lower() == "error"
  ]
  if fatal_errors:
    return (lines, 2)

  lines.append("Opengrep summary: 0 findings.")
  return (lines, 0)


def main(argv: list[str] | None = None) -> int:
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument(
      "report",
      type=Path,
      help="Path to Opengrep JSON output file",
  )
  args = parser.parse_args(argv)
  try:
    output_lines, code = format_report(args.report)
  except (OSError, json.JSONDecodeError) as exc:
    print(f"ERROR: Failed to parse Opengrep report: {exc}", file=sys.stderr)
    return 2

  stream = sys.stderr if code == 2 else sys.stdout
  for line in output_lines:
    print(line, file=stream)
  return code


if __name__ == "__main__":
  sys.exit(main())
