#!/usr/bin/env python3
"""Compose a caller repository's .gitleaks.toml on top of the canonical baseline.

Guarantees two invariants:
1. A repository-local `.gitleaks.toml` NEVER silently replaces or disables the
   canonical baseline rules (`url-query-or-fragment-secret`, etc.). Instead, its
   `[extend]` header is rewritten to inherit directly from the canonical baseline
   (which in turn sets `useDefault = true` to inherit Gitleaks built-in rules).
2. Repository-local configs are rejected (fail-closed) if they attempt to weaken
   core invariants: excluding `tests/`/`fixtures/`/lockfile paths or disabling
   canonical rule IDs via `disableRules`.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys
import tomllib

FORBIDDEN_PATH_PATTERNS = re.compile(
    r"(?i)(?:tests?|specs?|fixtures?|uv\\?\.lock|poetry\\?\.lock|package-lock\\?\.json|pnpm-lock\\?\.yaml|Cargo\\?\.lock)"
)
PROTECTED_RULE_IDS = frozenset({
    "url-query-or-fragment-secret",
    "authenticated-url-credentials",
    "unprefixed-header-api-key",
    "internal-corporate-hostname",
})
EXTEND_SECTION_RE = re.compile(
    r"(?ms)^\[extend\]\s*\n(?:(?!\[)[^\n]*\n?)*"
)


def validate_caller_config(data: dict[str, object], caller_path: Path) -> None:
  """Fail closed if a caller config weakens baseline security invariants."""
  extend = data.get("extend")
  if isinstance(extend, dict):
    disabled = extend.get("disableRules", [])
    if isinstance(disabled, list):
      overlap = PROTECTED_RULE_IDS.intersection(str(r) for r in disabled)
      if overlap:
        raise ValueError(
            f"{caller_path}: extend.disableRules cannot disable protected "
            f"baseline rules: {sorted(overlap)}"
        )

  rules = data.get("rules")
  if isinstance(rules, list):
    for rule in rules:
      if isinstance(rule, dict):
        rule_id = str(rule.get("id", ""))
        if rule_id in PROTECTED_RULE_IDS:
          raise ValueError(
              f"{caller_path}: caller [[rules]] cannot redefine protected "
              f"baseline rule {rule_id!r}"
          )

  allowlists: list[dict[str, object]] = []
  for key in ("allowlist", "allowlists"):
    top_allow = data.get(key)
    if isinstance(top_allow, dict):
      allowlists.append(top_allow)
    elif isinstance(top_allow, list):
      allowlists.extend(a for a in top_allow if isinstance(a, dict))

  for entry in allowlists:
    paths = entry.get("paths", [])
    if isinstance(paths, list):
      for pat in paths:
        pat_str = str(pat)
        if FORBIDDEN_PATH_PATTERNS.search(pat_str) or pat_str.strip() in {
            ".*",
            ".+",
            "^.*$",
        }:
          raise ValueError(
              f"{caller_path}: global path exclusion {pat!r} is prohibited "
              "(tests, fixtures, and lockfiles must remain scanned; allowlist "
              "specific rotated commit SHAs or secret fingerprints instead)."
          )


def build_effective_config(
    baseline_path: Path, caller_path: Path | None, output_path: Path
) -> Path:
  """Return path to the effective Gitleaks TOML config."""
  baseline_abs = baseline_path.resolve()
  if not baseline_abs.is_file():
    raise FileNotFoundError(f"Baseline config not found: {baseline_abs}")

  # Validate baseline TOML syntax up front.
  with baseline_abs.open("rb") as f:
    tomllib.load(f)

  if caller_path is None or not caller_path.is_file():
    return baseline_abs

  caller_abs = caller_path.resolve()
  if caller_abs == baseline_abs:
    return baseline_abs

  raw_text = caller_abs.read_text(encoding="utf-8")
  caller_data = tomllib.loads(raw_text)
  validate_caller_config(caller_data, caller_abs)

  # Strip any existing [extend] block from caller and chain onto baseline_abs.
  stripped = EXTEND_SECTION_RE.sub("", raw_text)
  escaped_baseline = str(baseline_abs).replace("\\", "\\\\").replace('"', '\\"')
  composed = (
      f'# Auto-composed effective Gitleaks configuration\n'
      f'[extend]\npath = "{escaped_baseline}"\n\n'
      f"{stripped.lstrip()}"
  )

  # Verify the composed file parses cleanly as valid TOML before returning.
  tomllib.loads(composed)
  output_path.parent.mkdir(parents=True, exist_ok=True)
  output_path.write_text(composed, encoding="utf-8")
  return output_path.resolve()


def main(argv: list[str] | None = None) -> int:
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument(
      "--baseline",
      required=True,
      type=Path,
      help="Path to canonical baseline .gitleaks.toml",
  )
  parser.add_argument(
      "--caller",
      default=None,
      type=Path,
      help="Optional path to caller repository .gitleaks.toml",
  )
  parser.add_argument(
      "--output",
      required=True,
      type=Path,
      help="Where to write composed .gitleaks.toml when caller config exists",
  )
  args = parser.parse_args(argv)

  try:
    effective = build_effective_config(args.baseline, args.caller, args.output)
  except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
    print(f"ERROR: {exc}", file=sys.stderr)
    return 2

  print(effective)
  return 0


if __name__ == "__main__":
  sys.exit(main())
