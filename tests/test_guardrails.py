#!/usr/bin/env python3
"""End-to-end verification suite for the hardened security guardrails.

All secret-shaped test strings are synthesized dynamically in memory inside
temporary directories so zero literal secret fixtures exist in the repository.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
import re
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import format_opengrep_findings  # noqa: E402
import prepare_gitleaks_config  # noqa: E402

GITLEAKS_BIN: str | None = None


def _synth_token(seed: int, length: int = 32, alphabet: str | None = None) -> str:
  rng = random.Random(seed)
  chars = alphabet or "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
  return "".join(rng.choice(chars) for _ in range(length))


class PrepareGitleaksConfigTests(unittest.TestCase):

  def test_returns_baseline_when_no_caller_config(self) -> None:
    baseline = REPO_ROOT / ".gitleaks.toml"
    with tempfile.TemporaryDirectory() as td:
      out = Path(td) / "effective.toml"
      res = prepare_gitleaks_config.build_effective_config(baseline, None, out)
      self.assertEqual(res, baseline.resolve())
      self.assertFalse(out.exists())

  def test_returns_baseline_when_caller_is_identical_checkout(self) -> None:
    baseline = REPO_ROOT / ".gitleaks.toml"
    with tempfile.TemporaryDirectory() as td:
      cloned_baseline = Path(td) / "repo_checkout.toml"
      cloned_baseline.write_bytes(baseline.read_bytes())
      out = Path(td) / "effective.toml"
      res = prepare_gitleaks_config.build_effective_config(
          baseline, cloned_baseline, out
      )
      self.assertEqual(res, baseline.resolve())
      self.assertFalse(out.exists())

  def test_composes_valid_caller_config_onto_baseline(self) -> None:
    baseline = REPO_ROOT / ".gitleaks.toml"
    with tempfile.TemporaryDirectory() as td:
      caller = Path(td) / "caller.toml"
      caller.write_text(
          'title = "caller"\n\n[extend]\nuseDefault = true\n\n'
          '[allowlist]\ndescription = "historical rotated commit"\n'
          'commits = ["0123456789abcdef0123456789abcdef01234567"]\n',
          encoding="utf-8",
      )
      out = Path(td) / "effective.toml"
      res = prepare_gitleaks_config.build_effective_config(baseline, caller, out)
      self.assertEqual(res, out.resolve())
      composed = out.read_text(encoding="utf-8")
      self.assertIn(f'path = "{baseline.resolve()}"', composed)
      self.assertNotIn("useDefault = true", composed)
      self.assertIn("0123456789abcdef0123456789abcdef01234567", composed)

  def test_rejects_caller_excluding_tests_or_lockfiles(self) -> None:
    baseline = REPO_ROOT / ".gitleaks.toml"
    for header in ("[allowlist]", "[[allowlists]]"):
      for bad_path in [r"(^|/)tests/", r"uv\.lock$", r"fixtures/.*", r".*"]:
        with (
            self.subTest(header=header, bad_path=bad_path),
            tempfile.TemporaryDirectory() as td,
        ):
          caller = Path(td) / "caller.toml"
          caller.write_text(
              f"{header}\npaths = ['''{bad_path}''']\n",
              encoding="utf-8",
          )
          out = Path(td) / "effective.toml"
          with self.assertRaises(ValueError):
            prepare_gitleaks_config.build_effective_config(baseline, caller, out)

  def test_rejects_caller_disabling_or_redefining_protected_rules(self) -> None:
    baseline = REPO_ROOT / ".gitleaks.toml"
    with tempfile.TemporaryDirectory() as td:
      caller = Path(td) / "caller_disable.toml"
      caller.write_text(
          '[extend]\nuseDefault = true\n'
          'disableRules = ["url-query-or-fragment-secret"]\n',
          encoding="utf-8",
      )
      out = Path(td) / "effective.toml"
      with self.assertRaises(ValueError):
        prepare_gitleaks_config.build_effective_config(baseline, caller, out)

      caller_redef = Path(td) / "caller_redef.toml"
      caller_redef.write_text(
          '[[rules]]\nid = "url-query-or-fragment-secret"\n'
          'description = "weakened"\nregex = "NEVER_MATCHES"\n',
          encoding="utf-8",
      )
      with self.assertRaises(ValueError):
        prepare_gitleaks_config.build_effective_config(
            baseline, caller_redef, out
        )


class FormatOpengrepFindingsTests(unittest.TestCase):

  def test_suppresses_raw_source_lines_on_findings(self) -> None:
    canary_secret = _synth_token(9001, 36)
    payload = {
        "results": [{
            "check_id": "python.lang.security.audit.eval-detected",
            "path": "app/handler.py",
            "start": {"line": 42, "col": 5},
            "end": {"line": 42, "col": 55},
            "extra": {
                "severity": "ERROR",
                "message": "Detected dynamic eval() execution.",
                "lines": f'eval("{canary_secret}")',
                "is_ignored": False,
            },
        }],
        "errors": [],
    }
    with tempfile.TemporaryDirectory() as td:
      rep = Path(td) / "og.json"
      rep.write_text(json.dumps(payload), encoding="utf-8")
      lines, code = format_opengrep_findings.format_report(rep)
      rendered = "\n".join(lines)
      self.assertEqual(code, 1)
      self.assertIn("app/handler.py:42:5 [ERROR]", rendered)
      self.assertNotIn(canary_secret, rendered)

  def test_ignores_nosemgrep_suppressed_entries(self) -> None:
    payload = {
        "results": [{
            "check_id": "rule.id",
            "path": "a.py",
            "start": {"line": 1, "col": 1},
            "extra": {
                "severity": "ERROR",
                "message": "suppressed",
                "lines": "SENSITIVE_VALUE",
                "is_ignored": True,
            },
        }],
        "errors": [],
    }
    with tempfile.TemporaryDirectory() as td:
      rep = Path(td) / "og.json"
      rep.write_text(json.dumps(payload), encoding="utf-8")
      lines, code = format_opengrep_findings.format_report(rep)
      self.assertEqual(code, 0)
      self.assertIn("0 findings", "\n".join(lines))


class WorkflowStaticSecurityAuditTests(unittest.TestCase):

  def test_workflow_enforces_sha_pinning_least_privilege_and_no_injection(self) -> None:
    wf_path = REPO_ROOT / ".github" / "workflows" / "security.yml"
    text = wf_path.read_text(encoding="utf-8")

    # 1. Top-level deny-all permissions and no security-events: write
    self.assertRegex(text, r"(?m)^permissions:\s*\{\}\s*$")
    self.assertNotIn("security-events: write", text)

    # 2. Every uses: directive must be pinned to a full 40-char lowercase hex SHA
    uses_matches = re.findall(r"(?m)^\s*-?\s*uses:\s*([^\s#]+)", text)
    self.assertGreaterEqual(len(uses_matches), 4)
    for target in uses_matches:
      self.assertRegex(
          target,
          r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$",
          f"Unpinned GitHub Action reference: {target}",
      )

    # 3. Every actions/checkout step must set persist-credentials: false
    checkout_count = sum(1 for u in uses_matches if u.startswith("actions/checkout@"))
    persist_false_count = len(
        re.findall(r"(?m)^\s*persist-credentials:\s*false\s*$", text)
    )
    self.assertEqual(checkout_count, persist_false_count)

    # 4. Zero unpinned 'releases/latest' downloads and zero third-party trivy-action
    self.assertNotIn("releases/latest", text)
    self.assertNotIn("aquasecurity/trivy-action", text)
    self.assertNotIn("generic/secrets", text)

    # 5. Zero ${{ ... }} expressions inside run: | blocks (prevents template injection)
    lines = text.splitlines()
    in_run_block = False
    run_indent = 0
    for idx, line in enumerate(lines, start=1):
      stripped = line.lstrip()
      indent = len(line) - len(stripped)
      if in_run_block:
        if stripped and indent <= run_indent:
          in_run_block = False
        else:
          self.assertNotIn(
              "${{",
              line,
              f"Template expression inside run: block at security.yml:{idx}",
          )
      if re.match(r"^run:\s*\|", stripped):
        in_run_block = True
        run_indent = indent

    # 6. The baseline repository must never be hard-coded; it is resolved from
    #    github.workflow_ref so forks and SHA-pinned callers load the right ref.
    self.assertNotRegex(text, r"(?m)^\s*repository:\s*[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\s*$")
    self.assertIn("steps.baseline_meta.outputs.repository", text)
    self.assertIn("steps.baseline_meta.outputs.ref", text)


class GitleaksIntegrationTests(unittest.TestCase):

  def _scan_dir(self, target_dir: Path, config_path: Path) -> list[dict[str, object]]:
    assert GITLEAKS_BIN is not None
    gitleaks_exe = str(Path(GITLEAKS_BIN).resolve(strict=True))
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
      rep_path = Path(tf.name)
    try:
      # nosemgrep: dangerous-subprocess-use-audit
      subprocess.run(
          [
              gitleaks_exe,
              "dir",
              str(target_dir),
              "--config",
              str(config_path),
              "--redact=100",
              "--no-banner",
              "--report-format",
              "json",
              "--report-path",
              str(rep_path),
          ],
          check=False,
          capture_output=True,
          text=True,
      )
      content = rep_path.read_text(encoding="utf-8").strip()
      return json.loads(content) if content else []
    finally:
      rep_path.unlink(missing_ok=True)

  def test_detects_all_secret_vectors_and_allows_safe_fixtures(self) -> None:
    if not GITLEAKS_BIN:
      self.skipTest("--gitleaks-bin not supplied")

    baseline = REPO_ROOT / ".gitleaks.toml"
    tok_query = _synth_token(101, 32)
    tok_pct = _synth_token(102, 12) + "%2B" + _synth_token(103, 12) + "%3D"
    tok_frag = "ya29." + _synth_token(104, 34)
    tok_test_prefix = "test-only-" + _synth_token(105, 28).lower()
    tok_basic = _synth_token(106, 24)
    tok_soar = _synth_token(107, 36)
    corp_host = "git-mirror." + "corp" + ".example-ent.org"

    with tempfile.TemporaryDirectory() as td:
      root = Path(td)
      # Positive cases (including inside tests/ and uv.lock!)
      (root / "tests").mkdir()
      (root / "tests" / "test_leak.py").write_text(
          f'u1 = "https://api.example.com/v1?key={tok_query}"\n'
          f'u2 = "https://api.example.com/v1?api_key={tok_pct}"\n'
          f'u3 = "https://app.example.com/cb#access_token={tok_frag}"\n'
          f'u4 = "https://api.example.com/v1?key={tok_test_prefix}"\n'
          f'h1 = {{"AppKey": "{tok_soar}"}}\n',
          encoding="utf-8",
      )
      (root / "uv.lock").write_text(
          f'[[package]]\nname = "pkg"\nsource = {{ registry = "https://ci-bot:{tok_basic}@pypi.pkg.dev/simple" }}\n'
          f'mirror = "https://{corp_host}/simple"\n',
          encoding="utf-8",
      )

      findings = self._scan_dir(root, baseline)
      rule_ids = [str(f["RuleID"]) for f in findings]
      self.assertGreaterEqual(
          rule_ids.count("url-query-or-fragment-secret"),
          4,
          f"Expected >=4 URL secret hits (query, %-encoded, #fragment, test-only- prefix), got: {rule_ids}",
      )
      self.assertIn("unprefixed-header-api-key", rule_ids)
      self.assertIn("authenticated-url-credentials", rule_ids)
      self.assertIn("internal-corporate-hostname", rule_ids)
      for f in findings:
        self.assertEqual(f["Secret"], "REDACTED")

    # Negative (safe synthetic fixtures) must produce 0 findings. The
    # placeholders are assembled at runtime so no "key=<placeholder>" literal
    # exists in tracked source for any config revision to trip over.
    shodan_ph = "SYNTHETIC_TEST_" + "SHODAN_000001"
    soar_ph = "SYNTHETIC_TEST_" + "SOAR_KEY_000001"
    with tempfile.TemporaryDirectory() as td_safe:
      safe = Path(td_safe)
      (safe / "test_safe.py").write_text(
          f'u1 = "https://api.example.com/v1?key={shodan_ph}"\n'
          'u2 = "https://api.example.com/v1?key=REDACTED"\n'
          'u3 = "https://user:REDACTED@example.com/simple"\n'
          f'h1 = {{"AppKey": "{soar_ph}"}}\n'
          'd1 = "http://host.docker.internal:8080/healthz"\n',
          encoding="utf-8",
      )
      safe_findings = self._scan_dir(safe, baseline)
      self.assertEqual(safe_findings, [])

      # Verify a composed caller config (with commit allowlist) preserves both
      # baseline SYNTHETIC_TEST_* allowlists AND real secret detection.
      caller_cfg = safe / "caller.toml"
      caller_cfg.write_text(
          'title = "caller"\n[allowlist]\n'
          'commits = ["0123456789abcdef0123456789abcdef01234567"]\n',
          encoding="utf-8",
      )
      effective_cfg = prepare_gitleaks_config.build_effective_config(
          baseline, caller_cfg, safe / "effective.toml"
      )
      self.assertEqual(self._scan_dir(safe / "test_safe.py", effective_cfg), [])
      leak_probe = safe / "probe"
      leak_probe.mkdir()
      (leak_probe / "leak.py").write_text(
          f'u1 = "https://api.example.com/v1?key={tok_query}"\n',
          encoding="utf-8",
      )
      composed_hits = self._scan_dir(leak_probe, effective_cfg)
      self.assertEqual(len(composed_hits), 1)
      self.assertEqual(composed_hits[0]["RuleID"], "url-query-or-fragment-secret")

  def test_repository_itself_is_completely_clean(self) -> None:
    if not GITLEAKS_BIN:
      self.skipTest("--gitleaks-bin not supplied")
    # Scan exactly what git would commit (tracked + untracked, minus ignored
    # artifacts such as __pycache__), copied into a temp dir so stale local
    # build output cannot mask or fake a result.
    listed = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files", "--cached", "--others",
         "--exclude-standard", "-z"],
        check=True,
        capture_output=True,
    ).stdout.split(b"\0")
    rel_paths = [p.decode("utf-8") for p in listed if p]
    self.assertIn(".gitleaks.toml", rel_paths)
    with tempfile.TemporaryDirectory() as td:
      snapshot = Path(td)
      for rel in rel_paths:
        src = REPO_ROOT / rel
        if not src.is_file():
          continue
        dst = snapshot / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(src.read_bytes())
      findings = self._scan_dir(snapshot, snapshot / ".gitleaks.toml")
    self.assertEqual(findings, [], f"Self-scan flagged findings: {findings}")


def main() -> int:
  global GITLEAKS_BIN
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument(
      "--gitleaks-bin",
      default=None,
      help="Path to gitleaks binary for live rule integration tests",
  )
  args, remaining = parser.parse_known_args()
  GITLEAKS_BIN = args.gitleaks_bin
  suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
  runner = unittest.TextTestRunner(verbosity=2)
  result = runner.run(suite)
  return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
  sys.exit(main())
