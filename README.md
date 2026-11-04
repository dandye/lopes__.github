# .github

Shared GitHub Actions reusable security workflows, canonical `.gitleaks.toml` baseline, and default community health files for `github.com/lopes` repositories.

## What Lives Here

- **[`.github/workflows/security.yml`](.github/workflows/security.yml)** — Reusable workflow (`workflow_call`) executing three open-source deterministic checks across all repository paths (including `tests/`):
  1. **`gitleaks`** (`v8.30.1`, SHA-256 verified) — Scans both full git commit history (`fetch-depth: 0`) and the working tree with `--redact=100`. Uses the caller repository's `.gitleaks.toml` if present, or falls back to this repository's canonical [`.gitleaks.toml`](.gitleaks.toml).
  2. **`opengrep`** (`v1.33.1`, SHA-256 + Sigstore Cosign verified) — Multi-language static analysis (`python`, `bash`, `rust`, `go`, `typescript`, `javascript`, `dockerfile`, `terraform` including AWS/GCP/Azure, `yaml/github-actions`) at `ERROR` severity, pinned to an immutable `semgrep-rules` commit. Findings are rendered by [`scripts/format_opengrep_findings.py`](scripts/format_opengrep_findings.py) so matched source lines are never echoed into Actions logs.
  3. **`trivy`** (`v0.76.1`, SHA-256 verified standalone binary) — Filesystem dependency vulnerability (`CRITICAL,HIGH`, including unfixed CVEs unless `trivy_ignore_unfixed: true`) and IaC misconfiguration scan (Terraform, Ansible, Dockerfiles, GitHub Actions, and lockfiles).
- **[`.gitleaks.toml`](.gitleaks.toml)** — Canonical secret-scanning ruleset extending Gitleaks defaults with explicit URL query-parameter credential detection (`?key=`, `?api_key=`, `?token=`, `?access_token=`, `?license_key=`) and zero `tests/` exclusions.
- **[`SECURITY.md`](SECURITY.md)** — Account-wide default vulnerability disclosure policy inherited automatically by all public repositories under `github.com/lopes` unless overridden locally.

> [!IMPORTANT]
> **Why maintain an account-owned `.github` repository instead of calling a third-party workflow?**
> 1. **Supply-chain containment:** Referencing an external vendor's `uses: org/repo/.github/workflows/...@main` across every public and private repository delegates runner execution and `GITHUB_TOKEN` access to a mutable third-party branch. Owning `lopes/.github` keeps version pinning (`gitleaks`, `opengrep`, `trivy`, `actions/checkout`) under direct control while still pulling official upstream binaries and actions.
> 2. **Fast, focused execution (~25s vs. 5+ min):** Multi-linter suites (`super-linter`, `megalinter`) pull multi-gigabyte container images on every run and do not bundle `opengrep` or account-wide `.gitleaks.toml` inheritance.
> 3. **Single source of truth:** Updating a scanner version or adding a custom secret rule in `.gitleaks.toml` happens in one commit here rather than opening pull requests across every repository, and GitHub only inherits default community health files (`SECURITY.md`) from `<owner>/.github`.

## Supply-Chain & CI Security Model

1. **Deny-all default token scope:** Workflow-level `permissions: {}` with per-job `contents: read` only (no unused `security-events: write` scope).
2. **Ephemeral checkout credentials:** Every `actions/checkout` step is pinned to a 40-character commit SHA and sets `persist-credentials: false` so `GITHUB_TOKEN` is wiped from `.git/config` before any scanner executes.
3. **Cryptographic binary & rule verification:** Every downloaded scanner binary (`gitleaks`, `opengrep`, `trivy`) is pinned by exact version and verified via `sha256sum -c` (plus Sigstore `cosign verify-blob` on `opengrep`), and SAST rules are fetched by immutable 40-character commit SHA.
4. **Zero template injection:** No `${{ ... }}` expressions appear inside `run:` shell scripts; all inputs pass through `env:` variables with strict regex validation.
5. **Self-referential baseline resolution:** The baseline checkout resolves its repository and ref from `github.workflow_ref`, so callers pinned to a commit SHA also load `.gitleaks.toml` and helper scripts from that exact commit.

## Caller Usage

Pin the reusable workflow to a full 40-character commit SHA in `.github/workflows/security.yml`:

```yaml
---
name: Security

on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "17 4 * * 1"

permissions: {}

jobs:
  security:
    permissions:
      contents: read
    uses: lopes/.github/.github/workflows/security.yml@<40-char-commit-sha>
```
