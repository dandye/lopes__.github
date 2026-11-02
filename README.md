# .github

Shared GitHub Actions reusable security workflows, canonical `.gitleaks.toml` baseline, and default community health files for `github.com/lopes` repositories.

## What Lives Here

- **[`.github/workflows/security.yml`](.github/workflows/security.yml)** — Reusable workflow (`workflow_call`) executing three open-source deterministic checks across all repository paths (including `tests/`):
  1. **`gitleaks`** (`v8.30.1`) — Full git commit-history secret scan (`fetch-depth: 0`, `--redact`). Uses the caller repository's `.gitleaks.toml` if present, or falls back to this repository's canonical [`.gitleaks.toml`](.gitleaks.toml).
  2. **`opengrep`** — Open-source multi-language static analysis (`python`, `bash`, `rust`, `terraform`, `yaml/github-actions`, `generic/secrets`) at `ERROR` severity.
  3. **`trivy`** (`aquasecurity/trivy-action`) — Filesystem dependency vulnerability (`CRITICAL,HIGH` with available fixes) and IaC misconfiguration scan (Terraform, Ansible, Dockerfiles, GitHub Actions, and lockfiles).
- **[`.gitleaks.toml`](.gitleaks.toml)** — Canonical secret-scanning ruleset extending Gitleaks defaults with explicit URL query-parameter credential detection (`?key=`, `?api_key=`, `?token=`, `?access_token=`, `?license_key=`) and zero `tests/` exclusions.
- **[`SECURITY.md`](SECURITY.md)** — Account-wide default vulnerability disclosure policy inherited automatically by all public repositories under `github.com/lopes` unless overridden locally.

> [!IMPORTANT]
> **Why maintain an account-owned `.github` repository instead of calling a third-party workflow?**
> 1. **Supply-chain containment:** Referencing an external vendor's `uses: org/repo/.github/workflows/...@main` across every public and private repository delegates runner execution and `GITHUB_TOKEN` access to a mutable third-party branch. Owning `lopes/.github` keeps version pinning (`gitleaks`, `opengrep`, `trivy-action`, `actions/checkout`) under direct control while still pulling official upstream binaries and actions.
> 2. **Fast, focused execution (~25s vs. 5+ min):** Multi-linter suites (`super-linter`, `megalinter`) pull multi-gigabyte container images on every run and do not bundle `opengrep` or account-wide `.gitleaks.toml` inheritance.
> 3. **Single source of truth:** Updating a scanner version or adding a custom secret rule in `.gitleaks.toml` happens in one commit here rather than opening pull requests across every repository, and GitHub only inherits default community health files (`SECURITY.md`) from `<owner>/.github`.

## Caller Usage

Add `.github/workflows/security.yml` to any repository:

```yaml
---
name: Security

on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "17 4 * * 1"

permissions:
  contents: read
  security-events: write

jobs:
  security:
    uses: lopes/.github/.github/workflows/security.yml@main
```
