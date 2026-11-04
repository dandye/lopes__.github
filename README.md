# .github

Shared GitHub Actions reusable security workflows, canonical `.gitleaks.toml` baseline, and default community health files for `github.com/lopes` repositories.

## What Lives Here

- **[`.github/workflows/security.yml`](.github/workflows/security.yml)** — Reusable workflow (`workflow_call`) executing three open-source deterministic checks across all repository paths (including `tests/`):
  1. **`gitleaks`** (`v8.30.1`, SHA-256 verified) — Scans both full git commit history (`fetch-depth: 0`) and the working tree with `--redact=100`. Composes any caller `.gitleaks.toml` on top of this repository's canonical [`.gitleaks.toml`](.gitleaks.toml) via [`scripts/prepare_gitleaks_config.py`](scripts/prepare_gitleaks_config.py) so caller allowlists never drop baseline rules and cannot exclude `tests/` or lockfiles.
  2. **`opengrep`** (`v1.33.1`, SHA-256 + Sigstore Cosign verified) — Multi-language static analysis (`python`, `bash`, `rust`, `go`, `typescript`, `javascript`, `dockerfile`, `terraform` including AWS/GCP/Azure, `yaml/github-actions`) at `ERROR` severity, pinned to an immutable `semgrep-rules` commit. Findings are rendered by [`scripts/format_opengrep_findings.py`](scripts/format_opengrep_findings.py) so matched source lines are never echoed into Actions logs.
  3. **`trivy`** (`v0.76.1`, SHA-256 verified standalone binary) — Filesystem dependency vulnerability (`CRITICAL,HIGH`, including unfixed CVEs unless `trivy_ignore_unfixed: true`) and IaC misconfiguration scan (Terraform, Ansible, Dockerfiles, GitHub Actions, and lockfiles).
- **[`.gitleaks.toml`](.gitleaks.toml)** — Canonical secret-scanning ruleset extending Gitleaks defaults with zero `tests/` or lockfile exclusions and these rules:
  - `url-query-or-fragment-secret`: URL query (`?key=`, `&token=`, `&sig=`) and OAuth fragment (`#access_token=`, `#id_token=`) credentials, including percent-encoded (`%2B`, `%2F`, `%3D`) and Base64 (`+`, `/`, `=`) characters.
  - `authenticated-url-credentials`: Basic-auth or token credentials embedded in HTTP/Git/SSH URLs or lockfiles (`uv.lock`, `poetry.lock`, `.npmrc`).
  - `unprefixed-header-api-key`: High-entropy unprefixed keys assigned to `AppKey`, `X-Api-Key`, `shodan_api_key`, or `soar_api_key`.
  - `internal-corporate-hostname`: Non-public `.corp.*`, `.internal`, and `.localdomain` hostnames.
- **[`scripts/prepare_gitleaks_config.py`](scripts/prepare_gitleaks_config.py)** — Composes a caller repository's `.gitleaks.toml` on top of this baseline via `[extend]` and rejects configs that disable baseline rules or exclude `tests/` or lockfiles.
- **[`scripts/scan_secrets.sh`](scripts/scan_secrets.sh)** — Offline local secret scanner that bootstraps a SHA-256-verified `gitleaks` binary into `~/.cache/security-guardrails/` and scans either a single repository or an entire directory fleet (`--fleet`) with `--redact=100`.
- **[`tests/test_guardrails.py`](tests/test_guardrails.py)** — Self-test suite verifying secret detection rules, allowlist boundaries, two-level config composition, CI log redaction, and workflow supply-chain invariants.
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

## Local Secret Scanning Usage

Scan a single repository or worktree (full git history plus untracked and unstaged working-tree files):

```bash
TARGET_REPO="$HOME/Projects/my_project"
./scripts/scan_secrets.sh "$TARGET_REPO"
```

Scan an entire directory of repositories and linked worktrees offline:

```bash
PROJECTS_DIR="$HOME/Projects"
./scripts/scan_secrets.sh --fleet "$PROJECTS_DIR"
```

Optional workstation-local rules (kept outside public repositories) can be placed in `${XDG_CONFIG_HOME:-$HOME/.config}/security-guardrails/local.toml` and are layered onto `.gitleaks.toml` automatically.

## Running the Self-Test Suite

```bash
GITLEAKS_BIN="$HOME/.cache/security-guardrails/gitleaks-8.30.1/gitleaks"
python3 tests/test_guardrails.py --gitleaks-bin "$GITLEAKS_BIN"
```
