# lopes__.github (Hardened Security Guardrails)

Hardened reusable GitHub Actions security workflow, canonical [`.gitleaks.toml`](.gitleaks.toml) secret-scanning baseline, and offline local fleet scanner for `github.com/dandye` repositories.

Adapted from upstream [`lopes/.github`](https://github.com/lopes/.github) with supply-chain, log-redaction, and configuration-inheritance hardening.

## What Lives Here

- **[`.github/workflows/security.yml`](.github/workflows/security.yml)** — Reusable workflow (`workflow_call`) executing three deterministic checks across all repository paths (including `tests/` and lockfiles):
  1. **`gitleaks`** (`v8.30.1`, SHA-256 verified) — Scans both full Git commit history (`fetch-depth: 0`) and working-tree files with `--redact=100`. Composes any caller `.gitleaks.toml` **on top of** [`.gitleaks.toml`](.gitleaks.toml) via [`scripts/prepare_gitleaks_config.py`](scripts/prepare_gitleaks_config.py) so caller allowlists never drop baseline rules and cannot exclude `tests/` or lockfiles.
  2. **`opengrep`** (`v1.33.1`, SHA-256 + Sigstore Cosign verified) — Multi-language AST static analysis (`python`, `bash`, `rust`, `go`, `typescript`, `javascript`, `dockerfile`, `terraform` including AWS/GCP/Azure, and `yaml/github-actions`) pinned to an immutable `semgrep-rules` commit SHA. Renders findings via [`scripts/format_opengrep_findings.py`](scripts/format_opengrep_findings.py) so matched source lines are never echoed into GitHub Actions logs.
  3. **`trivy`** (`v0.76.1`, SHA-256 verified) — Direct standalone binary vulnerability and IaC misconfiguration scan (eliminating third-party composite action tag chains), failing on `CRITICAL,HIGH` findings (including unfixed 0-day CVEs by default).
- **[`.gitleaks.toml`](.gitleaks.toml)** — Canonical secret-scanning ruleset extending Gitleaks defaults with:
  - `url-query-or-fragment-secret`: URL query (`?key=`, `&token=`, `&sig=`) and OAuth fragment (`#access_token=`, `#id_token=`) credentials, including URL percent-encoded (`%2B`, `%2F`, `%3D`) and Base64 (`+`, `/`, `=`) characters.
  - `authenticated-url-credentials`: Basic-auth or token credentials embedded in HTTP/Git/SSH URLs or lockfiles (`uv.lock`, `poetry.lock`, `.npmrc`).
  - `unprefixed-header-api-key`: High-entropy unprefixed keys assigned to `AppKey`, `X-Api-Key`, `shodan_api_key`, or `soar_api_key`.
  - `internal-corporate-hostname`: Non-public `.corp.*`, `.internal`, and `.localdomain` hostnames.
- **[`scripts/scan_secrets.sh`](scripts/scan_secrets.sh)** — Offline local secret scanner that bootstraps a SHA-256-verified `gitleaks` binary into `~/.cache/security-guardrails/` and scans either a single repository or an entire directory fleet (`--fleet`) with `--redact=100`.
- **[`tests/test_guardrails.py`](tests/test_guardrails.py)** — Self-test suite verifying secret detection rules, allowlist boundaries, 2-level config composition, CI log redaction, and workflow supply-chain invariants.

## Supply-Chain & CI Security Model

1. **Deny-all default token scope:** Workflow-level `permissions: {}` with per-job `contents: read` only (no unused `security-events: write` scope).
2. **Ephemeral checkout credentials:** Every `actions/checkout` step is pinned to a 40-character commit SHA and sets `persist-credentials: false` so `GITHUB_TOKEN` is wiped from `.git/config` before any scanner executes.
3. **Cryptographic binary & rule verification:** Every downloaded scanner binary (`gitleaks`, `opengrep`, `trivy`) is pinned by exact version and verified via `sha256sum -c` (plus Sigstore `cosign verify-blob` on `opengrep`), and SAST rules are fetched by immutable 40-character commit SHA.
4. **Zero template injection:** No `${{ ... }}` expressions appear inside `run:` shell scripts; all inputs pass through `env:` variables with strict regex validation.
5. **Self-referential baseline resolution:** The baseline checkout dynamically resolves its repository and ref from `github.workflow_ref`, ensuring callers pinned to a commit SHA also load `.gitleaks.toml` from that exact commit.

## Local Secret Scanning Usage

Scan a single repository or worktree (both full Git history and untracked/unstaged working-tree files):

```bash
TARGET_REPO="$HOME/Projects/my_project__worktrees/main"
./scripts/scan_secrets.sh "$TARGET_REPO"
```

Scan an entire directory of repositories and linked worktrees offline:

```bash
PROJECTS_DIR="$HOME/Projects"
./scripts/scan_secrets.sh --fleet "$PROJECTS_DIR"
```

Optional workstation-local rules (kept outside public repositories) can be placed in `${XDG_CONFIG_HOME:-$HOME/.config}/security-guardrails/local.toml` and are automatically layered onto `.gitleaks.toml`.

## Caller Workflow Usage

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
    uses: dandye/lopes__.github/.github/workflows/security.yml@<40-char-commit-sha>
```

## Running the Self-Test Suite

```bash
GITLEAKS_BIN="$HOME/.cache/security-guardrails/gitleaks-8.30.1/gitleaks"
python3 tests/test_guardrails.py --gitleaks-bin "$GITLEAKS_BIN"
```
