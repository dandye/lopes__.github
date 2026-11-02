# .github

Central security guardrails and reusable GitHub Actions workflows shared across `github.com/lopes` repositories.

## Defense-in-Depth Architecture (`L0 -> L1 -> L2 -> L3`)

| Layer | Type | Enforcement Point | Controls |
| --- | --- | --- | --- |
| **L0** | Probabilistic | AI Agent Constitution (`AGENTS.md`) | Vendor-agnostic rules enforcing RFC 5737/2606 synthetic fixtures (`SYNTHETIC_TEST_*`), zero verbatim log copy-paste into `tests/`, zero raw secret reads into context, and pre-commit diff review. |
| **L1** | Deterministic | Workstation Git Hooks (`core.hooksPath`) | Global `pre-commit` and `pre-push` hooks running `gitleaks` (`--redact`) across all repositories and directories (including `tests/`) before commits or pushes occur, chaining any repo-local `.git/hooks/*`. |
| **L2** | Deterministic | Central CI Workflow (`security.yml`) | Reusable GitHub Actions workflow running `gitleaks` (full git history + working tree), `opengrep` (open-source multi-language SAST), and `trivy` (IaC misconfigurations + dependency vulnerabilities) with zero `tests/` exclusions. |
| **L3** | Deterministic | GitHub Platform Controls | Repository-level Secret Scanning, Push Protection, Non-Provider Pattern scanning, and Validity Checks enabled via API across public repositories. |

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
