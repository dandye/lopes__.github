## Description
<!-- Provide a brief, high-level summary of your changes. Explain WHY rather than WHAT. -->

## Related Issue / Context
<!-- Link to issue, reference, or ticket (e.g. Closes #12) -->

## Type of Change
- [ ] Reusable Security Workflow (`.github/workflows/security.yml`)
- [ ] Canonical Gitleaks Ruleset & Merger (`.gitleaks.toml`, `scripts/prepare_gitleaks_config.py`)
- [ ] Local Fleet Scanner (`scripts/scan_secrets.sh`)
- [ ] Security Policy & Documentation (`SECURITY.md`, `README.md`, `.github/`)

## Security & Quality Checklist
- [ ] Reusable workflow (`security.yml`) and `python3 tests/test_guardrails.py` pass on this PR.
- [ ] All GitHub Actions are pinned to 40-character commit SHAs with `persist-credentials: false`.
- [ ] All downloaded scanner binaries are pinned by exact version and verified via SHA-256 (plus Sigstore Cosign where supported).
- [ ] Zero `${{ ... }}` template expressions appear directly inside `run:` shell scripts.
- [ ] Downstream impact across caller repositories (`dandye/*`) reviewed.
