## Description
<!-- Provide a brief, high-level summary of your changes. Explain WHY rather than WHAT. -->

## Related Issue / Context
<!-- Link to issue, reference, or ticket (e.g. Closes #12) -->

## Type of Change
- [ ] Reusable Security Workflow (`.github/workflows/security.yml`)
- [ ] Canonical Gitleaks Ruleset (`.gitleaks.toml`)
- [ ] Account-Wide Security Policy (`SECURITY.md`)
- [ ] Documentation & Governance (`README.md`, `.github/`)

## Quality Checklist
- [ ] Reusable workflow (`security.yml`) passes on this PR (`gitleaks`, `opengrep`, `trivy`).
- [ ] Scanner versions and action tags are explicitly pinned.
- [ ] Downstream impact across caller repositories (`lopes/*`) reviewed.
- [ ] Commit follows [Scoped Commits](https://scopedcommits.com/) convention (`<scope>: <description>`).
