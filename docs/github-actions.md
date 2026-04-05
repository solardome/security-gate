# GitHub Actions Integration

This guide shows how to integrate `security-gate` into GitHub Actions workflows.

## Prerequisites

- Scanner reports (JSON) are generated in a prior workflow step
- A policy file exists in the repository (default: `.security-gate/policy.yaml`)
- The repository has GitHub releases with `security-gate` binaries (or you build from source)

## Composite Action

The repository ships a composite action at `.github/actions/security-gate/action.yml`.

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `scan` | Yes | — | Glob or comma-separated paths to scanner JSON files |
| `baseline-scan` | No | `''` | Glob or comma-separated paths to baseline scanner JSON files |
| `new-findings-only` | No | `false` | Score only findings not in baseline (pr/merge only) |
| `policy` | No | `.security-gate/policy.yaml` | Path to policy YAML |
| `accepted-risk` | No | `''` | Path to accepted-risk YAML |
| `context` | No | `''` | Path to context YAML. If omitted, uses `--context-auto` |
| `version` | No | `latest` | Release version to install |
| `fail-on-warn` | No | `false` | Fail the step on WARN (exit 1) in addition to BLOCK |

### Outputs

| Output | Description |
|--------|-------------|
| `decision` | `ALLOW`, `WARN`, or `BLOCK` |
| `exit-code` | `0`, `1`, or `2` |
| `risk-score` | Overall risk score (0-100) |
| `trust-score` | Trust score (0-100) |
| `report-json-path` | Path to the generated `report.json` |
| `report-html-path` | Path to the generated `report.html` |

Reports are automatically uploaded as workflow artifacts (`security-gate-reports`).

---

## Usage Examples

### Basic PR Check

Run Trivy, then gate the PR with security-gate. Context is auto-detected from the GitHub environment.

```yaml
name: PR Security Check
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          format: json
          output: trivy-report.json

      - name: Security Gate
        id: gate
        uses: ./.github/actions/security-gate
        with:
          scan: trivy-report.json
          policy: .security-gate/policy.yaml

      - name: Print decision
        if: always()
        run: |
          echo "Decision: ${{ steps.gate.outputs.decision }}"
          echo "Risk:     ${{ steps.gate.outputs.risk-score }}"
          echo "Trust:    ${{ steps.gate.outputs.trust-score }}"
```

### PR Check with Baseline Diff (new-findings-only)

Compare the PR scan against the main branch baseline so only new findings are scored. Useful for reducing noise on PRs that don't introduce new vulnerabilities.

```yaml
name: PR Security Check (Baseline Diff)
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Trivy on PR
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          format: json
          output: trivy-pr.json

      - name: Download baseline scan
        uses: actions/download-artifact@v4
        with:
          name: trivy-baseline
          path: baseline/
        continue-on-error: true  # first run may not have a baseline

      - name: Security Gate
        uses: ./.github/actions/security-gate
        with:
          scan: trivy-pr.json
          baseline-scan: baseline/trivy-main.json
          new-findings-only: 'true'
          policy: .security-gate/policy.yaml
```

### Multi-Scanner (Trivy + SARIF)

Run multiple scanners and pass all reports to security-gate. Findings are merged and scored together.

```yaml
name: Multi-Scanner Gate
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          format: json
          output: trivy-report.json

      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: auto
        env:
          SEMGREP_SARIF_OUTPUT: semgrep-report.sarif.json

      - name: Security Gate
        uses: ./.github/actions/security-gate
        with:
          scan: 'trivy-report.json, semgrep-report.sarif.json'
          policy: .security-gate/policy.yaml
```

### Release Gate with Strict Policy

Block releases if risk is too high. Use `fail-on-warn: true` and accepted-risk governance for a stricter posture.

```yaml
name: Release Gate
on:
  push:
    tags: ['v*']

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          format: json
          output: trivy-report.json

      - name: Security Gate
        uses: ./.github/actions/security-gate
        with:
          scan: trivy-report.json
          policy: .security-gate/policy.yaml
          accepted-risk: .security-gate/accepted-risk.yaml
          context: .security-gate/release-context.yaml
          fail-on-warn: 'true'

  release:
    needs: scan
    runs-on: ubuntu-latest
    steps:
      - name: Publish release
        run: echo "Release approved by security gate"
```

### Using the Reusable Workflow

The repository also provides a reusable workflow at `.github/workflows/security-gate.yml` that wraps the composite action in a callable job.

```yaml
name: CI
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          format: json
          output: trivy-report.json
      - uses: actions/upload-artifact@v4
        with:
          name: scan-reports
          path: trivy-report.json

  gate:
    needs: scan
    uses: ./.github/workflows/security-gate.yml
    with:
      scan: trivy-report.json
      policy: .security-gate/policy.yaml

  deploy:
    needs: gate
    if: needs.gate.outputs.decision == 'ALLOW'
    runs-on: ubuntu-latest
    steps:
      - run: echo "Deploying — gate decision was ALLOW"
```

---

## Exit Code Behavior

| Exit Code | Decision | Default Behavior | `fail-on-warn: true` |
|-----------|----------|------------------|-----------------------|
| 0 | ALLOW | Step passes | Step passes |
| 1 | WARN | Step passes (warning annotation) | Step fails |
| 2 | BLOCK | Step fails | Step fails |

Fatal errors (invalid input, missing policy) also exit with code 2.

## Artifacts

Every run uploads these files as the `security-gate-reports` artifact (retained for 90 days):

- `report.json` — authoritative machine-readable report
- `report.html` — human-readable HTML report
- `checksums.sha256` — SHA-256 hashes for integrity verification
- `security-gate.run.log` — structured audit log (JSON lines)

## Context Auto-Detection

When `context` is omitted, the action passes `--context-auto` which detects:

- `GITHUB_ACTIONS=true` → CI platform is GitHub
- `GITHUB_EVENT_NAME` → maps to pipeline stage (`pull_request` → `pr`, `push` to main → `merge`, tag push → `release`)
- `GITHUB_REF_NAME` → branch type detection
- `SECURITY_GATE_*` environment variables → repo criticality, exposure, scanner metadata, provenance

Set these as repository or environment variables to provide full context without a YAML file.
