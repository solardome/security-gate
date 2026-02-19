#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/examples/simulation/out"
mkdir -p "$OUT_DIR"
BINARY="$(mktemp "${TMPDIR:-/tmp}/security-gate.XXXXXX")"
trap 'rm -f "$BINARY"' EXIT
go build -o "$BINARY" ./cmd/security-gate

run_case() {
  local case_name="$1"
  shift
  echo "\n== Running simulation: ${case_name} =="
  set +e
  "$@" \
    --out-json "$OUT_DIR/${case_name}.report.json" \
    --out-html "$OUT_DIR/${case_name}.report.html" \
    --checksums "$OUT_DIR/${case_name}.checksums.sha256" \
    --run-log "$OUT_DIR/${case_name}.run.log"
  local exit_code=$?
  set -e
  echo "exit_code=${exit_code}"
  echo "json: $OUT_DIR/${case_name}.report.json"
  echo "html: $OUT_DIR/${case_name}.report.html"
  echo "checksums: $OUT_DIR/${case_name}.checksums.sha256"
  echo "run_log: $OUT_DIR/${case_name}.run.log"
}

run_case "warn" \
  "$BINARY" \
  --scan "$ROOT_DIR/examples/simulation/scanner-report.warn.json" \
  --context "$ROOT_DIR/examples/simulation/context.yaml" \
  --policy "$ROOT_DIR/examples/simulation/policy.yaml" \
  --accepted-risk "$ROOT_DIR/examples/simulation/accepted-risk.yaml"

run_case "block" \
  "$BINARY" \
  --scan "$ROOT_DIR/examples/simulation/scanner-report.block.json" \
  --context "$ROOT_DIR/examples/simulation/context.yaml" \
  --policy "$ROOT_DIR/examples/simulation/policy.yaml" \
  --accepted-risk "$ROOT_DIR/examples/simulation/accepted-risk.yaml"

run_case "block-sarif-pr" \
  "$BINARY" \
  --scan "$ROOT_DIR/examples/simulation/scanner-report.warn.sarif.json" \
  --context "$ROOT_DIR/examples/simulation/context.pr-feature.yaml" \
  --policy "$ROOT_DIR/examples/simulation/policy.yaml"

run_case "block-snyk-pr" \
  "$BINARY" \
  --scan "$ROOT_DIR/examples/simulation/scanner-report.warn.snyk.json" \
  --context "$ROOT_DIR/examples/simulation/context.pr-feature.yaml" \
  --policy "$ROOT_DIR/examples/simulation/policy.yaml"

run_case "block-checkmarx-pr" \
  "$BINARY" \
  --scan "$ROOT_DIR/examples/simulation/scanner-report.warn.checkmarx.json" \
  --context "$ROOT_DIR/examples/simulation/context.pr-feature.yaml" \
  --policy "$ROOT_DIR/examples/simulation/policy.yaml"

run_case "block-sonar-pr" \
  "$BINARY" \
  --scan "$ROOT_DIR/examples/simulation/scanner-report.warn.sonar.json" \
  --context "$ROOT_DIR/examples/simulation/context.pr-feature.yaml" \
  --policy "$ROOT_DIR/examples/simulation/policy.yaml"

run_case "block-context-auto-github-pr" \
  env -i \
  PATH="${PATH}" \
  HOME="${HOME:-/tmp}" \
  GITHUB_ACTIONS=true \
  GITHUB_EVENT_NAME=pull_request \
  GITHUB_REF_NAME=feature/simulation \
  SECURITY_GATE_REPO_CRITICALITY=high \
  SECURITY_GATE_EXPOSURE=internet \
  SECURITY_GATE_CHANGE_TYPE=security_sensitive \
  SECURITY_GATE_SCANNER_NAME=trivy \
  SECURITY_GATE_SCANNER_VERSION=0.50.0 \
  SECURITY_GATE_ARTIFACT_SIGNED=yes \
  SECURITY_GATE_PROVENANCE_LEVEL=verified \
  SECURITY_GATE_BUILD_CONTEXT_INTEGRITY=verified \
  "$BINARY" \
  --scan "$ROOT_DIR/examples/simulation/scanner-report.warn.json" \
  --context-auto \
  --policy "$ROOT_DIR/examples/simulation/policy.yaml" \
  --accepted-risk "$ROOT_DIR/examples/simulation/accepted-risk.yaml"

run_case "allow-new-findings-only-baseline-all" \
  "$BINARY" \
  --scan "$ROOT_DIR/examples/simulation/scanner-report.warn.json" \
  --baseline-scan "$ROOT_DIR/examples/simulation/scanner-report.warn.baseline-all.json" \
  --new-findings-only \
  --context "$ROOT_DIR/examples/simulation/context.pr-feature.yaml" \
  --policy "$ROOT_DIR/examples/simulation/policy.yaml"
