# Input Test Sets

This folder contains multiple end-to-end input sets for `security-gate`.

## Files

- `block/`: deterministic `BLOCK` scenario.
- `block-cve/`: deterministic `BLOCK` scenario caused by CVE risk.
- `allow/`: deterministic `ALLOW` scenario.
- `warn/`: deterministic `WARN` scenario.
- `trivy-report-full.json`, `context-full.json`, `policy-full.json`, `accepted-risks-full.json`: legacy full-input files used as the base for `block/`.

## Run Examples

```bash
./main \
  --input input/block/trivy-report.json \
  --context input/block/context.json \
  --policy input/block/policy.json \
  --accepted-risk input/block/accepted-risks.json \
  --report-html
```

```bash
./main \
  --input input/block-cve/trivy-report.json \
  --context input/block-cve/context.json \
  --policy input/block-cve/policy.json \
  --accepted-risk input/block-cve/accepted-risks.json \
  --report-html
```

```bash
./main \
  --input input/allow/trivy-report.json \
  --context input/allow/context.json \
  --policy input/allow/policy.json \
  --accepted-risk input/allow/accepted-risks.json \
  --report-html
```

```bash
./main \
  --input input/warn/trivy-report.json \
  --context input/warn/context.json \
  --policy input/warn/policy.json \
  --accepted-risk input/warn/accepted-risks.json \
  --report-html
```

## Notes

- Verified expected outcomes:
  - `input/block` -> `BLOCK` (exit code `2`)
  - `input/block-cve` -> `BLOCK` (exit code `2`)
  - `input/allow` -> `ALLOW` (exit code `0`)
  - `input/warn` -> `WARN` (exit code `1`)
- `input/block-cve` is the dedicated scenario where a CVE drives the **final release decision** to `BLOCK`.
  It contains one `CRITICAL` CVE (`CVE-2026-90001`) and no accepted-risk suppression.
- `input/block/trivy-report.json` includes 10 findings total (8 vulnerabilities + 2 misconfigurations).
- `input/block/accepted-risks.json` includes two real fingerprints from `input/block/trivy-report.json`:
  - `AR-2026-0001` -> `5b1de0ddbd2a9b4e235545cfa859c2f89d5650951479de9383f50cf64ec7a2ed`
  - `AR-2025-0999` -> `be5d3f5b372dffe80a5af06ea73abf7ce34605ac9167595228c90ef1867c1902`
- If you change scanner input content, fingerprints will change too. In that case, take values from `decision.json -> findings.items[].fingerprint` and update accepted risk selectors.
