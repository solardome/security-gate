# Full Test Input Data (All Parameters)

This folder contains a complete end-to-end test input set for `security-gate` with all supported input parameter groups filled.

## Files

- `trivy-report-full.json`: scanner input (Trivy format) with vulnerabilities + misconfigurations.
- `context-full.json`: context payload with all currently supported context fields.
- `policy-full.json`: full policy with top-level controls, rules, conditions, actions, and exception.
- `accepted-risks-full.json`: accepted risk records with complete schema fields.

## Run Example

```bash
./main \
  --input input/trivy-report-full.json \
  --context input/context-full.json \
  --policy input/policy-full.json \
  --accepted-risk input/accepted-risks-full.json \
  --output-dir reports/full-input-run \
  --report-html
```

## Notes

- `accepted-risks-full.json` already includes one real fingerprint from `trivy-report-full.json`:
  `87760c1a55296679e5f8382024e14c6ecaa7af4c21503a076cffb115dd5b0641`.
- If you change scanner input content, fingerprints will change too. In that case, take values from `decision.json -> findings.items[].fingerprint` and update accepted risk selectors.
