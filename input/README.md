# Input Test Set

This folder contains a single deterministic dataset for `security-gate`.

## Files

- `block/`: final `BLOCK` scenario with `20` findings total.

## Run

```bash
./main \
  --input input/block/trivy-report.json \
  --context input/block/context.json \
  --policy input/block/policy.json \
  --accepted-risk input/block/accepted-risks.json \
  --report-html
```

## Expected Result

- Final decision: `BLOCK` (exit code `2`)
- Findings total: `20`
- Suppressed: `2` (via accepted risks)
- Considered: `18`
- Triage intent: `Fix Now=5`, `Backlog=13`
