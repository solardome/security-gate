# security-gate summary

- Inputs: `examples/full-input/trivy-report-full.json`
- Decision: **BLOCK** (exit_code=2)
- Release risk: 100
- Trust score: 82
- Findings: 4 total, 0 hard-stop, 3 considered

## Recommended Next Steps
- `FIX_VULN`
- `MITIGATE_NO_FIX`
- `REFRESH_SCAN`

## Issue Statuses
| finding_id | fingerprint | domain | severity | risk_score | status |
|---|---|---|---|---:|---|
| CVE-2024-10001 | 87760c1a55296679e5f8382024e14c6ecaa7af4c21503a076cffb115dd5b0641 | VULNERABILITY | HIGH | 100 | SUPPRESSED |
| CVE-2023-77777 | 4cbbaac351fbcee5560df7cf180a71ca2c8d791d53bc29a0b3826de7ad2ca404 | VULNERABILITY | CRITICAL | 100 | CONSIDERED |
| KSV001 | 1ea37a6352857b369f56c8ff0b0f31998ec162cce45a74f9f7cc1f4c7b2bb76a | CONFIG | MEDIUM | 66 | CONSIDERED |
| KSV002 | 13d6c4a4d3d3b333d30b17cf9161365e288f223741f9a33b3e70836269f62796 | CONFIG | LOW | 41 | CONSIDERED |
