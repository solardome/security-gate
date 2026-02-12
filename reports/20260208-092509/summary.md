# security-gate summary

- Input: `/Users/denis/ws/security-gate/testdata/trivy-report-sample.json`
- Decision: **ALLOW** (exit_code=0)
- Release risk: 18
- Trust score: 33
- Findings: 2 total, 0 hard-stop, 0 considered

## Recommended Next Steps
- `FIX_VULN`
- `PIN_SCANNER`
- `REFRESH_SCAN`
- `IMPROVE_TRUST`

## Issue Statuses
| finding_id | fingerprint | domain | severity | risk_score | status |
|---|---|---|---|---:|---|
| CVE-2026-12345 | 04d42764b49781b1b94f85a6c7e82d07f02bff047cef0e3f0bf83a4572e9bd21 | VULNERABILITY | HIGH | 100 | CONSIDERED |
| AVD-AWS-0001 | de60ff0d36b62484aa3c8e17fd70a06ac0f2fad9431de31014421fa93a4749e3 | CONFIG | MEDIUM | 66 | CONSIDERED |
