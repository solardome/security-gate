# security-gate

**Deterministic, stage-aware release decisions for CI/CD — not just scanner severities.**

AI Security Auditor is a **local, privacy-first DevSecOps control** that consumes security scanner outputs and converts them into **clear, deterministic CI/CD decisions**:  
**ALLOW / WARN / BLOCK**, with a full, auditable decision trace.

Optional local LLM support (e.g. via Ollama) can generate **human-friendly explanations**, but **never influences decisions**.

---

## Why this project exists

Security scanners are good at one thing: **classifying findings**.  
They are much worse at answering the real question CI/CD needs:

> *“Is this release safe to move forward at this stage?”*

Common problems teams face today:
- CRITICAL findings block PRs but get ignored later
- Hundreds of LOW/MEDIUM findings hide real risk
- Different repositories gate differently
- Suppressions become permanent and unaudited
- Security decisions are implicit, not explainable

**AI Security Auditor solves this by classifying releases, not findings.**

---

## Core principles

### 1. Severity ≠ Decision
Scanner severities (CRITICAL/HIGH/…) describe findings.  
This system produces **release decisions**: ALLOW, WARN, or BLOCK.

The same finding may result in different decisions depending on:
- pipeline stage
- environment exposure
- repository criticality
- trust and provenance signals

---

### 2. Deterministic by design
All decisions are derived from:
- a deterministic risk model
- explicit policy-as-code rules

There is **no probabilistic or AI-driven decision logic**.

---

### 3. Stage-aware escalation
Shift-left does not mean “block everything early”.

Typical behavior:
- **PR / feature branch** → signal and prioritize (WARN)
- **main / release** → enforce policy (WARN or BLOCK)
- **deploy-to-prod** → strict enforcement (BLOCK by default)

---

### 4. Privacy-first, local execution
- Runs fully offline
- No SaaS, no external APIs, no cloud dependency
- Designed for regulated and restricted environments

---

### 5. Governance is a first-class feature
The system includes a formal **Justification / Accepted Risk workflow**:
- time-bound risk acceptance
- required metadata (owner, ticket, expiry, scope)
- approval rules for high-risk scenarios
- automatic escalation when expiry is reached

No permanent suppressions. No silent bypasses.

---

### 6. Provenance- and trust-aware
Not all inputs are equally trustworthy.

Risk is influenced by:
- scanner version pinning and freshness
- artifact signing status
- provenance level and build context

Lower trust results in **stricter gating**, not silent acceptance.

---

### 7. LLM is optional and non-authoritative
If enabled, a local LLM may:
- explain *why* a decision was made
- summarize risk for developers

It **cannot**:
- change scores
- override policy
- suggest bypasses
- issue commands

LLM output is always clearly labeled as **non-authoritative**.

---

## How it works (high level)

1. **Ingest** scanner outputs (e.g. Trivy JSON)
2. **Normalize** findings into a unified schema
3. **Score** risk deterministically (including trust signals)
4. **Evaluate policies** based on stage and context
5. **Apply governance** (Accepted Risks, expiry, approvals)
6. **Emit a decision** with a full decision trace
7. *(Optional)* Generate an LLM-based explanation

---

## Scanner input model

- The system **does not run scanners**
- It consumes outputs produced by your CI pipeline

### Supported input mechanisms (MVP)
- **Local file paths** (primary)
- **stdin stream** (optional)

Multiple inputs are supported (e.g. multi-image scans).

All inputs are:
- treated as untrusted
- hashed
- recorded in the decision trace

A separate local context file (or CLI flags) provides CI metadata and provenance signals.

---

## Decision outcomes

The only CI-facing outcomes are:

| Decision | Meaning |
|--------|--------|
| **ALLOW** | Release may proceed |
| **WARN** | Release may proceed, attention required |
| **BLOCK** | Release must not proceed |

Exit codes are stable and deterministic:
- `0` → ALLOW  
- `1` → WARN  
- `2` → BLOCK  

Severity levels such as **CRITICAL** remain part of the input and audit trail, but are **not CI decisions**.

---

## Outputs

Each run produces deterministic artifacts:

- `decision.json` — authoritative, machine-readable decision
- `summary.md` — human-readable explanation
- `report.html` — optional static report

All artifacts include:
- final decision
- risk and trust scores
- triggered rules
- applied exceptions
- accepted risks and expiry status
- ranked top findings

---

## Security considerations

- All inputs are treated as attacker-controlled
- Strict schema validation and normalization
- No dynamic code execution
- Redaction before any LLM interaction
- Full decision trace for auditability

The system is designed to be safe-by-default and fail-closed in high-risk stages.

---

## MVP scope

**Included in v1**
- Trivy JSON ingestion
- Deterministic risk scoring
- Stage-aware decision matrix
- Accepted Risk governance
- File-based decision trace
- Optional local LLM explanations

**Out of scope for MVP**
- Running scanners
- CI system API integrations
- Network-based services
- Auto-remediation

---

## Roadmap (non-binding)

- Additional scanners (e.g. Gitleaks)
- Additional domains (IAM, licenses, SBOM)
- Pluggable report formats
- Policy testing and simulation tools

---

## Why not just gate on scanner severity?

Because:
- Severity is context-free
- CI/CD is context-rich
- Release risk is not the same as finding severity

This project exists to bridge that gap in a way that is:
- deterministic
- explainable
- auditable
- governance-friendly

---

## License and models

- Project code and policies are intended to be **Apache 2.0 compatible**
- Recommended LLMs are local, permissively licensed models
- Full functionality is available with **LLM disabled**

---

## Project philosophy

AI Security Auditor is designed so that:
- **policies decide**
- **humans govern**
- **AI explains**

Nothing more, nothing less.