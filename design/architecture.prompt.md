You are a Senior Staff DevSecOps / Platform Architect and a technical writer.

GOAL:
Create an enterprise-grade architecture + documentation pack for a project that is
code-generation-ready. The output will be used as the single “source of truth” for an
autonomous coding agent to implement the project.

PROJECT NAME (working title):
security-gate

ONE-LINER:
A local, privacy-first DevSecOps control that converts security scanner outputs into
deterministic, stage-aware CI/CD decisions (ALLOW / WARN / BLOCK) with a full decision trace,
and optionally uses a local LLM (Ollama) to generate developer-friendly explanations and
remediation guidance WITHOUT influencing the decision.

HARD CONSTRAINTS:
- Local execution only (offline mode). No SaaS, no external APIs, no cloud dependency.
- Deterministic decision-making is mandatory. LLM must not affect decisions.
- Inputs are untrusted. Include provenance/trust handling and prompt-injection awareness.
- Stage-aware behavior: PR/feature → merge/main → release → deploy-to-prod.
- Scope-limited MVP that can be built in 2–3 weeks, but the design must look enterprise-ready.
- Prefer Go for the core CLI/engine; optional small Python module allowed only for LLM I/O.
- Avoid writing implementation code; produce documentation and specs only.
- Use consistent terminology across all docs; introduce a glossary if needed.

PRIMARY USER:
Dev teams and DevSecOps engineers who already run security scanners but struggle with noise,
false positives, prioritization, and inconsistent gating rules across repositories.

CORE IDEA:
Scanners classify findings. This system classifies releases.
Release decisions are derived from a deterministic risk model and policy-as-code.
LLM output (if enabled) is explanation-only and strictly non-authoritative.

SECURITY GOVERNANCE REQUIREMENTS (MUST HAVE):
- Explicit Justification Workflow (“Accepted Risk”):
  - temporary risk acceptance with owner, ticket, scope, expiry/SLA, rationale
  - escalation when expiry is reached
  - approval rules (e.g. security approval required for prod + critical)
- Data Provenance / Trust awareness:
  - scanner version pinning and freshness
  - artifact signing / provenance level
  - build context trust signals
  - lower trust must increase risk or enforce stricter gating
- Prompt Injection Awareness for any LLM usage:
  - scanner outputs and metadata are attacker-controlled
  - sanitize, redact, and minimize LLM inputs
  - prevent LLM from issuing commands, policy changes, or override suggestions
  - clearly label all LLM output as non-authoritative

SCANNER OUTPUT ACQUISITION (MUST):
- The system does NOT run scanners. It consumes their outputs.
- MVP-supported input mechanisms:
  1) Pull-by-file-path (primary): one or more local JSON files produced by scanners
  2) Stdin stream (optional): scanner output piped into the tool
- No network calls, no CI API integration, no webhooks in MVP.
- Multiple inputs MAY be provided (e.g. multi-image, multi-module scans).
- All inputs MUST be:
  - hashed (e.g. SHA-256)
  - recorded in the decision trace
- A separate local context file (e.g. `context.json`) or equivalent CLI inputs provides:
  - pipeline_stage, branch_type
  - repo_criticality, exposure, change_type
  - scanner name/version pinning (if known)
  - artifact signing / provenance signals (if known)
- Missing or unknown signals MUST reduce trust and/or tighten gating (safe defaults).

RISK MODEL CLARIFICATIONS (MUST):
- Risk score scale: 0–100.
- Overall release risk is computed as:
  - max(finding risk score) PLUS contextual modifiers (stage, exposure, trust).
- Numeric risk aggregation MUST be monotonic (adding findings cannot reduce risk).
- Certain domains (e.g. SECRET detection, provenance violations) bypass numeric scoring
  and enforce hard-stop rules.
- A normalized Trust Score (0–100) MUST be computed and included in decision artifacts.
- Trust score MUST be usable as a first-class input in policy rules.

NOISE BUDGET GUARDRAILS (MUST):
- Noise budget (top-K findings / risk budget) is intended to reduce PR friction only.
- Noise budget MUST NOT apply to hard-stop domains (e.g. SECRET, signing violations).
- Noise budget is evaluated after scoring but before final stage decision.
- Noise budget is stage-scoped (PR ≠ prod).

EXIT CODE CONTRACT (MUST):
- 0 = ALLOW
- 1 = WARN (pipeline continues but annotations/report required)
- 2 = BLOCK (pipeline must fail)
- Policies MAY map WARN to BLOCK for higher-risk stages (e.g. prod).

DETERMINISTIC VS LLM REMEDIATION (MUST):
- Deterministic “recommended_next_steps” are rule-based and predefined
  (e.g. rotate secret, upgrade dependency ≥ X, add justification record).
- LLM-generated text MAY elaborate or rephrase but MUST NOT introduce new actions,
  policy changes, or decisions.

INPUTS:
- Scanner outputs:
  - MVP: Trivy JSON
  - Later: Gitleaks, others
- CI context:
  - pipeline_stage, branch_type, environment
  - repo_criticality, exposure, change_type
- Optional enrichment flags (reachable, exploit maturity) may be missing/unknown.
- Optional provenance signals (scanner pinned, artifact signed, provenance level)
  may be missing/unknown and must affect trust.

OUTPUTS:
- Deterministic decision artifacts:
  - report.json (machine-readable, authoritative)
  - summary.md (human-readable)
  - optional static HTML report
- CI-friendly exit code (per contract above)
- Optional LLM-generated explanation text, clearly marked as non-authoritative.

YOUR TASK:
Produce the following documentation artifacts. Use the exact file names and structure below.
Write in clear, concise English suitable for a GitHub repository.

========================================================
OUTPUT FILE 1:
README.md
========================================================
README must include:
1) Problem statement (noise → action; release decisions vs finding severities)
2) Key principles:
   - deterministic decisions
   - decision trace
   - stage-aware escalation
   - privacy-first local execution
   - Accepted Risk / Justification Workflow
   - provenance-aware trust
   - optional, non-authoritative LLM
3) Conceptual Quickstart (no real commands)
4) Architecture overview (components + data flow)
5) Decision model summary
6) High-level Decision Matrix by stage
7) Outputs and their meaning
8) Security considerations (untrusted inputs, redaction, prompt injection, auditability)
9) MVP scope vs roadmap
10) License considerations (Apache 2.0 preferred; LLM-off mode)
11) “Why scanner severity ≠ release decision”

========================================================
OUTPUT FILE 2:
docs/md/architecture.md
========================================================
Include:
- High-level ASCII diagram
- Module boundaries
- Data flow (ingest → normalize → score → policy → decision trace → report)
- Deterministic vs AI boundary
- Failure modes and safe defaults (fail-closed vs fail-open per stage)
- Extensibility approach
- Trust/provenance flow and its effect on decisions

========================================================
OUTPUT FILE 3:
docs/md/core-decision-engine.md
========================================================
MOST IMPORTANT DOCUMENT.
Specify in detail:
1) Unified Finding schema
2) Risk scoring model (factors, weights, unknown handling)
3) Trust score computation and usage
4) Explicit Decision Matrices for:
   - PR / feature
   - merge / main
   - release
   - deploy-to-prod
5) Escalation logic across stages and via expiry
6) Noise budget mechanism with guardrails
7) False positives, exceptions, Accepted Risk governance
8) report.json schema (authoritative)
9) Deterministic recommended_next_steps
10) Example walkthroughs:
    - same HIGH CVE in PR vs prod
    - CRITICAL CVE with no fix + justification
    - SECRET detection hard-stop

========================================================
OUTPUT FILE 4:
docs/md/policy-format.md
========================================================
Define minimal policy-as-code format:
- rule structure
- stage-aware conditions
- domain-specific overrides
- exceptions with scope + expiry
- Accepted Risk objects
- trust-based tightening
Provide 6–10 example rules.

========================================================
OUTPUT FILE 5:
docs/md/modules.md
========================================================
For each module describe:
- purpose
- inputs / outputs
- public interfaces (CLI flags, file formats, responsibilities)
- error handling strategy
- logging and traceability
- security considerations
Modules:
- cmd/cli
- ingest/trivy
- normalize
- score (risk + trust)
- policy
- decision_trace
- governance (Accepted Risk)
- report
- llm (optional, local only)

========================================================
OUTPUT FILE 6:
docs/md/llm-boundary.md
========================================================
Specify:
- LLM threat model
- what is sent vs never sent
- redaction rules
- safe prompt template (explanation-only)
- output schema
- non-authoritative labeling
- grounding in deterministic decision trace

========================================================
OUTPUT FILE 7:
docs/md/governance-accepted-risk.md
========================================================
Define Justification Workflow:
- Accepted Risk schema
- storage location in MVP (repo file)
- validation rules
- approval rules
- expiry-based escalation
- audit trail
- concrete examples

STYLE REQUIREMENTS:
- Do NOT write implementation code.
- Pseudocode allowed only if it clarifies logic.
- Use consistent terminology and glossary if needed.
- Keep MVP minimal but enterprise-ready.
- Assume the reader is a coding agent.
- End each document with Acceptance Criteria checklist.

DELIVERABLE:
Output all files in order, with clear separators:
--- FILE: README.md ---
...
--- FILE: docs/md/architecture.md ---
...
etc.