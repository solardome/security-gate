# Security-Gate — Project Constitution (AGENTS.md)

This file defines the project’s non-negotiable principles and decision rules.
Docs are not sacred: they may be changed, but any change must preserve the core intent below.

## 1) Core intent
Security-Gate is a deterministic, stage-aware security gate / release decision engine.
It produces explainable decisions with strong provenance and governance, not "vibes".

## 2) Decision philosophy
1. Determinism first: given the same inputs, output must be stable and reproducible.
2. Explainability: every decision must be traceable to evidence + policy rule(s).
3. Secure-by-default: prefer least privilege, deny-by-default, safe defaults.
4. Auditability: decisions, inputs, and policy versions must be auditable.
5. Operability: observable, debuggable, and safe to run in CI and production.

## 3) Non-negotiable invariants (red lines)
A change MUST NOT:
- Turn a policy decision into a non-deterministic “LLM decides” step.
- Execute untrusted code or unreviewed scripts without sandboxing/controls.
- Hide or drop evidence/provenance needed to audit decisions.
- Introduce secret leakage (logs, prompts, traces, artifacts).
- Expand privileges (tokens, cloud perms, DB access) without explicit justification.

If a proposed change violates any red line:
- Either reject it, or
- Update an ADR documenting the new principle and include migration + risk acceptance.

## 4) Policy model
- Policies are explicit artifacts (policy-as-code), versioned in Git.
- Policy evaluation is stage-aware (e.g., PR -> build -> deploy -> prod).
- Policy outputs are structured and machine-readable (e.g., JSON), with:
  - decision (allow/deny/needs-approval)
  - risk score (bounded scale)
  - evidence references
  - policy version/hash
  - rationale summary

## 5) Evidence & provenance
- Evidence must carry source, timestamp, tool version, and integrity metadata.
- SBOM/provenance inputs (when present) are treated as first-class evidence.
- Any transformation of evidence must be tracked (no “black boxes”).

## 6) LLM usage boundaries
LLMs (local or remote) are allowed ONLY for:
- Summarization, explanation, categorization of already-collected evidence
- Triage suggestions that do not change final deterministic decision logic

LLMs are NOT allowed to:
- Be the sole arbiter of allow/deny decisions
- Generate policy rules without human review + versioning
- Access secrets beyond what a normal evaluator needs (least privilege)

If an LLM is used:
- Inputs must be minimized and redacted.
- Outputs must be treated as advisory signals, not truth.

## 7) Security model
- Least privilege everywhere (tokens, filesystem, network).
- No secrets in repo; secrets via environment/secret manager only.
- Logging must be redaction-aware (explicit denylist/allowlist).
- Threat modeling artifacts should exist for core flows (DFD + abuse cases).

## 8) Compatibility & UX
- CLI and CI integration are first-class.
- Backward compatibility is preferred; breaking changes require ADR + migration notes.
- Output formats must remain stable (versioned schema if needed).

## 9) Observability & resilience
- Structured logging (machine-parsable).
- Metrics hooks for key events (policy eval duration, deny reasons distribution).
- Clear error taxonomy: user error vs system error vs policy failure.
- Fail safe: on uncertainty or missing evidence, prefer deny/needs-approval.

## 10) How to change the rules
Any change to principles or red lines must include:
- An ADR explaining the change
- Updated docs
- Tests proving the new behavior
- Migration/rollout plan if behavior changes

## Mandatory review rule

Before implementing ANY change that affects:
- architecture
- policy logic
- risk scoring
- LLM integration
- security model
- CI/CD behavior
- permissions or secrets
- output schema

The agent MUST:
1) Activate $architecture-challenger
2) Run contradiction scan
3) Produce structured review
4) Only after approval, proceed to implementation

Do NOT modify code before review phase is completed.