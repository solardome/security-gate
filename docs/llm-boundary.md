# LLM Boundary

This document specifies the boundary between deterministic decision logic and optional
LLM-based explanation. It is consistent with `docs/core-decision-engine.md`.

## Threat Model
- Prompt injection via scanner outputs or metadata.
- Data exfiltration of secrets or sensitive source content.
- Hallucinated policy changes or unauthorized remediation steps.
- Social engineering attempts embedded in findings or package metadata.

## What Is Sent to the LLM (Allowlist)
Only sanitized, minimal data derived from the decision trace:
- Decision status (ALLOW/WARN/BLOCK) and deterministic rationale summary.
- Aggregated counts (total findings, hard-stop count, max_finding_risk).
- Deterministic recommended_next_steps (IDs and short descriptions).
- High-level context (pipeline_stage, exposure, change_type).
- Non-sensitive finding summaries (title + severity + domain) with IDs only.

## What Is Never Sent (Denylist)
- Raw scanner outputs or full JSON blobs.
- Secrets, tokens, credentials, or secret-like patterns.
- Full file contents, diffs, or source code.
- CI environment variables or system paths.
- Any data not present in the decision trace allowlist.

## Redaction and Minimization Rules
- Strip or mask any suspected secrets (replace with [REDACTED]).
- Truncate free-text fields to a safe length.
- Remove URLs, stack traces, or inline code from LLM input.
- Allowlist only approved fields; drop everything else.
- Record all redactions in the decision_trace.

## Safe Prompt Template (Explanation-Only)
This is a conceptual template; it must be used verbatim in intent.

"""
You are an explanation assistant for security-gate.
Your job is to rephrase the deterministic decision and steps provided.
You MUST NOT change the decision, invent new actions, or suggest policy changes.
Use only the provided inputs. If information is missing, say so.

Decision status: {decision_status}
Deterministic rationale: {decision_rationale}
Recommended next steps (authoritative): {recommended_next_steps}
Context: stage={pipeline_stage}, exposure={exposure}, change_type={change_type}
Finding summaries: {finding_summaries}

Produce:
- A short explanation suitable for developers.
- A numbered list of the same recommended_next_steps (no additions).
- A note that this text is non-authoritative.
"""

## Output Schema (Non-Authoritative)
The LLM output is a separate artifact referenced from decision.json.
It must be clearly labeled and must not introduce new actions.

Minimum fields:
- non_authoritative: true
- decision_status: ALLOW | WARN | BLOCK (copied)
- explanation: string
- recommended_next_steps: array of step IDs (subset of decision.json)
- references: array of finding_id or decision_trace event IDs

decision.json must include:
- llm_explanation.enabled: boolean
- llm_explanation.non_authoritative: true
- llm_explanation.content_ref: string (path or identifier for the LLM artifact)

## Grounding and Labeling
- All LLM text must cite deterministic inputs by ID, not raw data.
- Every LLM artifact must include the label: "Non-authoritative explanation." 
- Any mismatch with decision.json is treated as an LLM error and ignored.

## Acceptance Criteria
- [ ] Threat model includes prompt injection and data exfiltration risks.
- [ ] Allowlist and denylist are explicit and conservative.
- [ ] Redaction and minimization rules are defined.
- [ ] Safe prompt template enforces explanation-only behavior.
- [ ] Output schema aligns with decision.json and is non-authoritative.
- [ ] Grounding and labeling requirements are explicit.
