# Modules

This document specifies module responsibilities, interfaces, and operational constraints.
It aligns with `docs/core-decision-engine.md` and remains implementation-agnostic.

## Fatal Errors and Fail-Closed Defaults (Authoritative)
Fatal errors are deterministic pipeline failures that make the decision non-authoritative. The following conditions are fatal:
- invalid/unsupported input format
- cannot hash decision-affecting inputs
- schema validation failure
- policy parse failure
- accepted risk parse/validation failure

Fail-closed defaults:
- stage=main/release/prod: fatal error => BLOCK and emit minimal decision.json with error metadata.
- stage=pr: fatal error => WARN (exit_code=1) with low-trust defaults ONLY if scanner input is present and hashable; otherwise BLOCK.

All fatal errors MUST be recorded in decision_trace: event error.fatal with error_code and affected input.

## cmd/cli
Purpose:
- Orchestrate the deterministic pipeline and produce exit codes 0/1/2.

Inputs and Outputs:
- Inputs: scanner outputs (file paths or stdin), context.json, policy file, accepted risk file.
- Outputs: decision.json, summary.md, optional HTML report, process exit code.

Public Interfaces:
- CLI flags (minimal):
  - --input <path> (repeatable)
  - --stdin (read scanner output from stdin)
  - --context <path>
  - --policy <path>
  - --accepted-risk <path>
  - --output-dir <path>
- --stage <pr|main|release|prod> (override context.pipeline_stage if provided)
  - --report-html (optional)
  - --llm <on|off> (optional, default off)

Error Handling:
- Fatal errors follow "Fatal Errors and Fail-Closed Defaults (Authoritative)".
- LLM failures never change the decision status.

Logging and Traceability:
- Emits a summary of key inputs and outputs.
- Ensures decision_trace is persisted as part of decision.json.
- Records SHA-256 hashes for every decision-affecting input (scanner outputs, context, policy, and accepted risk files) so the trace ties each decision to the exact file contents.

Security Considerations:
- No network calls; local execution only.
- Treats all inputs as untrusted and enforces size limits.

## ingest/trivy
Purpose:
- Parse Trivy JSON outputs and extract raw findings and metadata.
- Hash inputs (SHA-256) for traceability.

Inputs and Outputs:
- Inputs: local Trivy JSON file(s) or stdin stream.
- Outputs: raw findings list, scan metadata, input_sha256.

Public Interfaces:
- Accepts file paths or stdin; records source_scanner=trivy and source_version if present.

Error Handling:
- Invalid/unsupported input format (including unreadable or non-JSON input) is a fatal error.
- Cannot hash decision-affecting inputs is a fatal error.

Logging and Traceability:
- Records input hashes, scan timestamps, and finding counts.

Security Considerations:
- Inputs are attacker-controlled; no parsing side effects or execution.

## normalize
Purpose:
- Convert scanner-specific data into the Unified Finding Schema.
- Enforce required fields and canonical enumerations.

Inputs and Outputs:
- Inputs: raw findings and ingest metadata.
- Outputs: normalized findings with required fields present.

Public Interfaces:
- Produces normalized findings with domain, severity, and evidence_ref set.

Error Handling:
- Required fields must be populated; missing scan_timestamp uses ingest_time with timestamp_source=ingest, and input_sha256 must be computed at ingest.
- Schema validation failure is a fatal error.
- Cannot hash decision-affecting inputs is a fatal error.
- If domain cannot be mapped, emit a synthetic hard-stop finding with title=UNKNOWN_DOMAIN_MAPPING, domain=CONFIG, severity=HIGH. Record the raw domain value in decision_trace. This finding is never suppressible and bypasses noise budget.

Logging and Traceability:
- Records normalization warnings and field substitutions in decision_trace.

Security Considerations:
- Redacts or truncates sensitive content; never stores raw secrets.

## score (risk + trust)
Purpose:
- Compute per-finding risk_score and global trust_score deterministically.

Inputs and Outputs:
- Inputs: normalized findings, context inputs, provenance signals.
- Outputs: scored findings, trust_score, trust_signals.

Public Interfaces:
- Outputs risk_score, hard_stop flag, and trust_score per core decision engine.

Error Handling:
- Missing trust signals are treated as unknown with safe penalties.
- Schema validation failure is a fatal error.

Logging and Traceability:
- Records all scoring inputs, modifiers, and outputs in decision_trace.

Security Considerations:
- No external lookups; strictly local computation.

## policy
Purpose:
- Apply noise budget, exceptions, accepted risks, and stage decision matrix.

Inputs and Outputs:
- Inputs: scored findings, trust_score, policy rules, accepted risks, pipeline_stage.
- Outputs: decision status, exit code, evaluated rule list, applied exceptions/risks.

Public Interfaces:
- Consumes policy-as-code and accepted risk objects.
- Produces decision status and recommended_next_steps (deterministic only).

Error Handling:
- Policy parse failure is a fatal error.
- Expired Accepted Risk handling follows the authoritative rules in the core decision engine and governance module.

Logging and Traceability:
- Records evaluated rules, exceptions, noise budget effects, and stage matrix outcome.

Security Considerations:
- No policy rule can override hard-stop findings or conditions.
- Hard-stop domains tracked by the core spec are SECRET, MALWARE, PROVENANCE (including signing/provenance synthetic findings), and UNKNOWN_DOMAIN_MAPPING; they bypass noise budget, cannot be suppressed, and always force BLOCK.

## decision_trace
Purpose:
- Maintain an ordered, append-only trace of ingest, normalize, score, and policy events.

Inputs and Outputs:
- Inputs: module events, hashes, normalized findings, scoring details.
- Outputs: decision_trace array embedded in decision.json (and optional standalone file).

Public Interfaces:
- Provides a canonical trace structure for reporting and LLM explanation.

Error Handling:
- All fatal errors MUST be recorded in decision_trace: event error.fatal with error_code and affected input.

Logging and Traceability:
- Ensures deterministic ordering and timestamped events.
- Includes hash and source metadata for every decision-affecting input (scanner outputs, context, policy, accepted risks) so each event can be audited.

Security Considerations:
- Redacts sensitive fields; stores references to evidence, not raw secrets.

## governance (accepted risk)
Purpose:
- Validate accepted risk objects and enforce scope, approval, and expiry.

Inputs and Outputs:
- Inputs: accepted risk file, context stage/environment, findings.
- Outputs: accepted_risks_applied list and governance warnings.

Public Interfaces:
- Accepts a repo-local accepted risk file and returns applicable records.

Error Handling:
- Accepted risk parse/validation failure is a fatal error.
- Expired Accepted Risks are treated as INVALID (ignored for governance effects and gating).
- Additionally, expiry escalation is enforced deterministically:
  - stage=pr/main: if an expired Accepted Risk would have matched a HIGH/CRITICAL finding, the final outcome is at least WARN (do not silently ignore; record governance.expired).
  - stage=release/prod: if an expired Accepted Risk would have matched a HIGH/CRITICAL finding, the final outcome is BLOCK (fail-closed), even if other factors would allow WARN/ALLOW.
- Expired Accepted Risks never apply to hard-stop findings or conditions (unchanged).

Logging and Traceability:
- Records accepted risk IDs, scope checks, and expiry handling in decision_trace.

Security Considerations:
- No accepted risk can suppress hard-stop findings or conditions.

## report
Purpose:
- Generate decision.json, summary.md, and optional HTML report.

Inputs and Outputs:
- Inputs: decision object, findings summary, decision_trace.
- Outputs: files written to output directory.

Public Interfaces:
- Emits decision.json with the authoritative schema and summary.md for humans.

Error Handling:
- Schema validation failure for decision.json is a fatal error.

Logging and Traceability:
- Report files include references to input hashes and policy version.

Security Considerations:
- Ensure reports do not include raw secrets or unredacted evidence.

## llm (optional, local only)
Purpose:
- Generate non-authoritative explanations and remediation guidance.

Inputs and Outputs:
- Inputs: sanitized decision_trace, deterministic recommended_next_steps.
- Outputs: explanation text and content_ref in decision.json.

Public Interfaces:
- Enabled by CLI flag; uses local LLM only (e.g., Ollama).

Error Handling:
- LLM failures never change decision status; produce warnings only.

Logging and Traceability:
- Records LLM invocation metadata and non_authoritative flag.

Security Considerations:
- Inputs are sanitized to prevent prompt injection and data leakage.

## Acceptance Criteria
- [ ] Each module lists purpose, inputs/outputs, public interfaces, error handling, logging, and security considerations.
- [ ] Module responsibilities align with the core decision engine pipeline.
- [ ] Noise budget, hard-stop, and accepted risk governance are assigned to the policy/governance modules.
- [ ] LLM module is explicitly non-authoritative and isolated from decisions.
- [ ] No implementation code is included.
