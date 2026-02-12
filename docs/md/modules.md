# Modules

Authority Notice
This document is descriptive and non-authoritative. Design intent lives in design/architecture.prompt.md, deterministic decision logic and evaluation order live in docs/md/core-decision-engine.md, and the policy schema lives in docs/md/policy-format.md. In conflicts, those authoritative sources prevail and this document must not override or reinterpret them.

This document specifies module responsibilities, interfaces, and operational constraints.
It aligns with `docs/md/core-decision-engine.md` and remains implementation-agnostic.

## Fatal Errors and Fail-Closed Defaults (Authoritative)
Fatal errors are deterministic pipeline failures that make the decision non-authoritative. The following conditions are fatal:
- invalid/unsupported input format
- cannot hash decision-affecting inputs
- schema validation failure
- policy parse failure
- accepted risk parse/validation failure

Fail-closed defaults:
- stage=main/release/prod: fatal error => BLOCK and emit minimal report.json with error metadata.
- stage=pr: fatal error => WARN (exit_code=1) with low-trust defaults ONLY if scanner input is present and hashable; otherwise BLOCK.

All fatal errors MUST be recorded in decision_trace: event error.fatal with error_code and affected input.

## cmd/security-gate
Purpose:
- Orchestrate the deterministic pipeline and produce exit codes 0/1/2.

Inputs and Outputs:
- Inputs: scanner outputs (file paths or stdin), context.json, policy file, accepted risk file.
- Outputs: report.json, optional HTML report, process exit code.

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

Stage precedence and recording:
- The effective stage used for all gating and decision matrices is derived as follows:
  - If `--stage` is provided, it is authoritative and overrides any
    `context.payload.pipeline_stage` value.
  - If `--stage` is not provided, `context.payload.pipeline_stage` is used.
- `report.json.inputs.context.payload.pipeline_stage` MUST reflect the **effective**
  stage used for evaluation. If a conflicting stage was present in the original context
  payload and overridden by `--stage`, the engine MUST record this in `decision_trace`
  (for example, via a `context.stage_override` event with both values) so audits can
  reconstruct the discrepancy.

Error Handling:
- Fatal errors follow "Fatal Errors and Fail-Closed Defaults (Authoritative)".
- LLM failures never change the decision status.

Logging and Traceability:
- Emits a summary of key inputs and outputs.
- Ensures decision_trace is persisted as part of report.json.
- Records SHA-256 hashes for every decision-affecting input (scanner outputs, context, policy, and accepted risk files) so the trace ties each decision to the exact file contents.

Security Considerations:
- No network calls; local execution only.
- Treats all inputs as untrusted and enforces size limits. MVP limits: scanner input file size ≤ 50 MiB per file; total scanner input ≤ 100 MiB; policy file ≤ 1 MiB; accepted risk file ≤ 1 MiB; context file ≤ 256 KiB; max finding count per scan ≤ 10,000. Exceeding any limit is a fatal error (fail-closed per stage).

## ingest/trivy
Purpose:
- Parse Trivy JSON outputs and extract raw findings and metadata.
- Hash inputs (SHA-256) for traceability.

Inputs and Outputs:
- Inputs: local Trivy JSON file(s) or stdin stream.
- Outputs: raw findings list, scan metadata, input_sha256.

Public Interfaces:
- Accepts file paths or stdin; records `source_scanner=trivy` and any provided metadata.
- When `source_version` is missing, immediately normalize it to the deterministic sentinel (e.g., `"unknown"`), persist that value in every normalized finding, and emit a `context.source_version_missing` `decision_trace` event that references the input path/stream so downstream scoring sees the canonical version and the incident remains auditable.

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
- If domain cannot be mapped, emit the synthetic `UNKNOWN_DOMAIN_MAPPING` hard-stop condition as defined in `docs/md/core-decision-engine.md` under **“Hard-Stop Conditions (Authoritative)”**, implemented as a normalized finding with `title=UNKNOWN_DOMAIN_MAPPING`, `domain=CONFIG`, and `severity=HIGH`. Record the raw domain value in decision_trace.

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
- No policy rule can override hard-stop conditions.
- The exhaustive set of hard-stop conditions is defined authoritatively in
  `docs/md/core-decision-engine.md` under **“Hard-Stop Conditions (Authoritative)”**; all of
  these conditions bypass noise budget, cannot be suppressed, and always force BLOCK.

## decision_trace
Purpose:
- Maintain an ordered, append-only trace of ingest, normalize, score, and policy events.

Inputs and Outputs:
- Inputs: module events, hashes, normalized findings, scoring details.
- Outputs: decision_trace array embedded in report.json (and optional standalone file).

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
- Accepted risk parse/shape/validation failure (malformed file, missing required fields,
  invalid enum values) is a fatal error and follows "Fatal Errors and Fail-Closed Defaults
  (Authoritative)" above.
- Records that are schema-valid but **governance-invalid** (for example, attempting to
  apply effects to hard-stop domains, omitting a canonical fingerprint in
  finding_selector, or declaring allow_warn_in_prod=true without required approvals)
  MUST be ignored for suppression and coverage purposes, but recorded as governance
  warnings in `decision_trace` with risk_id and reason.
- Expired Accepted Risks are treated as INVALID for governance effects and gating (never
  considered active for suppression or prod WARN coverage).
- Additionally, expiry escalation is enforced deterministically:
  - stage=pr/main: if an expired Accepted Risk would have matched a HIGH/CRITICAL finding, the final outcome is at least WARN (do not silently ignore; record governance.expired).
  - stage=release/prod: if an expired Accepted Risk would have matched a HIGH/CRITICAL finding, the final outcome is BLOCK (fail-closed), even if other factors would allow WARN/ALLOW).
- Expired Accepted Risks never apply to hard-stop findings or conditions (unchanged).

Logging and Traceability:
- Records accepted risk IDs, scope checks, and expiry handling in decision_trace.

Security Considerations:
- No accepted risk can suppress hard-stop findings or conditions.

## report
Purpose:
- Generate report.json and optional HTML report.

Inputs and Outputs:
- Inputs: decision object, findings summary, decision_trace.
- Outputs: files written to output directory.

Public Interfaces:
- Emits report.json with the authoritative schema; HTML is optional for humans.

Error Handling:
- Schema validation failure for report.json is a fatal error.

Logging and Traceability:
- Report files include references to input hashes and policy version.

Security Considerations:
- Ensure reports do not include raw secrets or unredacted evidence.

## llm (optional, local only)
Purpose:
- Generate non-authoritative explanations and remediation guidance.

Inputs and Outputs:
- Inputs: sanitized decision_trace, deterministic recommended_next_steps.
- Outputs: explanation text and content_ref in report.json.

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
