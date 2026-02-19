# Modules

Module contracts below are implementation-facing and align to authoritative logic in:
- `docs/md/core-decision-engine.md`
- `docs/md/policy-format.md`

## Module: `cmd/cli`

Purpose:
- Entry point for local execution.
- Parse flags/paths and orchestrate engine pipeline.

Inputs:
- paths: scanner JSON files, optional baseline scanner JSON files, policy YAML, optional context YAML, optional accepted-risk YAML
- runtime flags (for example output path, llm mode)
- context mode: explicit context YAML or deterministic CI environment auto-detection
- optional baseline diff mode: score only findings not present in baseline (`pr`/`merge` only)

Outputs:
- process exit code (`0|1|2`)
- writes `report.json` and optional `report.html`

Conceptual interfaces:
- `Run(args) -> (decision, exit_code, report_path, err)`

Error handling:
- converts internal validation/processing errors into stage-aware final status
- guarantees report emission when possible

Logging:
- start/end, input count, effective stage, decision summary
- no secret leakage; no raw full finding dumps at info level
- write structured JSON-lines run audit log (`security-gate.run.log`)

Security considerations:
- reject unknown flags in strict mode
- sanitize file path logging
- never execute scanner-provided content

## Module: `ingest/*` adapters

Purpose:
- Parse scanner-specific JSON outputs into intermediate adapter model.
- Current adapters:
  - `ingest/trivy` (Trivy JSON)
  - `ingest/sarif` (SARIF 2.1.0 JSON)
  - `ingest/snyk` (Snyk vulnerability JSON)
  - `ingest/checkmarx` (Checkmarx JSON v2)
  - `ingest/sonar` (Sonar Generic Issues JSON)

Inputs:
- local scanner JSON file(s)

Outputs:
- adapter findings list with stable source references

Conceptual interfaces:
- `Parse<Adapter>(path) -> ([]AdapterFinding, ParseMetadata, err)`

Error handling:
- strict JSON parsing
- strict adapter-level envelope validation (required sections + schema/version checks where defined)
- clear diagnostics for invalid sections

Logging:
- file path, hash, parsed finding count

Security considerations:
- treat all payload fields as untrusted strings
- enforce maximum file size limits
- parser selection is deterministic and local-only

## Module: `normalize`

Purpose:
- Convert adapter findings into canonical `UnifiedFinding` records.

Inputs:
- scanner adapter findings
- context hints for missing field normalization

Outputs:
- ordered list of `UnifiedFinding`

Conceptual interfaces:
- `Normalize(adapterFindings, context) -> ([]UnifiedFinding, []NormalizationIssue)`

Error handling:
- unknown enum values mapped to canonical `unknown`
- missing identity fields produce deterministic fallback IDs

Logging:
- counts by category/severity and unknown-field counts

Security considerations:
- deterministic mapping only, no heuristic/LLM rewriting
- avoid string-based command interpolation

## Module: `score`

Purpose:
- Compute `FindingRiskScore`, `TrustScore`, and `OverallRiskScore` deterministically.

Inputs:
- active normalized findings
- validated context fields
- trust signals
- policy overlays that affect scoring/tightening

Outputs:
- per-finding scores
- trust object
- overall risk object

Conceptual interfaces:
- `ComputeTrust(context, metadata, policy) -> TrustResult`
- `ScoreFindings(findings, context, policy) -> []ScoredFinding`
- `AggregateOverall(scoredFindings, context, trust, policy) -> OverallRisk`

Error handling:
- numeric overflow guarded and clamped
- missing required scoring inputs routed to validation status logic

Logging:
- trust penalties applied, top findings, final risk score

Security considerations:
- monotonic scoring guarantees
- no negative risk modifiers from unknown signals

## Module: `policy`

Purpose:
- Parse and validate policy YAML; evaluate stage-aware rule effects.

Inputs:
- `.security-gate/policy.yaml`

Outputs:
- validated policy object
- deterministic resolved adjustments for current run

Conceptual interfaces:
- `LoadPolicy(path) -> (Policy, err)`
- `ResolvePolicy(policy, context) -> PolicyResolution`

Error handling:
- unknown/duplicate fields and invalid versions are hard errors
- deterministic rule conflict resolution
- schema diagnostics should include file, field path, and line number

Logging:
- policy_id, schema_version, enabled rules, resolved effects

Security considerations:
- strict schema mode
- no dynamic includes or remote references in MVP

## Module: `decision_trace`

Purpose:
- Record ordered, machine-readable explanations for each phase.

Inputs:
- per-phase results from ingest/normalize/governance/score/decision

Outputs:
- ordered trace entries in `report.json`

Conceptual interfaces:
- `AppendPhase(order, phase, result, details)`
- `Finalize() -> []TraceEntry`

Error handling:
- trace write failures should not silently drop mandatory phases

Logging:
- phase completion events (debug level)

Security considerations:
- redact or truncate sensitive payload content
- include file hashes, not full file contents

## Module: `governance`

Purpose:
- Load, validate, and apply Accepted Risk records.

Inputs:
- accepted-risk YAML
- policy exception rules
- normalized findings and effective stage

Outputs:
- accepted/rejected record decisions
- invalid/expired diagnostics
- per-finding accepted flags

Conceptual interfaces:
- `LoadAcceptedRisk(path) -> (AcceptedRiskSet, err)`
- `ApplyAcceptedRisk(findings, acceptedRisk, context, policy) -> GovernanceResult`

Error handling:
- invalid or expired records feed stage-aware fail behavior
- YAML schema errors should include file, field path, and line number

Logging:
- records evaluated/applied/invalid and expiry horizon warnings

Security considerations:
- hard-stop findings cannot be accepted
- approval signatures/identities validated offline via local data

## Module: `report`

Purpose:
- Emit authoritative JSON and derived HTML summaries.

Inputs:
- final decision state, trace, scored findings, governance outputs

Outputs:
- `report.json`
- `report.html` (optional)
- `checksums.sha256`
- `security-gate.run.log`

Conceptual interfaces:
- `WriteJSON(report, path) -> err`
- `WriteHTML(report, path) -> err`
- `WriteChecksums(paths, outputPath) -> err`
- `AppendRunAuditEvent(event, fields) -> err`

Error handling:
- JSON output failure is fatal
- HTML output failure does not change decision/exit code if JSON succeeded

Logging:
- output paths, bytes written, render mode

Security considerations:
- escape rendered content in HTML
- mark non-authoritative sections clearly

## Acceptance Criteria Checklist

- [ ] All required modules are defined with clear purposes.
- [ ] Inputs/outputs are explicit and stage-compatible.
- [ ] Conceptual interfaces are specified for each module.
- [ ] Error handling behavior is defined per module.
- [ ] Logging expectations are documented with security hygiene.
- [ ] Security considerations are included for each module.
