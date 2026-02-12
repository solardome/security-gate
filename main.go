package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/solardome/security-gate/internal/domain"

	"github.com/solardome/security-gate/internal/ingest/trivy"
	"github.com/solardome/security-gate/internal/policy"
	"github.com/solardome/security-gate/internal/scoring"
)

const (
	schemaVersion            = "1.0"
	toolVersion              = "dev"
	defaultEnvironment       = "dev"
	defaultExposure          = "unknown"
	defaultChangeType        = "unknown"
	emptyAcceptedRisksJSON   = "[]"
	embeddedDefaultPolicyRaw = `{"policy_version":"embedded-default","rules":[],"exceptions":[]}`
	maxContextBytes          = 256 * 1024
	maxPolicyBytes           = 1 * 1024 * 1024
)

type contextPayload struct {
	PipelineStage         string `json:"pipeline_stage"`
	Environment           string `json:"environment"`
	Exposure              string `json:"exposure"`
	ChangeType            string `json:"change_type"`
	ScannerVersion        string `json:"scanner_version,omitempty"`
	ArtifactSigningStatus string `json:"artifact_signing_status,omitempty"`
	ProvenanceLevel       string `json:"provenance_level,omitempty"`
	BranchProtected       *bool  `json:"branch_protected,omitempty"`
}

type decisionReport struct {
	SchemaVersion string `json:"schema_version"`
	ToolVersion   string `json:"tool_version"`
	GeneratedAt   string `json:"generated_at"`
	policy.DecisionArtifact
}

type contextWrapper struct {
	Payload contextPayload `json:"payload"`
}

type stringSliceFlag []string

type codedError struct {
	code string
	err  error
}

func (e codedError) Error() string {
	if e.err == nil {
		return e.code
	}
	return e.err.Error()
}

func (e codedError) Unwrap() error {
	return e.err
}

func (e codedError) ErrorCode() string {
	return e.code
}

func withErrorCode(code string, err error) error {
	return codedError{code: code, err: err}
}

func resolveFatalCode(defaultCode string, err error) string {
	type codeCarrier interface {
		ErrorCode() string
	}
	var coded codeCarrier
	if errors.As(err, &coded) {
		if code := strings.TrimSpace(coded.ErrorCode()); code != "" {
			return code
		}
	}
	return defaultCode
}

func (f *stringSliceFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *stringSliceFlag) Set(value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fmt.Errorf("input path cannot be empty")
	}
	*f = append(*f, trimmed)
	return nil
}

func main() {
	now := time.Now().UTC()
	cfg, err := parseCLI(now)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid arguments: %v\n", err)
		os.Exit(2)
	}

	ctxPayload, contextHash, err := loadContext(cfg.contextPath)
	if err != nil {
		fatalExit(now, cfg.outputDir, policy.StagePR, false, resolveFatalCode("CONTEXT_LOAD_FAILED", err), "context", err, contextPayload{}, "", "", "", nil, nil)
	}
	declaredStage := strings.TrimSpace(ctxPayload.PipelineStage)
	stage := policy.StagePR
	if declaredStage != "" {
		stage, err = parseStage(ctxPayload.PipelineStage)
		if err != nil {
			overrideStage, parseErr := parseStage(strings.TrimSpace(cfg.stageOverride))
			if parseErr == nil {
				stage = overrideStage
			}
			fatalExit(now, cfg.outputDir, stage, false, resolveFatalCode("CONTEXT_STAGE_INVALID", err), "context.pipeline_stage", err, ctxPayload, contextHash, "", "", nil, nil)
		}
	}
	if strings.TrimSpace(cfg.stageOverride) != "" {
		stage, err = parseStage(cfg.stageOverride)
		if err != nil {
			fatalExit(now, cfg.outputDir, stage, false, resolveFatalCode("CLI_STAGE_INVALID", err), "cli.--stage", err, ctxPayload, contextHash, "", "", nil, nil)
		}
	}
	ctxPayload.PipelineStage = string(stage)

	ingestPaths := append([]string{}, cfg.inputs...)
	if cfg.useStdin {
		ingestPaths = append(ingestPaths, "-")
	}
	ingestResult, err := trivy.Ingest(context.Background(), trivy.Stage(stage), ingestPaths)
	if err != nil {
		fatalExit(now, cfg.outputDir, stage, false, resolveFatalCode("INGEST_FAILED", err), "scan_input", err, ctxPayload, contextHash, "", "", nil, nil)
	}

	scanMetadata := buildScanMetadata(ingestResult.Findings, ingestResult.InputHashes)
	scanTimestamp := firstScanTimestamp(ingestResult.Findings, now)
	trustCtx := buildTrustContext(ctxPayload, scanMetadata, scanTimestamp)
	scoreResult := scoring.Score(ingestResult.Findings, trustCtx, now)
	if strings.TrimSpace(cfg.stageOverride) != "" && declaredStage != "" && !strings.EqualFold(declaredStage, cfg.stageOverride) {
		scoreResult.Trace = append(scoreResult.Trace, trivy.TraceEvent{
			Timestamp: now,
			Type:      "context.stage_override",
			Message:   "CLI stage override applied",
			Details: map[string]any{
				"context_stage": strings.ToLower(strings.TrimSpace(declaredStage)),
				"cli_stage":     strings.ToLower(strings.TrimSpace(cfg.stageOverride)),
				"effective":     string(stage),
			},
		})
	}

	effectivePolicy := policy.Policy{
		PolicyVersion: "embedded-default",
		Rules:         []policy.Rule{},
		Exceptions:    []policy.Exception{},
	}
	policyHash := hashBytes([]byte(embeddedDefaultPolicyRaw))
	if cfg.policyPath != "" {
		effectivePolicy, policyHash, err = loadPolicy(cfg.policyPath)
		if err != nil {
			fatalExit(now, cfg.outputDir, stage, true, resolveFatalCode("POLICY_LOAD_FAILED", err), "policy", err, ctxPayload, contextHash, policyHash, "", ingestResult.InputHashes, scanMetadataForFatal(ingestResult.Findings, ingestResult.InputHashes))
		}
	}

	acceptedRisks := []policy.AcceptedRisk(nil)
	acceptedRiskHash := hashBytes([]byte(emptyAcceptedRisksJSON))
	if cfg.acceptedRiskPath != "" {
		acceptedRisks, acceptedRiskHash, err = policy.LoadAcceptedRisks(cfg.acceptedRiskPath)
		if err != nil {
			fatalExit(now, cfg.outputDir, stage, true, resolveFatalCode("ACCEPTED_RISK_LOAD_FAILED", err), "accepted_risks", err, ctxPayload, contextHash, policyHash, acceptedRiskHash, ingestResult.InputHashes, scanMetadataForFatal(ingestResult.Findings, ingestResult.InputHashes))
		}
	}

	artifact, err := policy.Evaluate(policy.EvaluationInput{
		Stage:       stage,
		Environment: ctxPayload.Environment,
		Exposure:    ctxPayload.Exposure,
		ChangeType:  ctxPayload.ChangeType,
		ContextPayload: policy.ContextPayload{
			PipelineStage:         ctxPayload.PipelineStage,
			Environment:           ctxPayload.Environment,
			Exposure:              ctxPayload.Exposure,
			ChangeType:            ctxPayload.ChangeType,
			ScannerVersion:        ctxPayload.ScannerVersion,
			ArtifactSigningStatus: ctxPayload.ArtifactSigningStatus,
			ProvenanceLevel:       ctxPayload.ProvenanceLevel,
			BranchProtected:       ctxPayload.BranchProtected,
		},
		ContextHash:      contextHash,
		PolicyHash:       policyHash,
		AcceptedRiskHash: acceptedRiskHash,
		ScanHashes:       ingestResult.InputHashes,
		ScanMetadata:     scanMetadata,
		Policy:           effectivePolicy,
		ScoreResult:      scoreResult,
		AcceptedRisks:    acceptedRisks,
		Now:              now,
		LLMEnabled:       cfg.llmEnabled,
	})
	if err != nil {
		fatalExit(now, cfg.outputDir, stage, true, resolveFatalCode("POLICY_EVALUATION_FAILED", err), "policy_evaluator", err, ctxPayload, contextHash, policyHash, acceptedRiskHash, ingestResult.InputHashes, scanMetadata)
	}

	report := decisionReport{
		SchemaVersion:    schemaVersion,
		ToolVersion:      toolVersion,
		GeneratedAt:      now.Format(time.RFC3339),
		DecisionArtifact: artifact,
	}

	outputDir := cfg.outputDir
	if outputDir == "" {
		outputDir = filepath.Join("reports", now.Format("20060102-150405"))
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		fatalExit(now, outputDir, stage, true, resolveFatalCode("OUTPUT_DIR_CREATE_FAILED", err), "output_dir", err, ctxPayload, contextHash, policyHash, acceptedRiskHash, ingestResult.InputHashes, scanMetadata)
	}

	decisionPath := filepath.Join(outputDir, "decision.json")
	if err := writeJSON(decisionPath, report); err != nil {
		fatalExit(now, outputDir, stage, true, resolveFatalCode("DECISION_WRITE_FAILED", err), "decision.json", err, ctxPayload, contextHash, policyHash, acceptedRiskHash, ingestResult.InputHashes, scanMetadata)
	}

	summaryPath := filepath.Join(outputDir, "summary.md")
	if err := os.WriteFile(summaryPath, []byte(buildSummary(artifact, ingestPaths)), 0o644); err != nil {
		fatalExit(now, outputDir, stage, true, resolveFatalCode("SUMMARY_WRITE_FAILED", err), "summary.md", err, ctxPayload, contextHash, policyHash, acceptedRiskHash, ingestResult.InputHashes, scanMetadata)
	}

	htmlPath := ""
	if cfg.reportHTML {
		htmlPath = filepath.Join(outputDir, "report.html")
		if err := writeHTMLReport(htmlPath, artifact, ingestPaths); err != nil {
			fatalExit(now, outputDir, stage, true, resolveFatalCode("HTML_WRITE_FAILED", err), "report.html", err, ctxPayload, contextHash, policyHash, acceptedRiskHash, ingestResult.InputHashes, scanMetadata)
		}
	}

	fmt.Printf("Report generated.\n- Decision JSON: %s\n- Summary: %s\n", decisionPath, summaryPath)
	if htmlPath != "" {
		fmt.Printf("- HTML: %s\n", htmlPath)
	}
	os.Exit(artifact.Decision.ExitCode)
}

func firstScanTimestamp(findings []trivy.CanonicalFinding, fallback time.Time) time.Time {
	for _, finding := range findings {
		if !finding.ScanTimestamp.IsZero() {
			return finding.ScanTimestamp
		}
	}
	return fallback
}

func buildScanMetadata(findings []trivy.CanonicalFinding, hashes map[string]string) map[string]policy.ScanMetadata {
	meta := make(map[string]policy.ScanMetadata, len(hashes))
	for path := range hashes {
		meta[path] = policy.ScanMetadata{
			SourceScanner: "trivy",
			SourceVersion: "unknown",
			ScanTimestamp: "",
		}
	}

	for _, finding := range findings {
		for path, hash := range hashes {
			if finding.InputSHA256 != hash {
				continue
			}
			entry := meta[path]
			if strings.TrimSpace(entry.SourceScanner) == "" && strings.TrimSpace(finding.SourceScanner) != "" {
				entry.SourceScanner = finding.SourceScanner
			}
			if entry.SourceVersion == "unknown" && strings.TrimSpace(finding.SourceVersion) != "" {
				entry.SourceVersion = finding.SourceVersion
			}
			if entry.ScanTimestamp == "" && !finding.ScanTimestamp.IsZero() {
				entry.ScanTimestamp = finding.ScanTimestamp.Format(time.RFC3339)
			}
			meta[path] = entry
		}
	}

	return meta
}

func scanMetadataForFatal(findings []trivy.CanonicalFinding, hashes map[string]string) map[string]policy.ScanMetadata {
	if len(hashes) == 0 {
		return map[string]policy.ScanMetadata{}
	}
	return buildScanMetadata(findings, hashes)
}

func fatalExit(now time.Time, outputDir string, stage policy.Stage, scannerHashable bool, errorCode, affectedInput string, cause error, ctx contextPayload, contextHash, policyHash, acceptedRiskHash string, scanHashes map[string]string, scanMetadata map[string]policy.ScanMetadata) {
	decisionStatus := domain.DecisionBlock
	exitCode := 2
	if stage == policy.StagePR && scannerHashable {
		decisionStatus = domain.DecisionWarn
		exitCode = 1
	}

	if strings.TrimSpace(outputDir) == "" {
		outputDir = filepath.Join("reports", now.Format("20060102-150405"))
	}
	if strings.TrimSpace(ctx.PipelineStage) == "" {
		ctx.PipelineStage = string(stage)
	}
	if strings.TrimSpace(ctx.Environment) == "" {
		ctx.Environment = defaultEnvironment
	}
	if strings.TrimSpace(ctx.Exposure) == "" {
		ctx.Exposure = defaultExposure
	}
	if strings.TrimSpace(ctx.ChangeType) == "" {
		ctx.ChangeType = defaultChangeType
	}
	if strings.TrimSpace(contextHash) == "" {
		if hash, err := hashJSON(ctx); err == nil {
			contextHash = hash
		}
	}
	if strings.TrimSpace(policyHash) == "" {
		policyHash = hashBytes([]byte(embeddedDefaultPolicyRaw))
	}
	if strings.TrimSpace(acceptedRiskHash) == "" {
		acceptedRiskHash = hashBytes([]byte(emptyAcceptedRisksJSON))
	}
	if scanHashes == nil {
		scanHashes = map[string]string{}
	}
	if scanMetadata == nil {
		scanMetadata = map[string]policy.ScanMetadata{}
	}

	scans := make([]policy.ScanInput, 0, len(scanHashes))
	for path, hash := range scanHashes {
		meta := scanMetadata[path]
		sourceScanner := strings.TrimSpace(meta.SourceScanner)
		if sourceScanner == "" {
			sourceScanner = "trivy"
		}
		scans = append(scans, policy.ScanInput{
			SourceScanner: sourceScanner,
			SourceVersion: meta.SourceVersion,
			InputSHA256:   hash,
			ScanTimestamp: meta.ScanTimestamp,
			Path:          path,
		})
	}
	sort.Slice(scans, func(i, j int) bool { return scans[i].Path < scans[j].Path })

	traceEvent := policy.DecisionTraceEvent{
		EventID:   fmt.Sprintf("evt-%d", now.UnixNano()),
		Timestamp: now,
		Type:      "error.fatal",
		Details: map[string]any{
			"error_code":     errorCode,
			"affected_input": affectedInput,
			"message":        cause.Error(),
		},
	}

	artifact := policy.DecisionArtifact{
		Inputs: policy.DecisionInputs{
			Scans: scans,
			Context: policy.ContextRef{
				InputRef: policy.InputRef{
					SHA256: contextHash,
					Source: "context",
				},
				Payload: policy.ContextPayload{
					PipelineStage:         ctx.PipelineStage,
					Environment:           ctx.Environment,
					Exposure:              ctx.Exposure,
					ChangeType:            ctx.ChangeType,
					ScannerVersion:        ctx.ScannerVersion,
					ArtifactSigningStatus: ctx.ArtifactSigningStatus,
					ProvenanceLevel:       ctx.ProvenanceLevel,
					BranchProtected:       ctx.BranchProtected,
				},
			},
			Policy: policy.InputRef{
				SHA256: policyHash,
				Source: "policy",
			},
			AcceptedRisks: policy.InputRef{
				SHA256: acceptedRiskHash,
				Source: "accepted_risks",
			},
		},
		Trust: policy.TrustResult{
			TrustScore:    0,
			TrustModifier: 15,
		},
		Findings: policy.FindingsSummary{
			TotalCount:      0,
			HardStopCount:   0,
			ConsideredCount: 0,
			Items:           []scoring.ScoredFinding{},
		},
		Scoring: policy.ScoringSummary{
			ReleaseRisk: 100,
			Modifiers: policy.Modifiers{
				TrustModifier: 15,
			},
		},
		Decision: policy.PolicyDecision{
			Status:    decisionStatus,
			ExitCode:  exitCode,
			Rationale: fmt.Sprintf("fatal error: %s", errorCode),
		},
		Policy: policy.PolicyEvaluation{
			EvaluatedRules:         []string{},
			ExceptionsApplied:      []string{},
			AcceptedRisksApplied:   []string{},
			AcceptedRisksCoverage:  map[string][]string{},
			AllowWarnInProdApplied: false,
			PolicyVersion:          "fatal",
		},
		RecommendedSteps: nil,
		Trace: policy.DecisionTrace{
			Events: []policy.DecisionTraceEvent{traceEvent},
		},
		LLMExplanation: policy.LLMExplanation{
			Enabled:          false,
			NonAuthoritative: true,
			ContentRef:       "",
			References:       nil,
		},
	}

	report := decisionReport{
		SchemaVersion:    schemaVersion,
		ToolVersion:      toolVersion,
		GeneratedAt:      now.Format(time.RFC3339),
		DecisionArtifact: artifact,
	}

	if err := os.MkdirAll(outputDir, 0o755); err == nil {
		decisionPath := filepath.Join(outputDir, "decision.json")
		if writeErr := writeJSON(decisionPath, report); writeErr == nil {
			fmt.Fprintf(os.Stderr, "fatal error artifact written: %s\n", decisionPath)
		}
	}

	fmt.Fprintf(os.Stderr, "fatal error (%s): %v\n", errorCode, cause)
	os.Exit(exitCode)
}

func hashJSON(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return hashBytes(raw), nil
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func writeJSON(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0o644)
}

func buildSummary(artifact policy.DecisionArtifact, inputPaths []string) string {
	var b strings.Builder
	b.WriteString("# security-gate summary\n\n")
	b.WriteString(fmt.Sprintf("- Inputs: `%s`\n", strings.Join(inputPaths, ", ")))
	b.WriteString(fmt.Sprintf("- Decision: **%s** (exit_code=%d)\n", artifact.Decision.Status, artifact.Decision.ExitCode))
	b.WriteString(fmt.Sprintf("- Release risk: %d\n", artifact.Scoring.ReleaseRisk))
	b.WriteString(fmt.Sprintf("- Trust score: %d\n", artifact.Trust.TrustScore))
	b.WriteString(fmt.Sprintf("- Findings: %d total, %d hard-stop, %d considered\n\n", artifact.Findings.TotalCount, artifact.Findings.HardStopCount, artifact.Findings.ConsideredCount))

	if len(artifact.RecommendedSteps) > 0 {
		b.WriteString("## Recommended Next Steps\n")
		for _, step := range artifact.RecommendedSteps {
			b.WriteString(fmt.Sprintf("- `%s`\n", step))
		}
		b.WriteString("\n")
	}

	b.WriteString("## Issue Statuses\n")
	b.WriteString("| finding_id | fingerprint | domain | severity | risk_score | status |\n")
	b.WriteString("|---|---|---|---|---:|---|\n")
	for _, finding := range artifact.Findings.Items {
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %d | %s |\n",
			finding.Finding.FindingID,
			finding.Finding.Fingerprint,
			finding.Finding.Domain,
			finding.Finding.Severity,
			finding.RiskScore,
			issueStatus(finding),
		))
	}

	return b.String()
}

func issueStatus(f scoring.ScoredFinding) string {
	switch {
	case f.HardStop:
		return string(domain.DecisionBlock)
	case f.SuppressedByAcceptedRisk || f.SuppressedByException || f.SuppressedByNoiseBudget:
		return "SUPPRESSED"
	default:
		return "CONSIDERED"
	}
}

type cliConfig struct {
	inputs           []string
	useStdin         bool
	contextPath      string
	policyPath       string
	acceptedRiskPath string
	outputDir        string
	stageOverride    string
	reportHTML       bool
	llmEnabled       bool
}

func parseCLI(now time.Time) (cliConfig, error) {
	var cfg cliConfig
	var inputFlags stringSliceFlag
	var llmFlag string

	flag.Var(&inputFlags, "input", "path to Trivy JSON input (repeatable)")
	flag.BoolVar(&cfg.useStdin, "stdin", false, "read Trivy JSON from stdin")
	flag.StringVar(&cfg.contextPath, "context", "", "path to context JSON")
	flag.StringVar(&cfg.policyPath, "policy", "", "path to policy JSON")
	flag.StringVar(&cfg.acceptedRiskPath, "accepted-risk", "", "path to accepted risks JSON")
	flag.StringVar(&cfg.outputDir, "output-dir", filepath.Join("reports", now.Format("20060102-150405")), "output directory for reports")
	flag.StringVar(&cfg.stageOverride, "stage", "", "pipeline stage override: pr|main|release|prod")
	flag.BoolVar(&cfg.reportHTML, "report-html", false, "emit optional static HTML report")
	flag.StringVar(&llmFlag, "llm", "off", "LLM mode: on|off")
	flag.Parse()

	if len(flag.Args()) > 0 {
		return cfg, fmt.Errorf("unexpected positional arguments: %s", strings.Join(flag.Args(), " "))
	}
	if len(inputFlags) == 0 && !cfg.useStdin {
		return cfg, fmt.Errorf("provide at least one --input or --stdin")
	}

	cfg.inputs = append(cfg.inputs, inputFlags...)
	for _, path := range cfg.inputs {
		if _, err := os.Stat(path); err != nil {
			return cfg, fmt.Errorf("cannot access --input %q: %w", path, err)
		}
	}

	switch strings.ToLower(strings.TrimSpace(llmFlag)) {
	case "on":
		cfg.llmEnabled = true
	case "off":
		cfg.llmEnabled = false
	default:
		return cfg, fmt.Errorf("--llm must be one of: on, off")
	}

	return cfg, nil
}

func parseStage(raw string) (policy.Stage, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "pr":
		return policy.StagePR, nil
	case "main":
		return policy.StageMain, nil
	case "release":
		return policy.StageRelease, nil
	case "prod":
		return policy.StageProd, nil
	default:
		return "", fmt.Errorf("unknown stage %q (expected pr|main|release|prod)", raw)
	}
}

func loadContext(path string) (contextPayload, string, error) {
	if strings.TrimSpace(path) == "" {
		payload := contextPayload{
			PipelineStage: string(policy.StagePR),
			Environment:   defaultEnvironment,
			Exposure:      defaultExposure,
			ChangeType:    defaultChangeType,
		}
		hash, err := hashJSON(payload)
		return payload, hash, err
	}
	if stat, err := os.Stat(path); err == nil && stat.Size() > maxContextBytes {
		return contextPayload{}, "", withErrorCode("CONTEXT_TOO_LARGE", fmt.Errorf("context file too large: %d bytes (max %d)", stat.Size(), maxContextBytes))
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return contextPayload{}, "", fmt.Errorf("read context file %s: %w", path, err)
	}

	payload := contextPayload{}
	wrapper := contextWrapper{}
	if err := json.Unmarshal(raw, &wrapper); err == nil && wrapper.Payload != (contextPayload{}) {
		payload = wrapper.Payload
	} else if err := json.Unmarshal(raw, &payload); err != nil {
		return contextPayload{}, "", fmt.Errorf("parse context file %s: %w", path, err)
	}

	if strings.TrimSpace(payload.Environment) == "" {
		payload.Environment = defaultEnvironment
	}
	if strings.TrimSpace(payload.Exposure) == "" {
		payload.Exposure = defaultExposure
	}
	if strings.TrimSpace(payload.ChangeType) == "" {
		payload.ChangeType = defaultChangeType
	}

	return payload, hashBytes(raw), nil
}

func loadPolicy(path string) (policy.Policy, string, error) {
	if stat, err := os.Stat(path); err == nil && stat.Size() > maxPolicyBytes {
		return policy.Policy{}, "", withErrorCode("POLICY_TOO_LARGE", fmt.Errorf("policy file too large: %d bytes (max %d)", stat.Size(), maxPolicyBytes))
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return policy.Policy{}, "", fmt.Errorf("read policy file %s: %w", path, err)
	}

	var loaded policy.Policy
	if err := json.Unmarshal(raw, &loaded); err != nil {
		return policy.Policy{}, "", fmt.Errorf("parse policy file %s: %w", path, err)
	}
	if strings.TrimSpace(loaded.PolicyVersion) == "" {
		loaded.PolicyVersion = "unknown"
	}
	if loaded.Rules == nil {
		loaded.Rules = []policy.Rule{}
	}
	if loaded.Exceptions == nil {
		loaded.Exceptions = []policy.Exception{}
	}

	return loaded, hashBytes(raw), nil
}

func buildTrustContext(ctx contextPayload, scanMetadata map[string]policy.ScanMetadata, scanTimestamp time.Time) scoring.TrustContext {
	expectedVersion := strings.TrimSpace(ctx.ScannerVersion)
	scannerPinned := false
	if expectedVersion != "" && len(scanMetadata) > 0 {
		scannerPinned = true
		for _, meta := range scanMetadata {
			if !strings.EqualFold(strings.TrimSpace(meta.SourceVersion), expectedVersion) {
				scannerPinned = false
				break
			}
		}
	}

	signingStatus := strings.ToLower(strings.TrimSpace(ctx.ArtifactSigningStatus))
	if signingStatus == "" {
		signingStatus = "unknown"
	}
	provenanceLevel := strings.ToLower(strings.TrimSpace(ctx.ProvenanceLevel))
	if provenanceLevel == "" {
		provenanceLevel = "unknown"
	}

	return scoring.TrustContext{
		ScannerPinned:         scannerPinned,
		ScanTimestamp:         &scanTimestamp,
		InputIntegrityStatus:  "verified",
		ArtifactSigningStatus: signingStatus,
		ProvenanceLevel:       provenanceLevel,
		BuildContextProtected: ctx.BranchProtected,
	}
}

func writeHTMLReport(path string, artifact policy.DecisionArtifact, inputPaths []string) error {
	tmpl := template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>security-gate report</title></head>
<body>
<h1>security-gate report</h1>
<p><strong>Inputs:</strong> {{.Inputs}}</p>
<p><strong>Decision:</strong> {{.Decision}} (exit_code={{.ExitCode}})</p>
<p><strong>Release risk:</strong> {{.ReleaseRisk}}</p>
<p><strong>Trust score:</strong> {{.TrustScore}}</p>
<p><strong>Findings:</strong> {{.TotalFindings}} total, {{.HardStops}} hard-stop, {{.Considered}} considered</p>
</body>
</html>`))

	data := struct {
		Inputs        string
		Decision      string
		ExitCode      int
		ReleaseRisk   int
		TrustScore    int
		TotalFindings int
		HardStops     int
		Considered    int
	}{
		Inputs:        strings.Join(inputPaths, ", "),
		Decision:      string(artifact.Decision.Status),
		ExitCode:      artifact.Decision.ExitCode,
		ReleaseRisk:   artifact.Scoring.ReleaseRisk,
		TrustScore:    artifact.Trust.TrustScore,
		TotalFindings: artifact.Findings.TotalCount,
		HardStops:     artifact.Findings.HardStopCount,
		Considered:    artifact.Findings.ConsideredCount,
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, data)
}
