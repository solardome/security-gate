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
	"io"
	"log/slog"
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
	defaultReportsDir        = "reports"
	defaultLogsDir           = "logs"
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

type fatalHandler struct {
	now              time.Time
	outputDir        string
	stage            policy.Stage
	scannerHashable  bool
	ctx              contextPayload
	contextHash      string
	policyHash       string
	acceptedRiskHash string
	scanHashes       map[string]string
	scanMetadata     map[string]policy.ScanMetadata
	logger           *runLogger
}

type fatalSnapshot struct {
	outputDir        string
	ctx              contextPayload
	contextHash      string
	policyHash       string
	acceptedRiskHash string
	scanHashes       map[string]string
	scanMetadata     map[string]policy.ScanMetadata
	decisionStatus   domain.DecisionType
	exitCode         int
}

type runLogger struct {
	base *slog.Logger
	file *os.File
	path string
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
	cfg, err := parseCLI()
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid arguments: %v\n", err)
		os.Exit(2)
	}
	logger, err := initRunLogger(now)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logger init failed: %v\n", err)
		os.Exit(2)
	}
	defer logger.close()
	logger.info("run.start", "inputs", len(cfg.inputs), "stdin", cfg.useStdin, "report_html", cfg.reportHTML, "llm", cfg.llmEnabled)

	fatalState := fatalHandler{
		now:       now,
		outputDir: cfg.outputDir,
		stage:     policy.StagePR,
		logger:    logger,
	}

	ctxPayload, contextHash, err := loadContext(cfg.contextPath)
	if err != nil {
		fatalState.fail("CONTEXT_LOAD_FAILED", "context", err)
	}
	logger.info("context.loaded", "context_hash", contextHash)
	fatalState.ctx = ctxPayload
	fatalState.contextHash = contextHash

	stage, declaredStage, err := resolveStage(ctxPayload, cfg.stageOverride)
	if err != nil {
		affected := "context.pipeline_stage"
		if resolveFatalCode("", err) == "CLI_STAGE_INVALID" {
			affected = "cli.--stage"
		}
		fatalState.stage = stage
		fatalState.fail("CONTEXT_STAGE_INVALID", affected, err)
	}
	ctxPayload.PipelineStage = string(stage)
	fatalState.ctx = ctxPayload
	fatalState.stage = stage

	ingestPaths := append([]string{}, cfg.inputs...)
	if cfg.useStdin {
		ingestPaths = append(ingestPaths, "-")
	}
	ingestResult, err := trivy.Ingest(context.Background(), trivy.Stage(stage), ingestPaths)
	if err != nil {
		fatalState.fail("INGEST_FAILED", "scan_input", err)
	}
	logger.info("ingest.completed", "findings", len(ingestResult.Findings), "scan_inputs", len(ingestResult.InputHashes))
	fatalState.scannerHashable = true
	fatalState.scanHashes = ingestResult.InputHashes

	scanMetadata := buildScanMetadata(ingestResult.Findings, ingestResult.InputHashes)
	fatalState.scanMetadata = scanMetadata
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

	effectivePolicy, policyHash, err := loadEffectivePolicy(cfg.policyPath)
	if err != nil {
		fatalState.policyHash = policyHash
		fatalState.scanMetadata = scanMetadataForFatal(ingestResult.Findings, ingestResult.InputHashes)
		fatalState.fail("POLICY_LOAD_FAILED", "policy", err)
	}
	fatalState.policyHash = policyHash
	logger.info("policy.loaded", "policy_version", effectivePolicy.PolicyVersion, "policy_hash", policyHash)

	acceptedRisks, acceptedRiskHash, err := loadAcceptedRisks(cfg.acceptedRiskPath)
	if err != nil {
		fatalState.acceptedRiskHash = acceptedRiskHash
		fatalState.scanMetadata = scanMetadataForFatal(ingestResult.Findings, ingestResult.InputHashes)
		fatalState.fail("ACCEPTED_RISK_LOAD_FAILED", "accepted_risks", err)
	}
	fatalState.acceptedRiskHash = acceptedRiskHash
	logger.info("accepted_risks.loaded", "count", len(acceptedRisks), "accepted_risk_hash", acceptedRiskHash)

	resolvedOutputDir := resolveOutputDir(cfg, now, stage, contextHash, policyHash, acceptedRiskHash, ingestResult.InputHashes)
	fatalState.outputDir = resolvedOutputDir
	logger.info("report.output_dir_resolved", "output_dir", resolvedOutputDir)

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
		fatalState.fail("POLICY_EVALUATION_FAILED", "policy_evaluator", err)
	}

	report := decisionReport{
		SchemaVersion:    schemaVersion,
		ToolVersion:      toolVersion,
		GeneratedAt:      now.Format(time.RFC3339),
		DecisionArtifact: artifact,
	}

	decisionPath, htmlPath, checksumsPath, err := writeReports(now, resolvedOutputDir, report, artifact, ingestPaths, cfg.reportHTML)
	if err != nil {
		fatalState.fail("REPORT_WRITE_FAILED", reportWriteAffectedInput(err), err)
	}
	logger.info("report.generated", "decision", artifact.Decision.Status, "exit_code", artifact.Decision.ExitCode, "decision_json", decisionPath, "html", htmlPath, "checksums", checksumsPath)

	fmt.Printf("Report generated.\n- Decision JSON: %s\n- Checksums: %s\n", decisionPath, checksumsPath)
	if htmlPath != "" {
		fmt.Printf("- HTML: %s\n", htmlPath)
	}
	fmt.Printf("- Logs: %s\n", logger.path)
	os.Exit(artifact.Decision.ExitCode)
}

func (h fatalHandler) fail(defaultCode, affectedInput string, err error) {
	resolvedCode := resolveFatalCode(defaultCode, err)
	if h.logger != nil {
		h.logger.error("run.fatal", "error_code", resolvedCode, "affected_input", affectedInput, "error", err.Error())
	}
	fatalExit(
		h.now,
		h.outputDir,
		h.stage,
		h.scannerHashable,
		resolvedCode,
		affectedInput,
		err,
		h.ctx,
		h.contextHash,
		h.policyHash,
		h.acceptedRiskHash,
		h.scanHashes,
		h.scanMetadata,
	)
}

func initRunLogger(now time.Time) (*runLogger, error) {
	if err := os.MkdirAll(defaultLogsDir, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(defaultLogsDir, fmt.Sprintf("security-gate-%s.log", now.Format("20060102-150405")))
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	handler := slog.NewJSONHandler(file, &slog.HandlerOptions{Level: slog.LevelInfo})
	return &runLogger{
		base: slog.New(handler).With("component", "security-gate"),
		file: file,
		path: path,
	}, nil
}

func (l *runLogger) info(msg string, kv ...any) {
	if l == nil || l.base == nil {
		return
	}
	l.base.Info(msg, kv...)
}

func (l *runLogger) error(msg string, kv ...any) {
	if l == nil || l.base == nil {
		return
	}
	l.base.Error(msg, kv...)
}

func (l *runLogger) close() {
	if l == nil || l.file == nil {
		return
	}
	_ = l.file.Close()
}

func reportWriteAffectedInput(err error) string {
	switch resolveFatalCode("", err) {
	case "OUTPUT_DIR_CREATE_FAILED":
		return "output_dir"
	case "DECISION_WRITE_FAILED":
		return "decision.json"
	case "HTML_WRITE_FAILED":
		return "report.html"
	case "CHECKSUMS_WRITE_FAILED":
		return "checksums.sha256"
	default:
		return "report_output"
	}
}

func resolveStage(ctx contextPayload, stageOverride string) (policy.Stage, string, error) {
	declaredStage := strings.TrimSpace(ctx.PipelineStage)
	stage := policy.StagePR
	if declaredStage != "" {
		parsed, err := parseStage(declaredStage)
		if err != nil {
			if overrideStage, parseErr := parseStage(strings.TrimSpace(stageOverride)); parseErr == nil {
				stage = overrideStage
			}
			return stage, declaredStage, withErrorCode("CONTEXT_STAGE_INVALID", err)
		}
		stage = parsed
	}

	if strings.TrimSpace(stageOverride) != "" {
		overrideStage, err := parseStage(stageOverride)
		if err != nil {
			return stage, declaredStage, withErrorCode("CLI_STAGE_INVALID", err)
		}
		stage = overrideStage
	}

	return stage, declaredStage, nil
}

func loadEffectivePolicy(path string) (policy.Policy, string, error) {
	defaultPolicy := policy.Policy{
		PolicyVersion: "embedded-default",
		Rules:         []policy.Rule{},
		Exceptions:    []policy.Exception{},
	}
	defaultHash := hashBytes([]byte(embeddedDefaultPolicyRaw))
	if strings.TrimSpace(path) == "" {
		return defaultPolicy, defaultHash, nil
	}

	loaded, hash, err := loadPolicy(path)
	if err != nil {
		return defaultPolicy, hash, err
	}
	return loaded, hash, nil
}

func loadAcceptedRisks(path string) ([]policy.AcceptedRisk, string, error) {
	defaultHash := hashBytes([]byte(emptyAcceptedRisksJSON))
	if strings.TrimSpace(path) == "" {
		return nil, defaultHash, nil
	}
	loaded, hash, err := policy.LoadAcceptedRisks(path)
	if err != nil {
		return nil, hash, err
	}
	return loaded, hash, nil
}

func resolveOutputDir(cfg cliConfig, now time.Time, stage policy.Stage, contextHash, policyHash, acceptedRiskHash string, scanHashes map[string]string) string {
	if cfg.outputDirExplicit && strings.TrimSpace(cfg.outputDir) != "" {
		return cfg.outputDir
	}
	return filepath.Join(defaultReportsDir, fmt.Sprintf("%s-%s", now.Format("20060102-150405"), buildRunID(stage, contextHash, policyHash, acceptedRiskHash, scanHashes)))
}

func buildRunID(stage policy.Stage, contextHash, policyHash, acceptedRiskHash string, scanHashes map[string]string) string {
	paths := make([]string, 0, len(scanHashes))
	for path := range scanHashes {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	var b strings.Builder
	b.WriteString("stage=")
	b.WriteString(string(stage))
	b.WriteString("|context=")
	b.WriteString(contextHash)
	b.WriteString("|policy=")
	b.WriteString(policyHash)
	b.WriteString("|accepted_risks=")
	b.WriteString(acceptedRiskHash)
	for _, path := range paths {
		b.WriteString("|scan:")
		b.WriteString(path)
		b.WriteString("=")
		b.WriteString(scanHashes[path])
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])[:12]
}

func writeReports(now time.Time, outputDir string, report decisionReport, artifact policy.DecisionArtifact, inputPaths []string, includeHTML bool) (string, string, string, error) {
	if strings.TrimSpace(outputDir) == "" {
		outputDir = filepath.Join(defaultReportsDir, now.Format("20060102-150405"))
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", "", "", withErrorCode("OUTPUT_DIR_CREATE_FAILED", err)
	}

	decisionPath := filepath.Join(outputDir, "decision.json")
	if err := writeJSON(decisionPath, report); err != nil {
		return "", "", "", withErrorCode("DECISION_WRITE_FAILED", err)
	}

	htmlPath := ""
	if includeHTML {
		htmlPath = filepath.Join(outputDir, "report.html")
		if err := writeHTMLReport(htmlPath, artifact, inputPaths); err != nil {
			return "", "", "", withErrorCode("HTML_WRITE_FAILED", err)
		}
	}

	checksumsPath, err := writeReportChecksums(outputDir, decisionPath, htmlPath)
	if err != nil {
		return "", "", "", withErrorCode("CHECKSUMS_WRITE_FAILED", err)
	}

	return decisionPath, htmlPath, checksumsPath, nil
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
	snapshot := buildFatalSnapshot(now, outputDir, stage, scannerHashable, ctx, contextHash, policyHash, acceptedRiskHash, scanHashes, scanMetadata)

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

	artifact := buildFatalArtifact(snapshot, errorCode, traceEvent)

	report := decisionReport{
		SchemaVersion:    schemaVersion,
		ToolVersion:      toolVersion,
		GeneratedAt:      now.Format(time.RFC3339),
		DecisionArtifact: artifact,
	}

	if err := os.MkdirAll(snapshot.outputDir, 0o755); err == nil {
		decisionPath := filepath.Join(snapshot.outputDir, "decision.json")
		if writeErr := writeJSON(decisionPath, report); writeErr == nil {
			fmt.Fprintf(os.Stderr, "fatal error artifact written: %s\n", decisionPath)
		}
	}

	fmt.Fprintf(os.Stderr, "fatal error (%s): %v\n", errorCode, cause)
	os.Exit(snapshot.exitCode)
}

func buildFatalSnapshot(now time.Time, outputDir string, stage policy.Stage, scannerHashable bool, ctx contextPayload, contextHash, policyHash, acceptedRiskHash string, scanHashes map[string]string, scanMetadata map[string]policy.ScanMetadata) fatalSnapshot {
	snapshot := fatalSnapshot{
		outputDir:        outputDir,
		ctx:              ctx,
		contextHash:      contextHash,
		policyHash:       policyHash,
		acceptedRiskHash: acceptedRiskHash,
		scanHashes:       scanHashes,
		scanMetadata:     scanMetadata,
		decisionStatus:   domain.DecisionBlock,
		exitCode:         2,
	}
	if stage == policy.StagePR && scannerHashable {
		snapshot.decisionStatus = domain.DecisionWarn
		snapshot.exitCode = 1
	}

	if strings.TrimSpace(snapshot.outputDir) == "" {
		snapshot.outputDir = filepath.Join(defaultReportsDir, now.Format("20060102-150405"))
	}
	if strings.TrimSpace(snapshot.ctx.PipelineStage) == "" {
		snapshot.ctx.PipelineStage = string(stage)
	}
	if strings.TrimSpace(snapshot.ctx.Environment) == "" {
		snapshot.ctx.Environment = defaultEnvironment
	}
	if strings.TrimSpace(snapshot.ctx.Exposure) == "" {
		snapshot.ctx.Exposure = defaultExposure
	}
	if strings.TrimSpace(snapshot.ctx.ChangeType) == "" {
		snapshot.ctx.ChangeType = defaultChangeType
	}
	if strings.TrimSpace(snapshot.contextHash) == "" {
		if hash, err := hashJSON(snapshot.ctx); err == nil {
			snapshot.contextHash = hash
		}
	}
	if strings.TrimSpace(snapshot.policyHash) == "" {
		snapshot.policyHash = hashBytes([]byte(embeddedDefaultPolicyRaw))
	}
	if strings.TrimSpace(snapshot.acceptedRiskHash) == "" {
		snapshot.acceptedRiskHash = hashBytes([]byte(emptyAcceptedRisksJSON))
	}
	if snapshot.scanHashes == nil {
		snapshot.scanHashes = map[string]string{}
	}
	if snapshot.scanMetadata == nil {
		snapshot.scanMetadata = map[string]policy.ScanMetadata{}
	}
	return snapshot
}

func buildFatalScans(scanHashes map[string]string, scanMetadata map[string]policy.ScanMetadata) []policy.ScanInput {
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
	return scans
}

func buildFatalArtifact(snapshot fatalSnapshot, errorCode string, traceEvent policy.DecisionTraceEvent) policy.DecisionArtifact {
	return policy.DecisionArtifact{
		Inputs: policy.DecisionInputs{
			Scans: buildFatalScans(snapshot.scanHashes, snapshot.scanMetadata),
			Context: policy.ContextRef{
				InputRef: policy.InputRef{
					SHA256: snapshot.contextHash,
					Source: "context",
				},
				Payload: policy.ContextPayload{
					PipelineStage:         snapshot.ctx.PipelineStage,
					Environment:           snapshot.ctx.Environment,
					Exposure:              snapshot.ctx.Exposure,
					ChangeType:            snapshot.ctx.ChangeType,
					ScannerVersion:        snapshot.ctx.ScannerVersion,
					ArtifactSigningStatus: snapshot.ctx.ArtifactSigningStatus,
					ProvenanceLevel:       snapshot.ctx.ProvenanceLevel,
					BranchProtected:       snapshot.ctx.BranchProtected,
				},
			},
			Policy: policy.InputRef{
				SHA256: snapshot.policyHash,
				Source: "policy",
			},
			AcceptedRisks: policy.InputRef{
				SHA256: snapshot.acceptedRiskHash,
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
			Status:    snapshot.decisionStatus,
			ExitCode:  snapshot.exitCode,
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

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func writeReportChecksums(outputDir, decisionPath, htmlPath string) (string, error) {
	type entry struct {
		name string
		path string
	}
	entries := []entry{
		{name: "decision.json", path: decisionPath},
	}
	if strings.TrimSpace(htmlPath) != "" {
		entries = append(entries, entry{name: "report.html", path: htmlPath})
	}

	var b strings.Builder
	for _, e := range entries {
		sum, err := fileSHA256(e.path)
		if err != nil {
			return "", err
		}
		b.WriteString(sum)
		b.WriteString("  ")
		b.WriteString(e.name)
		b.WriteByte('\n')
	}

	path := filepath.Join(outputDir, "checksums.sha256")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return "", err
	}
	return path, nil
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
	inputs            []string
	useStdin          bool
	contextPath       string
	policyPath        string
	acceptedRiskPath  string
	outputDir         string
	outputDirExplicit bool
	stageOverride     string
	reportHTML        bool
	llmEnabled        bool
}

func parseCLI() (cliConfig, error) {
	var cfg cliConfig
	var inputFlags stringSliceFlag
	var llmFlag string

	flag.Var(&inputFlags, "input", "path to Trivy JSON input (repeatable)")
	flag.BoolVar(&cfg.useStdin, "stdin", false, "read Trivy JSON from stdin")
	flag.StringVar(&cfg.contextPath, "context", "", "path to context JSON")
	flag.StringVar(&cfg.policyPath, "policy", "", "path to policy JSON")
	flag.StringVar(&cfg.acceptedRiskPath, "accepted-risk", "", "path to accepted risks JSON")
	flag.StringVar(&cfg.outputDir, "output-dir", "", "output directory for reports (default: reports/<timestamp>-<runid>)")
	flag.StringVar(&cfg.stageOverride, "stage", "", "pipeline stage override: pr|main|release|prod")
	flag.BoolVar(&cfg.reportHTML, "report-html", false, "emit optional static HTML report")
	flag.StringVar(&llmFlag, "llm", "off", "LLM mode: on|off")
	flag.Parse()
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "output-dir" {
			cfg.outputDirExplicit = true
		}
	})

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
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.ReportTitle}}</title>
<style>
:root {
  --bg: #120c08;
  --panel: #1d1410;
  --ink: #ffe7c2;
  --muted: #d2a777;
  --accent: #ff9f2f;
  --accent-soft: #3a2416;
  --line: #5e3a22;
  --ok: #43d17f;
  --warn: #ffcf5a;
  --block: #ff6b6b;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
  color: var(--ink);
  background: var(--bg);
  line-height: 1.6;
  position: relative;
}
body::before {
  content: "";
  position: fixed;
  inset: 0;
  pointer-events: none;
  z-index: -1;
  background:
    radial-gradient(900px 520px at 0% 0%, #ff8b2f55 0%, transparent 60%),
    radial-gradient(760px 460px at 100% 0%, #ffbf3f2e 0%, transparent 62%),
    radial-gradient(860px 480px at 50% 100%, #ff6a0035 0%, transparent 65%),
    var(--bg);
}
.layout {
  width: min(1100px, calc(100vw - 2.4rem));
  margin: 1.2rem auto 2rem;
}
.site-header {
  padding: 0.85rem 1.2rem;
  border: 1px solid var(--line);
  background: rgba(27, 17, 12, 0.92);
  border-radius: 14px;
  margin-bottom: 1rem;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.8rem;
}
.brand {
  display: flex;
  align-items: center;
  gap: 0.65rem;
}
.brand-logo {
  width: 34px;
  height: 34px;
  object-fit: contain;
}
.brand-text { line-height: 1.2; }
.brand-app { font-weight: 700; font-size: 1.05rem; }
.brand-sub { color: var(--muted); font-size: 0.85rem; }
.header {
  padding: 1rem 1.2rem;
  border: 1px solid var(--line);
  background: rgba(40, 25, 17, 0.82);
  border-radius: 14px;
  margin-bottom: 1rem;
}
.header h1 { margin: 0; font-size: clamp(1.2rem, 2.5vw, 1.7rem); }
.header p { margin: 0.2rem 0 0; color: var(--muted); }
.card {
  background: var(--panel);
  border-radius: 16px;
  border: 1px solid var(--line);
  box-shadow: 0 20px 35px -28px rgba(12, 35, 66, 0.45);
  padding: clamp(1rem, 2.4vw, 2rem);
}
.stats {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 0.75rem;
  margin-bottom: 1rem;
}
.stat {
  border: 1px solid var(--line);
  border-radius: 12px;
  background: #2b1a11;
  padding: 0.7rem;
}
.stat .label { color: var(--muted); font-size: 0.82rem; }
.stat .value { font-weight: 700; font-size: 1rem; margin-top: 0.1rem; }
.decision-badge {
  border: 1px solid var(--line);
  border-radius: 999px;
  padding: 0.2rem 0.7rem;
  font-weight: 700;
  display: inline-block;
}
.decision-allow { color: var(--ok); background: #17311f; border-color: #2a6f41; }
.decision-warn { color: var(--warn); background: #3b2f0f; border-color: #7a5f19; }
.decision-block { color: var(--block); background: #3a1818; border-color: #7c2d2d; }
.table-wrap { overflow-x: auto; margin-top: 0.7rem; max-width: 100%; }
table {
  width: 100%;
  border-collapse: collapse;
  margin: 0;
  table-layout: fixed;
}
thead tr { background: #3a2316; }
th, td {
  border: 1px solid var(--line);
  padding: 0.55rem 0.65rem;
  text-align: left;
  vertical-align: top;
  overflow-wrap: anywhere;
  word-break: break-word;
}
tr:nth-child(even) td { background: #26170f; }
code {
  display: inline-block;
  max-width: 100%;
  white-space: normal;
  overflow-wrap: anywhere;
  background: #2d1a11;
  border: 1px solid #6a4328;
  padding: 0.1rem 0.32rem;
  border-radius: 6px;
}
.status {
  border: 1px solid var(--line);
  border-radius: 999px;
  padding: 0.1rem 0.55rem;
  font-size: 0.82rem;
  font-weight: 700;
}
.status-considered { color: #9fb3c8; background: #1e2630; border-color: #3a4d63; }
.status-suppressed { color: #c9b27a; background: #2f2818; border-color: #6f5c30; }
.status-block { color: var(--block); background: #3a1818; border-color: #7c2d2d; }
@media (max-width: 920px) {
  .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  th, td { font-size: 0.88rem; }
}
</style>
</head>
<body>
<div class="layout">
  <div class="site-header">
    <div class="brand">
      <svg class="brand-logo" viewBox="0 0 48 48" aria-hidden="true">
        <defs>
          <linearGradient id="logoGradient" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#ffcf5a"/>
            <stop offset="100%" stop-color="#ff7a1a"/>
          </linearGradient>
        </defs>
        <circle cx="24" cy="24" r="18" fill="none" stroke="url(#logoGradient)" stroke-width="4"/>
        <path d="M16 26c3 0 5-2 6-5 2 5 5 7 10 7" fill="none" stroke="#ffcf5a" stroke-width="4" stroke-linecap="round"/>
      </svg>
      <div class="brand-text">
        <div class="brand-app">security-gate</div>
        <div class="brand-sub">Deterministic CI/CD Decision Report</div>
      </div>
    </div>
    <div><code>{{.GeneratedAt}}</code></div>
  </div>

  <div class="header">
    <h1>Release Decision</h1>
    <p><strong>Final status:</strong> <span class="decision-badge {{.DecisionClass}}">{{.Decision}}</span></p>
    <p><strong>Policy version:</strong> <code>{{.PolicyVersion}}</code></p>
    <p><strong>Accepted risks used:</strong> <code>{{.AcceptedRisksUsed}}</code></p>
    <p><strong>Inputs:</strong> <code>{{.Inputs}}</code></p>
  </div>

  <div class="card">
    <div class="stats">
      <div class="stat" title="Max release risk score after policy, stage, exposure, and trust modifiers."><div class="label">Release risk</div><div class="value">{{.ReleaseRisk}}</div></div>
      <div class="stat" title="Input trust rating based on provenance, signing signals, and scanner confidence."><div class="label">Trust score</div><div class="value">{{.TrustScore}}</div></div>
      <div class="stat" title="Total normalized findings loaded from input scans."><div class="label">Findings total</div><div class="value">{{.TotalFindings}}</div></div>
      <div class="stat" title="Findings marked as non-suppressible hard-stop conditions."><div class="label">Hard-stop</div><div class="value">{{.HardStops}}</div></div>
      <div class="stat" title="Findings currently counted in decision/scoring after suppressions."><div class="label">Considered</div><div class="value">{{.Considered}}</div></div>
    </div>

    <h2>Issue Statuses</h2>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th title="Stable finding identifier from scanner or normalizer.">finding_id</th>
            <th title="Deterministic hash used for tracking and accepted-risk matching.">fingerprint</th>
            <th title="Finding domain used by policy logic (for example SECRET, VULNERABILITY, CONFIG).">domain</th>
            <th title="Normalized severity level reported for this finding.">severity</th>
            <th title="Calculated risk score for this finding after deterministic scoring.">risk_score</th>
            <th title="Evaluation outcome for this finding in the current run.">status</th>
            <th title="Short explanation of why this status was assigned.">explanation</th>
          </tr>
        </thead>
        <tbody>
          {{range .Issues}}
          <tr>
            <td><code>{{.FindingID}}</code></td>
            <td><code>{{.Fingerprint}}</code></td>
            <td>{{.Domain}}</td>
            <td>{{.Severity}}</td>
            <td>{{.RiskScore}}</td>
            <td><span class="status {{.StatusClass}}" title="{{.StatusHint}}">{{.Status}}</span></td>
            <td>{{.StatusHint}}</td>
          </tr>
          {{end}}
        </tbody>
      </table>
    </div>
  </div>
</div>
</body>
</html>`))

	type issueRow struct {
		FindingID   string
		Fingerprint string
		Domain      string
		Severity    string
		RiskScore   int
		Status      string
		StatusClass string
		StatusHint  string
	}

	acceptedRiskByFingerprint := make(map[string][]string)
	for riskID, fingerprints := range artifact.Policy.AcceptedRisksCoverage {
		for _, fp := range fingerprints {
			acceptedRiskByFingerprint[fp] = append(acceptedRiskByFingerprint[fp], riskID)
		}
	}
	for fp := range acceptedRiskByFingerprint {
		sort.Strings(acceptedRiskByFingerprint[fp])
	}

	issues := make([]issueRow, 0, len(artifact.Findings.Items))
	for _, finding := range artifact.Findings.Items {
		status := issueStatus(finding)
		statusClass := "status-considered"
		statusHint := "Included in scoring and final decision."
		switch status {
		case "SUPPRESSED":
			statusClass = "status-suppressed"
			reasons := make([]string, 0, 3)
			if finding.SuppressedByAcceptedRisk {
				ids := acceptedRiskByFingerprint[finding.Finding.Fingerprint]
				if len(ids) > 0 {
					reasons = append(reasons, "Suppressed by accepted risk: "+strings.Join(ids, ", ")+".")
				} else {
					reasons = append(reasons, "Suppressed by accepted risk.")
				}
			}
			if finding.SuppressedByException {
				reasons = append(reasons, "Suppressed by policy exception.")
			}
			if finding.SuppressedByNoiseBudget {
				reasons = append(reasons, "Suppressed by PR noise budget.")
			}
			if len(reasons) == 0 {
				reasons = append(reasons, "Suppressed by policy controls.")
			}
			statusHint = strings.Join(reasons, " ")
		case string(domain.DecisionBlock):
			statusClass = "status-block"
			if strings.TrimSpace(finding.HardStopReason) != "" {
				statusHint = "Hard-stop finding that forces BLOCK. Reason: " + finding.HardStopReason + "."
			} else {
				statusHint = "Hard-stop finding that forces BLOCK."
			}
		}
		issues = append(issues, issueRow{
			FindingID:   finding.Finding.FindingID,
			Fingerprint: finding.Finding.Fingerprint,
			Domain:      finding.Finding.Domain,
			Severity:    finding.Finding.Severity,
			RiskScore:   finding.RiskScore,
			Status:      status,
			StatusClass: statusClass,
			StatusHint:  statusHint,
		})
	}

	decisionClass := "decision-warn"
	switch artifact.Decision.Status {
	case domain.DecisionAllow:
		decisionClass = "decision-allow"
	case domain.DecisionBlock:
		decisionClass = "decision-block"
	}

	data := struct {
		ReportTitle       string
		GeneratedAt       string
		Inputs            string
		PolicyVersion     string
		AcceptedRisksUsed string
		Decision          string
		DecisionClass     string
		ExitCode          int
		ReleaseRisk       int
		TrustScore        int
		TotalFindings     int
		HardStops         int
		Considered        int
		Issues            []issueRow
	}{
		ReportTitle:       "security-gate Decision Report",
		GeneratedAt:       time.Now().UTC().Format(time.RFC3339),
		Inputs:            strings.Join(inputPaths, ", "),
		PolicyVersion:     policyVersionForReport(artifact.Policy.PolicyVersion),
		AcceptedRisksUsed: acceptedRisksUsedForReport(artifact.Policy.AcceptedRisksApplied),
		Decision:          string(artifact.Decision.Status),
		DecisionClass:     decisionClass,
		ExitCode:          artifact.Decision.ExitCode,
		ReleaseRisk:       artifact.Scoring.ReleaseRisk,
		TrustScore:        artifact.Trust.TrustScore,
		TotalFindings:     artifact.Findings.TotalCount,
		HardStops:         artifact.Findings.HardStopCount,
		Considered:        artifact.Findings.ConsideredCount,
		Issues:            issues,
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, data)
}

func policyVersionForReport(version string) string {
	version = strings.TrimSpace(version)
	if version == "" {
		return "unknown"
	}
	return version
}

func acceptedRisksUsedForReport(ids []string) string {
	if len(ids) == 0 {
		return "none"
	}
	ordered := append([]string(nil), ids...)
	sort.Strings(ordered)
	return strings.Join(ordered, ", ")
}
