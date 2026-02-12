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
	"regexp"
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

var cveIDPattern = regexp.MustCompile(`(?i)^CVE-[0-9]{4}-[0-9]{4,}$`)

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

	reportPath, htmlPath, checksumsPath, err := writeReports(now, resolvedOutputDir, report, artifact, ingestPaths, cfg.reportHTML)
	if err != nil {
		fatalState.fail("REPORT_WRITE_FAILED", reportWriteAffectedInput(err), err)
	}
	logger.info("report.generated", "decision", artifact.Decision.Status, "exit_code", artifact.Decision.ExitCode, "report_json", reportPath, "html", htmlPath, "checksums", checksumsPath)

	fmt.Printf("Report generated.\n- Report JSON: %s\n- Checksums: %s\n", reportPath, checksumsPath)
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
	case "REPORT_JSON_WRITE_FAILED":
		return "report.json"
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

	reportPath := filepath.Join(outputDir, "report.json")
	if err := writeJSON(reportPath, report); err != nil {
		return "", "", "", withErrorCode("REPORT_JSON_WRITE_FAILED", err)
	}

	htmlPath := ""
	if includeHTML {
		htmlPath = filepath.Join(outputDir, "report.html")
		if err := writeHTMLReport(htmlPath, artifact, inputPaths); err != nil {
			return "", "", "", withErrorCode("HTML_WRITE_FAILED", err)
		}
	}

	checksumsPath, err := writeReportChecksums(outputDir, reportPath, htmlPath)
	if err != nil {
		return "", "", "", withErrorCode("CHECKSUMS_WRITE_FAILED", err)
	}

	return reportPath, htmlPath, checksumsPath, nil
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
		reportPath := filepath.Join(snapshot.outputDir, "report.json")
		if writeErr := writeJSON(reportPath, report); writeErr == nil {
			fmt.Fprintf(os.Stderr, "fatal error artifact written: %s\n", reportPath)
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

func writeReportChecksums(outputDir, reportPath, htmlPath string) (string, error) {
	type entry struct {
		name string
		path string
	}
	entries := []entry{
		{name: "report.json", path: reportPath},
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

type remediationItem struct {
	FindingID   string
	Fingerprint string
	Domain      string
	Severity    string
	RiskScore   int
	Location    string
	FixVersion  string
	Reason      string
}

type remediationPlan struct {
	Title string
	Goal  string
	Notes []string
	Items []remediationItem
}

func writeMarkdownReport(path string, artifact policy.DecisionArtifact, inputPaths []string) error {
	plan := buildRemediationPlan(artifact)
	acceptedRiskByFingerprint := buildAcceptedRiskIndex(artifact.Policy.AcceptedRisksCoverage)
	required := make(map[string]bool, len(plan.Items))
	for _, item := range plan.Items {
		required[item.Fingerprint] = true
	}

	var b strings.Builder
	b.WriteString("# security-gate report\n\n")
	b.WriteString(fmt.Sprintf("- Decision: **%s**\n", artifact.Decision.Status))
	b.WriteString(fmt.Sprintf("- Stage: `%s`\n", firstNonEmpty(artifact.Inputs.Context.Payload.PipelineStage, "unknown")))
	b.WriteString(fmt.Sprintf("- Policy version: `%s`\n", policyVersionForReport(artifact.Policy.PolicyVersion)))
	b.WriteString(fmt.Sprintf("- Accepted risks used: `%s`\n", acceptedRisksUsedForReport(artifact.Policy.AcceptedRisksApplied)))
	b.WriteString(fmt.Sprintf("- Release risk: `%d`\n", artifact.Scoring.ReleaseRisk))
	b.WriteString(fmt.Sprintf("- Trust score: `%d`\n", artifact.Trust.TrustScore))
	b.WriteString(fmt.Sprintf("- Findings: total=%d, hard-stop=%d, considered=%d\n", artifact.Findings.TotalCount, artifact.Findings.HardStopCount, artifact.Findings.ConsideredCount))
	b.WriteString(fmt.Sprintf("- Inputs: `%s`\n\n", strings.Join(inputPaths, ", ")))

	if plan.Title != "" {
		b.WriteString("## Priority Actions\n\n")
		b.WriteString(fmt.Sprintf("- %s\n", plan.Title))
		b.WriteString(fmt.Sprintf("- Goal: %s\n", plan.Goal))
		for _, note := range plan.Notes {
			b.WriteString(fmt.Sprintf("- Note: %s\n", note))
		}
		if len(plan.Items) == 0 {
			b.WriteString("- No finding-level actions identified.\n\n")
		} else {
			b.WriteString("\n| priority | finding_id | severity | risk_score | location | fix_version | reason |\n")
			b.WriteString("| --- | --- | --- | --- | --- | --- | --- |\n")
			for i, item := range plan.Items {
				b.WriteString(fmt.Sprintf("| %d | `%s` | %s | %d | `%s` | `%s` | %s |\n",
					i+1,
					escapeMDPipe(item.FindingID),
					escapeMDPipe(item.Severity),
					item.RiskScore,
					escapeMDPipe(firstNonEmpty(item.Location, "n/a")),
					escapeMDPipe(firstNonEmpty(item.FixVersion, "n/a")),
					escapeMDPipe(item.Reason),
				))
			}
			b.WriteByte('\n')
		}
	}

	b.WriteString("## Issue Triage\n\n")
	b.WriteString("| finding_id | domain | severity | risk_score | status | priority_action |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- |\n")
	for _, finding := range artifact.Findings.Items {
		priority := "no"
		if required[finding.Finding.Fingerprint] {
			priority = "yes"
		}
		b.WriteString(fmt.Sprintf("| `%s` | %s | %s | %d | %s | %s |\n",
			escapeMDPipe(finding.Finding.FindingID),
			escapeMDPipe(finding.Finding.Domain),
			escapeMDPipe(finding.Finding.Severity),
			finding.RiskScore,
			escapeMDPipe(issueStatus(finding)),
			priority,
		))
	}
	b.WriteByte('\n')

	b.WriteString("## Issue Details\n\n")
	for _, finding := range artifact.Findings.Items {
		b.WriteString(fmt.Sprintf("### %s\n\n", finding.Finding.FindingID))
		b.WriteString(fmt.Sprintf("- Status: `%s`\n", issueStatus(finding)))
		b.WriteString(fmt.Sprintf("- Status explanation: %s\n", issueStatusHint(finding, acceptedRiskByFingerprint)))
		b.WriteString(fmt.Sprintf("- Domain / Severity: `%s / %s`\n", finding.Finding.Domain, finding.Finding.Severity))
		b.WriteString(fmt.Sprintf("- Risk score: `%d`\n", finding.RiskScore))
		b.WriteString(fmt.Sprintf("- Location: `%s`\n", firstNonEmpty(finding.Finding.Location.Path, finding.Finding.Location.Target, finding.Finding.Location.File, "n/a")))
		b.WriteString(fmt.Sprintf("- Package: `%s`\n", firstNonEmpty(finding.Finding.Location.Package, "n/a")))
		b.WriteString(fmt.Sprintf("- CVE: `%s`\n", firstNonEmpty(finding.Finding.CVE, "n/a")))
		b.WriteString(fmt.Sprintf("- CVSS v3: `%s`\n", cvssForReport(finding.Finding.CVSSv3)))
		b.WriteString(fmt.Sprintf("- Fix available: `%s`\n", firstNonEmpty(finding.Finding.FixAvailable, "unknown")))
		b.WriteString(fmt.Sprintf("- Fix version: `%s`\n", firstNonEmpty(finding.Finding.FixVersion, "n/a")))
		b.WriteString(fmt.Sprintf("- Remediation hint: `%s`\n", firstNonEmpty(finding.Finding.RemediationHint, "n/a")))
		b.WriteString(fmt.Sprintf("- Evidence ref: `%s`\n", firstNonEmpty(finding.Finding.EvidenceRef, "n/a")))
		b.WriteString(fmt.Sprintf("- Fingerprint: `%s`\n\n", firstNonEmpty(finding.Finding.Fingerprint, "n/a")))
	}

	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func buildRemediationPlan(artifact policy.DecisionArtifact) remediationPlan {
	stage := strings.ToLower(strings.TrimSpace(artifact.Inputs.Context.Payload.PipelineStage))
	allowRiskMax, warnRiskMax, allowTrustMin, warnTrustMin := stageThresholds(stage)
	considered := make([]scoring.ScoredFinding, 0, len(artifact.Findings.Items))
	for _, finding := range artifact.Findings.Items {
		if finding.SuppressedByAcceptedRisk || finding.SuppressedByException || finding.SuppressedByNoiseBudget {
			continue
		}
		considered = append(considered, finding)
	}
	sort.SliceStable(considered, func(i, j int) bool {
		if considered[i].HardStop != considered[j].HardStop {
			return considered[i].HardStop
		}
		if considered[i].RiskScore != considered[j].RiskScore {
			return considered[i].RiskScore > considered[j].RiskScore
		}
		return considered[i].Finding.FindingID < considered[j].Finding.FindingID
	})

	plan := remediationPlan{}
	switch artifact.Decision.Status {
	case domain.DecisionBlock:
		plan.Title = "Fix these findings first to remove BLOCK."
		plan.Goal = "Reach WARN or ALLOW."
		if artifact.Trust.TrustScore < warnTrustMin {
			plan.Notes = append(plan.Notes, fmt.Sprintf("Trust score %d is below stage minimum %d for non-BLOCK outcome; improve trust signals too.", artifact.Trust.TrustScore, warnTrustMin))
		}
		plan.Items = requiredFindingsForTarget(considered, warnRiskMax-artifact.Scoring.Modifiers.StageModifier-artifact.Scoring.Modifiers.ExposureModifier-artifact.Scoring.Modifiers.ChangeModifier-artifact.Scoring.Modifiers.TrustModifier)
	case domain.DecisionWarn:
		plan.Title = "Fix these findings first to move WARN -> ALLOW."
		plan.Goal = "Reach ALLOW."
		if artifact.Trust.TrustScore < allowTrustMin {
			plan.Notes = append(plan.Notes, fmt.Sprintf("Trust score %d is below stage ALLOW threshold %d; improve trust signals too.", artifact.Trust.TrustScore, allowTrustMin))
		}
		plan.Items = requiredFindingsForTarget(considered, allowRiskMax-artifact.Scoring.Modifiers.StageModifier-artifact.Scoring.Modifiers.ExposureModifier-artifact.Scoring.Modifiers.ChangeModifier-artifact.Scoring.Modifiers.TrustModifier)
	default:
		plan.Title = "Current state is ALLOW."
		plan.Goal = "No mandatory finding-level remediation to unblock."
	}
	return plan
}

func requiredFindingsForTarget(considered []scoring.ScoredFinding, maxFindingRiskTarget int) []remediationItem {
	items := make([]remediationItem, 0)
	if len(considered) == 0 {
		return items
	}
	if maxFindingRiskTarget < 0 {
		maxFindingRiskTarget = 0
	}
	for _, finding := range considered {
		if finding.HardStop {
			items = append(items, remediationItem{
				FindingID:   finding.Finding.FindingID,
				Fingerprint: finding.Finding.Fingerprint,
				Domain:      finding.Finding.Domain,
				Severity:    finding.Finding.Severity,
				RiskScore:   finding.RiskScore,
				Location:    firstNonEmpty(finding.Finding.Location.Path, finding.Finding.Location.Target, finding.Finding.Location.File, "n/a"),
				FixVersion:  firstNonEmpty(finding.Finding.FixVersion, "n/a"),
				Reason:      "Hard-stop finding always blocks release.",
			})
			continue
		}
		if finding.RiskScore > maxFindingRiskTarget {
			items = append(items, remediationItem{
				FindingID:   finding.Finding.FindingID,
				Fingerprint: finding.Finding.Fingerprint,
				Domain:      finding.Finding.Domain,
				Severity:    finding.Finding.Severity,
				RiskScore:   finding.RiskScore,
				Location:    firstNonEmpty(finding.Finding.Location.Path, finding.Finding.Location.Target, finding.Finding.Location.File, "n/a"),
				FixVersion:  firstNonEmpty(finding.Finding.FixVersion, "n/a"),
				Reason:      fmt.Sprintf("Risk score %d is above required max %d.", finding.RiskScore, maxFindingRiskTarget),
			})
		}
	}
	return items
}

func stageThresholds(stage string) (allowRiskMax, warnRiskMax, allowTrustMin, warnTrustMin int) {
	switch stage {
	case "main":
		return 35, 60, 30, 20
	case "release":
		return 30, 50, 40, 30
	case "prod":
		return 25, 40, 50, 40
	default:
		return 45, 70, 20, 10
	}
}

func escapeMDPipe(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "|", "\\|")
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

func buildAcceptedRiskIndex(coverage map[string][]string) map[string][]string {
	index := make(map[string][]string)
	for riskID, fingerprints := range coverage {
		for _, fp := range fingerprints {
			index[fp] = append(index[fp], riskID)
		}
	}
	for fp := range index {
		sort.Strings(index[fp])
	}
	return index
}

func issueStatusHint(f scoring.ScoredFinding, acceptedRiskByFingerprint map[string][]string) string {
	if f.HardStop {
		if strings.TrimSpace(f.HardStopReason) != "" {
			return "Hard-stop finding that forces BLOCK. Reason: " + f.HardStopReason + "."
		}
		return "Hard-stop finding that forces BLOCK."
	}
	if f.SuppressedByAcceptedRisk || f.SuppressedByException || f.SuppressedByNoiseBudget {
		reasons := make([]string, 0, 3)
		if f.SuppressedByAcceptedRisk {
			ids := acceptedRiskByFingerprint[f.Finding.Fingerprint]
			if len(ids) > 0 {
				reasons = append(reasons, "Suppressed by accepted risk: "+strings.Join(ids, ", ")+".")
			} else {
				reasons = append(reasons, "Suppressed by accepted risk.")
			}
		}
		if f.SuppressedByException {
			reasons = append(reasons, "Suppressed by policy exception.")
		}
		if f.SuppressedByNoiseBudget {
			reasons = append(reasons, "Suppressed by PR noise budget.")
		}
		if len(reasons) == 0 {
			reasons = append(reasons, "Suppressed by policy controls.")
		}
		return strings.Join(reasons, " ")
	}
	return "Included in scoring and final decision."
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
	plan := buildRemediationPlan(artifact)
	tmpl := template.Must(template.New("report").Funcs(template.FuncMap{
		"inc": func(i int) int { return i + 1 },
	}).Parse(`<!doctype html>
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
  width: calc(100vw - 1.2rem);
  margin: 0.6rem auto 1.2rem;
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
.triage-row { cursor: pointer; }
.triage-row:hover td { background: #322015; }
.triage-row:focus-visible {
  outline: 2px solid #ffb250;
  outline-offset: 2px;
}
.triage-detail td {
  background: #20130d !important;
  padding: 0.7rem;
}
.inline-details {
  border: 1px solid var(--line);
  border-radius: 10px;
  background: #25170f;
  padding: 0.65rem 0.75rem;
}
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
.severity {
  border: 1px solid var(--line);
  border-radius: 999px;
  padding: 0.08rem 0.5rem;
  font-size: 0.78rem;
  font-weight: 700;
  display: inline-block;
}
.severity-critical { color: #ff9e9e; background: #36191b; border-color: #7b3a3f; }
.severity-high { color: #ffd39e; background: #342313; border-color: #7e5a2f; }
.severity-medium { color: #efe19f; background: #332c14; border-color: #70633a; }
.severity-low { color: #b9d6f5; background: #1d2733; border-color: #3f5872; }
.severity-unknown { color: #c7cdd4; background: #242a31; border-color: #46515e; }
.status-considered { color: #9fb3c8; background: #1e2630; border-color: #3a4d63; }
.status-suppressed { color: #c9b27a; background: #2f2818; border-color: #6f5c30; }
.status-block { color: var(--block); background: #3a1818; border-color: #7c2d2d; }
.section-note {
  color: var(--muted);
  margin: 0.3rem 0 0.6rem;
  font-size: 0.9rem;
}
.finding-list {
  margin-top: 1rem;
  display: grid;
  gap: 0.7rem;
}
.finding-card {
  border: 1px solid var(--line);
  border-radius: 12px;
  background: #25170f;
  overflow: hidden;
}
.finding-card summary {
  cursor: pointer;
  list-style: none;
  display: flex;
  align-items: center;
  gap: 0.6rem;
  padding: 0.7rem 0.9rem;
}
.finding-card summary::-webkit-details-marker { display: none; }
.finding-title {
  font-weight: 700;
  margin-right: 0.35rem;
}
.finding-meta {
  color: var(--muted);
  font-size: 0.84rem;
}
.finding-body {
  border-top: 1px solid var(--line);
  padding: 0.75rem 0.9rem 0.9rem;
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.55rem 0.9rem;
}
.kv { min-width: 0; }
.kv-label {
  color: var(--muted);
  font-size: 0.78rem;
  margin-bottom: 0.1rem;
}
.kv-value {
  font-size: 0.9rem;
  overflow-wrap: anywhere;
  word-break: break-word;
  display: block;
  width: 100%;
  border: 1px solid #8b532b;
  border-radius: 8px;
  background: #301b10;
  box-shadow: inset 0 0 0 1px rgba(255, 170, 90, 0.08);
  padding: 0.34rem 0.5rem;
}
.kv-value code {
  border: 0;
  background: transparent;
  padding: 0;
}
.kv-value a {
  color: #ffd28a;
  text-decoration: underline;
  text-decoration-color: #8b532b;
}
@media (max-width: 920px) {
  .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  th, td { font-size: 0.88rem; }
  .finding-body { grid-template-columns: 1fr; }
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

	    <h2>Issue Triage</h2>
	    <p class="section-note">Open any row to expand technical details inline.</p>

	    <h3>Fix Now</h3>
	    <p class="section-note">Actionable findings that directly block moving to a better final decision.</p>
	    <div class="table-wrap">
	      <table>
	        <thead>
	          <tr>
	            <th title="Simple finding row index.">#</th>
	            <th title="Stable finding identifier from scanner or normalizer.">finding_id</th>
	            <th title="Finding domain used by policy logic (for example SECRET, VULNERABILITY, CONFIG).">domain</th>
	            <th title="Normalized severity level reported for this finding.">severity</th>
	            <th title="Calculated risk score for this finding after deterministic scoring.">risk_score</th>
	          </tr>
	        </thead>
	        <tbody>
	          {{if .MustFixIssues}}
	          {{range $i, $issue := .MustFixIssues}}
	          <tr class="triage-main" data-detail-id="{{$issue.AnchorID}}-detail">
	            <td>{{inc $i}}</td>
	            <td><code>{{$issue.FindingID}}</code></td>
	            <td>{{$issue.Domain}}</td>
	            <td><span class="severity {{$issue.SeverityClass}}">{{$issue.Severity}}</span></td>
	            <td>{{$issue.RiskScore}}</td>
	          </tr>
	          <tr id="{{$issue.AnchorID}}-detail" class="triage-detail" hidden>
	            <td colspan="5">
	              <div class="inline-details">
	                <div class="finding-meta"><span class="status {{$issue.StatusClass}}">{{$issue.Status}}</span> / <span class="severity {{$issue.SeverityClass}}">{{$issue.Severity}}</span> / risk={{$issue.RiskScore}}</div>
	                <div class="finding-body">
	                  <div class="kv"><div class="kv-label">Status explanation</div><div class="kv-value"><code>{{$issue.StatusHint}}</code></div></div>
	                  <div class="kv"><div class="kv-label">Title</div><div class="kv-value"><code>{{$issue.Title}}</code></div></div>
	                  <div class="kv"><div class="kv-label">Description</div><div class="kv-value"><code>{{$issue.Description}}</code></div></div>
	                  <div class="kv"><div class="kv-label">Location</div><div class="kv-value"><code>{{$issue.Location}}</code></div></div>
	                  <div class="kv"><div class="kv-label">Package</div><div class="kv-value"><code>{{$issue.PackageName}}</code></div></div>
	                  <div class="kv"><div class="kv-label">CVE</div><div class="kv-value"><code>{{$issue.CVEID}}</code></div></div>
	                  <div class="kv"><div class="kv-label">CVSS v3</div><div class="kv-value"><code>{{$issue.CVSSv3}}</code></div></div>
	                  <div class="kv"><div class="kv-label">Fix available</div><div class="kv-value"><code>{{$issue.FixAvailable}}</code></div></div>
	                  <div class="kv"><div class="kv-label">Fix version</div><div class="kv-value"><code>{{$issue.FixVersion}}</code></div></div>
	                  <div class="kv"><div class="kv-label">Remediation hint</div><div class="kv-value">{{if $issue.RemediationURL}}<a href="{{$issue.RemediationURL}}" target="_blank" rel="noopener noreferrer"><code>{{$issue.RemediationURL}}</code></a>{{else}}<code>n/a</code>{{end}}</div></div>
	                  <div class="kv"><div class="kv-label">Evidence ref</div><div class="kv-value"><code>{{$issue.EvidenceRef}}</code></div></div>
	                  <div class="kv"><div class="kv-label">Fingerprint</div><div class="kv-value"><code>{{$issue.Fingerprint}}</code></div></div>
	                  <div class="kv"><div class="kv-label">Source</div><div class="kv-value"><code>{{$issue.SourceScanner}}@{{$issue.SourceVersion}}</code></div></div>
	                </div>
	              </div>
	            </td>
	          </tr>
	          {{end}}
	          {{else}}
	          <tr><td colspan="5">No findings in this group.</td></tr>
	          {{end}}
	        </tbody>
	      </table>
	    </div>

	    <h3>Suppressed</h3>
	    <p class="section-note">Findings excluded from current decision due to accepted risk, exceptions, or noise suppression.</p>
	    <div class="table-wrap">
	      <table>
	        <thead>
	          <tr>
	            <th title="Simple finding row index.">#</th>
	            <th title="Stable finding identifier from scanner or normalizer.">finding_id</th>
	            <th title="Finding domain used by policy logic (for example SECRET, VULNERABILITY, CONFIG).">domain</th>
	            <th title="Normalized severity level reported for this finding.">severity</th>
	            <th title="Calculated risk score for this finding after deterministic scoring.">risk_score</th>
	            <th title="Suppression explanation for this finding.">suppression_reason</th>
	          </tr>
	        </thead>
	        <tbody>
	          {{if .SuppressedIssues}}
	          {{range $i, $issue := .SuppressedIssues}}
	          <tr class="triage-main" data-detail-id="{{$issue.AnchorID}}-detail">
	            <td>{{inc $i}}</td>
	            <td><code>{{$issue.FindingID}}</code></td>
	            <td>{{$issue.Domain}}</td>
	            <td><span class="severity {{$issue.SeverityClass}}">{{$issue.Severity}}</span></td>
	            <td>{{$issue.RiskScore}}</td>
	            <td>{{$issue.StatusHint}}</td>
	          </tr>
	          <tr id="{{$issue.AnchorID}}-detail" class="triage-detail" hidden>
	            <td colspan="6">
	              <div class="inline-details">
	                <div class="finding-meta"><span class="status {{$issue.StatusClass}}">{{$issue.Status}}</span> / <span class="severity {{$issue.SeverityClass}}">{{$issue.Severity}}</span> / risk={{$issue.RiskScore}}</div>
	                <div class="finding-body">
	                  <div class="kv"><div class="kv-label">Status explanation</div><div class="kv-value"><code>{{$issue.StatusHint}}</code></div></div>
	                  <div class="kv"><div class="kv-label">Title</div><div class="kv-value"><code>{{$issue.Title}}</code></div></div>
	                  <div class="kv"><div class="kv-label">Description</div><div class="kv-value"><code>{{$issue.Description}}</code></div></div>
	                  <div class="kv"><div class="kv-label">Location</div><div class="kv-value"><code>{{$issue.Location}}</code></div></div>
	                  <div class="kv"><div class="kv-label">Package</div><div class="kv-value"><code>{{$issue.PackageName}}</code></div></div>
	                  <div class="kv"><div class="kv-label">CVE</div><div class="kv-value"><code>{{$issue.CVEID}}</code></div></div>
	                  <div class="kv"><div class="kv-label">CVSS v3</div><div class="kv-value"><code>{{$issue.CVSSv3}}</code></div></div>
	                  <div class="kv"><div class="kv-label">Fix available</div><div class="kv-value"><code>{{$issue.FixAvailable}}</code></div></div>
	                  <div class="kv"><div class="kv-label">Fix version</div><div class="kv-value"><code>{{$issue.FixVersion}}</code></div></div>
	                  <div class="kv"><div class="kv-label">Remediation hint</div><div class="kv-value">{{if $issue.RemediationURL}}<a href="{{$issue.RemediationURL}}" target="_blank" rel="noopener noreferrer"><code>{{$issue.RemediationURL}}</code></a>{{else}}<code>n/a</code>{{end}}</div></div>
	                  <div class="kv"><div class="kv-label">Evidence ref</div><div class="kv-value"><code>{{$issue.EvidenceRef}}</code></div></div>
	                  <div class="kv"><div class="kv-label">Fingerprint</div><div class="kv-value"><code>{{$issue.Fingerprint}}</code></div></div>
	                  <div class="kv"><div class="kv-label">Source</div><div class="kv-value"><code>{{$issue.SourceScanner}}@{{$issue.SourceVersion}}</code></div></div>
	                </div>
	              </div>
	            </td>
	          </tr>
	          {{end}}
	          {{else}}
	          <tr><td colspan="6">No findings in this group.</td></tr>
	          {{end}}
	        </tbody>
	      </table>
	    </div>

	    <h3>Backlog</h3>
	    <p class="section-note">Findings counted in risk calculations but not first-priority for changing the current status.</p>
	    <div class="table-wrap">
	      <table>
	        <thead>
	          <tr>
	            <th title="Simple finding row index.">#</th>
	            <th title="Stable finding identifier from scanner or normalizer.">finding_id</th>
	            <th title="Finding domain used by policy logic (for example SECRET, VULNERABILITY, CONFIG).">domain</th>
	            <th title="Normalized severity level reported for this finding.">severity</th>
	            <th title="Calculated risk score for this finding after deterministic scoring.">risk_score</th>
	          </tr>
	        </thead>
	        <tbody>
	          {{if .OtherIssues}}
	          {{range $i, $issue := .OtherIssues}}
	          <tr class="triage-main" data-detail-id="{{$issue.AnchorID}}-detail">
	            <td>{{inc $i}}</td>
	            <td><code>{{$issue.FindingID}}</code></td>
	            <td>{{$issue.Domain}}</td>
	            <td><span class="severity {{$issue.SeverityClass}}">{{$issue.Severity}}</span></td>
	            <td>{{$issue.RiskScore}}</td>
	          </tr>
	          <tr id="{{$issue.AnchorID}}-detail" class="triage-detail" hidden>
	            <td colspan="5">
	              <div class="inline-details">
	                <div class="finding-meta"><span class="status {{$issue.StatusClass}}">{{$issue.Status}}</span> / <span class="severity {{$issue.SeverityClass}}">{{$issue.Severity}}</span> / risk={{$issue.RiskScore}}</div>
	                <div class="finding-body">
	                  <div class="kv"><div class="kv-label">Status explanation</div><div class="kv-value"><code>{{$issue.StatusHint}}</code></div></div>
	                  <div class="kv"><div class="kv-label">Title</div><div class="kv-value"><code>{{$issue.Title}}</code></div></div>
	                  <div class="kv"><div class="kv-label">Description</div><div class="kv-value"><code>{{$issue.Description}}</code></div></div>
	                  <div class="kv"><div class="kv-label">Location</div><div class="kv-value"><code>{{$issue.Location}}</code></div></div>
	                  <div class="kv"><div class="kv-label">Package</div><div class="kv-value"><code>{{$issue.PackageName}}</code></div></div>
	                  <div class="kv"><div class="kv-label">CVE</div><div class="kv-value"><code>{{$issue.CVEID}}</code></div></div>
	                  <div class="kv"><div class="kv-label">CVSS v3</div><div class="kv-value"><code>{{$issue.CVSSv3}}</code></div></div>
	                  <div class="kv"><div class="kv-label">Fix available</div><div class="kv-value"><code>{{$issue.FixAvailable}}</code></div></div>
	                  <div class="kv"><div class="kv-label">Fix version</div><div class="kv-value"><code>{{$issue.FixVersion}}</code></div></div>
	                  <div class="kv"><div class="kv-label">Remediation hint</div><div class="kv-value">{{if $issue.RemediationURL}}<a href="{{$issue.RemediationURL}}" target="_blank" rel="noopener noreferrer"><code>{{$issue.RemediationURL}}</code></a>{{else}}<code>n/a</code>{{end}}</div></div>
	                  <div class="kv"><div class="kv-label">Evidence ref</div><div class="kv-value"><code>{{$issue.EvidenceRef}}</code></div></div>
	                  <div class="kv"><div class="kv-label">Fingerprint</div><div class="kv-value"><code>{{$issue.Fingerprint}}</code></div></div>
	                  <div class="kv"><div class="kv-label">Source</div><div class="kv-value"><code>{{$issue.SourceScanner}}@{{$issue.SourceVersion}}</code></div></div>
	                </div>
	              </div>
	            </td>
	          </tr>
	          {{end}}
	          {{else}}
	          <tr><td colspan="5">{{if .AllConsideredMustFix}}No backlog for this run: all considered findings are required to improve final status.{{else}}No findings in this group.{{end}}</td></tr>
	          {{end}}
	        </tbody>
	      </table>
	    </div>

  </div>
</div>
<script>
document.querySelectorAll('.triage-main').forEach(function (row) {
  var detailID = row.getAttribute('data-detail-id');
  if (!detailID) return;
  var detailRow = document.getElementById(detailID);
  if (!detailRow) return;
  row.classList.add('triage-row');
  row.tabIndex = 0;
  row.setAttribute('aria-expanded', 'false');
  var findingIDCell = row.querySelector('td code');
  var findingID = findingIDCell ? findingIDCell.textContent.trim() : 'finding';
  row.setAttribute('aria-label', 'Toggle details for ' + findingID);
  var toggle = function () {
    var tbody = row.closest('tbody');
    var isOpen = !detailRow.hidden;
    if (tbody) {
      tbody.querySelectorAll('.triage-detail').forEach(function (other) {
        other.hidden = true;
      });
      tbody.querySelectorAll('.triage-main').forEach(function (other) {
        other.setAttribute('aria-expanded', 'false');
      });
    }
    if (!isOpen) {
      detailRow.hidden = false;
      row.setAttribute('aria-expanded', 'true');
    }
  };
  row.addEventListener('click', function () { toggle(); });
  row.addEventListener('keydown', function (event) {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      toggle();
    }
  });
});
</script>
</body>
</html>`))

	type issueRow struct {
		AnchorID       string
		Index          int
		FindingID      string
		Fingerprint    string
		Domain         string
		Severity       string
		SeverityClass  string
		Title          string
		Description    string
		Location       string
		PackageName    string
		EvidenceRef    string
		CVEID          string
		CVSSv3         string
		FixAvailable   string
		FixVersion     string
		RemediationURL string
		SourceScanner  string
		SourceVersion  string
		RiskScore      int
		Status         string
		StatusClass    string
		StatusHint     string
	}

	acceptedRiskByFingerprint := buildAcceptedRiskIndex(artifact.Policy.AcceptedRisksCoverage)
	requiredFix := make(map[string]bool, len(plan.Items))
	for _, item := range plan.Items {
		requiredFix[item.Fingerprint] = true
	}
	issues := make([]issueRow, 0, len(artifact.Findings.Items))
	mustFixIssues := make([]issueRow, 0, len(artifact.Findings.Items))
	suppressedIssues := make([]issueRow, 0, len(artifact.Findings.Items))
	otherIssues := make([]issueRow, 0, len(artifact.Findings.Items))
	for idx, finding := range artifact.Findings.Items {
		status := issueStatus(finding)
		statusClass := "status-considered"
		statusHint := issueStatusHint(finding, acceptedRiskByFingerprint)
		switch status {
		case "SUPPRESSED":
			statusClass = "status-suppressed"
		case string(domain.DecisionBlock):
			statusClass = "status-block"
		}
		row := issueRow{
			AnchorID:       findingAnchorID(idx, finding.Finding),
			Index:          idx + 1,
			FindingID:      finding.Finding.FindingID,
			Fingerprint:    finding.Finding.Fingerprint,
			Domain:         finding.Finding.Domain,
			Severity:       finding.Finding.Severity,
			SeverityClass:  severityClassForReport(finding.Finding.Severity),
			Title:          firstNonEmpty(finding.Finding.Title, "n/a"),
			Description:    firstNonEmpty(finding.Finding.Description, "n/a"),
			Location:       firstNonEmpty(finding.Finding.Location.Path, finding.Finding.Location.Target, finding.Finding.Location.File, "n/a"),
			PackageName:    firstNonEmpty(finding.Finding.Location.Package, "n/a"),
			EvidenceRef:    firstNonEmpty(finding.Finding.EvidenceRef, "n/a"),
			CVEID:          firstNonEmpty(finding.Finding.CVE, "n/a"),
			CVSSv3:         cvssForReport(finding.Finding.CVSSv3),
			FixAvailable:   firstNonEmpty(finding.Finding.FixAvailable, "unknown"),
			FixVersion:     firstNonEmpty(finding.Finding.FixVersion, "n/a"),
			RemediationURL: remediationURLForReport(finding.Finding),
			SourceScanner:  firstNonEmpty(finding.Finding.SourceScanner, "n/a"),
			SourceVersion:  firstNonEmpty(finding.Finding.SourceVersion, "n/a"),
			RiskScore:      finding.RiskScore,
			Status:         status,
			StatusClass:    statusClass,
			StatusHint:     statusHint,
		}
		issues = append(issues, row)
		switch {
		case status == "SUPPRESSED":
			suppressedIssues = append(suppressedIssues, row)
		case requiredFix[finding.Finding.Fingerprint]:
			mustFixIssues = append(mustFixIssues, row)
		default:
			otherIssues = append(otherIssues, row)
		}
	}

	decisionClass := "decision-warn"
	switch artifact.Decision.Status {
	case domain.DecisionAllow:
		decisionClass = "decision-allow"
	case domain.DecisionBlock:
		decisionClass = "decision-block"
	}

	data := struct {
		ReportTitle          string
		GeneratedAt          string
		Inputs               string
		PolicyVersion        string
		AcceptedRisksUsed    string
		Decision             string
		DecisionClass        string
		ExitCode             int
		ReleaseRisk          int
		TrustScore           int
		TotalFindings        int
		HardStops            int
		Considered           int
		AllConsideredMustFix bool
		AllIssues            []issueRow
		MustFixIssues        []issueRow
		SuppressedIssues     []issueRow
		OtherIssues          []issueRow
	}{
		ReportTitle:          "security-gate Decision Report",
		GeneratedAt:          time.Now().UTC().Format(time.RFC3339),
		Inputs:               strings.Join(inputPaths, ", "),
		PolicyVersion:        policyVersionForReport(artifact.Policy.PolicyVersion),
		AcceptedRisksUsed:    acceptedRisksUsedForReport(artifact.Policy.AcceptedRisksApplied),
		Decision:             string(artifact.Decision.Status),
		DecisionClass:        decisionClass,
		ExitCode:             artifact.Decision.ExitCode,
		ReleaseRisk:          artifact.Scoring.ReleaseRisk,
		TrustScore:           artifact.Trust.TrustScore,
		TotalFindings:        artifact.Findings.TotalCount,
		HardStops:            artifact.Findings.HardStopCount,
		Considered:           artifact.Findings.ConsideredCount,
		AllConsideredMustFix: artifact.Findings.ConsideredCount > 0 && len(mustFixIssues) == artifact.Findings.ConsideredCount,
		AllIssues:            issues,
		MustFixIssues:        mustFixIssues,
		SuppressedIssues:     suppressedIssues,
		OtherIssues:          otherIssues,
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

func cvssForReport(score *float64) string {
	if score == nil {
		return "n/a"
	}
	return fmt.Sprintf("%.1f", *score)
}

func remediationURLForReport(finding trivy.CanonicalFinding) string {
	cve := strings.ToUpper(strings.TrimSpace(finding.CVE))
	if cveIDPattern.MatchString(cve) {
		return "https://nvd.nist.gov/vuln/detail/" + cve
	}

	hint := strings.TrimSpace(finding.RemediationHint)
	hintLower := strings.ToLower(hint)
	if strings.HasPrefix(hintLower, "https://") || strings.HasPrefix(hintLower, "http://") {
		return hint
	}

	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func findingAnchorID(index int, finding trivy.CanonicalFinding) string {
	base := strings.TrimSpace(finding.FindingID)
	if base == "" {
		base = strings.TrimSpace(finding.Fingerprint)
	}
	if base == "" {
		base = "finding"
	}
	return fmt.Sprintf("issue-%d-%s", index+1, anchorSlug(base))
}

func anchorSlug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		case r == '-' || r == '_':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "finding"
	}
	return out
}

func severityClassForReport(severity string) string {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return "severity-critical"
	case "HIGH":
		return "severity-high"
	case "MEDIUM":
		return "severity-medium"
	case "LOW":
		return "severity-low"
	default:
		return "severity-unknown"
	}
}
