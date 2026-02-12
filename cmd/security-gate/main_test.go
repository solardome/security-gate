package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/solardome/security-gate/internal/domain"
	"github.com/solardome/security-gate/internal/ingest/trivy"

	"github.com/solardome/security-gate/internal/policy"
	"github.com/solardome/security-gate/internal/scoring"
)

func cmdFixturePath(name string) string {
	return filepath.Join("..", "..", "testdata", name)
}

func TestLoadContextFromWrappedFixture(t *testing.T) {
	t.Parallel()

	payload, hash, err := loadContext(cmdFixturePath("context-sample.json"))
	if err != nil {
		t.Fatalf("loadContext failed: %v", err)
	}
	if hash == "" {
		t.Fatalf("expected non-empty context hash")
	}
	if payload.PipelineStage != string(policy.StageRelease) {
		t.Fatalf("expected pipeline_stage=release, got %q", payload.PipelineStage)
	}
	if payload.Environment != "staging" {
		t.Fatalf("expected environment=staging, got %q", payload.Environment)
	}
	if payload.Exposure != "internal" {
		t.Fatalf("expected exposure=internal, got %q", payload.Exposure)
	}
	if payload.ChangeType != "moderate" {
		t.Fatalf("expected change_type=moderate, got %q", payload.ChangeType)
	}
	if payload.ScannerVersion != "0.58.1" {
		t.Fatalf("expected scanner_version=0.58.1, got %q", payload.ScannerVersion)
	}
	if payload.ArtifactSigningStatus != "verified" {
		t.Fatalf("expected artifact_signing_status=verified, got %q", payload.ArtifactSigningStatus)
	}
	if payload.ProvenanceLevel != "level2" {
		t.Fatalf("expected provenance_level=level2, got %q", payload.ProvenanceLevel)
	}
	if payload.BranchProtected == nil || !*payload.BranchProtected {
		t.Fatalf("expected branch_protected=true")
	}
}

func TestLoadContextAppliesDefaults(t *testing.T) {
	t.Parallel()

	payload, hash, err := loadContext(cmdFixturePath("context-minimal.json"))
	if err != nil {
		t.Fatalf("loadContext failed: %v", err)
	}
	if hash == "" {
		t.Fatalf("expected non-empty context hash")
	}
	if payload.PipelineStage != string(policy.StagePR) {
		t.Fatalf("expected pipeline_stage=pr, got %q", payload.PipelineStage)
	}
	if payload.Environment != defaultEnvironment {
		t.Fatalf("expected default environment=%q, got %q", defaultEnvironment, payload.Environment)
	}
	if payload.Exposure != defaultExposure {
		t.Fatalf("expected default exposure=%q, got %q", defaultExposure, payload.Exposure)
	}
	if payload.ChangeType != defaultChangeType {
		t.Fatalf("expected default change_type=%q, got %q", defaultChangeType, payload.ChangeType)
	}
}

func TestLoadPolicyFromFixture(t *testing.T) {
	t.Parallel()

	loaded, hash, err := loadPolicy(cmdFixturePath("policy-sample.json"))
	if err != nil {
		t.Fatalf("loadPolicy failed: %v", err)
	}
	if hash == "" {
		t.Fatalf("expected non-empty policy hash")
	}
	if loaded.PolicyVersion != "fixture-v1" {
		t.Fatalf("expected policy_version=fixture-v1, got %q", loaded.PolicyVersion)
	}
	if !loaded.RequiresSignedArtifact {
		t.Fatalf("expected requires_signed_artifact=true")
	}
	if loaded.RequiresProvenanceLevel != "level2" {
		t.Fatalf("expected requires_provenance_level=level2, got %q", loaded.RequiresProvenanceLevel)
	}
	if len(loaded.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(loaded.Rules))
	}
	if loaded.Rules[0].ID != "R-PR-NOISE" {
		t.Fatalf("unexpected rule ID %q", loaded.Rules[0].ID)
	}
	if loaded.Exceptions == nil {
		t.Fatalf("expected exceptions to be initialized as empty slice")
	}
}

func TestParseStage(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		raw     string
		want    policy.Stage
		wantErr bool
	}{
		{name: "pr", raw: "pr", want: policy.StagePR},
		{name: "main", raw: "main", want: policy.StageMain},
		{name: "release", raw: "release", want: policy.StageRelease},
		{name: "prod", raw: "prod", want: policy.StageProd},
		{name: "trim and case", raw: "  ReLeAsE ", want: policy.StageRelease},
		{name: "invalid", raw: "dev", wantErr: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseStage(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestResolveStage(t *testing.T) {
	t.Parallel()

	stage, declared, err := resolveStage(contextPayload{PipelineStage: "release"}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stage != policy.StageRelease || declared != "release" {
		t.Fatalf("unexpected stage resolution: stage=%q declared=%q", stage, declared)
	}

	stage, _, err = resolveStage(contextPayload{PipelineStage: "release"}, "prod")
	if err != nil {
		t.Fatalf("unexpected error with override: %v", err)
	}
	if stage != policy.StageProd {
		t.Fatalf("expected override stage prod, got %q", stage)
	}

	stage, _, err = resolveStage(contextPayload{PipelineStage: "bad"}, "main")
	if err == nil {
		t.Fatalf("expected error for invalid context stage")
	}
	if stage != policy.StageMain {
		t.Fatalf("expected fallback stage from override main, got %q", stage)
	}
	if resolveFatalCode("", err) != "CONTEXT_STAGE_INVALID" {
		t.Fatalf("expected CONTEXT_STAGE_INVALID, got %q", resolveFatalCode("", err))
	}

	_, _, err = resolveStage(contextPayload{PipelineStage: "pr"}, "bad")
	if err == nil {
		t.Fatalf("expected error for invalid override")
	}
	if resolveFatalCode("", err) != "CLI_STAGE_INVALID" {
		t.Fatalf("expected CLI_STAGE_INVALID, got %q", resolveFatalCode("", err))
	}
}

func TestReportWriteAffectedInput(t *testing.T) {
	t.Parallel()

	if got := reportWriteAffectedInput(withErrorCode("OUTPUT_DIR_CREATE_FAILED", errors.New("x"))); got != "output_dir" {
		t.Fatalf("expected output_dir, got %q", got)
	}
	if got := reportWriteAffectedInput(withErrorCode("REPORT_JSON_WRITE_FAILED", errors.New("x"))); got != "report.json" {
		t.Fatalf("expected report.json, got %q", got)
	}
	if got := reportWriteAffectedInput(withErrorCode("HTML_WRITE_FAILED", errors.New("x"))); got != "report.html" {
		t.Fatalf("expected report.html, got %q", got)
	}
	if got := reportWriteAffectedInput(withErrorCode("CHECKSUMS_WRITE_FAILED", errors.New("x"))); got != "checksums.sha256" {
		t.Fatalf("expected checksums.sha256, got %q", got)
	}
	if got := reportWriteAffectedInput(errors.New("x")); got != "report_output" {
		t.Fatalf("expected report_output, got %q", got)
	}
}

func TestLoadContextErrorsAndDefaults(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	invalidPath := filepath.Join(tmp, "invalid-context.json")
	if err := os.WriteFile(invalidPath, []byte("{bad-json"), 0o600); err != nil {
		t.Fatalf("write invalid context: %v", err)
	}
	if _, _, err := loadContext(invalidPath); err == nil {
		t.Fatalf("expected parse error")
	}

	tooLargePath := filepath.Join(tmp, "too-large-context.json")
	oversized := make([]byte, maxContextBytes+1)
	if err := os.WriteFile(tooLargePath, oversized, 0o600); err != nil {
		t.Fatalf("write oversized context: %v", err)
	}
	_, _, err := loadContext(tooLargePath)
	if err == nil {
		t.Fatalf("expected size error")
	}
	if resolveFatalCode("", err) != "CONTEXT_TOO_LARGE" {
		t.Fatalf("expected CONTEXT_TOO_LARGE, got %q", resolveFatalCode("", err))
	}

	payload, hash, err := loadContext("")
	if err != nil {
		t.Fatalf("unexpected error for empty context path: %v", err)
	}
	if hash == "" {
		t.Fatalf("expected hash for default context")
	}
	if payload.PipelineStage != string(policy.StagePR) {
		t.Fatalf("expected default pipeline_stage pr, got %q", payload.PipelineStage)
	}
}

func TestLoadPolicyDefaultsAndErrors(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	invalidPath := filepath.Join(tmp, "invalid-policy.json")
	if err := os.WriteFile(invalidPath, []byte("{bad-json"), 0o600); err != nil {
		t.Fatalf("write invalid policy: %v", err)
	}
	if _, _, err := loadPolicy(invalidPath); err == nil {
		t.Fatalf("expected parse error")
	}

	tooLargePath := filepath.Join(tmp, "too-large-policy.json")
	oversized := make([]byte, maxPolicyBytes+1)
	if err := os.WriteFile(tooLargePath, oversized, 0o600); err != nil {
		t.Fatalf("write oversized policy: %v", err)
	}
	_, _, err := loadPolicy(tooLargePath)
	if err == nil {
		t.Fatalf("expected size error")
	}
	if resolveFatalCode("", err) != "POLICY_TOO_LARGE" {
		t.Fatalf("expected POLICY_TOO_LARGE, got %q", resolveFatalCode("", err))
	}

	minimalPath := filepath.Join(tmp, "minimal-policy.json")
	if err := os.WriteFile(minimalPath, []byte(`{"policy_version":"","rules":null,"exceptions":null}`), 0o600); err != nil {
		t.Fatalf("write minimal policy: %v", err)
	}
	loaded, hash, err := loadPolicy(minimalPath)
	if err != nil {
		t.Fatalf("unexpected loadPolicy error: %v", err)
	}
	if hash == "" {
		t.Fatalf("expected non-empty hash")
	}
	if loaded.PolicyVersion != "unknown" {
		t.Fatalf("expected policy_version unknown, got %q", loaded.PolicyVersion)
	}
	if loaded.Rules == nil || loaded.Exceptions == nil {
		t.Fatalf("expected rules and exceptions initialized")
	}
}

func TestLoadEffectivePolicyAndAcceptedRiskDefaults(t *testing.T) {
	t.Parallel()

	pol, polHash, err := loadEffectivePolicy("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pol.PolicyVersion != "embedded-default" {
		t.Fatalf("expected embedded-default policy, got %q", pol.PolicyVersion)
	}
	if polHash != hashBytes([]byte(embeddedDefaultPolicyRaw)) {
		t.Fatalf("unexpected embedded policy hash")
	}

	risks, riskHash, err := loadAcceptedRisks("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if risks != nil {
		t.Fatalf("expected nil risks for empty path")
	}
	if riskHash != hashBytes([]byte(emptyAcceptedRisksJSON)) {
		t.Fatalf("unexpected accepted risk hash")
	}
}

func TestBuildTrustContext(t *testing.T) {
	t.Parallel()

	ts := time.Now().UTC()
	ctx := contextPayload{
		ScannerVersion:        "1.2.3",
		ArtifactSigningStatus: "",
		ProvenanceLevel:       "",
	}
	metaMatch := map[string]policy.ScanMetadata{
		"a": {SourceVersion: "1.2.3"},
		"b": {SourceVersion: "1.2.3"},
	}
	trust := buildTrustContext(ctx, metaMatch, ts)
	if !trust.ScannerPinned {
		t.Fatalf("expected scanner pinned for matching versions")
	}
	if trust.ArtifactSigningStatus != "unknown" || trust.ProvenanceLevel != "unknown" {
		t.Fatalf("expected unknown defaults, got signing=%q provenance=%q", trust.ArtifactSigningStatus, trust.ProvenanceLevel)
	}

	metaMismatch := map[string]policy.ScanMetadata{"a": {SourceVersion: "9.9.9"}}
	trust = buildTrustContext(ctx, metaMismatch, ts)
	if trust.ScannerPinned {
		t.Fatalf("expected scanner pinned false for mismatch")
	}
}

func TestScanMetadataAndTimestamps(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	earlier := now.Add(-time.Hour)
	findings := []trivy.CanonicalFinding{
		{InputSHA256: "h1", SourceScanner: "trivy", SourceVersion: "0.1.0", ScanTimestamp: earlier},
		{InputSHA256: "h2", SourceScanner: "trivy", SourceVersion: "0.2.0", ScanTimestamp: now},
	}
	hashes := map[string]string{"a.json": "h1", "b.json": "h2", "c.json": "h3"}
	meta := buildScanMetadata(findings, hashes)
	if meta["a.json"].SourceVersion != "0.1.0" {
		t.Fatalf("unexpected source version for a.json: %q", meta["a.json"].SourceVersion)
	}
	if meta["c.json"].SourceVersion != "unknown" {
		t.Fatalf("expected unknown source version for unmatched hash")
	}

	gotTS := firstScanTimestamp(findings, now.Add(-2*time.Hour))
	if !gotTS.Equal(earlier) {
		t.Fatalf("expected first non-zero timestamp")
	}
	emptyTS := firstScanTimestamp(nil, now)
	if !emptyTS.Equal(now) {
		t.Fatalf("expected fallback timestamp")
	}

	if len(scanMetadataForFatal(nil, nil)) != 0 {
		t.Fatalf("expected empty map for no hashes")
	}
}

func TestIssueStatus(t *testing.T) {
	t.Parallel()

	if got := issueStatus(scoring.ScoredFinding{HardStop: true}); got != string(domain.DecisionBlock) {
		t.Fatalf("expected BLOCK status, got %q", got)
	}
	if got := issueStatus(scoring.ScoredFinding{SuppressedByNoiseBudget: true}); got != "SUPPRESSED" {
		t.Fatalf("expected SUPPRESSED status, got %q", got)
	}
	if got := issueStatus(scoring.ScoredFinding{}); got != "CONSIDERED" {
		t.Fatalf("expected CONSIDERED status, got %q", got)
	}
}

func TestWriteReportsAndFatalBuilders(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 12, 12, 0, 0, 0, time.UTC)
	tmp := t.TempDir()
	artifact := policy.DecisionArtifact{
		Decision: policy.PolicyDecision{Status: domain.DecisionAllow, ExitCode: 0},
	}
	report := decisionReport{
		SchemaVersion:    schemaVersion,
		ToolVersion:      toolVersion,
		GeneratedAt:      now.Format(time.RFC3339),
		DecisionArtifact: artifact,
	}
	reportPath, htmlPath, checksumsPath, err := writeReports(now, tmp, report, artifact, []string{"input/a.json"}, true)
	if err != nil {
		t.Fatalf("writeReports failed: %v", err)
	}
	for _, p := range []string{reportPath, htmlPath, checksumsPath} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected file %s: %v", p, err)
		}
	}
	content, err := os.ReadFile(checksumsPath)
	if err != nil {
		t.Fatalf("read checksums: %v", err)
	}
	if !strings.Contains(string(content), "report.json") || !strings.Contains(string(content), "report.html") {
		t.Fatalf("checksums file missing expected entries: %s", string(content))
	}

	snapshot := buildFatalSnapshot(now, "", policy.StagePR, true, contextPayload{}, "", "", "", nil, nil)
	if snapshot.exitCode != 1 || snapshot.decisionStatus != domain.DecisionWarn {
		t.Fatalf("expected WARN/exit 1 for PR hashable fatal")
	}
	if snapshot.contextHash == "" || snapshot.policyHash == "" || snapshot.acceptedRiskHash == "" {
		t.Fatalf("expected hashes to be initialized")
	}
	scans := buildFatalScans(map[string]string{"a": "h"}, map[string]policy.ScanMetadata{"a": {}})
	if len(scans) != 1 || scans[0].SourceScanner != "trivy" {
		t.Fatalf("unexpected fatal scans: %+v", scans)
	}
	artifactFatal := buildFatalArtifact(snapshot, "X", policy.DecisionTraceEvent{})
	if artifactFatal.Decision.ExitCode != 1 {
		t.Fatalf("expected fatal artifact exit code 1, got %d", artifactFatal.Decision.ExitCode)
	}
}

func TestResolveOutputDirAndRunID(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 12, 12, 0, 0, 0, time.UTC)
	hashes := map[string]string{"b.json": "h2", "a.json": "h1"}
	runID1 := buildRunID(policy.StageRelease, "ctx", "pol", "ar", hashes)
	runID2 := buildRunID(policy.StageRelease, "ctx", "pol", "ar", hashes)
	if runID1 != runID2 || len(runID1) != 12 {
		t.Fatalf("run id should be stable and 12 chars, got %q / %q", runID1, runID2)
	}

	cfg := cliConfig{outputDir: "/tmp/custom", outputDirExplicit: true}
	if got := resolveOutputDir(cfg, now, policy.StageRelease, "ctx", "pol", "ar", hashes); got != "/tmp/custom" {
		t.Fatalf("expected explicit output dir, got %q", got)
	}

	cfg = cliConfig{}
	got := resolveOutputDir(cfg, now, policy.StageRelease, "ctx", "pol", "ar", hashes)
	if !strings.HasPrefix(got, filepath.Join(defaultReportsDir, now.Format("20060102-150405")+"-")) {
		t.Fatalf("unexpected auto output dir format: %q", got)
	}
}
