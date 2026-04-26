package securitygate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestEffectiveStageMapping(t *testing.T) {
	cases := []struct {
		ctx  Context
		want string
	}{
		{Context{BranchType: "main", PipelineStage: "pr", Environment: "ci"}, "merge"},
		{Context{BranchType: "feature", PipelineStage: "release", Environment: "ci"}, "release"},
		{Context{BranchType: "release", PipelineStage: "merge", Environment: "prod"}, "deploy"},
	}
	for _, c := range cases {
		if got := effectiveStage(c.ctx); got != c.want {
			t.Fatalf("effectiveStage()=%s want=%s", got, c.want)
		}
	}
}

func TestRiskMonotonicity(t *testing.T) {
	pol := defaultPolicy()
	ctx := Context{
		BranchType:      "feature",
		PipelineStage:   "pr",
		Environment:     "ci",
		RepoCriticality: "high",
		Exposure:        "internet",
		ChangeType:      "application",
	}
	trust := trustScore(ctx, pol, nil, []string{"0.50.0"}, []string{time.Now().UTC().Format(time.RFC3339)}, time.Now().UTC())

	f1 := UnifiedFinding{Class: UnifiedClassification{Severity: "low", ExploitMaturity: "none", Reachability: "not_reachable", Confidence: "high", DomainID: "VULN_GENERIC"}}
	f2 := UnifiedFinding{Class: UnifiedClassification{Severity: "critical", ExploitMaturity: "known_exploited", Reachability: "reachable", Confidence: "high", DomainID: "VULN_GENERIC"}}
	f1.FindingRiskScore = scoreFinding(f1, ctx, pol, "pr")
	base := aggregateOverall([]UnifiedFinding{f1}, ctx, "pr", trust, 0, false)

	f2.FindingRiskScore = scoreFinding(f2, ctx, pol, "pr")
	withMore := aggregateOverall([]UnifiedFinding{f1, f2}, ctx, "pr", trust, 0, false)

	if withMore.OverallScore < base.OverallScore {
		t.Fatalf("risk decreased after adding finding: base=%d new=%d", base.OverallScore, withMore.OverallScore)
	}
}

func TestHardStopPrecedenceBlocks(t *testing.T) {
	dir := t.TempDir()
	paths := writeScenario(t, dir, scenarioConfig{
		BranchType:    "feature",
		PipelineStage: "pr",
		Environment:   "ci",
		Severity:      "low",
		DomainID:      "HS_POLICY_INTEGRITY_BROKEN",
		WithAR:        false,
		ExpiredAR:     false,
	})
	report, err := Run(context.Background(), Config{
		ScanPaths:   []string{paths.Scan},
		ContextPath: paths.Context,
		PolicyPath:  paths.Policy,
		OutJSONPath: filepath.Join(dir, "out.json"),
		OutHTMLPath: filepath.Join(dir, "out.html"),
		WriteHTML:   false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Decision != DecisionBlock {
		t.Fatalf("expected BLOCK got %s", report.Decision)
	}
}

func TestAcceptedRiskExpiredStageBehavior(t *testing.T) {
	t.Run("release_blocks", func(t *testing.T) {
		dir := t.TempDir()
		paths := writeScenario(t, dir, scenarioConfig{
			BranchType:    "release",
			PipelineStage: "release",
			Environment:   "ci",
			Severity:      "high",
			DomainID:      "VULN_GENERIC",
			WithAR:        true,
			ExpiredAR:     true,
		})
		report, err := Run(context.Background(), Config{
			ScanPaths:        []string{paths.Scan},
			ContextPath:      paths.Context,
			PolicyPath:       paths.Policy,
			AcceptedRiskPath: paths.AcceptedRisk,
			OutJSONPath:      filepath.Join(dir, "out.json"),
			OutHTMLPath:      filepath.Join(dir, "out.html"),
			WriteHTML:        false,
		})
		if err != nil {
			t.Fatal(err)
		}
		if report.Decision != DecisionBlock {
			t.Fatalf("expected BLOCK got %s (stage=%s trace=%v)", report.Decision, report.EffectiveStage, report.DecisionTrace)
		}
	})

	t.Run("pr_warns", func(t *testing.T) {
		dir := t.TempDir()
		paths := writeScenario(t, dir, scenarioConfig{
			BranchType:    "feature",
			PipelineStage: "pr",
			Environment:   "ci",
			Severity:      "high",
			DomainID:      "VULN_GENERIC",
			WithAR:        true,
			ExpiredAR:     true,
		})
		report, err := Run(context.Background(), Config{
			ScanPaths:        []string{paths.Scan},
			ContextPath:      paths.Context,
			PolicyPath:       paths.Policy,
			AcceptedRiskPath: paths.AcceptedRisk,
			OutJSONPath:      filepath.Join(dir, "out.json"),
			OutHTMLPath:      filepath.Join(dir, "out.html"),
			WriteHTML:        false,
		})
		if err != nil {
			t.Fatal(err)
		}
		if report.Decision != DecisionWarn {
			t.Fatalf("expected WARN got %s (stage=%s trace=%v)", report.Decision, report.EffectiveStage, report.DecisionTrace)
		}
	})
}

func TestReportAcceptedRiskJSONContract(t *testing.T) {
	dir := t.TempDir()
	paths := writeScenario(t, dir, scenarioConfig{
		BranchType:    "feature",
		PipelineStage: "pr",
		Environment:   "ci",
		Severity:      "high",
		DomainID:      "VULN_GENERIC",
		WithAR:        true,
		ExpiredAR:     false,
	})
	outJSON := filepath.Join(dir, "out.json")
	_, err := Run(context.Background(), Config{
		ScanPaths:        []string{paths.Scan},
		ContextPath:      paths.Context,
		PolicyPath:       paths.Policy,
		AcceptedRiskPath: paths.AcceptedRisk,
		OutJSONPath:      outJSON,
		OutHTMLPath:      filepath.Join(dir, "out.html"),
		WriteHTML:        false,
	})
	if err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(outJSON)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	arAny, ok := payload["accepted_risk"]
	if !ok {
		t.Fatalf("accepted_risk missing from report")
	}
	ar, ok := arAny.(map[string]any)
	if !ok {
		t.Fatalf("accepted_risk must be object, got %T", arAny)
	}
	if _, exists := ar["NearExpiry"]; exists {
		t.Fatalf("accepted_risk contains non-canonical field NearExpiry")
	}
	if _, exists := ar["ApprovalUnmet"]; exists {
		t.Fatalf("accepted_risk contains non-canonical field ApprovalUnmet")
	}
	if len(ar) != 3 {
		t.Fatalf("accepted_risk expected exactly 3 fields, got %d: %v", len(ar), ar)
	}
}

func TestTrustUsesScannerReportVersionNotContext(t *testing.T) {
	dir := t.TempDir()
	paths := writeScenario(t, dir, scenarioConfig{
		BranchType:    "feature",
		PipelineStage: "pr",
		Environment:   "ci",
		Severity:      "low",
		DomainID:      "VULN_GENERIC",
		WithAR:        false,
		ExpiredAR:     false,
	})

	ctx := Context{
		BranchType:      "feature",
		PipelineStage:   "pr",
		Environment:     "ci",
		RepoCriticality: "high",
		Exposure:        "internet",
		ChangeType:      "application",
		Scanner:         ScannerMeta{Name: "trivy", Version: "999.999.999"},
		Provenance:      Provenance{ArtifactSigned: "yes", Level: "verified", BuildContextIntegrity: "verified"},
	}
	writeYAMLFile(t, paths.Context, ctx)
	writeJSONFile(t, paths.Scan, map[string]any{
		"ArtifactName": "registry.local/app@sha256:deadbeef",
		"GeneratedAt":  "2026-02-19T11:00:00Z",
		"Results": []any{
			map[string]any{
				"Target": "app",
				"Vulnerabilities": []any{
					map[string]any{
						"VulnerabilityID": "CVE-2025-1111",
						"PkgName":         "openssl",
						"Severity":        "LOW",
						"Title":           "openssl issue",
						"DomainID":        "VULN_GENERIC",
					},
				},
			},
		},
	})

	report, err := Run(context.Background(), Config{
		ScanPaths:      []string{paths.Scan},
		ContextPath:    paths.Context,
		PolicyPath:     paths.Policy,
		OutJSONPath:    filepath.Join(dir, "out.json"),
		OutHTMLPath:    filepath.Join(dir, "out.html"),
		WriteHTML:      false,
		EvaluationTime: "2026-02-19T12:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reportHasTrustPenalty(report, "SCANNER_VERSION_UNKNOWN") {
		t.Fatalf("expected scanner version to be derived from scan evidence, got penalties %+v", report.Trust.Penalties)
	}
}

func TestEvaluationTimeControlsReportAndFreshness(t *testing.T) {
	dir := t.TempDir()
	paths := writeScenario(t, dir, scenarioConfig{
		BranchType:    "feature",
		PipelineStage: "pr",
		Environment:   "ci",
		Severity:      "low",
		DomainID:      "VULN_GENERIC",
		WithAR:        false,
		ExpiredAR:     false,
	})
	writeJSONFile(t, paths.Scan, map[string]any{
		"ArtifactName": "registry.local/app@sha256:deadbeef",
		"Scanner":      map[string]any{"Name": "trivy", "Version": "0.50.0"},
		"GeneratedAt":  "2026-02-19T11:00:00Z",
		"Results": []any{
			map[string]any{
				"Target": "app",
				"Vulnerabilities": []any{
					map[string]any{
						"VulnerabilityID": "CVE-2025-1111",
						"PkgName":         "openssl",
						"Severity":        "LOW",
						"Title":           "openssl issue",
						"DomainID":        "VULN_GENERIC",
					},
				},
			},
		},
	})

	report, err := Run(context.Background(), Config{
		ScanPaths:      []string{paths.Scan},
		ContextPath:    paths.Context,
		PolicyPath:     paths.Policy,
		OutJSONPath:    filepath.Join(dir, "out.json"),
		OutHTMLPath:    filepath.Join(dir, "out.html"),
		WriteHTML:      false,
		EvaluationTime: "2026-02-19T12:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.GeneratedAt != "2026-02-19T12:00:00Z" {
		t.Fatalf("expected generated_at to use evaluation time, got %s", report.GeneratedAt)
	}
	if reportHasTrustPenalty(report, "SCAN_FRESHNESS_UNKNOWN_OR_STALE") {
		t.Fatalf("did not expect freshness penalty with explicit evaluation time, got %+v", report.Trust.Penalties)
	}
}

func TestRunCancelledReturnsContextError(t *testing.T) {
	dir := t.TempDir()
	paths := writeScenario(t, dir, scenarioConfig{
		BranchType:    "feature",
		PipelineStage: "pr",
		Environment:   "ci",
		Severity:      "low",
		DomainID:      "VULN_GENERIC",
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Run(ctx, Config{
		ScanPaths:   []string{paths.Scan},
		ContextPath: paths.Context,
		PolicyPath:  paths.Policy,
		OutJSONPath: filepath.Join(dir, "out.json"),
		OutHTMLPath: filepath.Join(dir, "out.html"),
		WriteHTML:   false,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context canceled", err)
	}
}

func TestRunRejectsInvalidEvaluationTime(t *testing.T) {
	dir := t.TempDir()
	paths := writeScenario(t, dir, scenarioConfig{
		BranchType:    "feature",
		PipelineStage: "pr",
		Environment:   "ci",
		Severity:      "low",
		DomainID:      "VULN_GENERIC",
	})
	_, err := Run(context.Background(), Config{
		ScanPaths:      []string{paths.Scan},
		ContextPath:    paths.Context,
		PolicyPath:     paths.Policy,
		OutJSONPath:    filepath.Join(dir, "out.json"),
		OutHTMLPath:    filepath.Join(dir, "out.html"),
		WriteHTML:      false,
		EvaluationTime: "not-rfc3339",
	})
	if err == nil || !strings.Contains(err.Error(), "invalid --evaluation-time") {
		t.Fatalf("expected invalid evaluation-time error, got %v", err)
	}
}

func reportHasTrustPenalty(report Report, code string) bool {
	for _, p := range report.Trust.Penalties {
		if p.Code == code {
			return true
		}
	}
	return false
}

func TestLoadPolicyWrapsSentinelError(t *testing.T) {
	state := &EngineState{}
	err := loadPolicy(state, filepath.Join(t.TempDir(), "missing-policy.yaml"))
	if !errors.Is(err, ErrPolicyLoad) {
		t.Fatalf("loadPolicy() error = %v, want ErrPolicyLoad", err)
	}
}

func TestRunSupportsSARIFInput(t *testing.T) {
	dir := t.TempDir()
	paths := writeScenario(t, dir, scenarioConfig{
		BranchType:    "feature",
		PipelineStage: "pr",
		Environment:   "ci",
		Severity:      "low",
		DomainID:      "VULN_GENERIC",
		WithAR:        false,
		ExpiredAR:     false,
	})

	sarifScan := map[string]any{
		"version": "2.1.0",
		"runs": []any{
			map[string]any{
				"tool": map[string]any{
					"driver": map[string]any{
						"name":            "snyk-code",
						"semanticVersion": "1.2.3",
						"rules": []any{
							map[string]any{
								"id": "CVE-2026-5555",
								"shortDescription": map[string]any{
									"text": "sample finding",
								},
								"properties": map[string]any{
									"category": "vuln",
								},
							},
						},
					},
				},
				"invocations": []any{
					map[string]any{"endTimeUtc": "2026-02-19T10:00:00Z"},
				},
				"results": []any{
					map[string]any{
						"ruleId": "CVE-2026-5555",
						"level":  "note",
						"message": map[string]any{
							"text": "sample finding",
						},
						"properties": map[string]any{
							"component":         "openssl",
							"domain_id":         "VULN_GENERIC",
							"severity":          "low",
							"exploit_maturity":  "none",
							"reachability":      "not_reachable",
							"confidence":        "high",
							"target_ref":        "registry.local/app@sha256:abc",
							"security_severity": "3.0",
						},
					},
				},
			},
		},
	}
	writeJSONFile(t, paths.Scan, sarifScan)

	report, err := Run(context.Background(), Config{
		ScanPaths:   []string{paths.Scan},
		ContextPath: paths.Context,
		PolicyPath:  paths.Policy,
		OutJSONPath: filepath.Join(dir, "out.json"),
		OutHTMLPath: filepath.Join(dir, "out.html"),
		WriteHTML:   false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Decision != DecisionAllow {
		t.Fatalf("expected ALLOW for low SARIF finding in pr context, got %s", report.Decision)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 report finding, got %d", len(report.Findings))
	}
	if report.Context.Scanner.Name != "trivy" {
		t.Fatalf("expected context scanner to remain unchanged, got %s", report.Context.Scanner.Name)
	}
}

func TestRunSupportsSnykInput(t *testing.T) {
	dir := t.TempDir()
	paths := writeScenario(t, dir, scenarioConfig{
		BranchType:    "feature",
		PipelineStage: "pr",
		Environment:   "ci",
		Severity:      "low",
		DomainID:      "VULN_GENERIC",
		WithAR:        false,
		ExpiredAR:     false,
	})

	snykScan := map[string]any{
		"generatedAt": "2026-02-19T10:00:00Z",
		"projectName": "payments-api",
		"vulnerabilities": []any{
			map[string]any{
				"id":          "SNYK-TEST-1",
				"title":       "low vuln",
				"severity":    "low",
				"packageName": "lodash",
			},
		},
	}
	writeJSONFile(t, paths.Scan, snykScan)

	report, err := Run(context.Background(), Config{
		ScanPaths:   []string{paths.Scan},
		ContextPath: paths.Context,
		PolicyPath:  paths.Policy,
		OutJSONPath: filepath.Join(dir, "out.json"),
		OutHTMLPath: filepath.Join(dir, "out.html"),
		WriteHTML:   false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Decision != DecisionWarn {
		t.Fatalf("expected WARN for low snyk finding in pr context, got %s", report.Decision)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 report finding, got %d", len(report.Findings))
	}
}

func TestRunSupportsCheckmarxInput(t *testing.T) {
	dir := t.TempDir()
	paths := writeScenario(t, dir, scenarioConfig{
		BranchType:    "feature",
		PipelineStage: "pr",
		Environment:   "ci",
		Severity:      "low",
		DomainID:      "VULN_GENERIC",
		WithAR:        false,
		ExpiredAR:     false,
	})

	checkmarxScan := map[string]any{
		"reportType": "json-v2",
		"scanInfo": map[string]any{
			"projectName": "payments-api",
			"finishedAt":  "2026-02-19T10:00:00Z",
		},
		"scanResults": []any{
			map[string]any{
				"queryId":   111,
				"queryName": "Low signal",
				"severity":  "low",
				"filePath":  "src/app.go",
			},
		},
	}
	writeJSONFile(t, paths.Scan, checkmarxScan)

	report, err := Run(context.Background(), Config{
		ScanPaths:   []string{paths.Scan},
		ContextPath: paths.Context,
		PolicyPath:  paths.Policy,
		OutJSONPath: filepath.Join(dir, "out.json"),
		OutHTMLPath: filepath.Join(dir, "out.html"),
		WriteHTML:   false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Decision != DecisionWarn {
		t.Fatalf("expected WARN for low checkmarx finding in pr context, got %s", report.Decision)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 report finding, got %d", len(report.Findings))
	}
}

func TestRunSupportsSonarGenericInput(t *testing.T) {
	dir := t.TempDir()
	paths := writeScenario(t, dir, scenarioConfig{
		BranchType:    "feature",
		PipelineStage: "pr",
		Environment:   "ci",
		Severity:      "low",
		DomainID:      "VULN_GENERIC",
		WithAR:        false,
		ExpiredAR:     false,
	})

	sonarScan := map[string]any{
		"generatedAt": "2026-02-19T10:00:00Z",
		"projectKey":  "payments-api",
		"rules": []any{
			map[string]any{
				"id":       "R1",
				"name":     "Low issue",
				"severity": "LOW",
				"type":     "CODE_SMELL",
			},
		},
		"issues": []any{
			map[string]any{
				"ruleId": "R1",
				"primaryLocation": map[string]any{
					"message":  "Low issue",
					"filePath": "src/app.go",
				},
			},
		},
	}
	writeJSONFile(t, paths.Scan, sonarScan)

	report, err := Run(context.Background(), Config{
		ScanPaths:   []string{paths.Scan},
		ContextPath: paths.Context,
		PolicyPath:  paths.Policy,
		OutJSONPath: filepath.Join(dir, "out.json"),
		OutHTMLPath: filepath.Join(dir, "out.html"),
		WriteHTML:   false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Decision != DecisionWarn {
		t.Fatalf("expected WARN for low sonar finding in pr context, got %s", report.Decision)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 report finding, got %d", len(report.Findings))
	}
}

type scenarioConfig struct {
	BranchType    string
	PipelineStage string
	Environment   string
	Severity      string
	DomainID      string
	WithAR        bool
	ExpiredAR     bool
}

type scenarioPaths struct {
	Scan         string
	Context      string
	Policy       string
	AcceptedRisk string
}

func writeScenario(t *testing.T, dir string, cfg scenarioConfig) scenarioPaths {
	t.Helper()
	policy := defaultPolicy()
	policyPath := filepath.Join(dir, "policy.yaml")
	writeYAMLFile(t, policyPath, policy)

	ctx := Context{
		BranchType:      cfg.BranchType,
		PipelineStage:   cfg.PipelineStage,
		Environment:     cfg.Environment,
		RepoCriticality: "high",
		Exposure:        "internet",
		ChangeType:      "application",
		Scanner:         ScannerMeta{Name: "trivy", Version: "0.50.0"},
		Provenance:      Provenance{ArtifactSigned: "yes", Level: "verified", BuildContextIntegrity: "verified"},
	}
	contextPath := filepath.Join(dir, "context.yaml")
	writeYAMLFile(t, contextPath, ctx)

	scan := map[string]any{
		"ArtifactName": "registry.local/app@sha256:deadbeef",
		"Results": []any{
			map[string]any{
				"Target": "app",
				"Vulnerabilities": []any{
					map[string]any{
						"VulnerabilityID":  "CVE-2025-1111",
						"PkgName":          "openssl",
						"InstalledVersion": "1.1.1",
						"Severity":         cfg.Severity,
						"Title":            "openssl issue",
						"PrimaryURL":       "https://example.local/cve",
						"DomainID":         cfg.DomainID,
						"ExploitMaturity":  "none",
						"Reachability":     "reachable",
						"Confidence":       "high",
					},
				},
			},
		},
	}
	scanPath := filepath.Join(dir, "scan.json")
	writeJSONFile(t, scanPath, scan)

	paths := scenarioPaths{Scan: scanPath, Context: contextPath, Policy: policyPath}
	if cfg.WithAR {
		expiresAt := "2099-01-01T00:00:00Z"
		if cfg.ExpiredAR {
			expiresAt = "2020-01-01T00:00:00Z"
		}
		ar := AcceptedRiskSet{
			SchemaVersion: "1.0",
			Records: []AcceptedRiskRecord{
				{
					ID:        "AR-1",
					Status:    "active",
					Owner:     "team",
					Approvers: []string{"sec-lead"},
					Ticket:    "SEC-1",
					Rationale: "temp",
					Scope: AcceptedRiskScope{
						Type:  "cve",
						Value: "CVE-2025-1111",
					},
					Constraints: AcceptedRiskConstraints{
						MaxSeverity:  "high",
						Environments: []string{"ci", "prod"},
					},
					Timeline: AcceptedRiskTimeline{
						CreatedAt: "2024-01-01T00:00:00Z",
						ExpiresAt: expiresAt,
						SLADays:   365,
					},
				},
			},
		}
		arPath := filepath.Join(dir, "accepted-risk.yaml")
		writeYAMLFile(t, arPath, ar)
		paths.AcceptedRisk = arPath
	}
	return paths
}

func writeJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeYAMLFile(t *testing.T, path string, v any) {
	t.Helper()
	j, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var any any
	if err := json.Unmarshal(j, &any); err != nil {
		t.Fatal(err)
	}
	b, err := yaml.Marshal(any)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
