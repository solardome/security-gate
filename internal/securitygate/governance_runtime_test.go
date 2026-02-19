package securitygate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAcceptedRiskScopeTypeDisallowedByPolicy(t *testing.T) {
	dir := t.TempDir()
	paths := writeScenario(t, dir, scenarioConfig{
		BranchType:    "feature",
		PipelineStage: "pr",
		Environment:   "ci",
		Severity:      "low",
		DomainID:      "VULN_GENERIC",
		WithAR:        true,
		ExpiredAR:     false,
	})

	pol := defaultPolicy()
	pol.ExceptionRules.AllowScopeTypes = []string{"finding_id"}
	writeYAMLFile(t, paths.Policy, pol)

	report, err := Run(Config{
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
		t.Fatalf("expected WARN due validation failure, got %s", report.Decision)
	}
	if report.AcceptedRisk.InvalidRecords == 0 {
		t.Fatalf("expected invalid accepted-risk record due disallowed scope type")
	}
}

func TestReleaseCriticalApprovalUsesEffectiveStage(t *testing.T) {
	dir := t.TempDir()
	paths := writeScenario(t, dir, scenarioConfig{
		BranchType:    "feature",
		PipelineStage: "release",
		Environment:   "ci",
		Severity:      "critical",
		DomainID:      "VULN_GENERIC",
		WithAR:        true,
		ExpiredAR:     false,
	})

	ar := AcceptedRiskSet{
		SchemaVersion: "1.0",
		Records: []AcceptedRiskRecord{
			{
				ID:        "AR-REL-1",
				Status:    "active",
				Owner:     "team",
				Approvers: []string{"dev-lead"},
				Ticket:    "SEC-2",
				Rationale: "temporary",
				Scope: AcceptedRiskScope{
					Type:   "cve",
					Value:  "CVE-2025-1111",
					Stages: []string{"release"},
				},
				Constraints: AcceptedRiskConstraints{
					MaxSeverity:  "critical",
					Environments: []string{"ci"},
				},
				Timeline: AcceptedRiskTimeline{
					CreatedAt: "2024-01-01T00:00:00Z",
					ExpiresAt: "2099-01-01T00:00:00Z",
					SLADays:   365,
				},
			},
		},
	}
	writeYAMLFile(t, paths.AcceptedRisk, ar)

	report, err := Run(Config{
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
	if report.EffectiveStage != "release" {
		t.Fatalf("expected effective stage release, got %s", report.EffectiveStage)
	}
	if report.Decision != DecisionBlock {
		t.Fatalf("expected BLOCK due missing security approval at release stage, got %s", report.Decision)
	}
}

func TestRecordMatchesFindingScopeFilters(t *testing.T) {
	rec := AcceptedRiskRecord{
		Scope: AcceptedRiskScope{
			Type:       "cve",
			Value:      "CVE-2026-1",
			Scanner:    "trivy",
			Repository: "registry.local/payment-api",
			Stages:     []string{"merge"},
		},
		Constraints: AcceptedRiskConstraints{
			MaxSeverity:  "high",
			Environments: []string{"ci"},
		},
	}
	f := UnifiedFinding{
		Scanner: ScannerMeta{Name: "trivy"},
		Artifact: UnifiedArtifact{
			TargetRef: "registry.local/payment-api@sha256:abc",
			Component: "openssl",
		},
		Class: UnifiedClassification{
			CVE:      "CVE-2026-1",
			Severity: "high",
		},
	}
	ctx := Context{
		BranchType:    "main",
		Environment:   "ci",
		PipelineStage: "merge",
	}
	if !recordMatchesFinding(rec, f, ctx, "merge") {
		t.Fatalf("expected record to match with scanner/repository filters")
	}
	rec.Scope.Scanner = "grype"
	if recordMatchesFinding(rec, f, ctx, "merge") {
		t.Fatalf("expected scanner filter mismatch")
	}
	rec.Scope.Scanner = "trivy"
	rec.Scope.Repository = "orders-api"
	if recordMatchesFinding(rec, f, ctx, "merge") {
		t.Fatalf("expected repository filter mismatch")
	}
	rec.Scope.Repository = "payment-api"
	if recordMatchesFinding(rec, f, ctx, "merge") {
		t.Fatalf("expected strict repository identity match, basename should not match")
	}
	rec.Scope.Repository = "*"
	if !recordMatchesFinding(rec, f, ctx, "merge") {
		t.Fatalf("expected wildcard repository to match")
	}

	rec.Scope.Scanner = "snyk"
	f.Scanner.Name = "snyk-code"
	if !recordMatchesFinding(rec, f, ctx, "merge") {
		t.Fatalf("expected canonical scanner matcher to map snyk-code to snyk")
	}
}

func TestUnknownSignalModeBlockRelease(t *testing.T) {
	dir := t.TempDir()
	paths := writeScenario(t, dir, scenarioConfig{
		BranchType:    "feature",
		PipelineStage: "release",
		Environment:   "ci",
		Severity:      "low",
		DomainID:      "VULN_GENERIC",
		WithAR:        true,
		ExpiredAR:     false,
	})

	pol := defaultPolicy()
	pol.Defaults.UnknownSignalMode = "block_release"
	writeYAMLFile(t, paths.Policy, pol)

	report, err := Run(Config{
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
		t.Fatalf("expected BLOCK due unknown_signal_mode=block_release, got %s", report.Decision)
	}
	if !hasTracePhase(report.DecisionTrace, "unknown_signal_mode") {
		t.Fatalf("expected unknown_signal_mode trace entry")
	}
}

func TestUnknownSignalModeBlockReleaseAllowsKnownScanTimestampWithoutFindings(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	contextPath := filepath.Join(dir, "context.yaml")
	scanPath := filepath.Join(dir, "scan.json")

	pol := defaultPolicy()
	pol.Defaults.UnknownSignalMode = "block_release"
	writeYAMLFile(t, policyPath, pol)

	ctx := Context{
		BranchType:      "release",
		PipelineStage:   "release",
		Environment:     "ci",
		RepoCriticality: "high",
		Exposure:        "internet",
		ChangeType:      "application",
		Scanner:         ScannerMeta{Name: "trivy", Version: "0.50.0"},
		Provenance:      Provenance{ArtifactSigned: "yes", Level: "verified", BuildContextIntegrity: "verified"},
	}
	writeYAMLFile(t, contextPath, ctx)

	scan := map[string]interface{}{
		"ArtifactName": "registry.local/app@sha256:deadbeef",
		"GeneratedAt":  time.Now().UTC().Format(time.RFC3339),
		"Results": []interface{}{
			map[string]interface{}{
				"Target":          "app",
				"Vulnerabilities": []interface{}{},
			},
		},
	}
	b, err := json.Marshal(scan)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scanPath, b, 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := Run(Config{
		ScanPaths:   []string{scanPath},
		ContextPath: contextPath,
		PolicyPath:  policyPath,
		OutJSONPath: filepath.Join(dir, "out.json"),
		OutHTMLPath: filepath.Join(dir, "out.html"),
		WriteHTML:   false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if hasTracePhase(report.DecisionTrace, "unknown_signal_mode") {
		t.Fatalf("did not expect unknown_signal_mode validation error when scan timestamp is known")
	}
	if report.Decision != DecisionAllow {
		t.Fatalf("expected ALLOW with known scan timestamp and no findings, got %s", report.Decision)
	}
}

func TestDecisionTraceVerbosityMinimal(t *testing.T) {
	dir := t.TempDir()
	paths := writeScenario(t, dir, scenarioConfig{
		BranchType:    "feature",
		PipelineStage: "pr",
		Environment:   "ci",
		Severity:      "low",
		DomainID:      "VULN_GENERIC",
		WithAR:        true,
		ExpiredAR:     false,
	})
	pol := defaultPolicy()
	pol.Defaults.DecisionTraceVerbosity = "minimal"
	writeYAMLFile(t, paths.Policy, pol)

	report, err := Run(Config{
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
	if len(report.DecisionTrace) == 0 {
		t.Fatalf("expected non-empty decision trace")
	}
	for _, e := range report.DecisionTrace {
		if e.Details != nil {
			t.Fatalf("expected no trace details in minimal verbosity, got %+v", e)
		}
	}
}

func TestInvalidScanEnvelopeStageBehavior(t *testing.T) {
	t.Run("pr_warns", func(t *testing.T) {
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
		if err := os.WriteFile(paths.Scan, []byte(`{"ArtifactName":"registry.local/app@sha256:deadbeef"}`), 0o644); err != nil {
			t.Fatal(err)
		}

		report, err := Run(Config{
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
			t.Fatalf("expected WARN for invalid scan envelope in pr stage, got %s", report.Decision)
		}
		result, ok := traceResultForPhase(report.DecisionTrace, "input_validation")
		if !ok {
			t.Fatalf("missing input_validation trace phase")
		}
		if result != "validation_error" {
			t.Fatalf("expected validation_error input_validation result, got %s", result)
		}
	})

	t.Run("release_blocks", func(t *testing.T) {
		dir := t.TempDir()
		paths := writeScenario(t, dir, scenarioConfig{
			BranchType:    "release",
			PipelineStage: "release",
			Environment:   "ci",
			Severity:      "low",
			DomainID:      "VULN_GENERIC",
			WithAR:        false,
			ExpiredAR:     false,
		})
		if err := os.WriteFile(paths.Scan, []byte(`{"ArtifactName":"registry.local/app@sha256:deadbeef"}`), 0o644); err != nil {
			t.Fatal(err)
		}

		report, err := Run(Config{
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
			t.Fatalf("expected BLOCK for invalid scan envelope in release stage, got %s", report.Decision)
		}
		result, ok := traceResultForPhase(report.DecisionTrace, "input_validation")
		if !ok {
			t.Fatalf("missing input_validation trace phase")
		}
		if result != "validation_error" {
			t.Fatalf("expected validation_error input_validation result, got %s", result)
		}
	})
}

func TestRunAcceptsMinimalScannerEnvelopesWithoutParseFailure(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{name: "snyk_minimal", payload: `{"vulnerabilities":[]}`},
		{name: "snyk_with_runs_array_missing_sarif_version", payload: `{"runs":[],"vulnerabilities":[]}`},
		{name: "checkmarx_minimal", payload: `{"scanResults":[]}`},
		{name: "sonar_minimal", payload: `{"issues":[]}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
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
			if err := os.WriteFile(paths.Scan, []byte(tc.payload), 0o644); err != nil {
				t.Fatal(err)
			}

			report, err := Run(Config{
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
			if len(report.Findings) != 0 {
				t.Fatalf("expected 0 findings for minimal envelope, got %d", len(report.Findings))
			}
			result, ok := traceResultForPhase(report.DecisionTrace, "input_validation")
			if !ok {
				t.Fatalf("missing input_validation trace phase")
			}
			if result != "validation_ok" {
				t.Fatalf("expected validation_ok input_validation result, got %s", result)
			}
			if hasErrorContaining(report.DecisionTrace, "input_validation", "scan parse failed") {
				t.Fatalf("unexpected parse failure in input_validation trace")
			}
			decisionResult, ok := traceResultForPhase(report.DecisionTrace, "decision")
			if !ok {
				t.Fatalf("missing decision trace phase")
			}
			if decisionResult == "validation_warn" || decisionResult == "validation_block" {
				t.Fatalf("decision should not be validation-gated for minimal envelope: %s", decisionResult)
			}
		})
	}
}

func TestInputValidationTraceResultTaxonomy(t *testing.T) {
	state := &EngineState{}
	if got := inputValidationTraceResult(state); got != "validation_ok" {
		t.Fatalf("expected validation_ok, got %s", got)
	}
	state.ValidationWarnings = []string{"warning"}
	if got := inputValidationTraceResult(state); got != "validation_warn" {
		t.Fatalf("expected validation_warn, got %s", got)
	}
	state.ValidationErrors = []string{"error"}
	if got := inputValidationTraceResult(state); got != "validation_error" {
		t.Fatalf("expected validation_error, got %s", got)
	}
}

func TestAcceptedRiskCanonicalScannerMatchesSarifVariant(t *testing.T) {
	dir := t.TempDir()
	paths := writeScenario(t, dir, scenarioConfig{
		BranchType:    "feature",
		PipelineStage: "pr",
		Environment:   "ci",
		Severity:      "low",
		DomainID:      "VULN_GENERIC",
		WithAR:        true,
		ExpiredAR:     false,
	})

	sarifScan := map[string]interface{}{
		"version": "2.1.0",
		"runs": []interface{}{
			map[string]interface{}{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name": "snyk-code",
					},
				},
				"results": []interface{}{
					map[string]interface{}{
						"ruleId": "CVE-2026-5555",
						"level":  "warning",
						"message": map[string]interface{}{
							"text": "x",
						},
						"properties": map[string]interface{}{
							"cve":       "CVE-2026-5555",
							"domain_id": "VULN_GENERIC",
							"category":  "vuln",
						},
					},
				},
			},
		},
	}
	writeJSONFile(t, paths.Scan, sarifScan)

	ar := AcceptedRiskSet{
		SchemaVersion: "1.0",
		Records: []AcceptedRiskRecord{
			{
				ID:        "AR-SARIF-SNYK-1",
				Status:    "active",
				Owner:     "team",
				Approvers: []string{"sec-lead"},
				Ticket:    "SEC-42",
				Rationale: "temporary",
				Scope: AcceptedRiskScope{
					Type:    "cve",
					Value:   "CVE-2026-5555",
					Scanner: "snyk",
					Stages:  []string{"pr"},
				},
				Constraints: AcceptedRiskConstraints{
					MaxSeverity:  "critical",
					Environments: []string{"ci"},
				},
				Timeline: AcceptedRiskTimeline{
					CreatedAt: "2024-01-01T00:00:00Z",
					ExpiresAt: "2099-01-01T00:00:00Z",
					SLADays:   365,
				},
			},
		},
	}
	if paths.AcceptedRisk == "" {
		paths.AcceptedRisk = filepath.Join(dir, "accepted-risk.yaml")
	}
	writeYAMLFile(t, paths.AcceptedRisk, ar)

	report, err := Run(Config{
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
	if report.AcceptedRisk.RecordsApplied != 1 {
		t.Fatalf("expected accepted-risk scanner canonical match to apply exactly 1 record, got %d", report.AcceptedRisk.RecordsApplied)
	}
	if len(report.Findings) == 0 || !report.Findings[0].Accepted {
		t.Fatalf("expected finding to be marked accepted")
	}
}

func TestAcceptedRiskScannerTrivyMatchesEvenWithDifferentContextScanner(t *testing.T) {
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

	ctx := Context{
		BranchType:      "feature",
		PipelineStage:   "pr",
		Environment:     "ci",
		RepoCriticality: "high",
		Exposure:        "internet",
		ChangeType:      "application",
		Scanner:         ScannerMeta{Name: "grype", Version: "0.90.0"},
		Provenance:      Provenance{ArtifactSigned: "yes", Level: "verified", BuildContextIntegrity: "verified"},
	}
	writeYAMLFile(t, paths.Context, ctx)

	ar := AcceptedRiskSet{
		SchemaVersion: "1.0",
		Records: []AcceptedRiskRecord{
			{
				ID:        "AR-TRIVY-SCANNER-1",
				Status:    "active",
				Owner:     "team",
				Approvers: []string{"sec-lead"},
				Ticket:    "SEC-TRIVY-1",
				Rationale: "temporary",
				Scope: AcceptedRiskScope{
					Type:    "cve",
					Value:   "CVE-2025-1111",
					Scanner: "trivy",
					Stages:  []string{"pr"},
				},
				Constraints: AcceptedRiskConstraints{
					MaxSeverity:  "critical",
					Environments: []string{"ci"},
				},
				Timeline: AcceptedRiskTimeline{
					CreatedAt: "2024-01-01T00:00:00Z",
					ExpiresAt: "2099-01-01T00:00:00Z",
					SLADays:   365,
				},
				Metadata: map[string]string{
					"created_by": "tester",
				},
			},
		},
	}
	writeYAMLFile(t, paths.AcceptedRisk, ar)

	report, err := Run(Config{
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
	if report.AcceptedRisk.RecordsApplied != 1 {
		t.Fatalf("expected trivy scanner-scoped accepted risk to apply once, got %d", report.AcceptedRisk.RecordsApplied)
	}
	if len(report.Findings) == 0 || !report.Findings[0].Accepted {
		t.Fatalf("expected finding to be accepted")
	}
}

func hasTracePhase(trace []TraceEntry, phase string) bool {
	for _, e := range trace {
		if e.Phase == phase {
			return true
		}
	}
	return false
}

func traceResultForPhase(trace []TraceEntry, phase string) (string, bool) {
	for _, e := range trace {
		if e.Phase == phase {
			return e.Result, true
		}
	}
	return "", false
}

func hasErrorContaining(trace []TraceEntry, phase, needle string) bool {
	for _, e := range trace {
		if e.Phase != phase || e.Details == nil {
			continue
		}
		rawErrors, ok := e.Details["errors"]
		if !ok {
			continue
		}
		switch v := rawErrors.(type) {
		case []string:
			for _, msg := range v {
				if strings.Contains(msg, needle) {
					return true
				}
			}
		case []interface{}:
			for _, msg := range v {
				s, ok := msg.(string)
				if ok && strings.Contains(s, needle) {
					return true
				}
			}
		}
	}
	return false
}

func TestHasSecurityApproverExactIDOrGroupMatch(t *testing.T) {
	rules := ExceptionRules{
		SecurityApproverIDs:    []string{"sec-lead"},
		SecurityApproverGroups: []string{"security"},
	}
	if hasSecurityApprover([]string{"devsecops"}, rules) {
		t.Fatalf("unexpected substring-based security approver match")
	}
	if !hasSecurityApprover([]string{"sec-lead"}, rules) {
		t.Fatalf("expected exact id match")
	}
	if !hasSecurityApprover([]string{"user:sec-lead"}, rules) {
		t.Fatalf("expected explicit user prefix match")
	}
	if !hasSecurityApprover([]string{"group:security"}, rules) {
		t.Fatalf("expected explicit group match")
	}
}

func TestNewFindingsOnlyIgnoresBaselineMatchesInPR(t *testing.T) {
	dir := t.TempDir()
	paths := writeScenario(t, dir, scenarioConfig{
		BranchType:    "feature",
		PipelineStage: "pr",
		Environment:   "ci",
		Severity:      "high",
		DomainID:      "VULN_GENERIC",
		WithAR:        false,
		ExpiredAR:     false,
	})
	baselinePath := filepath.Join(dir, "baseline-scan.json")
	rawScan, err := os.ReadFile(paths.Scan)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(baselinePath, rawScan, 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := Run(Config{
		ScanPaths:         []string{paths.Scan},
		BaselineScanPaths: []string{baselinePath},
		NewFindingsOnly:   true,
		ContextPath:       paths.Context,
		PolicyPath:        paths.Policy,
		OutJSONPath:       filepath.Join(dir, "out.json"),
		OutHTMLPath:       filepath.Join(dir, "out.html"),
		WriteHTML:         false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Decision != DecisionAllow {
		t.Fatalf("expected ALLOW with fully matched baseline findings, got %s", report.Decision)
	}
	if !hasTracePhase(report.DecisionTrace, "baseline_diff") {
		t.Fatalf("expected baseline_diff trace phase")
	}
}

func TestNewFindingsOnlyHardStopStillBlocks(t *testing.T) {
	dir := t.TempDir()
	paths := writeScenario(t, dir, scenarioConfig{
		BranchType:    "feature",
		PipelineStage: "pr",
		Environment:   "ci",
		Severity:      "low",
		DomainID:      "HS_SECRET_IN_PROD_PATH",
		WithAR:        false,
		ExpiredAR:     false,
	})
	baselinePath := filepath.Join(dir, "baseline-scan.json")
	rawScan, err := os.ReadFile(paths.Scan)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(baselinePath, rawScan, 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := Run(Config{
		ScanPaths:         []string{paths.Scan},
		BaselineScanPaths: []string{baselinePath},
		NewFindingsOnly:   true,
		ContextPath:       paths.Context,
		PolicyPath:        paths.Policy,
		OutJSONPath:       filepath.Join(dir, "out.json"),
		OutHTMLPath:       filepath.Join(dir, "out.html"),
		WriteHTML:         false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Decision != DecisionBlock {
		t.Fatalf("expected BLOCK because hard-stop is always enforced, got %s", report.Decision)
	}
}

func TestNewFindingsOnlyUnsupportedStageBlocksRelease(t *testing.T) {
	dir := t.TempDir()
	paths := writeScenario(t, dir, scenarioConfig{
		BranchType:    "release",
		PipelineStage: "release",
		Environment:   "ci",
		Severity:      "high",
		DomainID:      "VULN_GENERIC",
		WithAR:        false,
		ExpiredAR:     false,
	})
	baselinePath := filepath.Join(dir, "baseline-scan.json")
	rawScan, err := os.ReadFile(paths.Scan)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(baselinePath, rawScan, 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := Run(Config{
		ScanPaths:         []string{paths.Scan},
		BaselineScanPaths: []string{baselinePath},
		NewFindingsOnly:   true,
		ContextPath:       paths.Context,
		PolicyPath:        paths.Policy,
		OutJSONPath:       filepath.Join(dir, "out.json"),
		OutHTMLPath:       filepath.Join(dir, "out.html"),
		WriteHTML:         false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Decision != DecisionBlock {
		t.Fatalf("expected BLOCK for release stage new-findings-only usage, got %s", report.Decision)
	}
}

func TestNewFindingsOnlyRequiresBaselineScan(t *testing.T) {
	dir := t.TempDir()
	paths := writeScenario(t, dir, scenarioConfig{
		BranchType:    "feature",
		PipelineStage: "pr",
		Environment:   "ci",
		Severity:      "high",
		DomainID:      "VULN_GENERIC",
		WithAR:        false,
		ExpiredAR:     false,
	})
	_, err := Run(Config{
		ScanPaths:       []string{paths.Scan},
		NewFindingsOnly: true,
		ContextPath:     paths.Context,
		PolicyPath:      paths.Policy,
		OutJSONPath:     filepath.Join(dir, "out.json"),
		OutHTMLPath:     filepath.Join(dir, "out.html"),
		WriteHTML:       false,
	})
	if err == nil {
		t.Fatalf("expected immediate configuration error for missing --baseline-scan")
	}
}

func TestNoiseBudgetDoesNotAffectDecision(t *testing.T) {
	dir := t.TempDir()
	paths := writeScenario(t, dir, scenarioConfig{
		BranchType:    "feature",
		PipelineStage: "pr",
		Environment:   "ci",
		Severity:      "high",
		DomainID:      "VULN_GENERIC",
		WithAR:        false,
		ExpiredAR:     false,
	})

	polEnabled := defaultPolicy()
	polEnabled.NoiseBudget.Enabled = true
	polEnabled.NoiseBudget.StageLimits["pr"] = 1
	polEnabled.NoiseBudget.SuppressBelowSeverity = "high"
	writeYAMLFile(t, paths.Policy, polEnabled)

	reportEnabled, err := Run(Config{
		ScanPaths:   []string{paths.Scan},
		ContextPath: paths.Context,
		PolicyPath:  paths.Policy,
		OutJSONPath: filepath.Join(dir, "enabled.json"),
		OutHTMLPath: filepath.Join(dir, "enabled.html"),
		WriteHTML:   false,
	})
	if err != nil {
		t.Fatal(err)
	}

	polDisabled := polEnabled
	polDisabled.NoiseBudget.Enabled = false
	writeYAMLFile(t, paths.Policy, polDisabled)
	reportDisabled, err := Run(Config{
		ScanPaths:   []string{paths.Scan},
		ContextPath: paths.Context,
		PolicyPath:  paths.Policy,
		OutJSONPath: filepath.Join(dir, "disabled.json"),
		OutHTMLPath: filepath.Join(dir, "disabled.html"),
		WriteHTML:   false,
	})
	if err != nil {
		t.Fatal(err)
	}

	if reportEnabled.Decision != reportDisabled.Decision {
		t.Fatalf("noise budget changed decision: enabled=%s disabled=%s", reportEnabled.Decision, reportDisabled.Decision)
	}
	if reportEnabled.Risk.OverallScore != reportDisabled.Risk.OverallScore {
		t.Fatalf("noise budget changed overall risk: enabled=%d disabled=%d", reportEnabled.Risk.OverallScore, reportDisabled.Risk.OverallScore)
	}
}

func TestBaselineScanIgnoredWhenNewFindingsOnlyDisabled(t *testing.T) {
	dir := t.TempDir()
	paths := writeScenario(t, dir, scenarioConfig{
		BranchType:    "feature",
		PipelineStage: "pr",
		Environment:   "ci",
		Severity:      "high",
		DomainID:      "VULN_GENERIC",
		WithAR:        false,
		ExpiredAR:     false,
	})
	baselinePath := filepath.Join(dir, "baseline-scan.json")
	rawScan, err := os.ReadFile(paths.Scan)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(baselinePath, rawScan, 0o644); err != nil {
		t.Fatal(err)
	}

	withBaseline, err := Run(Config{
		ScanPaths:         []string{paths.Scan},
		BaselineScanPaths: []string{baselinePath},
		NewFindingsOnly:   false,
		ContextPath:       paths.Context,
		PolicyPath:        paths.Policy,
		OutJSONPath:       filepath.Join(dir, "out.json"),
		OutHTMLPath:       filepath.Join(dir, "out.html"),
		WriteHTML:         false,
	})
	if err != nil {
		t.Fatal(err)
	}
	withoutBaseline, err := Run(Config{
		ScanPaths:   []string{paths.Scan},
		ContextPath: paths.Context,
		PolicyPath:  paths.Policy,
		OutJSONPath: filepath.Join(dir, "out-no-baseline.json"),
		OutHTMLPath: filepath.Join(dir, "out-no-baseline.html"),
		WriteHTML:   false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if withBaseline.Decision != withoutBaseline.Decision {
		t.Fatalf("baseline input changed decision with new-findings-only disabled: with=%s without=%s", withBaseline.Decision, withoutBaseline.Decision)
	}
	if withBaseline.Risk.OverallScore != withoutBaseline.Risk.OverallScore {
		t.Fatalf("baseline input changed overall risk with new-findings-only disabled: with=%d without=%d", withBaseline.Risk.OverallScore, withoutBaseline.Risk.OverallScore)
	}
}

func TestInputDigestsDifferentiatePrimaryAndBaselineScans(t *testing.T) {
	dir := t.TempDir()
	paths := writeScenario(t, dir, scenarioConfig{
		BranchType:    "feature",
		PipelineStage: "pr",
		Environment:   "ci",
		Severity:      "high",
		DomainID:      "VULN_GENERIC",
		WithAR:        false,
		ExpiredAR:     false,
	})
	baselinePath := filepath.Join(dir, "baseline-scan.json")
	rawScan, err := os.ReadFile(paths.Scan)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(baselinePath, rawScan, 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := Run(Config{
		ScanPaths:         []string{paths.Scan},
		BaselineScanPaths: []string{baselinePath},
		NewFindingsOnly:   true,
		ContextPath:       paths.Context,
		PolicyPath:        paths.Policy,
		OutJSONPath:       filepath.Join(dir, "out.json"),
		OutHTMLPath:       filepath.Join(dir, "out.html"),
		WriteHTML:         false,
	})
	if err != nil {
		t.Fatal(err)
	}

	primary := 0
	baseline := 0
	for _, in := range report.Inputs {
		if in.Kind != "scan_json" {
			continue
		}
		if in.Role == "primary" {
			primary++
		}
		if in.Role == "baseline" {
			baseline++
		}
	}
	if primary == 0 {
		t.Fatalf("expected at least one primary scan_json input digest")
	}
	if baseline == 0 {
		t.Fatalf("expected at least one baseline scan_json input digest")
	}
}
