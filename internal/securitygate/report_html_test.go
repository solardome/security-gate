package securitygate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteReportHTMLRecommendedStepsNumberingAndSort(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report.html")
	report := Report{
		SchemaVersion:  "1.0.0",
		GeneratedAt:    "1970-01-01T00:00:00Z",
		RunID:          "test-run",
		EffectiveStage: "merge",
		Trust:          TrustResult{Score: 85},
		Risk:           RiskResult{OverallScore: 51, MaxFindingScore: 34},
		Decision:       DecisionWarn,
		ExitCode:       1,
		RecommendedSteps: []RecommendedStep{
			{ID: "ZETA", Priority: 200, Text: "z"},
			{ID: "OMEGA", Priority: 100, Text: "o"},
			{ID: "ALPHA", Priority: 200, Text: "a"},
		},
	}

	if err := writeReportHTML(out, report); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)

	s1 := "Step 1:</strong> <strong class=\"mono\">OMEGA</strong> (priority 1)"
	s2 := "Step 2:</strong> <strong class=\"mono\">ALPHA</strong> (priority 2)"
	s3 := "Step 3:</strong> <strong class=\"mono\">ZETA</strong> (priority 3)"

	i1 := strings.Index(html, s1)
	i2 := strings.Index(html, s2)
	i3 := strings.Index(html, s3)
	if i1 == -1 || i2 == -1 || i3 == -1 {
		t.Fatalf("missing expected numbered recommended steps in html")
	}
	if !(i1 < i2 && i2 < i3) {
		t.Fatalf("recommended steps not sorted/numbered deterministically: i1=%d i2=%d i3=%d", i1, i2, i3)
	}
}

func TestWriteReportHTMLNoiseBudgetPreview(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report.html")
	report := Report{
		SchemaVersion:  "1.0.0",
		GeneratedAt:    "1970-01-01T00:00:00Z",
		RunID:          "test-run",
		EffectiveStage: "pr",
		Trust:          TrustResult{Score: 90},
		Risk:           RiskResult{OverallScore: 20, MaxFindingScore: 15},
		Decision:       DecisionAllow,
		ExitCode:       0,
		Findings: []ReportFinding{
			{FindingID: "F-1", Severity: "low", HardStop: false, Accepted: false, FindingRiskScore: 10},
			{FindingID: "F-2", Severity: "info", HardStop: false, Accepted: false, FindingRiskScore: 5},
		},
		DecisionTrace: []TraceEntry{
			{
				Order:  1,
				Phase:  "noise_budget",
				Result: "presentation_only",
				Details: map[string]interface{}{
					"enabled":                 true,
					"bypassed":                false,
					"stage_supported":         true,
					"stage":                   "pr",
					"stage_limit":             1,
					"suppress_below_severity": "medium",
					"total_findings":          2,
					"suppressed_by_severity":  2,
					"suppressed_by_limit":     0,
					"suppressed_total":        2,
					"displayed_count":         0,
				},
			},
		},
	}

	if err := writeReportHTML(out, report); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	if !strings.Contains(html, "Noise Budget Preview") {
		t.Fatalf("expected noise budget section in html")
	}
	if !strings.Contains(html, "below_severity_floor") {
		t.Fatalf("expected suppression reason in html noise budget section")
	}
}
