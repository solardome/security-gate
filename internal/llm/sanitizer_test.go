package llm

import (
	"strings"
	"testing"
	"time"
)

func TestBuildSanitizedRequestRedactsSensitiveText(t *testing.T) {
	t.Parallel()

	result := BuildSanitizedRequest(LLMInputParams{
		DecisionStatus:    "WARN",
		DecisionRationale: "token=abc123 see https://example.com",
		Counts:            LLMCounts{Total: 1, HardStop: 0, MaxFindingRisk: 70},
		RecommendedSteps:  []string{"ROTATE_SECRET"},
		Context:           LLMContext{Stage: "pr", Exposure: "internal", ChangeType: "moderate"},
		FindingSummaries: []LLMFindingSummary{{
			FindingID:   "F-1",
			Fingerprint: "fp-1",
			Title:       "password=secret-value",
			Domain:      "SECRET",
			Severity:    "HIGH",
		}},
		TraceEventIDs: []string{"trace-2", "trace-1", "trace-1"},
		Timestamp:     time.Unix(10, 0).UTC(),
	})

	if len(result.Redactions) == 0 {
		t.Fatalf("expected redactions to be recorded")
	}
	if !strings.Contains(result.Prompt, "[REDACTED_SECRET]") {
		t.Fatalf("expected secret redaction in prompt")
	}
	if strings.Contains(result.Prompt, "https://example.com") {
		t.Fatalf("expected URL to be removed")
	}
	if result.ContentRef == "" {
		t.Fatalf("expected non-empty content_ref")
	}
	if len(result.References) != 3 {
		t.Fatalf("expected deduplicated references length=3, got %d (%v)", len(result.References), result.References)
	}
}
