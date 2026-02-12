package llm

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

const safePromptTemplate = `"""
You are an explanation assistant for security-gate.
Your job is to rephrase the deterministic decision and steps provided.
You MUST NOT change the decision, invent new actions, or suggest policy changes.
Use only the provided inputs. If information is missing, say so.

Decision status: %s
Deterministic rationale: %s
Recommended next steps (authoritative): %s
Context: stage=%s, exposure=%s, change_type=%s
Finding summaries: %s

Produce:
- A short explanation suitable for developers.
- A numbered list of the same recommended_next_steps (no additions).
- A note that this text is non-authoritative.
"""
`

var (
	secretPattern    = regexp.MustCompile(`(?i)\b(password|pass|token|secret|key|apikey|bearer|sig)=\S+`)
	urlPattern       = regexp.MustCompile(`https?://[^\s]+`)
	stackPattern     = regexp.MustCompile(`(?m)^\s*(at |\.\.\.)`)
	redactionCounter atomic.Uint64
)

var recommendedStepDescriptions = map[string]string{
	"ROTATE_SECRET":     "Rotate secret, purge from history, invalidate tokens.",
	"FIX_VULN":          "Upgrade to fix_version or patched release.",
	"MITIGATE_NO_FIX":   "Apply compensating controls and open vendor ticket.",
	"ADD_ACCEPTED_RISK": "Create accepted risk record with owner and expiry.",
	"VERIFY_PROVENANCE": "Rebuild with verified provenance and signing.",
	"PIN_SCANNER":       "Pin scanner version and record in context.",
	"REFRESH_SCAN":      "Re-run scanner to refresh data.",
	"IMPROVE_TRUST":     "Add missing provenance signals or protected CI.",
}

// BuildSanitizedRequest applies LLM boundary rules and returns the prompt plus metadata.
func BuildSanitizedRequest(params LLMInputParams) LLMSanitizationResult {
	redactions := make([]RedactionRecord, 0, 8)

	sanitizedRationale := sanitizeField("decision_rationale", params.DecisionRationale, &redactions)
	countsText := fmt.Sprintf("total findings=%d; hard_stop=%d; max_finding_risk=%d", params.Counts.Total, params.Counts.HardStop, params.Counts.MaxFindingRisk)
	if sanitizedRationale != "" {
		sanitizedRationale = fmt.Sprintf("%s (%s)", sanitizedRationale, countsText)
	} else {
		sanitizedRationale = countsText
	}

	sanitizedSteps := make([]string, 0, len(params.RecommendedSteps))
	for _, stepID := range params.RecommendedSteps {
		desc := recommendedStepDescriptions[stepID]
		if desc == "" {
			desc = "Deterministic recommended next step."
		}
		sanitizedDesc := sanitizeField(fmt.Sprintf("recommended_next_steps.%s", stepID), desc, &redactions)
		sanitizedSteps = append(sanitizedSteps, fmt.Sprintf("%s (%s)", stepID, sanitizedDesc))
	}
	stepsText := strings.Join(sanitizedSteps, "; ")
	if stepsText == "" {
		stepsText = "None"
	}

	sanitizedStage := sanitizeField("context.stage", params.Context.Stage, &redactions)
	sanitizedExposure := sanitizeField("context.exposure", params.Context.Exposure, &redactions)
	sanitizedChange := sanitizeField("context.change_type", params.Context.ChangeType, &redactions)

	sanitizedFindings := make([]string, 0, len(params.FindingSummaries))
	for idx, summary := range params.FindingSummaries {
		sanitizedTitle := sanitizeField(fmt.Sprintf("finding_summaries[%d].title", idx), summary.Title, &redactions)
		entry := fmt.Sprintf("%s/%s %s (severity=%s domain=%s)", summary.FindingID, summary.Fingerprint, sanitizedTitle, summary.Severity, summary.Domain)
		sanitizedFindings = append(sanitizedFindings, entry)
	}
	findingsText := "None"
	if len(sanitizedFindings) > 0 {
		findingsText = strings.Join(sanitizedFindings, "; ")
	}

	prompt := fmt.Sprintf(safePromptTemplate,
		params.DecisionStatus,
		sanitizedRationale,
		stepsText,
		sanitizedStage,
		sanitizedExposure,
		sanitizedChange,
		findingsText,
	)

	references := make([]string, 0, len(params.TraceEventIDs)+len(params.FindingSummaries))
	references = append(references, params.TraceEventIDs...)
	for _, summary := range params.FindingSummaries {
		if summary.FindingID != "" {
			references = append(references, summary.FindingID)
		}
	}
	references = deduplicateReferences(references)

	contentRef := fmt.Sprintf("llm-prompt-%d", params.Timestamp.UnixNano())

	return LLMSanitizationResult{
		Prompt:     prompt,
		ContentRef: contentRef,
		References: references,
		Redactions: redactions,
	}
}

func sanitizeField(path, value string, redactions *[]RedactionRecord) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return trimmed
	}
	sanitized := trimmed
	reasons := make([]string, 0, 3)

	if secretPattern.MatchString(sanitized) {
		sanitized = secretPattern.ReplaceAllString(sanitized, "[REDACTED_SECRET]")
		reasons = append(reasons, "masked secret-like token")
	}

	if locChanged := replaceURLs(&sanitized); locChanged {
		reasons = append(reasons, "removed URL")
	}

	if stackChanged := removeStackLines(&sanitized); stackChanged {
		reasons = append(reasons, "removed stack trace")
	}

	if len(sanitized) > 256 {
		sanitized = sanitized[:256]
		reasons = append(reasons, "truncated to safe length")
	}

	if sanitized != trimmed {
		reason := "sanitized text"
		if len(reasons) > 0 {
			reason = strings.Join(uniqueStrings(reasons), "; ")
		}
		recordRedaction(path, reason, sanitized, trimmed, redactions)
	}

	return sanitized
}

func replaceURLs(value *string) bool {
	if !urlPattern.MatchString(*value) {
		return false
	}
	*value = urlPattern.ReplaceAllString(*value, "[REDACTED_URL]")
	return true
}

func removeStackLines(value *string) bool {
	if !stackPattern.MatchString(*value) {
		return false
	}
	lines := strings.Split(*value, "\n")
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		if stackPattern.MatchString(line) {
			continue
		}
		filtered = append(filtered, line)
	}
	*value = strings.Join(filtered, " ")
	return true
}

func recordRedaction(path, reason, sanitized, original string, redactions *[]RedactionRecord) {
	if redactions == nil {
		return
	}
	hash := sha256.Sum256([]byte(original))
	*redactions = append(*redactions, RedactionRecord{
		EventID:       newRedactionID(),
		Timestamp:     time.Now().UTC(),
		RedactedField: path,
		Reason:        reason,
		SanitizedRef:  sanitized,
		OriginalHash:  hex.EncodeToString(hash[:]),
	})
}

func deduplicateReferences(list []string) []string {
	if len(list) == 0 {
		return nil
	}
	sort.Strings(list)
	deduped := make([]string, 0, len(list))
	last := ""
	for _, item := range list {
		if item == last {
			continue
		}
		deduped = append(deduped, item)
		last = item
	}
	return deduped
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func newRedactionID() string {
	id := redactionCounter.Add(1)
	return fmt.Sprintf("llm-redaction-%d", id)
}
