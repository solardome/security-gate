package scoring

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/solardome/security-gate/internal/domain"
	"github.com/solardome/security-gate/internal/ingest/trivy"
)

const (
	scannerPinnedWeight   = 20.0
	scanFreshnessWeight   = 15.0
	inputIntegrityWeight  = 15.0
	artifactSigningWeight = 20.0
	provenanceLevelWeight = 20.0
	buildContextWeight    = 10.0

	maxScanAgeDays = 30
)

// TrustContext carries the inputs required for computing trust_score.
type TrustContext struct {
	ScannerPinned         bool
	ScanTimestamp         *time.Time
	InputIntegrityStatus  string // verified | missing | mismatch | unknown
	ArtifactSigningStatus string // verified | unsigned | invalid | unknown
	ProvenanceLevel       string // level3+ | level2 | level1 | none | unknown
	BuildContextProtected *bool
}

// SignalDetail exposes a single trust signal's value and the raw input that produced it.
type SignalDetail struct {
	Score float64
	Raw   string
}

// TrustSignals groups every individual signal for visibility and traceability.
type TrustSignals struct {
	ScannerPinned   SignalDetail
	ScanFreshness   SignalDetail
	InputIntegrity  SignalDetail
	ArtifactSigning SignalDetail
	ProvenanceLevel SignalDetail
	BuildContext    SignalDetail
}

// FindingModifiers tracks each deterministic modifier contribution to risk_score.
type FindingModifiers struct {
	ExploitMaturity int
	Reachability    int
	FixAvailable    int
	DependencyScope int
	LicenseType     int
}

// ScoredFinding enriches the normalized finding with deterministic scoring data.
type ScoredFinding struct {
	Finding                  trivy.CanonicalFinding
	RiskScore                int
	BaseScore                int
	Modifiers                FindingModifiers
	HardStop                 bool
	HardStopReason           string
	SuppressedByAcceptedRisk bool
	SuppressedByException    bool
	SuppressedByNoiseBudget  bool
}

// ScoreResult contains the outputs required by downstream policy evaluation.
type ScoreResult struct {
	Findings       []ScoredFinding
	MaxFindingRisk int
	TrustScore     int
	TrustModifier  int
	TrustSignals   TrustSignals
	Trace          []trivy.TraceEvent
}

// Score consumes normalized findings and trust inputs, producing per-finding risk scores and trust_score.
func Score(findings []trivy.CanonicalFinding, trustCtx TrustContext, now time.Time) ScoreResult {
	var result ScoreResult
	traceEvents := make([]trivy.TraceEvent, 0, len(findings))

	scored := make([]ScoredFinding, 0, len(findings))
	maxRisk := 0

	for _, finding := range findings {
		scoredFinding := scoreFinding(finding)
		if scoredFinding.HardStop {
			traceEvents = append(traceEvents, traceEvent("scoring.hard_stop", "hard-stop domain detected", map[string]any{"finding_id": finding.FindingID, "domain": finding.Domain}))
		}
		if scoredFinding.RiskScore > maxRisk {
			maxRisk = scoredFinding.RiskScore
		}
		scored = append(scored, scoredFinding)
	}

	trustSignals, freshnessEvents := computeTrustSignals(trustCtx, now)
	traceEvents = append(traceEvents, freshnessEvents...)

	trustScore := int(math.Round(
		scannerPinnedWeight*trustSignals.ScannerPinned.Score +
			scanFreshnessWeight*trustSignals.ScanFreshness.Score +
			inputIntegrityWeight*trustSignals.InputIntegrity.Score +
			artifactSigningWeight*trustSignals.ArtifactSigning.Score +
			provenanceLevelWeight*trustSignals.ProvenanceLevel.Score +
			buildContextWeight*trustSignals.BuildContext.Score,
	))
	trustScore = clamp(trustScore, 0, 100)

	trustModifier := trustScoreModifier(trustScore)

	result.Findings = scored
	result.MaxFindingRisk = maxRisk
	result.TrustScore = trustScore
	result.TrustModifier = trustModifier
	result.TrustSignals = trustSignals
	result.Trace = traceEvents
	return result
}

func scoreFinding(finding trivy.CanonicalFinding) ScoredFinding {
	sf := ScoredFinding{Finding: finding}

	if isHardStop(finding.Domain) {
		sf.RiskScore = 100
		sf.BaseScore = 100
		sf.HardStop = true
		sf.HardStopReason = fmt.Sprintf("domain=%s", finding.Domain)
		return sf
	}

	base, baseMsg := baseScore(finding)
	sf.BaseScore = base

	modifiers := FindingModifiers{
		ExploitMaturity: exploitMaturityModifier(finding.ExploitMaturity),
		Reachability:    reachabilityModifier(finding.Reachability),
		FixAvailable:    fixAvailableModifier(finding.FixAvailable),
		DependencyScope: dependencyScopeModifier(finding.DependencyScope),
	}
	if strings.EqualFold(finding.Domain, string(domain.DomainLicense)) {
		modifiers.LicenseType = licenseTypeModifier(finding.LicenseType)
	}

	total := base + modifiers.ExploitMaturity + modifiers.Reachability + modifiers.FixAvailable + modifiers.DependencyScope + modifiers.LicenseType
	sf.Modifiers = modifiers
	sf.RiskScore = clamp(total, 0, 100)
	if baseMsg != "" {
		sf.HardStopReason = baseMsg
	}
	return sf
}

func baseScore(finding trivy.CanonicalFinding) (int, string) {
	if finding.CVSSv3 != nil {
		rounded := int(math.Round(*finding.CVSSv3 * 10))
		return clamp(rounded, 0, 100), "cvss"
	}

	switch strings.ToUpper(strings.TrimSpace(finding.Severity)) {
	case "CRITICAL":
		return 90, "severity"
	case "HIGH":
		return 70, "severity"
	case "MEDIUM":
		return 50, "severity"
	case "LOW":
		return 25, "severity"
	case "INFO":
		return 5, "severity"
	case "UNKNOWN":
		fallthrough
	default:
		return 50, "severity"
	}
}

func exploitMaturityModifier(raw string) int {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "confirmed":
		return 15
	case "functional":
		return 10
	case "poc":
		return 5
	case "none":
		return 0
	default:
		return 5
	}
}

func reachabilityModifier(raw string) int {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "reachable":
		return 15
	case "potentially":
		return 8
	case "not_reachable":
		return 0
	default:
		return 5
	}
}

func fixAvailableModifier(raw string) int {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "false":
		return 5
	case "true":
		return 0
	default:
		return 3
	}
}

func dependencyScopeModifier(raw string) int {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "direct":
		return 5
	case "transitive":
		return 0
	default:
		return 3
	}
}

func licenseTypeModifier(raw string) int {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "strong_copyleft":
		return 10
	case "weak_copyleft":
		return 5
	case "permissive":
		return 0
	default:
		return 5
	}
}

func isHardStop(domainValue string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(domainValue))
	return normalized == string(domain.DomainSecret) || normalized == string(domain.DomainMalware) || normalized == string(domain.DomainProvenance)
}

func computeTrustSignals(ctx TrustContext, now time.Time) (TrustSignals, []trivy.TraceEvent) {
	var events []trivy.TraceEvent

	scannerScore := 0.2
	if ctx.ScannerPinned {
		scannerScore = 1.0
	}

	freshnessScore, freshnessEvents := scanFreshnessScore(ctx.ScanTimestamp, now)
	events = append(events, freshnessEvents...)

	inputIntegrityScore := 0.2
	switch strings.ToLower(strings.TrimSpace(ctx.InputIntegrityStatus)) {
	case "verified":
		inputIntegrityScore = 1.0
	case "mismatch":
		inputIntegrityScore = 0.0
	case "missing", "unknown":
		inputIntegrityScore = 0.2
	}

	artifactScore := 0.2
	switch strings.ToLower(strings.TrimSpace(ctx.ArtifactSigningStatus)) {
	case "verified":
		artifactScore = 1.0
	case "invalid":
		artifactScore = 0.0
	case "unsigned", "unknown":
		artifactScore = 0.2
	}

	provenanceScore := 0.2
	switch strings.ToLower(strings.TrimSpace(ctx.ProvenanceLevel)) {
	case "level3+":
		provenanceScore = 1.0
	case "level2":
		provenanceScore = 0.7
	case "level1":
		provenanceScore = 0.4
	default:
		provenanceScore = 0.2
	}

	buildContextScore := 0.3
	if ctx.BuildContextProtected != nil && *ctx.BuildContextProtected {
		buildContextScore = 1.0
	}

	signals := TrustSignals{
		ScannerPinned:   SignalDetail{Score: scannerScore, Raw: fmt.Sprintf("pinned=%t", ctx.ScannerPinned)},
		ScanFreshness:   SignalDetail{Score: freshnessScore, Raw: fmt.Sprintf("timestamp=%v", ctx.ScanTimestamp)},
		InputIntegrity:  SignalDetail{Score: inputIntegrityScore, Raw: ctx.InputIntegrityStatus},
		ArtifactSigning: SignalDetail{Score: artifactScore, Raw: ctx.ArtifactSigningStatus},
		ProvenanceLevel: SignalDetail{Score: provenanceScore, Raw: ctx.ProvenanceLevel},
		BuildContext:    SignalDetail{Score: buildContextScore, Raw: fmt.Sprintf("protected=%v", ctx.BuildContextProtected)},
	}
	return signals, events
}

func scanFreshnessScore(scanTimestamp *time.Time, now time.Time) (float64, []trivy.TraceEvent) {
	if scanTimestamp == nil {
		return 0.2, nil
	}

	futureThreshold := now.Add(5 * time.Minute)
	if scanTimestamp.After(futureThreshold) {
		event := traceEvent("scoring.scan_timestamp_future", "scan timestamp >5m in future", map[string]any{"scan_timestamp": scanTimestamp.Format(time.RFC3339)})
		return 0.2, []trivy.TraceEvent{event}
	}

	age := now.Sub(*scanTimestamp)
	maxAge := time.Duration(maxScanAgeDays) * 24 * time.Hour
	if age > maxAge {
		event := traceEvent("scoring.scan_timestamp_stale", "scan timestamp >30d old", map[string]any{"scan_timestamp": scanTimestamp.Format(time.RFC3339)})
		return 0.2, append([]trivy.TraceEvent{}, event)
	}

	switch {
	case age <= 24*time.Hour:
		return 1.0, nil
	case age <= 7*24*time.Hour:
		return 0.7, nil
	case age <= 30*24*time.Hour:
		return 0.4, nil
	default:
		return 0.2, nil
	}
}

func trustScoreModifier(score int) int {
	switch {
	case score >= 80:
		return 0
	case score >= 60:
		return 3
	case score >= 40:
		return 6
	case score >= 20:
		return 10
	default:
		return 15
	}
}

func clamp(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func traceEvent(typ, message string, details map[string]any) trivy.TraceEvent {
	return trivy.TraceEvent{
		Timestamp: time.Now().UTC(),
		Type:      typ,
		Message:   message,
		Details:   details,
	}
}
