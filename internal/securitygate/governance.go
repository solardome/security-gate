package securitygate

import (
	"errors"
	"sort"
	"strings"
	"time"
)

func applyHardStops(findings []UnifiedFinding, pol Policy) []string {
	hardStopSet := map[string]bool{}
	for _, d := range canonicalHardStops {
		hardStopSet[d] = true
	}
	for _, d := range pol.DomainOverrides.AdditionalHardStops {
		if strings.TrimSpace(d) != "" {
			hardStopSet[d] = true
		}
	}
	triggered := map[string]bool{}
	for i := range findings {
		if hardStopSet[findings[i].Class.DomainID] {
			findings[i].HardStop = true
			triggered[findings[i].Class.DomainID] = true
		}
	}
	out := make([]string, 0, len(triggered))
	for d := range triggered {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

func applyAcceptedRisk(state *EngineState) {
	ar := state.AcceptedRisk
	if len(ar.Records) == 0 {
		return
	}
	for _, rec := range ar.Records {
		state.GovernanceSummary.RecordsEvaluated++
		if strings.ToLower(strings.TrimSpace(rec.Status)) != "active" {
			continue
		}
		if !scopeTypeAllowedByPolicy(rec.Scope.Type, state.Policy.ExceptionRules.AllowScopeTypes) {
			state.GovernanceSummary.InvalidRecords++
			state.ValidationErrors = append(state.ValidationErrors, "accepted risk record "+rec.ID+": scope type not allowed by policy")
			continue
		}
		if err := validateAcceptedRiskRecord(rec, state); err != nil {
			state.GovernanceSummary.InvalidRecords++
			state.ValidationErrors = append(state.ValidationErrors, "accepted risk record "+rec.ID+": "+err.Error())
			continue
		}
		for i := range state.Findings {
			f := &state.Findings[i]
			if f.HardStop || f.Accepted {
				continue
			}
			if recordMatchesFinding(rec, *f, state.Context, state.EffectiveStage) {
				if approvalRequiredButMissing(rec, *f, state.Context, state.EffectiveStage, state.Policy) {
					state.GovernanceSummary.InvalidRecords++
					state.GovernanceSummary.ApprovalUnmet = true
					state.ValidationErrors = append(state.ValidationErrors, "accepted risk record "+rec.ID+": security approval required")
					continue
				}
				f.Accepted = true
				f.AcceptedRiskRecordID = rec.ID
				state.GovernanceSummary.RecordsApplied++
			}
		}
		if expSoon(rec, state.Now) {
			state.GovernanceSummary.NearExpiry = true
		}
	}
}

func validateAcceptedRiskRecord(rec AcceptedRiskRecord, state *EngineState) error {
	if strings.TrimSpace(rec.ID) == "" || strings.TrimSpace(rec.Owner) == "" || strings.TrimSpace(rec.Ticket) == "" || strings.TrimSpace(rec.Rationale) == "" {
		return errors.New("missing required record fields")
	}
	if strings.TrimSpace(rec.Scope.Type) == "" || strings.TrimSpace(rec.Scope.Value) == "" {
		return errors.New("scope type/value required")
	}
	for _, approver := range rec.Approvers {
		if strings.TrimSpace(approver) == "" {
			return errors.New("approvers cannot contain empty values")
		}
	}
	if rec.Timeline.SLADays <= 0 {
		return errors.New("timeline.sla_days must be positive")
	}
	created, err := time.Parse(time.RFC3339, rec.Timeline.CreatedAt)
	if err != nil {
		return errors.New("invalid timeline.created_at")
	}
	expires, err := time.Parse(time.RFC3339, rec.Timeline.ExpiresAt)
	if err != nil {
		return errors.New("invalid timeline.expires_at")
	}
	if !expires.After(created) {
		return errors.New("expires_at must be after created_at")
	}
	if !expires.After(state.Now) {
		return errors.New("record expired")
	}
	return nil
}

func recordMatchesFinding(rec AcceptedRiskRecord, f UnifiedFinding, ctx Context, stage string) bool {
	if !scopeScannerMatches(rec.Scope.Scanner, f.Scanner.Name) {
		return false
	}
	if !scopeRepositoryMatches(rec.Scope.Repository, f.Artifact.TargetRef) {
		return false
	}
	if !contains(rec.Scope.BranchTypes, normalizeToken(ctx.BranchType)) {
		return false
	}
	if !contains(rec.Scope.Stages, stage) {
		return false
	}
	if !contains(rec.Constraints.Environments, normalizeToken(ctx.Environment)) {
		return false
	}
	if rec.Constraints.MaxSeverity != "" && !severityAtMost(f.Class.Severity, rec.Constraints.MaxSeverity) {
		return false
	}
	scopeType := normalizeToken(rec.Scope.Type)
	scopeVal := strings.TrimSpace(rec.Scope.Value)
	switch scopeType {
	case "finding_id":
		return f.FindingID == scopeVal
	case "cve":
		return strings.EqualFold(f.Class.CVE, scopeVal)
	case "component":
		return strings.EqualFold(f.Artifact.Component, scopeVal)
	default:
		return false
	}
}

func approvalRequiredButMissing(rec AcceptedRiskRecord, f UnifiedFinding, ctx Context, stage string, pol Policy) bool {
	severeHighOrAbove := severityRank[f.Class.Severity] <= severityRank["high"]
	critical := strings.EqualFold(f.Class.Severity, "critical")
	securityApproverPresent := hasSecurityApprover(rec.Approvers, pol.ExceptionRules)
	if pol.ExceptionRules.RequireSecurityApproval.ReleaseCritical && stage == "release" && critical && !securityApproverPresent {
		return true
	}
	if pol.ExceptionRules.RequireSecurityApproval.DeployHighOrAbove && stage == "deploy" && severeHighOrAbove && !securityApproverPresent {
		return true
	}
	return false
}

func hasSecurityApprover(approvers []string, rules ExceptionRules) bool {
	if len(approvers) == 0 {
		return false
	}
	ids := map[string]bool{}
	groups := map[string]bool{}
	for _, id := range rules.SecurityApproverIDs {
		norm := normalizeToken(id)
		if norm != "unknown" {
			ids[norm] = true
		}
	}
	for _, group := range rules.SecurityApproverGroups {
		norm := normalizeToken(group)
		if norm != "unknown" {
			groups[norm] = true
		}
	}
	for _, raw := range approvers {
		token := strings.TrimSpace(strings.ToLower(raw))
		if token == "" {
			continue
		}
		if strings.HasPrefix(token, "group:") {
			group := normalizeToken(strings.TrimSpace(strings.TrimPrefix(token, "group:")))
			if groups[group] {
				return true
			}
			continue
		}
		if strings.HasPrefix(token, "user:") {
			user := normalizeToken(strings.TrimSpace(strings.TrimPrefix(token, "user:")))
			if ids[user] {
				return true
			}
			continue
		}
		if ids[normalizeToken(token)] {
			return true
		}
	}
	return false
}

func expSoon(rec AcceptedRiskRecord, now time.Time) bool {
	exp, err := time.Parse(time.RFC3339, rec.Timeline.ExpiresAt)
	if err != nil {
		return false
	}
	return exp.After(now) && exp.Sub(now) <= 7*24*time.Hour
}

func scopeTypeAllowedByPolicy(scopeType string, allowed []string) bool {
	if len(allowed) == 0 {
		return false
	}
	target := normalizeToken(scopeType)
	for _, v := range allowed {
		if normalizeToken(v) == target {
			return true
		}
	}
	return false
}

func scopeScannerMatches(scannerFilter, findingScanner string) bool {
	filter := normalizeToken(scannerFilter)
	if filter == "" || filter == "unknown" || filter == "*" {
		return true
	}
	return canonicalScannerID(filter) == canonicalScannerID(findingScanner)
}

func scopeRepositoryMatches(repositoryFilter, artifactTargetRef string) bool {
	filter := strings.TrimSpace(strings.ToLower(repositoryFilter))
	if filter == "" || filter == "*" {
		return true
	}
	repo := normalizeRepoIdentity(artifactTargetRef)
	if repo == "" {
		return false
	}
	return repo == filter
}

func normalizeRepoIdentity(targetRef string) string {
	ref := strings.TrimSpace(strings.ToLower(targetRef))
	if ref == "" || ref == "unknown" {
		return ""
	}
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref = ref[:i]
	}
	ref = strings.TrimSpace(ref)
	return ref
}
