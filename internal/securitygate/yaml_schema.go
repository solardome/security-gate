package securitygate

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type schemaError struct {
	Path    string
	Line    int
	Message string
}

func (e schemaError) String() string {
	if e.Line > 0 {
		return fmt.Sprintf("line %d field %s: %s", e.Line, e.Path, e.Message)
	}
	return fmt.Sprintf("field %s: %s", e.Path, e.Message)
}

func formatSchemaErrors(path string, errs []schemaError) string {
	sort.Slice(errs, func(i, j int) bool {
		if errs[i].Line != errs[j].Line {
			return errs[i].Line < errs[j].Line
		}
		if errs[i].Path != errs[j].Path {
			return errs[i].Path < errs[j].Path
		}
		return errs[i].Message < errs[j].Message
	})
	var b strings.Builder
	b.WriteString("schema validation failed for ")
	b.WriteString(path)
	for _, e := range errs {
		b.WriteString("\n- ")
		b.WriteString(e.String())
	}
	return b.String()
}

func validateYAMLSchema(kind string, root *yaml.Node) []schemaError {
	if root == nil || len(root.Content) == 0 {
		return []schemaError{{Path: kind, Line: 0, Message: "empty YAML document"}}
	}
	node := root.Content[0]
	switch kind {
	case "context":
		return validateContextYAML(node)
	case "policy":
		return validatePolicyYAML(node)
	case "accepted_risk":
		return validateAcceptedRiskYAML(node)
	default:
		return nil
	}
}

func validateContextYAML(node *yaml.Node) []schemaError {
	errList := []schemaError{}
	allowed := []string{"branch_type", "pipeline_stage", "environment", "repo_criticality", "exposure", "change_type", "scanner", "provenance"}
	required := []string{"branch_type", "pipeline_stage", "environment", "repo_criticality", "exposure", "change_type"}
	m := validateMapNode(node, "context", allowed, required, &errList)
	if v, ok := m["scanner"]; ok {
		validateMapNode(v, "context.scanner", []string{"name", "version"}, []string{"name", "version"}, &errList)
	}
	if v, ok := m["provenance"]; ok {
		validateMapNode(v, "context.provenance", []string{"artifact_signed", "level", "build_context_integrity"}, []string{"artifact_signed", "level", "build_context_integrity"}, &errList)
	}
	return errList
}

func validatePolicyYAML(node *yaml.Node) []schemaError {
	errList := []schemaError{}
	topAllowed := []string{"schema_version", "policy_id", "policy_name", "defaults", "stage_overrides", "trust_tightening", "domain_overrides", "noise_budget", "exception_rules", "rules"}
	topRequired := append([]string{}, topAllowed...)
	m := validateMapNode(node, "policy", topAllowed, topRequired, &errList)

	if v, ok := m["defaults"]; ok {
		validateMapNode(v, "policy.defaults", []string{"enforce_offline_only", "llm_enabled", "scan_freshness_hours", "unknown_signal_mode", "decision_trace_verbosity"}, []string{"enforce_offline_only", "llm_enabled", "scan_freshness_hours", "unknown_signal_mode", "decision_trace_verbosity"}, &errList)
	}
	if v, ok := m["stage_overrides"]; ok {
		s := validateMapNode(v, "policy.stage_overrides", []string{"pr", "merge", "release", "deploy"}, []string{"pr", "merge", "release", "deploy"}, &errList)
		for _, stage := range []string{"pr", "merge", "release", "deploy"} {
			if sv, ok := s[stage]; ok {
				validateMapNode(sv, "policy.stage_overrides."+stage, []string{"warn_floor", "block_floor"}, []string{"warn_floor", "block_floor"}, &errList)
			}
		}
	}
	if v, ok := m["trust_tightening"]; ok {
		t := validateMapNode(v, "policy.trust_tightening", []string{"enabled", "release_warn_if_trust_below", "deploy_block_if_trust_below", "additional_risk_penalties"}, []string{"enabled", "release_warn_if_trust_below", "deploy_block_if_trust_below", "additional_risk_penalties"}, &errList)
		if p, ok := t["additional_risk_penalties"]; ok {
			validateMapNode(p, "policy.trust_tightening.additional_risk_penalties", []string{"trust_60_79", "trust_40_59", "trust_20_39", "trust_0_19"}, []string{"trust_60_79", "trust_40_59", "trust_20_39", "trust_0_19"}, &errList)
		}
	}
	if v, ok := m["domain_overrides"]; ok {
		d := validateMapNode(v, "policy.domain_overrides", []string{"additional_hard_stops", "severity_boosts"}, []string{"additional_hard_stops", "severity_boosts"}, &errList)
		if boosts, ok := d["severity_boosts"]; ok {
			seq := validateSequenceNode(boosts, "policy.domain_overrides.severity_boosts", &errList)
			for i, item := range seq {
				validateMapNode(item, fmt.Sprintf("policy.domain_overrides.severity_boosts[%d]", i), []string{"domain_id", "add_points", "stages"}, []string{"domain_id", "add_points", "stages"}, &errList)
			}
		}
	}
	if v, ok := m["noise_budget"]; ok {
		validateMapNode(v, "policy.noise_budget", []string{"enabled", "stage_limits", "suppress_below_severity"}, []string{"enabled", "stage_limits", "suppress_below_severity"}, &errList)
	}
	if v, ok := m["exception_rules"]; ok {
		e := validateMapNode(v, "policy.exception_rules", []string{"require_security_approval", "allow_scope_types", "security_approver_ids", "security_approver_groups"}, []string{"require_security_approval", "allow_scope_types"}, &errList)
		if a, ok := e["require_security_approval"]; ok {
			validateMapNode(a, "policy.exception_rules.require_security_approval", []string{"release_critical", "deploy_high_or_above"}, []string{"release_critical", "deploy_high_or_above"}, &errList)
		}
	}
	if v, ok := m["rules"]; ok {
		seq := validateSequenceNode(v, "policy.rules", &errList)
		for i, item := range seq {
			r := validateMapNode(item, fmt.Sprintf("policy.rules[%d]", i), []string{"rule_id", "enabled", "when", "then"}, []string{"rule_id", "enabled", "when", "then"}, &errList)
			if w, ok := r["when"]; ok {
				validateMapNode(w, fmt.Sprintf("policy.rules[%d].when", i), []string{"stages", "branch_types", "environments", "repo_criticality", "exposure", "change_type"}, []string{"stages", "branch_types", "environments", "repo_criticality", "exposure", "change_type"}, &errList)
			}
			if th, ok := r["then"]; ok {
				validateMapNode(th, fmt.Sprintf("policy.rules[%d].then", i), []string{"add_risk_points", "min_decision", "require_trust_at_least", "add_recommended_step_ids"}, []string{"add_risk_points", "min_decision", "require_trust_at_least", "add_recommended_step_ids"}, &errList)
			}
		}
	}
	return errList
}

func validateAcceptedRiskYAML(node *yaml.Node) []schemaError {
	errList := []schemaError{}
	m := validateMapNode(node, "accepted_risk", []string{"schema_version", "records"}, []string{"schema_version", "records"}, &errList)
	if records, ok := m["records"]; ok {
		seq := validateSequenceNode(records, "accepted_risk.records", &errList)
		for i, item := range seq {
			r := validateMapNode(item, fmt.Sprintf("accepted_risk.records[%d]", i), []string{"id", "status", "owner", "approvers", "ticket", "rationale", "scope", "constraints", "timeline", "metadata"}, []string{"id", "status", "owner", "approvers", "ticket", "rationale", "scope", "constraints", "timeline", "metadata"}, &errList)
			if scope, ok := r["scope"]; ok {
				validateMapNode(scope, fmt.Sprintf("accepted_risk.records[%d].scope", i), []string{"type", "value", "scanner", "repository", "branch_types", "stages"}, []string{"type", "value"}, &errList)
			}
			if constraints, ok := r["constraints"]; ok {
				validateMapNode(constraints, fmt.Sprintf("accepted_risk.records[%d].constraints", i), []string{"max_severity", "environments"}, []string{"max_severity", "environments"}, &errList)
			}
			if timeline, ok := r["timeline"]; ok {
				validateMapNode(timeline, fmt.Sprintf("accepted_risk.records[%d].timeline", i), []string{"created_at", "expires_at", "sla_days"}, []string{"created_at", "expires_at", "sla_days"}, &errList)
			}
		}
	}
	return errList
}

func validateMapNode(node *yaml.Node, path string, allowed, required []string, errs *[]schemaError) map[string]*yaml.Node {
	result := map[string]*yaml.Node{}
	if node == nil {
		*errs = append(*errs, schemaError{Path: path, Line: 0, Message: "missing object"})
		return result
	}
	if node.Kind != yaml.MappingNode {
		*errs = append(*errs, schemaError{Path: path, Line: node.Line, Message: "must be a mapping/object"})
		return result
	}
	allowedSet := map[string]bool{}
	for _, a := range allowed {
		allowedSet[a] = true
	}
	seen := map[string]int{}
	for i := 0; i+1 < len(node.Content); i += 2 {
		k := node.Content[i]
		v := node.Content[i+1]
		key := k.Value
		if prevLine, ok := seen[key]; ok {
			*errs = append(*errs, schemaError{Path: path + "." + key, Line: k.Line, Message: fmt.Sprintf("duplicate key (already defined at line %d)", prevLine)})
			continue
		}
		seen[key] = k.Line
		if !allowedSet[key] {
			*errs = append(*errs, schemaError{Path: path + "." + key, Line: k.Line, Message: "unknown field"})
		}
		result[key] = v
	}
	for _, req := range required {
		if _, ok := result[req]; !ok {
			*errs = append(*errs, schemaError{Path: path + "." + req, Line: node.Line, Message: "missing required field"})
		}
	}
	return result
}

func validateSequenceNode(node *yaml.Node, path string, errs *[]schemaError) []*yaml.Node {
	if node == nil {
		*errs = append(*errs, schemaError{Path: path, Line: 0, Message: "missing sequence"})
		return nil
	}
	if node.Kind != yaml.SequenceNode {
		*errs = append(*errs, schemaError{Path: path, Line: node.Line, Message: "must be a sequence/array"})
		return nil
	}
	return node.Content
}
