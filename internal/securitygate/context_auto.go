package securitygate

import "strings"

type envLookupFunc func(string) (string, bool)

func autoDetectContextFromEnv(lookup envLookupFunc) (Context, string) {
	source := detectCIProvider(lookup)
	ctx := defaultAutoContext()

	switch source {
	case "github":
		branchName := githubBranchName(lookup)
		ctx.BranchType = branchTypeFromName(branchName)
		ctx.PipelineStage = githubPipelineStage(lookup)
		if isProdLike(firstEnv(lookup, "DEPLOY_ENV", "ENVIRONMENT")) {
			ctx.Environment = "prod"
		}
	case "gitlab":
		branchName := firstEnv(lookup, "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME", "CI_COMMIT_BRANCH")
		ctx.BranchType = branchTypeFromName(branchName)
		ctx.PipelineStage = gitlabPipelineStage(lookup)
		if isProdLike(firstEnv(lookup, "CI_ENVIRONMENT_NAME")) {
			ctx.Environment = "prod"
		}
	case "jenkins":
		branchName := firstEnv(lookup, "BRANCH_NAME", "GIT_BRANCH")
		ctx.BranchType = branchTypeFromName(branchName)
		ctx.PipelineStage = jenkinsPipelineStage(lookup)
		if isProdLike(firstEnv(lookup, "DEPLOY_ENV", "ENVIRONMENT")) {
			ctx.Environment = "prod"
		}
	default:
		branchName := firstEnv(lookup, "GIT_BRANCH", "BRANCH_NAME")
		if strings.TrimSpace(branchName) != "" {
			ctx.BranchType = branchTypeFromName(branchName)
		}
	}

	applyAutoContextOverrides(&ctx, lookup)
	normalizeAutoContext(&ctx)

	return ctx, source
}

func defaultAutoContext() Context {
	return Context{
		BranchType:      "main",
		PipelineStage:   "merge",
		Environment:     "ci",
		RepoCriticality: "unknown",
		Exposure:        "unknown",
		ChangeType:      "unknown",
		Scanner: ScannerMeta{
			Name:    "unknown",
			Version: "unknown",
		},
		Provenance: Provenance{
			ArtifactSigned:        "unknown",
			Level:                 "unknown",
			BuildContextIntegrity: "unknown",
		},
	}
}

func detectCIProvider(lookup envLookupFunc) string {
	if isTrueEnv(lookup, "GITHUB_ACTIONS") {
		return "github"
	}
	if isTrueEnv(lookup, "GITLAB_CI") {
		return "gitlab"
	}
	if hasEnv(lookup, "JENKINS_URL") || hasEnv(lookup, "JENKINS_HOME") || (hasEnv(lookup, "BUILD_ID") && hasEnv(lookup, "JOB_NAME")) {
		return "jenkins"
	}
	return "generic"
}

func githubBranchName(lookup envLookupFunc) string {
	branch := firstEnv(lookup, "GITHUB_HEAD_REF", "GITHUB_REF_NAME")
	if strings.TrimSpace(branch) != "" {
		return branch
	}
	ref := firstEnv(lookup, "GITHUB_REF")
	ref = strings.TrimSpace(ref)
	const headsPrefix = "refs/heads/"
	if strings.HasPrefix(ref, headsPrefix) {
		return strings.TrimSpace(strings.TrimPrefix(ref, headsPrefix))
	}
	return ""
}

func githubPipelineStage(lookup envLookupFunc) string {
	event := normalizeToken(firstEnv(lookup, "GITHUB_EVENT_NAME"))
	ref := strings.TrimSpace(strings.ToLower(firstEnv(lookup, "GITHUB_REF")))
	if strings.HasPrefix(event, "pull_request") {
		return "pr"
	}
	if event == "release" || strings.HasPrefix(ref, "refs/tags/") {
		return "release"
	}
	return "merge"
}

func gitlabPipelineStage(lookup envLookupFunc) string {
	source := normalizeToken(firstEnv(lookup, "CI_PIPELINE_SOURCE"))
	if source == "merge_request_event" {
		return "pr"
	}
	if strings.TrimSpace(firstEnv(lookup, "CI_COMMIT_TAG")) != "" {
		return "release"
	}
	return "merge"
}

func jenkinsPipelineStage(lookup envLookupFunc) string {
	if strings.TrimSpace(firstEnv(lookup, "CHANGE_ID")) != "" {
		return "pr"
	}
	if strings.TrimSpace(firstEnv(lookup, "TAG_NAME")) != "" {
		return "release"
	}
	return "merge"
}

func branchTypeFromName(name string) string {
	n := strings.TrimSpace(strings.ToLower(name))
	n = strings.TrimPrefix(n, "refs/heads/")
	switch {
	case n == "main" || n == "master":
		return "main"
	case n == "release" || strings.HasPrefix(n, "release/") || strings.HasPrefix(n, "release-"):
		return "release"
	case n == "dev" || n == "develop" || strings.HasPrefix(n, "dev/"):
		return "dev"
	case n == "":
		return "main"
	default:
		return "feature"
	}
}

func applyAutoContextOverrides(ctx *Context, lookup envLookupFunc) {
	if v := firstEnv(lookup, "SECURITY_GATE_BRANCH_TYPE"); strings.TrimSpace(v) != "" {
		ctx.BranchType = v
	}
	if v := firstEnv(lookup, "SECURITY_GATE_PIPELINE_STAGE"); strings.TrimSpace(v) != "" {
		ctx.PipelineStage = v
	}
	if v := firstEnv(lookup, "SECURITY_GATE_ENVIRONMENT"); strings.TrimSpace(v) != "" {
		ctx.Environment = v
	}
	if v := firstEnv(lookup, "SECURITY_GATE_REPO_CRITICALITY"); strings.TrimSpace(v) != "" {
		ctx.RepoCriticality = v
	}
	if v := firstEnv(lookup, "SECURITY_GATE_EXPOSURE"); strings.TrimSpace(v) != "" {
		ctx.Exposure = v
	}
	if v := firstEnv(lookup, "SECURITY_GATE_CHANGE_TYPE"); strings.TrimSpace(v) != "" {
		ctx.ChangeType = v
	}
	if v := firstEnv(lookup, "SECURITY_GATE_SCANNER_NAME"); strings.TrimSpace(v) != "" {
		ctx.Scanner.Name = v
	}
	if v := firstEnv(lookup, "SECURITY_GATE_SCANNER_VERSION"); strings.TrimSpace(v) != "" {
		ctx.Scanner.Version = v
	}
	if v := firstEnv(lookup, "SECURITY_GATE_ARTIFACT_SIGNED"); strings.TrimSpace(v) != "" {
		ctx.Provenance.ArtifactSigned = v
	}
	if v := firstEnv(lookup, "SECURITY_GATE_PROVENANCE_LEVEL"); strings.TrimSpace(v) != "" {
		ctx.Provenance.Level = v
	}
	if v := firstEnv(lookup, "SECURITY_GATE_BUILD_CONTEXT_INTEGRITY"); strings.TrimSpace(v) != "" {
		ctx.Provenance.BuildContextIntegrity = v
	}
}

func normalizeAutoContext(ctx *Context) {
	ctx.BranchType = oneOfOrDefault(ctx.BranchType, map[string]bool{
		"dev": true, "feature": true, "main": true, "release": true,
	}, "main")
	ctx.PipelineStage = oneOfOrDefault(ctx.PipelineStage, map[string]bool{
		"pr": true, "merge": true, "release": true, "deploy": true,
	}, "merge")
	ctx.Environment = oneOfOrDefault(ctx.Environment, map[string]bool{
		"ci": true, "prod": true,
	}, "ci")
	ctx.RepoCriticality = oneOfOrDefault(ctx.RepoCriticality, map[string]bool{
		"low": true, "medium": true, "high": true, "mission_critical": true, "unknown": true,
	}, "unknown")
	ctx.Exposure = oneOfOrDefault(ctx.Exposure, map[string]bool{
		"isolated": true, "internal": true, "internet": true, "unknown": true,
	}, "unknown")
	ctx.ChangeType = oneOfOrDefault(ctx.ChangeType, map[string]bool{
		"docs_or_tests": true, "application": true, "infra_or_supply_chain": true, "security_sensitive": true, "unknown": true,
	}, "unknown")
	ctx.Scanner.Name = oneOfOrDefault(ctx.Scanner.Name, map[string]bool{}, "unknown")
	ctx.Scanner.Version = oneOfOrDefault(ctx.Scanner.Version, map[string]bool{}, "unknown")
	ctx.Provenance.ArtifactSigned = oneOfOrDefault(ctx.Provenance.ArtifactSigned, map[string]bool{
		"yes": true, "no": true, "unknown": true,
	}, "unknown")
	ctx.Provenance.Level = oneOfOrDefault(ctx.Provenance.Level, map[string]bool{
		"none": true, "basic": true, "verified": true, "unknown": true,
	}, "unknown")
	ctx.Provenance.BuildContextIntegrity = oneOfOrDefault(ctx.Provenance.BuildContextIntegrity, map[string]bool{
		"verified": true, "partial": true, "unknown": true,
	}, "unknown")
}

func oneOfOrDefault(value string, allowed map[string]bool, fallback string) string {
	n := normalizeToken(value)
	if len(allowed) == 0 {
		if n == "unknown" {
			return fallback
		}
		return n
	}
	if allowed[n] {
		return n
	}
	return fallback
}

func isTrueEnv(lookup envLookupFunc, key string) bool {
	v, ok := lookup(key)
	if !ok {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(v), "true")
}

func hasEnv(lookup envLookupFunc, key string) bool {
	v, ok := lookup(key)
	return ok && strings.TrimSpace(v) != ""
}

func firstEnv(lookup envLookupFunc, keys ...string) string {
	for _, key := range keys {
		if v, ok := lookup(key); ok {
			if strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
	}
	return ""
}

func isProdLike(value string) bool {
	n := strings.TrimSpace(strings.ToLower(value))
	if n == "" {
		return false
	}
	return strings.Contains(n, "prod")
}
