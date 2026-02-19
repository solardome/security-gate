package securitygate

import (
	"path/filepath"
	"testing"
)

func TestAutoDetectContextFromEnvGitHubPR(t *testing.T) {
	env := map[string]string{
		"GITHUB_ACTIONS":    "true",
		"GITHUB_EVENT_NAME": "pull_request",
		"GITHUB_HEAD_REF":   "feature/new-api",
	}
	ctx, source := autoDetectContextFromEnv(mapLookup(env))
	if source != "github" {
		t.Fatalf("expected github source, got %s", source)
	}
	if ctx.BranchType != "feature" {
		t.Fatalf("expected feature branch type, got %s", ctx.BranchType)
	}
	if ctx.PipelineStage != "pr" {
		t.Fatalf("expected pr stage, got %s", ctx.PipelineStage)
	}
	if ctx.Environment != "ci" {
		t.Fatalf("expected ci environment, got %s", ctx.Environment)
	}
}

func TestAutoDetectContextFromEnvGitLabReleaseProd(t *testing.T) {
	env := map[string]string{
		"GITLAB_CI":           "true",
		"CI_COMMIT_BRANCH":    "release/2026.02",
		"CI_COMMIT_TAG":       "v1.2.3",
		"CI_ENVIRONMENT_NAME": "production",
	}
	ctx, source := autoDetectContextFromEnv(mapLookup(env))
	if source != "gitlab" {
		t.Fatalf("expected gitlab source, got %s", source)
	}
	if ctx.BranchType != "release" {
		t.Fatalf("expected release branch type, got %s", ctx.BranchType)
	}
	if ctx.PipelineStage != "release" {
		t.Fatalf("expected release stage, got %s", ctx.PipelineStage)
	}
	if ctx.Environment != "prod" {
		t.Fatalf("expected prod environment, got %s", ctx.Environment)
	}
}

func TestAutoDetectContextFromEnvOverride(t *testing.T) {
	env := map[string]string{
		"JENKINS_URL":                           "https://jenkins.local",
		"BRANCH_NAME":                           "main",
		"SECURITY_GATE_BRANCH_TYPE":             "release",
		"SECURITY_GATE_PIPELINE_STAGE":          "deploy",
		"SECURITY_GATE_ENVIRONMENT":             "prod",
		"SECURITY_GATE_REPO_CRITICALITY":        "mission_critical",
		"SECURITY_GATE_EXPOSURE":                "internet",
		"SECURITY_GATE_CHANGE_TYPE":             "security_sensitive",
		"SECURITY_GATE_SCANNER_NAME":            "trivy",
		"SECURITY_GATE_SCANNER_VERSION":         "0.51.0",
		"SECURITY_GATE_ARTIFACT_SIGNED":         "yes",
		"SECURITY_GATE_PROVENANCE_LEVEL":        "verified",
		"SECURITY_GATE_BUILD_CONTEXT_INTEGRITY": "verified",
	}
	ctx, _ := autoDetectContextFromEnv(mapLookup(env))
	if ctx.BranchType != "release" || ctx.PipelineStage != "deploy" || ctx.Environment != "prod" {
		t.Fatalf("override not applied to stage context: %+v", ctx)
	}
	if ctx.RepoCriticality != "mission_critical" || ctx.Exposure != "internet" || ctx.ChangeType != "security_sensitive" {
		t.Fatalf("override not applied to risk context: %+v", ctx)
	}
	if ctx.Scanner.Name != "trivy" || ctx.Scanner.Version != "0.51.0" {
		t.Fatalf("override not applied to scanner metadata: %+v", ctx.Scanner)
	}
	if ctx.Provenance.ArtifactSigned != "yes" || ctx.Provenance.Level != "verified" || ctx.Provenance.BuildContextIntegrity != "verified" {
		t.Fatalf("override not applied to provenance metadata: %+v", ctx.Provenance)
	}
}

func TestRunWithContextAuto(t *testing.T) {
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

	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_EVENT_NAME", "pull_request")
	t.Setenv("GITHUB_HEAD_REF", "feature/my-pr")

	report, err := Run(Config{
		ScanPaths:   []string{paths.Scan},
		ContextPath: "",
		AutoContext: true,
		PolicyPath:  paths.Policy,
		OutJSONPath: filepath.Join(dir, "out.json"),
		OutHTMLPath: filepath.Join(dir, "out.html"),
		WriteHTML:   false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Context.BranchType != "feature" || report.Context.PipelineStage != "pr" {
		t.Fatalf("auto context not reflected in report: %+v", report.Context)
	}
	foundContextInput := false
	for _, in := range report.Inputs {
		if in.Kind == "context_yaml" {
			foundContextInput = true
			if in.Path != "env://context-auto/github" {
				t.Fatalf("unexpected auto-context path: %s", in.Path)
			}
		}
	}
	if !foundContextInput {
		t.Fatalf("expected context_yaml input digest for auto context")
	}
}

func TestRunWithoutContextAndWithoutAutoFails(t *testing.T) {
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
	_, err := Run(Config{
		ScanPaths:   []string{paths.Scan},
		ContextPath: "",
		AutoContext: false,
		PolicyPath:  paths.Policy,
		OutJSONPath: filepath.Join(dir, "out.json"),
		OutHTMLPath: filepath.Join(dir, "out.html"),
		WriteHTML:   false,
	})
	if err == nil {
		t.Fatalf("expected error when neither --context nor --context-auto is provided")
	}
}

func mapLookup(values map[string]string) envLookupFunc {
	return func(key string) (string, bool) {
		v, ok := values[key]
		return v, ok
	}
}
