package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/solardome/security-gate/internal/securitygate"
)

type scanList []string

func (s *scanList) String() string { return strings.Join(*s, ",") }
func (s *scanList) Set(v string) error {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	*s = append(*s, v)
	return nil
}

func main() {
	var scans scanList
	var baselineScans scanList
	var newFindingsOnly bool
	var contextPath string
	var contextAuto bool
	var policyPath string
	var acceptedRiskPath string
	var outJSON string
	var outHTML string
	var checksumsPath string
	var runLogPath string
	var noHTML bool

	flag.Var(&scans, "scan", "Path to scanner JSON (repeatable)")
	flag.Var(&baselineScans, "baseline-scan", "Path to baseline scanner JSON (repeatable, used with --new-findings-only)")
	flag.BoolVar(&newFindingsOnly, "new-findings-only", false, "Score only findings not present in baseline scans (pr/merge only)")
	flag.StringVar(&contextPath, "context", "", "Path to context YAML")
	flag.BoolVar(&contextAuto, "context-auto", false, "Auto-detect context from CI environment when --context is omitted")
	flag.StringVar(&policyPath, "policy", "", "Path to policy YAML")
	flag.StringVar(&acceptedRiskPath, "accepted-risk", "", "Path to accepted risk YAML")
	flag.StringVar(&outJSON, "out-json", "report.json", "Output report.json path")
	flag.StringVar(&outHTML, "out-html", "report.html", "Output report.html path")
	flag.StringVar(&checksumsPath, "checksums", "", "Output checksums.sha256 path (default next to out-json)")
	flag.StringVar(&runLogPath, "run-log", "", "Output run log path (default next to out-json)")
	flag.BoolVar(&noHTML, "no-html", false, "Disable report.html output")
	flag.Parse()

	report, err := securitygate.Run(securitygate.Config{
		ScanPaths:         scans,
		BaselineScanPaths: baselineScans,
		NewFindingsOnly:   newFindingsOnly,
		ContextPath:       contextPath,
		AutoContext:       contextAuto,
		PolicyPath:        policyPath,
		AcceptedRiskPath:  acceptedRiskPath,
		OutJSONPath:       outJSON,
		OutHTMLPath:       outHTML,
		ChecksumsPath:     checksumsPath,
		RunLogPath:        runLogPath,
		WriteHTML:         !noHTML,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "security-gate error:", err)
		os.Exit(2)
	}
	if strings.TrimSpace(checksumsPath) == "" {
		checksumsPath = securitygate.DefaultChecksumsPath(outJSON)
	}
	if strings.TrimSpace(runLogPath) == "" {
		runLogPath = securitygate.DefaultRunLogPath(outJSON)
	}
	fmt.Printf("decision=%s exit_code=%d overall_risk=%d trust=%d report=%s checksums=%s run_log=%s\n", report.Decision, report.ExitCode, report.Risk.OverallScore, report.Trust.Score, outJSON, checksumsPath, runLogPath)
	os.Exit(report.ExitCode)
}
