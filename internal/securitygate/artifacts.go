package securitygate

import enginereport "github.com/solardome/security-gate/internal/report"

// DefaultChecksumsPath returns the default checksums artifact path for a report.
func DefaultChecksumsPath(outJSONPath string) string {
	return enginereport.DefaultChecksumsPath(outJSONPath)
}

// DefaultRunLogPath returns the default structured run log path for a report.
func DefaultRunLogPath(outJSONPath string) string {
	return enginereport.DefaultRunLogPath(outJSONPath)
}

func writeArtifactChecksums(checksumsPath string, artifactPaths []string) error {
	return enginereport.WriteChecksums(checksumsPath, artifactPaths)
}
