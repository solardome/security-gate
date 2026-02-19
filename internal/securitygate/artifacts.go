package securitygate

import enginereport "github.com/solardome/security-gate/internal/report"

func DefaultChecksumsPath(outJSONPath string) string {
	return enginereport.DefaultChecksumsPath(outJSONPath)
}

func DefaultRunLogPath(outJSONPath string) string {
	return enginereport.DefaultRunLogPath(outJSONPath)
}

func writeArtifactChecksums(checksumsPath string, artifactPaths []string) error {
	return enginereport.WriteChecksums(checksumsPath, artifactPaths)
}
