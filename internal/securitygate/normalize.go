package securitygate

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

func normalizeFindings(in []AdapterFinding) []UnifiedFinding {
	out := make([]UnifiedFinding, 0, len(in))
	for _, f := range in {
		sev := normalizeToken(f.Severity)
		if _, ok := severityRank[sev]; !ok {
			sev = "unknown"
		}
		conf := normalizeToken(f.Confidence)
		if conf != "high" && conf != "medium" && conf != "low" {
			conf = "unknown"
		}
		exploit := normalizeToken(f.ExploitMaturity)
		if exploit != "known_exploited" && exploit != "poc" && exploit != "none" {
			exploit = "unknown"
		}
		reach := normalizeToken(f.Reachability)
		if reach != "reachable" && reach != "potentially_reachable" && reach != "not_reachable" {
			reach = "unknown"
		}
		id := strings.TrimSpace(f.RawID)
		if id == "" {
			id = fallbackFindingID(f)
		}
		out = append(out, UnifiedFinding{
			FindingID: id,
			Scanner: ScannerMeta{
				Name:    canonicalScannerID(firstNonEmpty(strings.TrimSpace(f.ScannerName), "unknown")),
				Version: firstNonEmpty(strings.TrimSpace(f.ScannerVersion), "unknown"),
			},
			Artifact: UnifiedArtifact{
				TargetRef: firstNonEmpty(strings.TrimSpace(f.ArtifactTargetRef), "unknown"),
				Component: firstNonEmpty(strings.TrimSpace(f.Component), "unknown"),
				Location:  firstNonEmpty(strings.TrimSpace(f.Location), "unknown"),
			},
			Class: UnifiedClassification{
				Category:        normalizeToken(firstNonEmpty(f.Category, "unknown")),
				DomainID:        firstNonEmpty(strings.TrimSpace(f.DomainID), "UNKNOWN_DOMAIN"),
				CVE:             strings.TrimSpace(f.CVE),
				CWE:             strings.TrimSpace(f.CWE),
				Severity:        sev,
				Confidence:      conf,
				ExploitMaturity: exploit,
				Reachability:    reach,
			},
			Evidence: UnifiedEvidence{
				Title:       firstNonEmpty(strings.TrimSpace(f.Title), "unknown"),
				Description: strings.TrimSpace(f.Description),
				References:  append([]string{}, f.References...),
			},
			DetectedAt: firstNonEmpty(strings.TrimSpace(f.DetectedAt), "unknown"),
			Raw: UnifiedRaw{
				SourceFile:  f.SourceFile,
				SourceIndex: f.SourceIndex,
			},
		})
	}
	return out
}

func fallbackFindingID(f AdapterFinding) string {
	s := strings.Join([]string{
		canonicalScannerID(firstNonEmpty(f.ScannerName, "unknown")),
		firstNonEmpty(f.ScannerVersion, "unknown"),
		firstNonEmpty(f.ArtifactTargetRef, "unknown"),
		firstNonEmpty(f.Location, "unknown"),
		firstNonEmpty(f.Category, "unknown"),
		firstNonEmpty(f.Title, "unknown"),
	}, "|")
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func sortFindingsDeterministically(findings []UnifiedFinding) {
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.HardStop != b.HardStop {
			return a.HardStop
		}
		if a.FindingRiskScore != b.FindingRiskScore {
			return a.FindingRiskScore > b.FindingRiskScore
		}
		sa := severityRank[a.Class.Severity]
		sb := severityRank[b.Class.Severity]
		if sa != sb {
			return sa < sb
		}
		if a.Class.DomainID != b.Class.DomainID {
			return a.Class.DomainID < b.Class.DomainID
		}
		if a.FindingID != b.FindingID {
			return a.FindingID < b.FindingID
		}
		if a.Artifact.Location != b.Artifact.Location {
			return a.Artifact.Location < b.Artifact.Location
		}
		if a.Raw.SourceFile != b.Raw.SourceFile {
			return a.Raw.SourceFile < b.Raw.SourceFile
		}
		return a.Raw.SourceIndex < b.Raw.SourceIndex
	})
}
