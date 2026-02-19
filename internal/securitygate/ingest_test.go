package securitygate

import "testing"

func TestParseScanSupportsAllConfiguredFormats(t *testing.T) {
	trivyPayload := []byte(`{
  "ArtifactName":"registry.local/app@sha256:abc",
  "GeneratedAt":"2026-02-19T11:00:00Z",
  "Results":[
    {
      "Target":"app",
      "Vulnerabilities":[
        {"VulnerabilityID":"CVE-2026-0001","PkgName":"openssl","Severity":"HIGH","Title":"issue"}
      ]
    }
  ]
}`)
	trivyFindings, trivyDetectedAt, err := parseScan("scan.json", trivyPayload, "trivy", "0.50.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(trivyFindings) != 1 {
		t.Fatalf("expected 1 trivy finding, got %d", len(trivyFindings))
	}
	if trivyDetectedAt != "2026-02-19T11:00:00Z" {
		t.Fatalf("unexpected trivy detected_at: %s", trivyDetectedAt)
	}

	sarifPayload := []byte(`{
  "version":"2.1.0",
  "runs":[
    {
      "tool":{"driver":{"name":"snyk-code","semanticVersion":"1.2.3"}},
      "invocations":[{"endTimeUtc":"2026-02-19T12:00:00Z"}],
      "results":[{"ruleId":"RULE-1","message":{"text":"issue"}}]
    }
  ]
}`)
	sarifFindings, sarifDetectedAt, err := parseScan("scan.sarif", sarifPayload, "unknown", "unknown")
	if err != nil {
		t.Fatal(err)
	}
	if len(sarifFindings) != 1 {
		t.Fatalf("expected 1 sarif finding, got %d", len(sarifFindings))
	}
	if sarifFindings[0].ScannerName != "snyk" {
		t.Fatalf("expected scanner from sarif driver, got %s", sarifFindings[0].ScannerName)
	}
	if sarifDetectedAt != "2026-02-19T12:00:00Z" {
		t.Fatalf("unexpected sarif detected_at: %s", sarifDetectedAt)
	}

	snykPayload := []byte(`{"ok":false,"vulnerabilities":[]}`)
	snykFindings, _, err := parseScan("snyk.json", snykPayload, "snyk", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(snykFindings) != 0 {
		t.Fatalf("expected no snyk findings, got %d", len(snykFindings))
	}

	checkmarxPayload := []byte(`{"reportType":"json-v2","scanResults":[]}`)
	checkmarxFindings, _, err := parseScan("checkmarx.json", checkmarxPayload, "checkmarx", "3.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(checkmarxFindings) != 0 {
		t.Fatalf("expected no checkmarx findings, got %d", len(checkmarxFindings))
	}

	sonarPayload := []byte(`{
  "issues":[
    {"ruleId":"R1","primaryLocation":{"message":"x","filePath":"a.go"}}
  ]
}`)
	sonarFindings, sonarDetectedAt, err := parseScan("sonar.json", sonarPayload, "sonar", "unknown")
	if err != nil {
		t.Fatal(err)
	}
	if len(sonarFindings) != 1 {
		t.Fatalf("expected 1 sonar finding, got %d", len(sonarFindings))
	}
	if sonarDetectedAt != "unknown" {
		t.Fatalf("expected unknown sonar detected_at, got %s", sonarDetectedAt)
	}
}

func TestParseScanRejectsUnknownFormat(t *testing.T) {
	unknownPayload := []byte(`{"hello":"world"}`)
	_, _, err := parseScan("unknown.json", unknownPayload, "unknown", "unknown")
	if err == nil {
		t.Fatalf("expected unsupported format error")
	}
}

func TestParseScanUsesAdapterScannerIdentity(t *testing.T) {
	snykPayload := []byte(`{
  "ok": false,
  "projectName": "payments-api",
  "vulnerabilities": [
    {"id":"SNYK-1","severity":"high","packageName":"lodash"}
  ]
}`)
	snykFindings, _, err := parseScan("snyk.json", snykPayload, "trivy", "0.50.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(snykFindings) != 1 {
		t.Fatalf("expected 1 snyk finding, got %d", len(snykFindings))
	}
	if snykFindings[0].ScannerName != "snyk" {
		t.Fatalf("expected snyk scanner identity, got %s", snykFindings[0].ScannerName)
	}

	checkmarxPayload := []byte(`{
  "reportType":"json-v2",
  "scanInfo":{"projectName":"payments-api"},
  "scanResults":[{"queryId":1,"queryName":"x","severity":"high"}]
}`)
	checkmarxFindings, _, err := parseScan("checkmarx.json", checkmarxPayload, "trivy", "0.50.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(checkmarxFindings) != 1 {
		t.Fatalf("expected 1 checkmarx finding, got %d", len(checkmarxFindings))
	}
	if checkmarxFindings[0].ScannerName != "checkmarx" {
		t.Fatalf("expected checkmarx scanner identity, got %s", checkmarxFindings[0].ScannerName)
	}

	sonarPayload := []byte(`{
  "projectKey":"payments-api",
  "issues":[
    {
      "ruleId":"R1",
      "engineId":"sonar-security",
      "primaryLocation":{"message":"x","filePath":"a.go"}
    }
  ]
}`)
	sonarFindings, _, err := parseScan("sonar.json", sonarPayload, "trivy", "0.50.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(sonarFindings) != 1 {
		t.Fatalf("expected 1 sonar finding, got %d", len(sonarFindings))
	}
	if sonarFindings[0].ScannerName != "sonar" {
		t.Fatalf("expected canonical sonar scanner identity, got %s", sonarFindings[0].ScannerName)
	}
}

func TestDetectScanFormatAcceptsContractMinimalEnvelopes(t *testing.T) {
	cases := []struct {
		name       string
		payload    []byte
		wantFormat string
	}{
		{
			name:       "snyk_minimal",
			payload:    []byte(`{"vulnerabilities":[]}`),
			wantFormat: "snyk",
		},
		{
			name:       "checkmarx_minimal",
			payload:    []byte(`{"scanResults":[]}`),
			wantFormat: "checkmarx",
		},
		{
			name:       "sonar_minimal",
			payload:    []byte(`{"issues":[]}`),
			wantFormat: "sonar",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			format, err := detectScanFormat(tc.payload)
			if err != nil {
				t.Fatalf("detect scan format failed: %v", err)
			}
			if format != tc.wantFormat {
				t.Fatalf("unexpected format: got %s want %s", format, tc.wantFormat)
			}

			findings, _, err := parseScan(tc.name+".json", tc.payload, "trivy", "0.50.0")
			if err != nil {
				t.Fatalf("parseScan failed: %v", err)
			}
			if len(findings) != 0 {
				t.Fatalf("expected 0 findings for minimal envelope, got %d", len(findings))
			}
		})
	}
}

func TestDetectScanFormatUsesDeterministicTieBreakOrder(t *testing.T) {
	payload := []byte(`{
  "scanResults": [],
  "vulnerabilities": [],
  "issues": []
}`)
	format, err := detectScanFormat(payload)
	if err != nil {
		t.Fatal(err)
	}
	if format != "checkmarx" {
		t.Fatalf("expected deterministic tie-break to choose checkmarx, got %s", format)
	}
}

func TestDetectScanFormatSkipsInvalidHigherPrioritySignatures(t *testing.T) {
	t.Run("invalid_runs_falls_back_to_snyk", func(t *testing.T) {
		payload := []byte(`{
  "runs": {},
  "vulnerabilities": []
}`)
		format, err := detectScanFormat(payload)
		if err != nil {
			t.Fatal(err)
		}
		if format != "snyk" {
			t.Fatalf("expected snyk after skipping invalid runs signature, got %s", format)
		}
		findings, _, err := parseScan("fallback-snyk.json", payload, "unknown", "unknown")
		if err != nil {
			t.Fatalf("expected snyk parse to succeed, got %v", err)
		}
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d", len(findings))
		}
	})

	t.Run("runs_array_without_version_falls_back_to_snyk", func(t *testing.T) {
		payload := []byte(`{
  "runs": [],
  "vulnerabilities": []
}`)
		format, err := detectScanFormat(payload)
		if err != nil {
			t.Fatal(err)
		}
		if format != "snyk" {
			t.Fatalf("expected snyk when sarif version is missing, got %s", format)
		}
		findings, _, err := parseScan("fallback-snyk-missing-version.json", payload, "unknown", "unknown")
		if err != nil {
			t.Fatalf("expected snyk parse to succeed, got %v", err)
		}
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d", len(findings))
		}
	})

	t.Run("runs_array_with_non_string_version_falls_back_to_snyk", func(t *testing.T) {
		payload := []byte(`{
  "version": 2.1,
  "runs": [],
  "vulnerabilities": []
}`)
		format, err := detectScanFormat(payload)
		if err != nil {
			t.Fatal(err)
		}
		if format != "snyk" {
			t.Fatalf("expected snyk when sarif version is not a string, got %s", format)
		}
		findings, _, err := parseScan("fallback-snyk-non-string-version.json", payload, "unknown", "unknown")
		if err != nil {
			t.Fatalf("expected snyk parse to succeed, got %v", err)
		}
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d", len(findings))
		}
	})

	t.Run("invalid_results_falls_back_to_checkmarx", func(t *testing.T) {
		payload := []byte(`{
  "Results": {},
  "scanResults": []
}`)
		format, err := detectScanFormat(payload)
		if err != nil {
			t.Fatal(err)
		}
		if format != "checkmarx" {
			t.Fatalf("expected checkmarx after skipping invalid Results signature, got %s", format)
		}
		findings, _, err := parseScan("fallback-checkmarx.json", payload, "unknown", "unknown")
		if err != nil {
			t.Fatalf("expected checkmarx parse to succeed, got %v", err)
		}
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d", len(findings))
		}
	})
}

func TestDetectScanFormatUsesDeterministicTieBreakAcrossAllValidSignatures(t *testing.T) {
	payload := []byte(`{
  "version": "2.1.0",
  "runs": [],
  "Results": [],
  "scanResults": [],
  "vulnerabilities": [],
  "issues": []
}`)
	format, err := detectScanFormat(payload)
	if err != nil {
		t.Fatal(err)
	}
	if format != "sarif" {
		t.Fatalf("expected sarif due deterministic precedence, got %s", format)
	}
	findings, _, err := parseScan("ambiguous-all.json", payload, "unknown", "unknown")
	if err != nil {
		t.Fatalf("expected parse to follow sarif route, got %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseScanRejectsInvalidVulnerabilitiesType(t *testing.T) {
	payload := []byte(`{
  "vulnerabilities":{"id":"GENERIC-1","severity":"high"}
}`)
	_, _, err := parseScan("unknown-vulns.json", payload, "unknown", "unknown")
	if err == nil {
		t.Fatalf("expected unsupported snyk envelope error for non-array vulnerabilities")
	}
}
