package trivy

type trivyReport struct {
	SchemaVersion int           `json:"SchemaVersion"`
	ArtifactName  string        `json:"ArtifactName"`
	ArtifactType  string        `json:"ArtifactType"`
	Metadata      trivyMetadata `json:"Metadata"`
	Scanner       trivyScanner  `json:"Scanner"`
	Results       []trivyResult `json:"Results"`
}

type trivyMetadata struct {
	Timestamp      string       `json:"Timestamp"`
	ScanTime       string       `json:"ScanTime"`
	ScanTimestamp  string       `json:"scan_timestamp"`
	LastScannedAt  string       `json:"LastScannedAt"`
	ScannerVersion string       `json:"ScannerVersion"`
	Scanner        trivyScanner `json:"Scanner"`
}

type trivyScanner struct {
	Name    string `json:"Name"`
	Version string `json:"Version"`
	Release string `json:"Release"`
}

type trivyResult struct {
	Target            string                  `json:"Target"`
	Source            string                  `json:"Source"`
	Type              string                  `json:"Type"`
	Vulnerabilities   []trivyVulnerability    `json:"Vulnerabilities"`
	Misconfigurations []trivyMisconfiguration `json:"Misconfigurations"`
}

type trivyVulnerability struct {
	VulnerabilityID  string      `json:"VulnerabilityID"`
	PkgName          string      `json:"PkgName"`
	PkgVersion       string      `json:"PkgVersion"`
	InstalledVersion string      `json:"InstalledVersion"`
	FixedVersion     string      `json:"FixedVersion"`
	Severity         string      `json:"Severity"`
	Title            string      `json:"Title"`
	Description      string      `json:"Description"`
	PrimaryURL       string      `json:"PrimaryURL"`
	References       []string    `json:"References"`
	CVSS             []trivyCVSS `json:"CVSS"`
	VendorSeverity   string      `json:"VendorSeverity"`
}

type trivyMisconfiguration struct {
	ID          string   `json:"ID"`
	Title       string   `json:"Title"`
	Description string   `json:"Description"`
	Message     string   `json:"Message"`
	Severity    string   `json:"Severity"`
	PrimaryURL  string   `json:"PrimaryURL"`
	References  []string `json:"References"`
	Target      string   `json:"Target"`
}

type trivyCVSS struct {
	Version   string  `json:"Version"`
	Vector    string  `json:"Vector"`
	BaseScore float64 `json:"BaseScore"`
}
