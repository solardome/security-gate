package trivy

import (
	"os"
	"testing"
)

func FuzzParse(f *testing.F) {
	if data, err := os.ReadFile("../../../examples/simulation/scanner-report.warn.json"); err == nil {
		f.Add(data)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Parse("fuzz.json", data, "trivy", "fuzzer")
	})
}
