package snyk

import (
	"os"
	"testing"
)

func FuzzParse(f *testing.F) {
	if data, err := os.ReadFile("../../../examples/simulation/scanner-report.warn.snyk.json"); err == nil {
		f.Add(data)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Parse("fuzz.json", data, "snyk", "fuzzer")
	})
}
