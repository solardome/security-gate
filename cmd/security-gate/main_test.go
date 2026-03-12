package main

import "testing"

func TestScanListSetAndString(t *testing.T) {
	var scans scanList

	if err := scans.Set(" "); err != nil {
		t.Fatalf("Set(blank) error = %v", err)
	}
	if len(scans) != 0 {
		t.Fatalf("Set(blank) changed scans = %v", scans)
	}
	if err := scans.Set("first.json"); err != nil {
		t.Fatalf("Set(first) error = %v", err)
	}
	if err := scans.Set("second.json"); err != nil {
		t.Fatalf("Set(second) error = %v", err)
	}

	if got := scans.String(); got != "first.json,second.json" {
		t.Fatalf("String() = %q, want %q", got, "first.json,second.json")
	}
}
