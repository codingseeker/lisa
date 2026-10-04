package model

import (
	"encoding/json"
	"testing"
)

func TestSeverityString(t *testing.T) {
	cases := map[Severity]string{
		SeverityInfo:     "info",
		SeverityLow:      "low",
		SeverityMedium:   "medium",
		SeverityHigh:     "high",
		SeverityCritical: "critical",
	}
	for severity, expected := range cases {
		if got := severity.String(); got != expected {
			t.Errorf("Severity(%d).String() = %q, want %q", int(severity), got, expected)
		}
	}
}

func TestSeverityInvalidIsNotValid(t *testing.T) {
	invalid := Severity(99)
	if invalid.IsValid() {
		t.Fatal("Severity(99).IsValid() = true, want false")
	}
	if got := invalid.String(); got != "severity(99)" {
		t.Errorf("Severity(99).String() = %q, want %q", got, "severity(99)")
	}
}

func TestSeverityOrdering(t *testing.T) {
	ordered := Severities()
	for i := 1; i < len(ordered); i++ {
		if ordered[i-1] >= ordered[i] {
			t.Fatalf("severity scale is not ascending at index %d: %v", i, ordered)
		}
	}
	if !SeverityCritical.AtLeast(SeverityLow) {
		t.Error("critical should be at least low")
	}
	if SeverityLow.AtLeast(SeverityHigh) {
		t.Error("low should not be at least high")
	}
	if !SeverityHigh.AtLeast(SeverityHigh) {
		t.Error("high should be at least high")
	}
}

func TestParseSeverity(t *testing.T) {
	cases := map[string]Severity{
		"info":     SeverityInfo,
		"INFO":     SeverityInfo,
		"  Low  ":  SeverityLow,
		"medium":   SeverityMedium,
		"high":     SeverityHigh,
		"critical": SeverityCritical,
	}
	for input, expected := range cases {
		got, err := ParseSeverity(input)
		if err != nil {
			t.Fatalf("ParseSeverity(%q) returned error: %v", input, err)
		}
		if got != expected {
			t.Errorf("ParseSeverity(%q) = %v, want %v", input, got, expected)
		}
	}
}

func TestParseSeverityRejectsUnknown(t *testing.T) {
	for _, input := range []string{"", "severe", "3", "informational"} {
		if _, err := ParseSeverity(input); err == nil {
			t.Errorf("ParseSeverity(%q) returned no error, want error", input)
		}
	}
}

func TestSeverityJSONRoundTrip(t *testing.T) {
	for _, severity := range Severities() {
		data, err := json.Marshal(severity)
		if err != nil {
			t.Fatalf("marshalling %v failed: %v", severity, err)
		}
		var decoded Severity
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshalling %s failed: %v", data, err)
		}
		if decoded != severity {
			t.Errorf("round trip of %v produced %v", severity, decoded)
		}
	}
}

func TestSeverityMarshalRejectsInvalid(t *testing.T) {
	if _, err := json.Marshal(Severity(42)); err == nil {
		t.Error("marshalling invalid severity returned no error, want error")
	}
}

func TestSeverityUnmarshalRejectsNonString(t *testing.T) {
	var severity Severity
	if err := json.Unmarshal([]byte(`3`), &severity); err == nil {
		t.Error("unmarshalling numeric severity returned no error, want error")
	}
	if err := json.Unmarshal([]byte(`"extreme"`), &severity); err == nil {
		t.Error("unmarshalling unknown severity returned no error, want error")
	}
}
