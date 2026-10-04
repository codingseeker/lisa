package model

import (
	"encoding/json"
	"testing"
)

func TestConfidenceString(t *testing.T) {
	cases := map[Confidence]string{
		ConfidenceLow:    "low",
		ConfidenceMedium: "medium",
		ConfidenceHigh:   "high",
	}
	for confidence, expected := range cases {
		if got := confidence.String(); got != expected {
			t.Errorf("Confidence(%d).String() = %q, want %q", int(confidence), got, expected)
		}
	}
}

func TestConfidenceIsDistinctFromSeverity(t *testing.T) {
	if len(Confidences()) == len(Severities()) {
		t.Error("confidence and severity scales should not be identical in size")
	}
	if Confidences()[0] != ConfidenceLow || Confidences()[len(Confidences())-1] != ConfidenceHigh {
		t.Error("confidence scale should run from low to high")
	}
	for _, confidence := range Confidences() {
		if confidence.String() == SeverityInfo.String() && confidence.String() == "info" {
			t.Error("confidence scale must not include an informational level")
		}
	}
	confidences := Confidences()
	for i := 1; i < len(confidences); i++ {
		if confidences[i-1] >= confidences[i] {
			t.Fatalf("confidence scale is not ascending at index %d: %v", i, confidences)
		}
	}
}

func TestConfidenceInvalidIsNotValid(t *testing.T) {
	invalid := Confidence(7)
	if invalid.IsValid() {
		t.Fatal("Confidence(7).IsValid() = true, want false")
	}
	if got := invalid.String(); got != "confidence(7)" {
		t.Errorf("Confidence(7).String() = %q, want %q", got, "confidence(7)")
	}
}

func TestParseConfidence(t *testing.T) {
	cases := map[string]Confidence{
		"low":    ConfidenceLow,
		"MEDIUM": ConfidenceMedium,
		" high ": ConfidenceHigh,
	}
	for input, expected := range cases {
		got, err := ParseConfidence(input)
		if err != nil {
			t.Fatalf("ParseConfidence(%q) returned error: %v", input, err)
		}
		if got != expected {
			t.Errorf("ParseConfidence(%q) = %v, want %v", input, got, expected)
		}
	}
}

func TestParseConfidenceRejectsUnknown(t *testing.T) {
	for _, input := range []string{"", "none", "certain", "1"} {
		if _, err := ParseConfidence(input); err == nil {
			t.Errorf("ParseConfidence(%q) returned no error, want error", input)
		}
	}
}

func TestConfidenceJSONRoundTrip(t *testing.T) {
	for _, confidence := range Confidences() {
		data, err := json.Marshal(confidence)
		if err != nil {
			t.Fatalf("marshalling %v failed: %v", confidence, err)
		}
		var decoded Confidence
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshalling %s failed: %v", data, err)
		}
		if decoded != confidence {
			t.Errorf("round trip of %v produced %v", confidence, decoded)
		}
	}
	if _, err := json.Marshal(Confidence(9)); err == nil {
		t.Error("marshalling invalid confidence returned no error, want error")
	}
	var confidence Confidence
	if err := json.Unmarshal([]byte(`true`), &confidence); err == nil {
		t.Error("unmarshalling boolean confidence returned no error, want error")
	}
}
