package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func validReference() *ReferenceContext {
	return &ReferenceContext{
		Source:      "gtfobins-curated",
		Binary:      "find",
		Category:    "filesystem",
		Summary:     "Recursive file walker that evaluates an expression supplied on the command line.",
		Attribution: "Concept: GTFOBins (MIT licence). Independent curated subset.",
		Severity:    SeverityMedium,
		Caveat:      "A match does not indicate exploitation or compromise.",
	}
}

func TestReferenceContextValidateAcceptsCompleteContext(t *testing.T) {
	if err := validReference().Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
}

func TestReferenceContextValidateAcceptsNil(t *testing.T) {
	var absent *ReferenceContext
	if err := absent.Validate(); err != nil {
		t.Errorf("a nil reference must validate, got %v", err)
	}
}

func TestReferenceContextValidateRejectsIncompleteContext(t *testing.T) {
	cases := map[string]func(*ReferenceContext){
		"missing source":          func(r *ReferenceContext) { r.Source = "" },
		"missing binary":          func(r *ReferenceContext) { r.Binary = "" },
		"missing category":        func(r *ReferenceContext) { r.Category = "" },
		"missing summary":         func(r *ReferenceContext) { r.Summary = "" },
		"invalid severity":        func(r *ReferenceContext) { r.Severity = Severity(11) },
		"missing caveat":          func(r *ReferenceContext) { r.Caveat = "" },
		"attribution is optional": func(r *ReferenceContext) { r.Attribution = "" },
	}
	for name, mutate := range cases {
		reference := validReference()
		mutate(reference)
		err := reference.Validate()
		if name == "attribution is optional" {
			if err != nil {
				t.Errorf("%s: Validate returned %v, want no error", name, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: Validate returned no error, want error", name)
		}
	}
}

func TestFindingValidateRejectsInvalidReferenceContext(t *testing.T) {
	finding := validFinding().WithReference(&ReferenceContext{Source: "gtfobins-curated"})
	if err := finding.Validate(); err == nil {
		t.Fatal("Validate accepted a finding carrying an incomplete reference context")
	} else if !strings.Contains(err.Error(), "reference context") {
		t.Errorf("error %q should identify the reference context", err)
	}
}

func TestFindingValidateAcceptsReferenceContext(t *testing.T) {
	finding := validFinding().WithReference(validReference())
	if err := finding.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
}

func TestFindingHasReference(t *testing.T) {
	if validFinding().HasReference() {
		t.Error("a finding without supplemental context reported a reference")
	}
	if !validFinding().WithReference(validReference()).HasReference() {
		t.Error("HasReference did not observe the attached context")
	}
}

func TestReferenceContextSerializesAsAStructuredField(t *testing.T) {
	data, err := json.Marshal(validFinding().WithReference(validReference()))
	if err != nil {
		t.Fatalf("marshalling failed: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decoding failed: %v", err)
	}
	reference, ok := decoded["reference"].(map[string]any)
	if !ok {
		t.Fatalf("finding JSON has no reference object: %s", data)
	}
	for _, key := range []string{"source", "binary", "category", "summary", "attribution", "severity", "caveat"} {
		if _, present := reference[key]; !present {
			t.Errorf("reference JSON is missing %q: %s", key, data)
		}
	}
	if reference["source"] != "gtfobins-curated" {
		t.Errorf("source = %v", reference["source"])
	}
	if reference["severity"] != "medium" {
		t.Errorf("severity = %v", reference["severity"])
	}
}

func TestReferenceContextIsOmittedWhenUnset(t *testing.T) {
	data, err := json.Marshal(validFinding())
	if err != nil {
		t.Fatalf("marshalling failed: %v", err)
	}
	if strings.Contains(string(data), "reference") {
		t.Errorf("unset reference context leaked into JSON: %s", data)
	}
}

func TestReferenceContextRoundTripsThroughJSON(t *testing.T) {
	original := validFinding().WithReference(validReference())
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshalling failed: %v", err)
	}
	var decoded Finding
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshalling failed: %v", err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatalf("decoded finding is invalid: %v", err)
	}
	if decoded.Reference == nil {
		t.Fatal("the reference context did not survive the round trip")
	}
	if *decoded.Reference != *original.Reference {
		t.Errorf("reference context changed:\n got: %+v\nwant: %+v", decoded.Reference, original.Reference)
	}
	if !decoded.DetectedAt.Equal(original.DetectedAt) {
		t.Errorf("decoded timestamp = %v, want %v", decoded.DetectedAt, original.DetectedAt)
	}
}

func TestReferenceContextDoesNotDisturbTheOriginalDetection(t *testing.T) {
	plain := validFinding()
	enriched := plain.WithReference(validReference())

	if enriched.ID != plain.ID || enriched.RuleID != plain.RuleID {
		t.Error("identity changed when supplemental context was attached")
	}
	if enriched.Severity != plain.Severity {
		t.Errorf("severity changed: %v then %v", plain.Severity, enriched.Severity)
	}
	if enriched.Path != plain.Path {
		t.Errorf("path changed: %q then %q", plain.Path, enriched.Path)
	}
	if enriched.PermissionString() != plain.PermissionString() {
		t.Errorf("mode changed: %q then %q", plain.PermissionString(), enriched.PermissionString())
	}
	if !enriched.DetectedAt.Equal(plain.DetectedAt) {
		t.Error("timestamp changed")
	}
	if plain.Reference != nil {
		t.Error("WithReference mutated the receiver")
	}
}

func TestReferenceContextSourceIsNotHardCoded(t *testing.T) {
	reference := validReference()
	reference.Source = "vendor-catalog"
	if err := reference.Validate(); err != nil {
		t.Errorf("an alternative reference source was rejected: %v", err)
	}
}

func TestFindingWithReferenceAcceptsNil(t *testing.T) {
	finding := validFinding().WithReference(validReference()).WithReference(nil)
	if finding.HasReference() {
		t.Error("WithReference(nil) left a reference attached")
	}
	if err := finding.Validate(); err != nil {
		t.Errorf("Validate returned error for a cleared reference: %v", err)
	}
}
