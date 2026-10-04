package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func validFinding() Finding {
	finding := validRule().Finding("/tmp/payload")
	finding.Description = "File /tmp/payload is world-writable."
	finding.DetectedAt = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	finding = finding.
		WithEvidence("mode 0666", "owner root:root").
		WithOwner("root").
		WithGroup("root").
		WithMode(0o666)
	return finding
}

func TestFindingIDIsDeterministic(t *testing.T) {
	first := FindingID("LS-PERM-001", "/tmp/payload")
	second := FindingID("LS-PERM-001", "/tmp/payload")
	if first != second {
		t.Errorf("FindingID is not deterministic: %q != %q", first, second)
	}
	if !strings.HasPrefix(first, "LS-PERM-001-") {
		t.Errorf("FindingID %q should be prefixed with the rule id", first)
	}
}

func TestFindingIDSeparatesRuleFromPath(t *testing.T) {
	samePathOtherRule := FindingID("LS-PERM-002", "/tmp/payload")
	sameRuleOtherPath := FindingID("LS-PERM-001", "/tmp/other")
	if samePathOtherRule == sameRuleOtherPath {
		t.Fatal("rule id and path must both contribute to the finding id")
	}
	if FindingID("LS-PERM-001", "/tmp/payload") == FindingID("LS-PERM-001", "/tmp/other") {
		t.Error("different paths must produce different finding ids")
	}
}

func TestFindingIDHandlesPathBoundary(t *testing.T) {
	if FindingID("R", "/a") == FindingID("R", "/a/b") {
		t.Error("finding ids must not collide across path boundaries")
	}
	if FindingID("R", "ab") == FindingID("R", "a/b") {
		t.Error("finding ids must not collide when rule and path concatenate ambiguously")
	}
}

func TestFindingValidateAcceptsCompleteFinding(t *testing.T) {
	if err := validFinding().Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
}

func TestFindingValidateRejectsIncompleteFinding(t *testing.T) {
	cases := map[string]func(*Finding){
		"missing id":          func(f *Finding) { f.ID = "" },
		"missing rule id":     func(f *Finding) { f.RuleID = "" },
		"missing title":       func(f *Finding) { f.Title = "" },
		"invalid severity":    func(f *Finding) { f.Severity = Severity(11) },
		"invalid confidence":  func(f *Finding) { f.Confidence = Confidence(11) },
		"unknown category":    func(f *Finding) { f.Category = "nope" },
		"missing path":        func(f *Finding) { f.Path = "" },
		"missing timestamp":   func(f *Finding) { f.DetectedAt = time.Time{} },
		"malformed technique": func(f *Finding) { f.Technique = &Technique{ID: "T99", Name: "Bad"} },
	}
	for name, mutate := range cases {
		finding := validFinding()
		mutate(&finding)
		if err := finding.Validate(); err == nil {
			t.Errorf("%s: Validate returned no error, want error", name)
		}
	}
}

func TestFindingBuildersDoNotMutateReceiver(t *testing.T) {
	base := validFinding()
	derived := base.
		WithDescription("other").
		WithEvidence("extra").
		WithOwner("nobody").
		WithGroup("nogroup").
		WithMode(0o600).
		WithRemediation("other").
		WithRelated("LS-OTHER-1")

	if base.Description == derived.Description {
		t.Error("WithDescription mutated the receiver")
	}
	if len(base.Evidence) != len(derived.Evidence)-1 {
		t.Error("WithEvidence mutated the receiver")
	}
	if base.OwnerName() != "root" {
		t.Error("WithOwner mutated the receiver")
	}
	if base.GroupName() != "root" {
		t.Error("WithGroup mutated the receiver")
	}
	if base.PermissionString() != "0666" {
		t.Error("WithMode mutated the receiver")
	}
	if base.Remediation == derived.Remediation {
		t.Error("WithRemediation mutated the receiver")
	}
	if len(base.RelatedIDs) != 0 {
		t.Error("WithRelated mutated the receiver")
	}
}

func TestFindingWithModeMasksToPermissionBits(t *testing.T) {
	finding := validFinding().WithMode(0o104755)
	if got := finding.PermissionString(); got != "4755" {
		t.Errorf("PermissionString() = %q, want %q", got, "4755")
	}
	if got := validFinding().WithMode(0o2000).PermissionString(); got != "2000" {
		t.Errorf("sticky bit mode rendered as %q, want %q", got, "2000")
	}
}

func TestFindingOptionalFieldsAreEmptyByDefault(t *testing.T) {
	finding := validRule().Finding("/tmp/payload")
	finding.DetectedAt = time.Now()
	if finding.Mode != nil || finding.Owner != nil || finding.Group != nil {
		t.Error("optional file metadata must stay unset when not populated")
	}
	if finding.PermissionString() != "" {
		t.Error("PermissionString must be empty when mode is unset")
	}
	if finding.OwnerName() != "" || finding.GroupName() != "" {
		t.Error("owner and group accessors must be empty when unset")
	}
}

func TestFindingJSONShapeIsStable(t *testing.T) {
	finding := validFinding()
	data, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("marshalling failed: %v", err)
	}
	want := `{"id":"LS-PERM-001-7226d56595f6","rule_id":"LS-PERM-001","title":"World-writable regular file",` +
		`"description":"File /tmp/payload is world-writable.","severity":"medium","confidence":"high",` +
		`"category":"permissions","path":"/tmp/payload","evidence":["mode 0666","owner root:root"],` +
		`"owner":"root","group":"root","mode":438,"detected_at":"2026-03-04T05:06:07Z",` +
		`"remediation":"Restrict the mode to 0644 or stricter."}`
	if string(data) != want {
		t.Errorf("unexpected JSON shape\n got: %s\nwant: %s", data, want)
	}
}

func TestFindingJSONOmitsUnsetOptionalFields(t *testing.T) {
	finding := validRule().Finding("/tmp/payload")
	finding.DetectedAt = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	data, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("marshalling failed: %v", err)
	}
	for _, unwanted := range []string{"evidence", "owner", "group", "mode", "technique", "related_ids"} {
		if strings.Contains(string(data), `"`+unwanted+`"`) {
			t.Errorf("JSON should omit unset field %q, got %s", unwanted, data)
		}
	}
}

func TestFindingJSONRoundTrip(t *testing.T) {
	data, err := json.Marshal(validFinding())
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
	if decoded.PermissionString() != "0666" {
		t.Errorf("decoded mode = %q, want %q", decoded.PermissionString(), "0666")
	}
	if !decoded.DetectedAt.Equal(validFinding().DetectedAt) {
		t.Errorf("decoded timestamp = %v, want %v", decoded.DetectedAt, validFinding().DetectedAt)
	}
}
