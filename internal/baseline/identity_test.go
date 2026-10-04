package baseline

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"lisa/internal/detectors"
	"lisa/internal/model"
	"lisa/internal/scan"
)

var referenceTime = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

func testFinding(ruleID, path string) model.Finding {
	return model.Finding{
		ID:         model.FindingID(ruleID, path),
		RuleID:     ruleID,
		Title:      "test finding",
		Severity:   model.SeverityMedium,
		Confidence: model.ConfidenceMedium,
		Category:   model.CategoryPermissions,
		Path:       path,
		DetectedAt: referenceTime,
	}
}

func testDetectors() detectors.Stats {
	return detectors.Stats{Selected: detectors.DefaultRegistry().Names()}
}

func completeResult(paths ...string) *scan.Result {
	findings := make([]model.Finding, 0, len(paths))
	for _, path := range paths {
		findings = append(findings, testFinding("LS-PERM-001", path))
	}
	return &scan.Result{
		Status:      scan.StatusComplete,
		Findings:    findings,
		Roots:       []string{"/"},
		MinSeverity: model.SeverityInfo,
		StartedAt:   referenceTime,
		FinishedAt:  referenceTime,
		Detectors:   testDetectors(),
	}
}

func completeResultFor(ruleID string, paths ...string) *scan.Result {
	result := completeResult(paths...)
	for i := range result.Findings {
		result.Findings[i].RuleID = ruleID
		result.Findings[i].ID = model.FindingID(ruleID, result.Findings[i].Path)
	}
	return result
}

func testCreateOptions() CreateOptions {
	return CreateOptions{
		Tool:        Tool{Name: "lisa", Version: "0.1.0"},
		MinSeverity: model.SeverityInfo,
		CreatedAt:   referenceTime,
	}
}

func TestIdentityIDIsStableAndDistinct(t *testing.T) {
	first := IdentityID("LS-PERM-001", model.CategoryPermissions, "/etc/passwd")
	again := IdentityID("LS-PERM-001", model.CategoryPermissions, "/etc/passwd")
	if first != again {
		t.Fatalf("IdentityID is not deterministic: %q then %q", first, again)
	}
	if !strings.HasPrefix(first, "LS-PERM-001-") {
		t.Errorf("IdentityID = %q, want a rule id prefix for readability", first)
	}

	cases := []struct {
		name  string
		rule  string
		cat   model.Category
		path  string
		other string
	}{
		{"different rule", "LS-PERM-002", model.CategoryPermissions, "/etc/passwd", first},
		{"different category", "LS-PERM-001", model.CategoryOwnership, "/etc/passwd", first},
		{"different path", "LS-PERM-001", model.CategoryPermissions, "/etc/shadow", first},
	}
	for _, testCase := range cases {
		if got := IdentityID(testCase.rule, testCase.cat, testCase.path); got == testCase.other {
			t.Errorf("%s: identity collided with the reference identity", testCase.name)
		}
	}
}

func TestIdentityIDIsFieldSeparated(t *testing.T) {
	left := IdentityID("a", model.CategoryPermissions, "bc")
	right := IdentityID("ab", model.CategoryPermissions, "c")
	if left == right {
		t.Error("identities differing only in a field boundary collided")
	}
}

func TestIdentityOfUsesTheRecordedCategory(t *testing.T) {
	finding := testFinding("LS-PRIV-001", "/usr/bin/su")
	finding.Category = model.Category("not-a-category")

	if got := IdentityOf(finding).Category; got != model.Category("not-a-category") {
		t.Errorf("IdentityOf category = %q, want the recorded value passed through", got)
	}

	result := completeResult()
	result.Findings = []model.Finding{finding}
	if _, err := Create(result, testCreateOptions()); err == nil {
		t.Error("Create accepted a finding with an unknown category")
	}
}

func TestEntryOfKeepsOnlyComparableAttributes(t *testing.T) {
	mode := uint32(0o4755)
	finding := testFinding("LS-SUID-001", "/usr/bin/su").
		WithOwner("root").
		WithGroup("root").
		WithMode(mode).
		WithDescription("a long description").
		WithEvidence("mode=04755", "owner=root").
		WithRemediation("chmod u-s").
		WithReference(&model.ReferenceContext{
			Source:      "gtfobins-curated",
			Binary:      "su",
			Category:    "GTFOBins SUID",
			Summary:     strings.Repeat("x", maxSummaryLength+50),
			Severity:    model.SeverityHigh,
			Attribution: "https://gtfobins.github.io/",
			Caveat:      "Presence of the bit is not evidence of exploitation.",
		})

	entry := EntryOf(finding)
	if entry.Mode != "4755" {
		t.Errorf("Mode = %q, want 4755", entry.Mode)
	}
	if entry.Owner != "root" || entry.Group != "root" {
		t.Errorf("Owner/Group = %q/%q, want root/root", entry.Owner, entry.Group)
	}
	if entry.Reference == nil {
		t.Fatal("Reference = nil, want the supplemental context")
	}
	if len(entry.Reference.Summary) != maxSummaryLength {
		t.Errorf("Summary length = %d, want it truncated to %d", len(entry.Reference.Summary), maxSummaryLength)
	}

	encoded, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	rendered := string(encoded)
	for _, forbidden := range []string{"a long description", "chmod u-s", "owner=root"} {
		if strings.Contains(rendered, forbidden) {
			t.Errorf("entry JSON contains %q, which must not be stored", forbidden)
		}
	}
}

func TestEntryValidateRejectsInconsistentRecords(t *testing.T) {
	valid := EntryOf(testFinding("LS-PERM-001", "/etc/passwd"))

	cases := []struct {
		name    string
		mutate  func(*Entry)
		mustErr string
	}{
		{"empty rule id", func(e *Entry) { e.RuleID = ""; e.ID = "" }, "rule_id is required"},
		{"unknown category", func(e *Entry) { e.Category = "nope" }, "unknown category"},
		{"relative path", func(e *Entry) { e.Path = "etc/passwd" }, "must be absolute"},
		{"empty path", func(e *Entry) { e.Path = "" }, "path is required"},
		{"control character in path", func(e *Entry) { e.Path = "/etc/\npasswd" }, "control characters"},
		{"invalid severity", func(e *Entry) { e.Severity = model.Severity(99) }, "invalid severity"},
		{"invalid confidence", func(e *Entry) { e.Confidence = model.Confidence(99) }, "invalid confidence"},
		{"non octal mode", func(e *Entry) { e.Mode = "rwxr-xr-x" }, "must be octal"},
		{"mismatched identifier", func(e *Entry) { e.ID = "LS-PERM-001-deadbeefdeadbeef" }, "does not match its identity"},
		{"reference without source", func(e *Entry) {
			e.Reference = &Reference{Binary: "su", Category: "GTFOBins SUID", Severity: model.SeverityHigh}
		}, "requires a source"},
		{"reference without binary", func(e *Entry) {
			e.Reference = &Reference{Source: "gtfobins-curated", Category: "GTFOBins SUID", Severity: model.SeverityHigh}
		}, "requires a binary"},
		{"reference with invalid severity", func(e *Entry) {
			e.Reference = &Reference{Source: "gtfobins-curated", Binary: "su", Category: "GTFOBins SUID", Severity: 42}
		}, "invalid severity"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			entry := valid
			testCase.mutate(&entry)
			err := entry.Validate(3)
			if err == nil {
				t.Fatalf("Validate accepted a %s record", testCase.name)
			}
			if !strings.Contains(err.Error(), testCase.mustErr) {
				t.Errorf("Validate error = %q, want it to mention %q", err, testCase.mustErr)
			}
		})
	}

	if err := valid.Validate(0); err != nil {
		t.Errorf("Validate rejected a well formed entry: %v", err)
	}
}

func TestCreateNamesTheOffendingFinding(t *testing.T) {
	result := completeResult("/etc/passwd", "/etc/group")
	result.Findings = append(result.Findings, result.Findings[0])
	result.Findings[2].RuleID = ""

	_, err := Create(result, testCreateOptions())
	if err == nil {
		t.Fatal("Create accepted a finding without a rule identifier")
	}
	if !strings.Contains(err.Error(), "entry 2") {
		t.Errorf("Create error = %q, want it to name the position of the bad record", err)
	}
}

func TestCreateRequiresItsInputs(t *testing.T) {
	if _, err := Create(nil, testCreateOptions()); err == nil {
		t.Error("Create accepted a nil result")
	}
	if _, err := Create(completeResult("/etc/passwd"), CreateOptions{}); err == nil {
		t.Error("Create accepted options without a tool name")
	}
	if _, err := Create(completeResult("/etc/passwd"), CreateOptions{
		Tool: Tool{Name: "lisa"}, MinSeverity: model.Severity(99), CreatedAt: referenceTime,
	}); err == nil {
		t.Error("Create accepted an invalid minimum severity")
	}
	if _, err := Create(completeResult("/etc/passwd"), CreateOptions{
		Tool: Tool{Name: "lisa"}, MinSeverity: model.SeverityInfo,
	}); err == nil {
		t.Error("Create accepted a zero timestamp")
	}
}

func TestCreateIsDeterministic(t *testing.T) {
	first, err := Create(completeResult("/etc/shadow", "/etc/passwd", "/usr/bin/su"), testCreateOptions())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	second, err := Create(completeResult("/etc/passwd", "/usr/bin/su", "/etc/shadow"), testCreateOptions())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	firstBytes, err := first.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	secondBytes, err := second.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(firstBytes) != string(secondBytes) {
		t.Error("two creations over the same findings produced different bytes")
	}
	if !strings.HasSuffix(string(firstBytes), "\n") {
		t.Error("Marshal did not end with a newline")
	}
}

func TestCreateRejectsFindingsThatCannotBeRecorded(t *testing.T) {
	result := completeResult()
	result.Findings = []model.Finding{{RuleID: "LS-PERM-001", Path: "relative/path", DetectedAt: referenceTime}}
	if _, err := Create(result, testCreateOptions()); err == nil {
		t.Error("Create accepted a finding with a relative path")
	}
}

func TestCreateCollapsesIdenticalDuplicates(t *testing.T) {
	result := completeResult()
	finding := testFinding("LS-PERM-001", "/etc/passwd")
	result.Findings = []model.Finding{finding, finding, finding}

	document, err := Create(result, testCreateOptions())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(document.Findings) != 1 {
		t.Errorf("recorded %d entries, want 1", len(document.Findings))
	}
	if document.Summary.Duplicates != 2 {
		t.Errorf("Summary.Duplicates = %d, want 2", document.Summary.Duplicates)
	}
}

func TestCreateRejectsConflictingDuplicates(t *testing.T) {
	result := completeResult()
	first := testFinding("LS-PERM-001", "/etc/passwd")
	second := first.WithSeverity(model.SeverityHigh)
	result.Findings = []model.Finding{first, second}

	_, err := Create(result, testCreateOptions())
	if err == nil {
		t.Fatal("Create accepted conflicting duplicates")
	}
	if !strings.Contains(err.Error(), "ambiguous baseline identity") {
		t.Errorf("error = %q, want it to report an ambiguous identity", err)
	}
}

func TestCreateRecordsCoverage(t *testing.T) {
	result := completeResult("/etc/passwd")
	result.Status = scan.StatusPartial
	result.Files.Inaccessible = []string{"/root", "/etc/ssl/private"}
	result.Files.PermissionDenied = 2
	result.Detectors.DetectorFailures = map[string]int64{"suid": 3}
	result.Files.EntryLimitHit = true

	document, err := Create(result, testCreateOptions())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	coverage := document.Coverage
	if coverage.Complete {
		t.Error("Coverage.Complete = true for a partial scan")
	}
	if coverage.ScanStatus != "partial" {
		t.Errorf("Coverage.ScanStatus = %q, want partial", coverage.ScanStatus)
	}
	if coverage.LimitsReached != true {
		t.Error("Coverage.LimitsReached = false with the entry limit hit")
	}
	if len(coverage.FailedDetectors) != 1 || coverage.FailedDetectors[0] != "suid" {
		t.Errorf("Coverage.FailedDetectors = %v, want [suid]", coverage.FailedDetectors)
	}
	if len(coverage.Notes) == 0 {
		t.Error("Coverage.Notes is empty for an incomplete baseline")
	}
}

func TestSummarisesBySeverity(t *testing.T) {
	result := completeResult()
	high := testFinding("LS-PERM-001", "/etc/passwd").WithSeverity(model.SeverityHigh)
	low := testFinding("LS-PERM-002", "/etc/group").WithSeverity(model.SeverityLow)
	result.Findings = []model.Finding{high, low, high}

	document, err := Create(result, testCreateOptions())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if document.Summary.BySeverity["high"] != 1 {
		t.Errorf("high count = %d, want 1", document.Summary.BySeverity["high"])
	}
	if document.Summary.BySeverity["low"] != 1 {
		t.Errorf("low count = %d, want 1", document.Summary.BySeverity["low"])
	}
	if document.Summary.BySeverity["critical"] != 0 {
		t.Errorf("critical count = %d, want 0 recorded rather than omitted", document.Summary.BySeverity["critical"])
	}
}

func TestDigestTracksComparedAttributesOnly(t *testing.T) {
	result := completeResult("/etc/passwd")
	document, err := Create(result, testCreateOptions())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	before := document.Digest()

	document.Findings[0].Title = "a rewritten title"
	if document.Digest() != before {
		t.Error("Digest changed when only the descriptive title changed")
	}

	document.Findings[0].Severity = model.SeverityCritical
	if document.Digest() == before {
		t.Error("Digest did not change when severity changed")
	}
}
