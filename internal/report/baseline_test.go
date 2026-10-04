package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"lisa/internal/baseline"
	"lisa/internal/detectors"
	"lisa/internal/model"
	"lisa/internal/scan"
)

var baselineTime = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

func testResult() *scan.Result {
	mode := uint32(0o4755)
	now := baselineTime
	return &scan.Result{
		Status: scan.StatusComplete,
		Roots:  []string{"/srv"},
		Findings: []model.Finding{
			{
				ID: model.FindingID("LS-SUID-001", "/usr/bin/su"), RuleID: "LS-SUID-001",
				Title: "SUID binary", Severity: model.SeverityMedium, Confidence: model.ConfidenceMedium,
				Category: model.CategoryPermissions, Path: "/usr/bin/su", Mode: &mode, DetectedAt: now,
			},
			{
				ID: model.FindingID("LS-PERM-001", "/etc/shadow"), RuleID: "LS-PERM-001",
				Title: "World writable file", Severity: model.SeverityMedium, Confidence: model.ConfidenceMedium,
				Category: model.CategoryPermissions, Path: "/etc/shadow", DetectedAt: now,
			},
			{
				ID: model.FindingID("LS-PERM-001", "/etc/passwd"), RuleID: "LS-PERM-001",
				Title: "World writable file", Severity: model.SeverityMedium, Confidence: model.ConfidenceMedium,
				Category: model.CategoryPermissions, Path: "/etc/passwd", DetectedAt: now,
			},
		},
		MinSeverity: model.SeverityInfo,
		StartedAt:   now,
		FinishedAt:  now,
		Detectors:   detectors.Stats{Selected: detectors.DefaultRegistry().Names()},
	}
}

func newFileFinding(path string) model.Finding {
	return model.Finding{
		ID: model.FindingID("LS-PERM-001", path), RuleID: "LS-PERM-001",
		Title: "World writable file", Severity: model.SeverityMedium, Confidence: model.ConfidenceMedium,
		Category: model.CategoryPermissions, Path: path, DetectedAt: baselineTime,
	}
}

func cleanComparison(t *testing.T) (BaselineDocument, error) {
	t.Helper()
	document, err := baseline.Create(testResult(), baseline.CreateOptions{
		Tool:        baseline.Tool{Name: "lisa", Version: "0.1.0"},
		MinSeverity: model.SeverityInfo,
		CreatedAt:   baselineTime,
	})
	if err != nil {
		return BaselineDocument{}, err
	}
	comparison, err := baseline.Compare(document, testResult().Findings, baseline.CompareOptions{
		Current:            baseline.CurrentScanOf(testResult()),
		CurrentMinSeverity: model.SeverityInfo,
		ComparedAt:         baselineTime,
		IncludeUnchanged:   true,
	})
	if err != nil {
		return BaselineDocument{}, err
	}
	return BuildBaseline(comparison)
}

func testComparison(t *testing.T) *baseline.Comparison {
	t.Helper()
	document, err := baseline.Create(testResult(), baseline.CreateOptions{
		Tool:        baseline.Tool{Name: "lisa", Version: "0.1.0"},
		MinSeverity: model.SeverityInfo,
		CreatedAt:   baselineTime,
	})
	if err != nil {
		t.Fatalf("baseline.Create: %v", err)
	}

	current := append([]model.Finding(nil), testResult().Findings[:1]...)
	current = append(current, newFileFinding("/etc/newfile"))

	comparison, err := baseline.Compare(document, current, baseline.CompareOptions{
		BaselinePath:       "/tmp/baseline.json",
		Current:            baseline.CurrentScanOf(testResult()),
		CurrentMinSeverity: model.SeverityInfo,
		ComparedAt:         baselineTime,
	})
	if err != nil {
		t.Fatalf("baseline.Compare: %v", err)
	}
	return comparison
}

func TestBuildBaselineRejectsNothing(t *testing.T) {
	if _, err := BuildBaseline(nil); err == nil {
		t.Error("BuildBaseline accepted a nil comparison")
	}
}

func TestBaselineJSONShape(t *testing.T) {
	document, err := BuildBaseline(testComparison(t))
	if err != nil {
		t.Fatalf("BuildBaseline: %v", err)
	}

	var buffer bytes.Buffer
	if err := WriteBaselineJSON(&buffer, document); err != nil {
		t.Fatalf("WriteBaselineJSON: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(buffer.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	for _, field := range []string{"schema", "baseline", "scan", "summary", "reliability", "changes", "unchanged"} {
		if _, ok := decoded[field]; !ok {
			t.Errorf("output is missing the %q field", field)
		}
	}
	if decoded["schema"] != BaselineSchema {
		t.Errorf("schema = %v, want %q", decoded["schema"], BaselineSchema)
	}
}

func TestBaselineJSONOmitsUnchangedFindings(t *testing.T) {
	document, err := BuildBaseline(testComparison(t))
	if err != nil {
		t.Fatalf("BuildBaseline: %v", err)
	}
	if document.Unchanged != 1 {
		t.Errorf("Unchanged = %d, want 1", document.Unchanged)
	}
	for _, change := range document.Changes {
		if change.Status == baseline.StatusUnchanged {
			t.Errorf("unchanged finding %s was listed in the report", change.Path)
		}
	}
	if len(document.Changes) != 3 {
		t.Fatalf("changes = %d, want one new and two resolved findings", len(document.Changes))
	}
	counts := map[baseline.Status]int{}
	for _, change := range document.Changes {
		counts[change.Status]++
	}
	if counts[baseline.StatusNew] != 1 || counts[baseline.StatusResolved] != 2 {
		t.Errorf("statuses = %v, want one new and two resolved", counts)
	}
}

func TestBaselineJSONAlwaysHasAnArray(t *testing.T) {
	document, err := cleanComparison(t)
	if err != nil {
		t.Fatalf("cleanComparison: %v", err)
	}

	var buffer bytes.Buffer
	if err := WriteBaselineJSON(&buffer, document); err != nil {
		t.Fatalf("WriteBaselineJSON: %v", err)
	}
	if !strings.Contains(buffer.String(), `"changes": []`) {
		t.Errorf("output %q should contain an empty array", buffer.String())
	}
}

func TestBaselineTextShowsTheOutcomes(t *testing.T) {
	document, err := BuildBaseline(testComparison(t))
	if err != nil {
		t.Fatalf("BuildBaseline: %v", err)
	}

	var buffer bytes.Buffer
	if err := WriteBaselineText(&buffer, document); err != nil {
		t.Fatalf("WriteBaselineText: %v", err)
	}
	rendered := buffer.String()

	for _, fragment := range []string{"CHANGES", "NEW", "RESOLVED", "/etc/shadow"} {
		if !strings.Contains(rendered, fragment) {
			t.Errorf("text report is missing %q:\n%s", fragment, rendered)
		}
	}
	if !strings.Contains(rendered, "does not prove") {
		t.Errorf("text report should qualify what resolved means:\n%s", rendered)
	}
}

func TestBaselineTextShowsTheReliabilityBlock(t *testing.T) {
	document, err := BuildBaseline(testComparison(t))
	if err != nil {
		t.Fatalf("BuildBaseline: %v", err)
	}
	document.Reliability = baseline.Reliability{
		Complete:              false,
		Reliable:              false,
		ResolutionsSuppressed: true,
		Reasons:               []string{"the current scan was cancelled before it finished"},
	}

	var buffer bytes.Buffer
	if err := WriteBaselineText(&buffer, document); err != nil {
		t.Fatalf("WriteBaselineText: %v", err)
	}
	rendered := buffer.String()
	if !strings.Contains(rendered, "RELIABILITY") {
		t.Errorf("text report is missing the reliability block:\n%s", rendered)
	}
	if !strings.Contains(rendered, "no finding is reported as resolved") {
		t.Errorf("text report should state that nothing was resolved:\n%s", rendered)
	}
}

func TestBaselineTextFlattensUntrustedValues(t *testing.T) {
	document, err := BuildBaseline(testComparison(t))
	if err != nil {
		t.Fatalf("BuildBaseline: %v", err)
	}
	document.Changes[0].Path = "/tmp/injected\n  RESOLVED  everything"
	document.Changes[0].Changes = []baseline.Change{
		{Attribute: "mode\ninjected", Baseline: "0644\r\nRESOLVED", Current: "0666"},
	}

	var buffer bytes.Buffer
	if err := WriteBaselineText(&buffer, document); err != nil {
		t.Fatalf("WriteBaselineText: %v", err)
	}
	rendered := buffer.String()

	lines := strings.Split(rendered, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "RESOLVED" {
			t.Errorf("a crafted value forged a report line:\n%s", rendered)
		}
	}
	if !strings.Contains(rendered, "injected") {
		t.Errorf("the value should survive in flattened form:\n%s", rendered)
	}
}

func TestBaselineTextHandlesACleanComparison(t *testing.T) {
	reported, err := cleanComparison(t)
	if err != nil {
		t.Fatalf("cleanComparison: %v", err)
	}
	var buffer bytes.Buffer
	if err := WriteBaselineText(&buffer, reported); err != nil {
		t.Fatalf("WriteBaselineText: %v", err)
	}
	if !strings.Contains(buffer.String(), "nothing changed") {
		t.Errorf("a clean comparison should say so:\n%s", buffer.String())
	}
	if strings.Contains(buffer.String(), "RELIABILITY") {
		t.Errorf("a clean comparison should not print a reliability block:\n%s", buffer.String())
	}
}
