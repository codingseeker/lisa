package baseline

import (
	"strings"
	"testing"

	"lisa/internal/model"
	"lisa/internal/scan"
)

func completeCurrent() CurrentScan {
	return CurrentScan{
		Status:      scan.StatusComplete,
		MinSeverity: model.SeverityInfo,
		Detectors:   detectorsNames(),
	}
}

func detectorsNames() []string {
	return allDetectorNames()
}

func compare(t *testing.T, document *Document, findings []model.Finding, current CurrentScan) *Comparison {
	t.Helper()
	result, err := Compare(document, findings, CompareOptions{
		BaselinePath:       "/tmp/baseline.json",
		Current:            current,
		CurrentMinSeverity: model.SeverityInfo,
		ComparedAt:         referenceTime,
	})
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	return result
}

func baselineFor(t *testing.T, ruleID string, paths ...string) *Document {
	t.Helper()
	document, err := Create(completeResultFor(ruleID, paths...), testCreateOptions())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return document
}

func compareAll(t *testing.T, document *Document, findings []model.Finding, current CurrentScan) *Comparison {
	t.Helper()
	result, err := Compare(document, findings, CompareOptions{
		BaselinePath:       "/tmp/baseline.json",
		Current:            current,
		CurrentMinSeverity: model.SeverityInfo,
		ComparedAt:         referenceTime,
		IncludeUnchanged:   true,
	})
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	return result
}

func statusesOf(comparison *Comparison) map[string]Status {
	out := make(map[string]Status, len(comparison.Items))
	for _, item := range comparison.Items {
		out[item.RuleID+" "+item.Path] = item.Status
	}
	return out
}

func TestCompareClassifiesEveryOutcome(t *testing.T) {
	document := mustCreate(t, "/etc/passwd", "/etc/shadow", "/usr/bin/su")

	suid := testFinding("LS-SUID-001", "/usr/bin/su").WithMode(0o4755)
	changed := testFinding("LS-PERM-001", "/etc/shadow").WithSeverity(model.SeverityHigh)
	unchanged := testFinding("LS-PERM-001", "/etc/passwd")

	comparison := compareAll(t, document, []model.Finding{suid, changed, unchanged}, completeCurrent())

	got := statusesOf(comparison)
	want := map[string]Status{
		"LS-PERM-001 /etc/shadow": StatusChanged,
		"LS-PERM-001 /etc/passwd": StatusUnchanged,
		"LS-PERM-001 /usr/bin/su": StatusResolved,
		"LS-SUID-001 /usr/bin/su": StatusNew,
	}
	for key, status := range want {
		if got[key] != status {
			t.Errorf("%s = %q, want %q", key, got[key], status)
		}
	}
	if comparison.Counts.New != 1 || comparison.Counts.Changed != 1 ||
		comparison.Counts.Unchanged != 1 || comparison.Counts.Resolved != 1 {
		t.Errorf("counts = %+v, want one of each outcome", comparison.Counts)
	}
	if comparison.Counts.ChangeCount != 2 {
		t.Errorf("ChangeCount = %d, want 2", comparison.Counts.ChangeCount)
	}
}

func TestCompareDetectsResolution(t *testing.T) {
	document := mustCreate(t, "/etc/passwd", "/etc/shadow")

	comparison := compareAll(t, document,
		[]model.Finding{testFinding("LS-PERM-001", "/etc/passwd")}, completeCurrent())

	if len(comparison.Items) != 2 {
		t.Fatalf("items = %d, want 2", len(comparison.Items))
	}
	resolved := comparison.Items[0]
	if resolved.Status != StatusResolved || resolved.Path != "/etc/shadow" {
		t.Errorf("items[0] = %s %q, want /etc/shadow resolved", resolved.Status, resolved.Path)
	}
	if resolved.Current != nil {
		t.Error("a resolved item must not carry a current entry")
	}
	if resolved.Baseline == nil {
		t.Error("a resolved item must carry the baseline entry so it can be explained")
	}
	if comparison.Counts.Resolved != 1 {
		t.Errorf("resolved count = %d, want 1", comparison.Counts.Resolved)
	}
}

func TestCompareReportsADatasetUpdateAsChanged(t *testing.T) {
	document := baselineFor(t, "LS-SUID-001", "/etc/passwd")
	document.Findings[0].Reference = &Reference{
		Source:   "gtfobins-curated",
		Binary:   "su",
		Category: "GTFOBins SUID",
		Summary:  "an older description",
		Severity: model.SeverityHigh,
	}

	finding := testFinding("LS-SUID-001", "/etc/passwd").WithReference(&model.ReferenceContext{
		Source:   "gtfobins-curated",
		Binary:   "su",
		Category: "GTFOBins SUID",
		Summary:  "a rewritten description",
		Severity: model.SeverityCritical,
		Caveat:   "presence is not evidence of exploitation",
	})

	comparison := compare(t, document, []model.Finding{finding}, completeCurrent())

	if len(comparison.Items) != 1 {
		t.Fatalf("items = %d, want 1; a dataset change must not create a second finding", len(comparison.Items))
	}
	item := comparison.Items[0]
	if item.Status != StatusChanged {
		t.Fatalf("status = %q, want changed", item.Status)
	}
	changed := map[string]Change{}
	for _, change := range item.Changes {
		changed[change.Attribute] = change
	}
	summary, ok := changed["reference.summary"]
	if !ok {
		t.Fatal("the changed summary was not reported")
	}
	if summary.Baseline != "an older description" || summary.Current != "a rewritten description" {
		t.Errorf("summary change = %+v, want both the old and the new text", summary)
	}
	if _, ok := changed["reference.severity"]; !ok {
		t.Error("the changed reference severity was not reported")
	}
}

func TestCompareReportsEachKindOfAttributeChange(t *testing.T) {
	document := baselineFor(t, "LS-SUID-001", "/etc/passwd")

	finding := testFinding("LS-SUID-001", "/etc/passwd").
		WithSeverity(model.SeverityCritical).
		WithMode(0o4755).
		WithOwner("root").
		WithGroup("shadow")
	finding.Confidence = model.ConfidenceHigh

	comparison := compare(t, document, []model.Finding{finding}, completeCurrent())
	if len(comparison.Items) != 1 || comparison.Items[0].Status != StatusChanged {
		t.Fatalf("items = %+v, want a single changed item", comparison.Items)
	}

	got := map[string]Change{}
	for _, change := range comparison.Items[0].Changes {
		got[change.Attribute] = change
	}
	for _, attribute := range []string{"severity", "confidence", "mode", "owner", "group"} {
		if _, ok := got[attribute]; !ok {
			t.Errorf("%s was not reported as changed", attribute)
		}
	}
	if got["mode"].Baseline != "" || got["mode"].Current != "4755" {
		t.Errorf("mode change = %+v, want an addition from empty", got["mode"])
	}
}

func TestCompareIgnoresDescriptiveTitleChanges(t *testing.T) {
	document := mustCreate(t, "/etc/passwd")

	finding := testFinding("LS-PERM-001", "/etc/passwd")
	finding.Title = "a completely different title"

	comparison := compareAll(t, document, []model.Finding{finding}, completeCurrent())
	if len(comparison.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(comparison.Items))
	}
	if comparison.Items[0].Status != StatusUnchanged {
		t.Errorf("status = %q, want unchanged", comparison.Items[0].Status)
	}
}

func TestCompareExcludesUnchangedUnlessAsked(t *testing.T) {
	document := mustCreate(t, "/etc/passwd", "/etc/shadow")

	findings := []model.Finding{
		testFinding("LS-PERM-001", "/etc/passwd"),
		testFinding("LS-PERM-001", "/etc/shadow").WithSeverity(model.SeverityHigh),
	}

	without, err := Compare(document, findings, CompareOptions{
		Current: completeCurrent(), CurrentMinSeverity: model.SeverityInfo, ComparedAt: referenceTime,
	})
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if len(without.Items) != 1 {
		t.Errorf("items = %d, want unchanged findings excluded", len(without.Items))
	}
	if without.Counts.Unchanged != 1 {
		t.Errorf("unchanged count = %d, want it counted even when excluded", without.Counts.Unchanged)
	}

	with, err := Compare(document, findings, CompareOptions{
		Current: completeCurrent(), CurrentMinSeverity: model.SeverityInfo,
		ComparedAt: referenceTime, IncludeUnchanged: true,
	})
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if len(with.Items) != 2 {
		t.Errorf("items = %d, want unchanged findings included", len(with.Items))
	}
}

func TestCompareHandlesDuplicates(t *testing.T) {
	document := mustCreate(t, "/etc/passwd")
	entry := testFinding("LS-PERM-001", "/etc/passwd")

	comparison := compareAll(t, document, []model.Finding{entry, entry}, completeCurrent())
	if len(comparison.Items) != 1 {
		t.Errorf("items = %d, want identical duplicates collapsed to 1", len(comparison.Items))
	}
	if comparison.Duplicates != 1 {
		t.Errorf("Duplicates = %d, want 1", comparison.Duplicates)
	}

	conflicting := entry.WithSeverity(model.SeverityCritical)
	_, err := Compare(document, []model.Finding{entry, conflicting}, CompareOptions{
		Current: completeCurrent(), CurrentMinSeverity: model.SeverityInfo, ComparedAt: referenceTime,
	})
	if err == nil {
		t.Fatal("Compare accepted conflicting duplicates")
	}
	if !strings.Contains(err.Error(), "ambiguous baseline identity") {
		t.Errorf("error = %q, want it to report an ambiguous identity", err)
	}
}

func TestCompareIsDeterministic(t *testing.T) {
	document := mustCreate(t, "/etc/shadow", "/etc/passwd", "/usr/bin/su")
	findings := []model.Finding{
		testFinding("LS-SUID-001", "/usr/bin/su").WithMode(0o4755),
		testFinding("LS-PERM-001", "/etc/passwd"),
		testFinding("LS-PERM-001", "/etc/shadow").WithSeverity(model.SeverityHigh),
	}

	first := compare(t, document, findings, completeCurrent())
	shuffled := []model.Finding{findings[1], findings[2], findings[0]}
	second := compare(t, document, shuffled, completeCurrent())

	firstBytes, err := first.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	secondBytes, err := second.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(firstBytes) != string(secondBytes) {
		t.Error("comparison output depended on the order findings were supplied")
	}
}

func TestCompareOrdersItemsNewFirst(t *testing.T) {
	document := mustCreate(t, "/etc/passwd", "/etc/shadow")
	findings := []model.Finding{
		testFinding("LS-SUID-001", "/zzz/new"),
		testFinding("LS-PERM-001", "/etc/passwd"),
		testFinding("LS-PERM-001", "/etc/shadow").WithSeverity(model.SeverityHigh),
	}

	comparison := compareAll(t, document, findings, completeCurrent())
	want := []Status{StatusNew, StatusChanged, StatusUnchanged}
	if len(comparison.Items) != len(want) {
		t.Fatalf("items = %d, want %d", len(comparison.Items), len(want))
	}
	for index, status := range want {
		if comparison.Items[index].Status != status {
			t.Errorf("items[%d].Status = %q, want %q", index, comparison.Items[index].Status, status)
		}
	}
}

func TestCompareRequiresItsInputs(t *testing.T) {
	document := mustCreate(t, "/etc/passwd")

	if _, err := Compare(nil, nil, CompareOptions{ComparedAt: referenceTime}); err == nil {
		t.Error("Compare accepted a nil document")
	}
	if _, err := Compare(document, nil, CompareOptions{Current: completeCurrent()}); err == nil {
		t.Error("Compare accepted a zero timestamp")
	}
	invalid := mustCreate(t, "/etc/passwd")
	invalid.Findings[0].Path = "/etc/tampered"
	if _, err := Compare(invalid, nil, CompareOptions{
		Current: completeCurrent(), CurrentMinSeverity: model.SeverityInfo, ComparedAt: referenceTime,
	}); err == nil {
		t.Error("Compare accepted an invalid document")
	}
}

func TestChangesHelperFiltersAndOrders(t *testing.T) {
	document := mustCreate(t, "/etc/passwd", "/etc/shadow")
	comparison := compare(t, document, []model.Finding{
		testFinding("LS-PERM-001", "/etc/passwd"),
		testFinding("LS-SUID-001", "/zzz/new"),
	}, completeCurrent())

	changes := comparison.Changes()
	if len(changes) != 2 {
		t.Fatalf("Changes returned %d items, want 2", len(changes))
	}
	if changes[0].Status != StatusNew {
		t.Errorf("first change = %q, want new first", changes[0].Status)
	}
	for _, item := range changes {
		if item.Status == StatusUnchanged {
			t.Error("Changes returned an unchanged item")
		}
	}
}

func TestChangeString(t *testing.T) {
	cases := []struct {
		change Change
		want   string
	}{
		{Change{Attribute: "severity", Baseline: "low", Current: "high"}, "severity low -> high"},
		{Change{Attribute: "mode", Current: "4755"}, "mode added (4755)"},
		{Change{Attribute: "owner", Baseline: "root"}, "owner removed (was root)"},
	}
	for _, testCase := range cases {
		if got := testCase.change.String(); got != testCase.want {
			t.Errorf("String() = %q, want %q", got, testCase.want)
		}
	}
}
