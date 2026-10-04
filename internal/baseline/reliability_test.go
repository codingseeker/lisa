package baseline

import (
	"strings"
	"testing"

	"lisa/internal/fsscan"
	"lisa/internal/model"
	"lisa/internal/scan"
)

func TestCancelledScanResolvesNothing(t *testing.T) {
	document := mustCreate(t, "/etc/passwd", "/etc/shadow")
	current := completeCurrent()
	current.Status = scan.StatusCancelled

	comparison := compare(t, document, nil, current)

	if comparison.Counts.Resolved != 0 {
		t.Errorf("resolved = %d for a cancelled scan, want 0", comparison.Counts.Resolved)
	}
	if comparison.Counts.Unverified != 2 {
		t.Errorf("unverified = %d, want both findings unverified", comparison.Counts.Unverified)
	}
	if comparison.Reliability.Reliable {
		t.Error("Reliability.Reliable = true for a cancelled scan")
	}
	assertReasonContains(t, comparison, "cancelled")
}

func TestUnreliableScanStillReportsNewAndChanged(t *testing.T) {
	document := mustCreate(t, "/etc/passwd")
	current := completeCurrent()
	current.Status = scan.StatusCancelled

	findings := []model.Finding{
		testFinding("LS-PERM-001", "/etc/passwd").WithSeverity(model.SeverityCritical),
		testFinding("LS-SUID-001", "/usr/bin/su"),
	}
	comparison := compareAll(t, document, findings, current)

	if comparison.Counts.New != 1 {
		t.Errorf("new = %d for a cancelled scan, want 1", comparison.Counts.New)
	}
	if comparison.Counts.Changed != 1 {
		t.Errorf("changed = %d for a cancelled scan, want 1", comparison.Counts.Changed)
	}
	if comparison.Counts.Resolved != 0 {
		t.Errorf("resolved = %d for a cancelled scan, want 0", comparison.Counts.Resolved)
	}
}

func TestPartialScanResolvesNothing(t *testing.T) {
	document := mustCreate(t, "/etc/passwd", "/etc/shadow")
	current := completeCurrent()
	current.Status = scan.StatusPartial

	comparison := compare(t, document, nil, current)

	if comparison.Counts.Resolved != 0 {
		t.Errorf("resolved = %d for a partial scan, want 0", comparison.Counts.Resolved)
	}
	assertReasonContains(t, comparison, "partially")
}

func TestTraversalLimitsSuppressResolution(t *testing.T) {
	cases := []struct {
		name  string
		apply func(*fsscan.Stats)
		want  string
	}{
		{"entry limit", func(s *fsscan.Stats) { s.EntryLimitHit = true }, "entry limit"},
		{"depth limit", func(s *fsscan.Stats) { s.DepthLimitHit = true }, "depth limit"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			document := mustCreate(t, "/etc/passwd", "/etc/shadow")
			current := completeCurrent()
			testCase.apply(&current.Files)

			comparison := compare(t, document, nil, current)
			if comparison.Counts.Resolved != 0 {
				t.Errorf("resolved = %d with the %s hit, want 0", comparison.Counts.Resolved, testCase.name)
			}
			assertReasonContains(t, comparison, testCase.want)
		})
	}
}

func TestUnreadablePathIsScopedToThatPath(t *testing.T) {
	document := mustCreate(t, "/etc/passwd", "/root/.ssh/authorized_keys", "/var/log/audit.log")
	current := completeCurrent()

	current.Files.Inaccessible = []string{"/root (permission denied)"}
	current.Files.Errors = 1
	current.Files.PermissionDenied = 1

	comparison := compareAll(t, document, nil, current)

	if comparison.Counts.Resolved != 2 {
		t.Errorf("resolved = %d, want the two findings outside the unreadable path", comparison.Counts.Resolved)
	}
	if comparison.Counts.Unverified != 1 {
		t.Errorf("unverified = %d, want only the finding under /root", comparison.Counts.Unverified)
	}
	if comparison.Reliability.Reliable != true {
		t.Error("Reliability.Reliable = false, want a scoped problem to leave resolutions trustworthy")
	}

	unverified := comparison.Items[0]
	if unverified.Status != StatusUnverified {
		t.Fatalf("items[0] = %q, want unverified", unverified.Status)
	}
	if unverified.Path != "/root/.ssh/authorized_keys" {
		t.Errorf("unverified finding is %q, want the one under the unreadable path", unverified.Path)
	}
	if !comparison.Reliability.ResolutionsSuppressed {
		t.Error("ResolutionsSuppressed = false, want it recorded")
	}
}

func TestUnreadablePathMatchingIsExactOrDescendant(t *testing.T) {
	document := mustCreate(t, "/srv/data/report", "/srv", "/srvdata/report")
	current := completeCurrent()
	current.Files.Inaccessible = []string{"/srv (permission denied)"}

	comparison := compareAll(t, document, nil, current)

	suppressed := map[string]Status{}
	for _, item := range comparison.Items {
		suppressed[item.Path] = item.Status
	}
	if suppressed["/srv"] != StatusUnverified {
		t.Errorf("/srv = %q, want unverified", suppressed["/srv"])
	}
	if suppressed["/srv/data/report"] != StatusUnverified {
		t.Errorf("/srv/data/report = %q, want unverified", suppressed["/srv/data/report"])
	}

	if suppressed["/srvdata/report"] != StatusResolved {
		t.Errorf("/srvdata/report = %q, want resolved", suppressed["/srvdata/report"])
	}
}

func TestTruncatedUnreadableListSuppressesResolutionGlobally(t *testing.T) {
	document := mustCreate(t, "/etc/passwd", "/etc/shadow")
	current := completeCurrent()
	current.Files.Inaccessible = []string{"/root (permission denied)"}
	current.Files.InaccessibleTruncated = true
	current.Files.Errors = 500
	current.Files.PermissionDenied = 500

	comparison := compare(t, document, nil, current)

	if comparison.Counts.Resolved != 0 {
		t.Errorf("resolved = %d with a truncated unreadable list, want 0", comparison.Counts.Resolved)
	}
	assertReasonContains(t, comparison, "stopped recording unreadable paths")
}

func TestFailedDetectorSuppressesResolution(t *testing.T) {
	document := mustCreate(t, "/etc/passwd", "/etc/shadow")
	current := completeCurrent()
	current.Failures = map[string]int64{"suid": 2}

	comparison := compare(t, document, nil, current)

	if comparison.Counts.Resolved != 0 {
		t.Errorf("resolved = %d with a failed detector, want 0", comparison.Counts.Resolved)
	}
	assertReasonContains(t, comparison, "detectors suid failed")
}

func TestRaisedSeverityThresholdSuppressesResolution(t *testing.T) {
	document := mustCreate(t, "/etc/passwd", "/etc/shadow")

	decision := Policy(document.Coverage, document.MinSeverity, document.GTFOBins,
		completeCurrent(), model.SeverityHigh, false)
	joined := strings.Join(decision.BlockingReasons, " | ")
	if !strings.Contains(joined, "would look resolved") {
		t.Errorf("reasons = %q, want a note about the raised threshold", joined)
	}

	decision = Policy(document.Coverage, document.MinSeverity, document.GTFOBins,
		completeCurrent(), model.SeverityInfo, false)
	for _, reason := range decision.BlockingReasons {
		if strings.Contains(reason, "would look resolved") {
			t.Errorf("reasons = %q, want no note when the threshold is unchanged", decision.BlockingReasons)
		}
	}

	raised := *document
	raised.MinSeverity = model.SeverityMedium.String()
	decision = Policy(raised.Coverage, raised.MinSeverity, raised.GTFOBins,
		completeCurrent(), model.SeverityInfo, false)
	for _, reason := range decision.BlockingReasons {
		if strings.Contains(reason, "would look resolved") {
			t.Errorf("reasons = %q, want no note when the threshold was lowered", decision.BlockingReasons)
		}
	}
}

func TestNarrowerDetectorSelectionSuppressesResolution(t *testing.T) {
	document := mustCreate(t, "/etc/passwd", "/etc/shadow")
	current := completeCurrent()
	current.Detectors = []string{"permissions"}

	comparison := compare(t, document, nil, current)

	if comparison.Counts.Resolved != 0 {
		t.Errorf("resolved = %d with a narrower detector selection, want 0", comparison.Counts.Resolved)
	}
	assertReasonContains(t, comparison, "did not run detectors")
}

func TestUnknownScanStatusSuppressesResolution(t *testing.T) {
	document := mustCreate(t, "/etc/passwd")
	current := completeCurrent()
	current.Status = scan.Status("sideways")

	comparison := compare(t, document, nil, current)
	if comparison.Counts.Resolved != 0 {
		t.Errorf("resolved = %d for an unknown scan status, want 0", comparison.Counts.Resolved)
	}
}

func TestIncompleteBaselineIsReported(t *testing.T) {
	document := mustCreate(t, "/etc/passwd")
	document.Coverage.ScanStatus = "partial"
	document.Coverage.Complete = false

	comparison := compare(t, document, nil, completeCurrent())

	assertReasonContains(t, comparison, "baseline was recorded from a scan that did not complete")
	if comparison.Counts.Resolved != 0 {
		t.Errorf("resolved = %d against an incomplete baseline, want 0", comparison.Counts.Resolved)
	}
}

func TestGtfobinsFlagMismatchIsAdvisory(t *testing.T) {
	document := mustCreate(t, "/etc/passwd", "/etc/shadow")
	decision := Policy(document.Coverage, document.MinSeverity, false,
		completeCurrent(), model.SeverityInfo, true)

	if len(decision.BlockingReasons) != 0 {
		t.Errorf("BlockingReasons = %q, want none: a flag mismatch must not suppress resolutions",
			decision.BlockingReasons)
	}
	joined := strings.Join(decision.AdvisoryReasons, " | ")
	if !strings.Contains(joined, "GTFOBins") {
		t.Errorf("AdvisoryReasons = %q, want a note about the flag differing", joined)
	}

	comparison, err := Compare(document, nil, CompareOptions{
		Current:            completeCurrent(),
		CurrentMinSeverity: model.SeverityInfo,
		CurrentGTFOBins:    true,
		ComparedAt:         referenceTime,
	})
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if !comparison.Reliability.Reliable {
		t.Error("Reliability.Reliable = false for an advisory mismatch only")
	}
	if comparison.Counts.Resolved != 2 {
		t.Errorf("resolved = %d, want both findings still resolved", comparison.Counts.Resolved)
	}
	if len(comparison.Reliability.Reasons) == 0 {
		t.Error("the advisory reason should still be reported")
	}
}

func TestMayResolve(t *testing.T) {
	document := mustCreate(t, "/etc/passwd", "/root/.ssh/id_rsa")
	current := completeCurrent()
	current.Files.Inaccessible = []string{"/root (permission denied)"}
	comparison := compareAll(t, document, nil, current)

	for _, item := range comparison.Items {
		want := item.Status == StatusResolved
		if got := comparison.Reliability.MayResolve(item.ID); got != want {
			t.Errorf("MayResolve(%s) = %v for a %q item, want %v", item.Path, got, item.Status, want)
		}
	}
}

func TestFilesystemErrorsSuppressResolution(t *testing.T) {
	document := mustCreate(t, "/etc/passwd")
	current := completeCurrent()
	current.Files.Errors = 3

	comparison := compare(t, document, nil, current)
	if comparison.Counts.Resolved != 0 {
		t.Errorf("resolved = %d with filesystem errors, want 0", comparison.Counts.Resolved)
	}
	assertReasonContains(t, comparison, "filesystem error")
}

func TestPolicyReasonsAreDeterministic(t *testing.T) {
	document := mustCreate(t, "/etc/passwd")
	current := completeCurrent()
	current.Status = scan.StatusPartial
	current.Files.EntryLimitHit = true
	current.Files.DepthLimitHit = true
	current.Failures = map[string]int64{"suid": 1, "world-writable": 2}

	first := strings.Join(Policy(document.Coverage, document.MinSeverity, document.GTFOBins,
		current, model.SeverityHigh, true).BlockingReasons, "\n")
	second := strings.Join(Policy(document.Coverage, document.MinSeverity, document.GTFOBins,
		current, model.SeverityHigh, true).BlockingReasons, "\n")

	if first != second {
		t.Errorf("reasons differed between runs:\n%s\n---\n%s", first, second)
	}
	if !strings.Contains(first, "suid, world-writable") {
		t.Errorf("failed detectors were not sorted: %q", first)
	}
}

func TestCleanScanHasNoReasons(t *testing.T) {
	document := mustCreate(t, "/etc/passwd")
	decision := Policy(document.Coverage, document.MinSeverity, document.GTFOBins,
		completeCurrent(), model.SeverityInfo, false)

	if len(decision.BlockingReasons) != 0 {
		t.Errorf("BlockingReasons = %q for a clean, matched pair of scans, want none", decision.BlockingReasons)
	}
	if len(decision.AdvisoryReasons) != 0 {
		t.Errorf("AdvisoryReasons = %q for a clean, matched pair of scans, want none", decision.AdvisoryReasons)
	}
	if len(decision.ScopedReasons) != 0 {
		t.Errorf("ScopedReasons = %+v, want none", decision.ScopedReasons)
	}

	comparison := compare(t, document, nil, completeCurrent())
	if !comparison.Reliability.Reliable {
		t.Error("Reliability.Reliable = false for a clean scan")
	}
	if len(comparison.Reliability.Reasons) != 0 {
		t.Errorf("Reasons = %q, want none", comparison.Reliability.Reasons)
	}
	if comparison.Reliability.ResolutionsSuppressed {
		t.Error("ResolutionsSuppressed = true for a clean scan")
	}
}

func assertReasonContains(t *testing.T, comparison *Comparison, fragment string) {
	t.Helper()
	for _, reason := range comparison.Reliability.Reasons {
		if strings.Contains(reason, fragment) {
			return
		}
	}
	t.Errorf("no reason mentions %q; reasons were %q", fragment, comparison.Reliability.Reasons)
}

func TestInaccessiblePathsAreStrippedOfTheirReason(t *testing.T) {
	document := mustCreate(t, "/root/.ssh/id_rsa", "/etc/passwd")
	current := completeCurrent()
	current.Files.Inaccessible = []string{
		"/root (permission denied)",
		"/var/lib (permission denied)",
	}
	current.Files.Errors = 2
	current.Files.PermissionDenied = 2

	comparison := compareAll(t, document, nil, current)

	suppressed := map[string]Status{}
	for _, item := range comparison.Items {
		suppressed[item.Path] = item.Status
	}
	if suppressed["/root/.ssh/id_rsa"] != StatusUnverified {
		t.Errorf("/root/.ssh/id_rsa = %q, want unverified", suppressed["/root/.ssh/id_rsa"])
	}
	if suppressed["/etc/passwd"] != StatusResolved {
		t.Errorf("/etc/passwd = %q, want resolved", suppressed["/etc/passwd"])
	}
	if comparison.Counts.Resolved != 1 || comparison.Counts.Unverified != 1 {
		t.Errorf("counts = %+v, want one resolved and one unverified", comparison.Counts)
	}
}

func TestPermissionDenialsAreNotTreatedAsUnattributableErrors(t *testing.T) {
	document := mustCreate(t, "/etc/passwd", "/etc/shadow")
	current := completeCurrent()
	current.Files.Inaccessible = []string{"/root (permission denied)"}
	current.Files.Errors = 1
	current.Files.PermissionDenied = 1

	comparison := compareAll(t, document, nil, current)

	if comparison.Counts.Resolved != 2 {
		t.Errorf("resolved = %d, want both findings outside the unreadable path", comparison.Counts.Resolved)
	}
	if comparison.Reliability.Reliable != true {
		t.Error("a permission denial that is named in the record must not suppress every resolution")
	}
	for _, reason := range comparison.Reliability.Reasons {
		if strings.Contains(reason, "not permission denials") {
			t.Errorf("a permission denial was reported as an unattributable error: %q", reason)
		}
	}
}

func TestUnexplainedPartialStatusStillSuppressesResolution(t *testing.T) {
	document := mustCreate(t, "/etc/passwd", "/etc/shadow")
	current := completeCurrent()
	current.Status = scan.StatusPartial

	comparison := compare(t, document, nil, current)

	if comparison.Counts.Resolved != 0 {
		t.Errorf("resolved = %d for an unexplained partial scan, want 0", comparison.Counts.Resolved)
	}
	assertReasonContains(t, comparison, "unrecorded reason")
}

func TestUnrecordedDetectorSelectionIsNotTreatedAsMissingCoverage(t *testing.T) {
	result := completeResult("/etc/passwd")
	result.Detectors.Selected = nil

	document := mustCreate(t, "/etc/passwd", "/etc/shadow")
	decision := Policy(document.Coverage, document.MinSeverity, false,
		CurrentScanOf(result), model.SeverityInfo, false)
	if len(decision.BlockingReasons) != 0 {
		t.Errorf("BlockingReasons = %q, want none for a result with no coverage record", decision.BlockingReasons)
	}
}
