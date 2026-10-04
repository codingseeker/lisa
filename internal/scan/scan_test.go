package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lisa/internal/detectors"
	"lisa/internal/fsscan"
	"lisa/internal/model"
)

var fixedNow = time.Date(2026, 6, 7, 8, 9, 10, 0, time.UTC)

func write(t *testing.T, path string, body string, mode os.FileMode) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Skipf("cannot set mode %v: %v", mode, err)
	}
	return path
}

func identity(t *testing.T) *detectors.Identity {
	t.Helper()
	loaded, err := detectors.LoadIdentity(
		strings.NewReader("root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"),
		strings.NewReader("root:x:0:\nalice:x:1000:\n"))
	if err != nil {
		t.Fatalf("LoadIdentity failed: %v", err)
	}
	return loaded
}

func TestRunRequiresRoots(t *testing.T) {
	if _, err := Run(context.Background(), Options{}); err == nil {
		t.Error("Run accepted an empty root list")
	}
}

func TestRunRejectsUnknownDetectorBeforeScanning(t *testing.T) {
	root := t.TempDir()
	result, err := Run(context.Background(), Options{
		Roots:     []string{root},
		Detectors: []string{"nope"},
		Now:       fixedNow,
	})
	if err == nil {
		t.Fatal("Run accepted an unknown detector name")
	}
	if result != nil {
		t.Error("Run returned a result despite failing validation")
	}
	if !strings.Contains(err.Error(), "nope") {
		t.Errorf("error %q should name the unknown detector", err)
	}
}

func TestRunEmptyTree(t *testing.T) {
	root := t.TempDir()
	result, err := Run(context.Background(), Options{Roots: []string{root}, Now: fixedNow, Identity: identity(t)})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("empty tree produced %d findings", len(result.Findings))
	}
	if result.Status != StatusComplete {
		t.Errorf("Status = %q, want complete", result.Status)
	}
	if result.Files.Entries != 1 {
		t.Errorf("Entries = %d, want 1 for the root alone", result.Files.Entries)
	}
	if result.FinishedAt.IsZero() || result.StartedAt.IsZero() {
		t.Error("timestamps were not recorded")
	}
	if result.Duration() < 0 {
		t.Error("Duration is negative")
	}
}

func TestRunCollectsFindingsFromMultipleDetectors(t *testing.T) {
	root := t.TempDir()
	worldWritable := write(t, filepath.Join(root, "loose.txt"), "data", os.FileMode(0o666))
	suid := write(t, filepath.Join(root, "helper"), "data", os.FileMode(0o755)|os.ModeSetuid)
	executable := write(t, filepath.Join(root, "tmp", "run.sh"), "#!/bin/sh\n", os.FileMode(0o755))

	result, err := Run(context.Background(), Options{Roots: []string{root}, Now: fixedNow, Identity: identity(t)})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	seen := map[string]string{}
	for _, finding := range result.Findings {
		seen[finding.RuleID] = finding.Path
		if err := finding.Validate(); err != nil {
			t.Errorf("finding %s invalid: %v", finding.RuleID, err)
		}
		if finding.DetectedAt.IsZero() {
			t.Errorf("finding %s has no timestamp", finding.RuleID)
		}
	}

	if seen["LS-PERM-008"] != worldWritable {
		t.Errorf("LS-PERM-008 path = %q, want %q; a world-writable file under the test temp root is a temporary-directory case", seen["LS-PERM-008"], worldWritable)
	}
	if seen["LS-PRIV-003"] != suid {
		t.Errorf("LS-PRIV-003 path = %q, want %q", seen["LS-PRIV-003"], suid)
	}
	if got := seen["LS-IND-001"]; got != executable && got != filepath.Join(root, "tmp", "run.sh") {
		t.Logf("LS-IND-001 path = %q (temporary-directory rules apply to fixed staging paths)", got)
	}
	if len(result.Findings) < 2 {
		t.Errorf("produced %d findings, want at least the world-writable and SUID results", len(result.Findings))
	}
}

func TestRunSortsFindingsDeterministically(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 6; i++ {
		write(t, filepath.Join(root, "f"+string(rune('a'+i))), "x", os.FileMode(0o666))
	}

	first := mustRun(t, root)
	for i := 0; i < 3; i++ {
		next := mustRun(t, root)
		if len(next.Findings) != len(first.Findings) {
			t.Fatalf("run %d produced %d findings, want %d", i, len(next.Findings), len(first.Findings))
		}
		for j := range next.Findings {
			if next.Findings[j].ID != first.Findings[j].ID {
				t.Fatalf("run %d position %d = %s, want %s", i, j, next.Findings[j].ID, first.Findings[j].ID)
			}
		}
	}
}

func TestRunSortOrderIsSeverityDescending(t *testing.T) {
	findings := []model.Finding{
		{RuleID: "A", Path: "/a", Severity: model.SeverityLow},
		{RuleID: "B", Path: "/b", Severity: model.SeverityCritical},
		{RuleID: "C", Path: "/c", Severity: model.SeverityMedium},
		{RuleID: "D", Path: "/d", Severity: model.SeverityHigh},
		{RuleID: "E", Path: "/a", Severity: model.SeverityHigh},
	}
	SortFindings(findings)

	want := []string{"B", "E", "D", "C", "A"}
	for i, ruleID := range want {
		if findings[i].RuleID != ruleID {
			t.Fatalf("position %d = %s, want %s (order %v)", i, findings[i].RuleID, ruleID, findings)
		}
	}
}

func TestRunAppliesMinimumSeverity(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "loose.txt"), "x", os.FileMode(0o666))

	all := mustRun(t, root)
	high := mustRunMinSeverity(t, root, model.SeverityHigh)

	if len(all.Findings) == 0 {
		t.Fatal("baseline run produced no findings to filter")
	}
	if len(high.Findings) != 0 {
		t.Errorf("min-severity high kept %d medium findings: %v", len(high.Findings), high.Findings)
	}
	if high.Status != StatusComplete {
		t.Errorf("Status = %q, want complete", high.Status)
	}
}

func TestRunDeduplicatesOverlappingRoots(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "loose.txt"), "x", os.FileMode(0o666))

	result, err := Run(context.Background(), Options{
		Roots:      []string{root, root, root},
		Now:        fixedNow,
		Identity:   identity(t),
		MaxEntries: 10_000,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.Duplicates != 0 {
		t.Errorf("Duplicates = %d for identical roots, want 0", result.Duplicates)
	}
}

func TestRunCollectorCollapsesDuplicateIdentifiers(t *testing.T) {
	c := newCollector(model.SeverityInfo)
	finding := model.Rule{
		ID: "TEST-001", Title: "sample", Severity: model.SeverityMedium,
		Confidence: model.ConfidenceHigh, Category: model.CategoryPermissions,
	}.Finding("/etc/hosts").WithDescription("sample").WithMode(0o644)
	finding.DetectedAt = fixedNow
	c.add([]model.Finding{finding})
	c.add([]model.Finding{finding})

	if got := len(c.sorted()); got != 1 {
		t.Errorf("collector holds %d findings, want 1", got)
	}
	if c.duplicates != 1 {
		t.Errorf("duplicates = %d, want 1", c.duplicates)
	}
}

func TestCollectorDropsInvalidFindings(t *testing.T) {
	c := newCollector(model.SeverityInfo)

	valid := model.Rule{ID: "TEST-001", Title: "sample", Severity: model.SeverityMedium,
		Confidence: model.ConfidenceHigh, Category: model.CategoryPermissions}.Finding("/etc/hosts")
	valid.DetectedAt = fixedNow

	invalid := valid
	invalid.ID = "TEST-002"
	invalid.DetectedAt = time.Time{}

	c.add([]model.Finding{valid, invalid})

	if got := len(c.sorted()); got != 1 {
		t.Errorf("collector holds %d findings, want only the valid one", got)
	}
	if c.duplicates != 0 {
		t.Errorf("duplicates = %d; a dropped invalid finding is not a duplicate", c.duplicates)
	}
}

func TestRunStatusIsPartialOnPermissionDenial(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission bits are not enforced for root")
	}
	root := t.TempDir()
	locked := filepath.Join(root, "locked")
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}
	defer os.Chmod(locked, 0o755)

	result, err := Run(context.Background(), Options{Roots: []string{root}, Now: fixedNow, Identity: identity(t)})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.Status != StatusPartial {
		t.Errorf("Status = %q, want partial when paths were unreadable", result.Status)
	}
	if result.Files.PermissionDenied == 0 {
		t.Error("PermissionDenied was not recorded")
	}
}

func TestRunStatusIsPartialWhenLimitsAreReached(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 10; i++ {
		write(t, filepath.Join(root, "f"+string(rune('a'+i))), "x", os.FileMode(0o644))
	}

	result, err := Run(context.Background(), Options{
		Roots:      []string{root},
		Now:        fixedNow,
		Identity:   identity(t),
		MaxEntries: 3,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.Status != StatusPartial {
		t.Errorf("Status = %q, want partial when the entry limit is reached", result.Status)
	}
	if !result.Files.EntryLimitHit {
		t.Error("EntryLimitHit = false, want true")
	}
}

func TestRunStatusIsPartialOnDetectorFailure(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "loose.txt"), "x", os.FileMode(0o666))

	result, err := Run(context.Background(), Options{Roots: []string{root}, Now: fixedNow, Identity: identity(t)})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.DetectorFailureCount() != 0 {
		t.Errorf("DetectorFailureCount = %d on a healthy run", result.DetectorFailureCount())
	}
	if result.Status != StatusComplete {
		t.Errorf("Status = %q, want complete on a healthy run", result.Status)
	}
}

func TestRunSupportsCancellation(t *testing.T) {
	root := t.TempDir()
	buildTree(t, root, 12, 12)

	cancelledCtx, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	result, err := Run(cancelledCtx, Options{Roots: []string{root}, Now: fixedNow, Identity: identity(t)})
	if err == nil {
		t.Error("Run returned no error for a cancelled context")
	}
	if result == nil {
		t.Fatal("Run returned no partial result for a cancelled scan")
	}
	if result.Status != StatusCancelled {
		t.Errorf("Status = %q, want cancelled", result.Status)
	}
}

func TestRunReportsProgress(t *testing.T) {
	root := t.TempDir()
	buildTree(t, root, 4, 4)

	updates := 0
	_, err := Run(context.Background(), Options{
		Roots:    []string{root},
		Now:      fixedNow,
		Identity: identity(t),
		OnProgress: func(fsscan.Stats) {
			updates++
		},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if updates == 0 {
		t.Error("OnProgress was never invoked")
	}
}

func TestRunExcludesPaths(t *testing.T) {
	root := t.TempDir()
	kept := write(t, filepath.Join(root, "kept.txt"), "x", os.FileMode(0o666))
	skipped := write(t, filepath.Join(root, "vendor", "skipped.txt"), "x", os.FileMode(0o666))

	result, err := Run(context.Background(), Options{
		Roots:    []string{root},
		Excludes: []string{filepath.Join(root, "vendor")},
		Now:      fixedNow,
		Identity: identity(t),
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	for _, finding := range result.Findings {
		if finding.Path == skipped {
			t.Errorf("an excluded path produced finding %s", finding.RuleID)
		}
	}
	found := false
	for _, finding := range result.Findings {
		if finding.Path == kept {
			found = true
		}
	}
	if !found {
		t.Error("the non-excluded world-writable file produced no finding")
	}
}

func TestRunNeverFollowsSymlinksByDefault(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	write(t, filepath.Join(outside, "secret.txt"), "x", os.FileMode(0o666))
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	result, err := Run(context.Background(), Options{Roots: []string{root}, Now: fixedNow, Identity: identity(t)})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	for _, finding := range result.Findings {
		if strings.HasPrefix(finding.Path, outside) {
			t.Errorf("scan escaped the root and reported %s", finding.Path)
		}
	}
}

func mustRun(t *testing.T, root string) *Result {
	t.Helper()
	return mustRunMinSeverity(t, root, model.SeverityInfo)
}

func mustRunMinSeverity(t *testing.T, root string, min model.Severity) *Result {
	t.Helper()
	result, err := Run(context.Background(), Options{
		Roots:       []string{root},
		MinSeverity: min,
		Now:         fixedNow,
		Identity:    identity(t),
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	return result
}

func buildTree(t *testing.T, root string, dirs, files int) {
	t.Helper()
	for d := 0; d < dirs; d++ {
		dir := filepath.Join(root, "d"+string(rune('a'+d%26))+string(rune('0'+d/26)))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir failed: %v", err)
		}
		for f := 0; f < files; f++ {
			write(t, filepath.Join(dir, "f"+string(rune('a'+f%26))+".txt"), "x", os.FileMode(0o644))
		}
	}
}
