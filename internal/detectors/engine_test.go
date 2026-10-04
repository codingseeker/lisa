package detectors

import (
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"lisa/internal/fsscan"
	"lisa/internal/model"
)

type stubDetector struct {
	name     string
	findings []model.Finding
	panics   atomic.Bool
	calls    atomic.Int64
}

func (d *stubDetector) Name() string { return d.name }

func (d *stubDetector) Detect(ctx Context) []model.Finding {
	d.calls.Add(1)
	if d.panics.Load() {
		panic("detector failure with SECRET-canary-" + canaryPassword)
	}
	return d.findings
}

func (d *stubDetector) callCount() int64 {
	return d.calls.Load()
}

func sampleFinding(ruleID, path string) model.Finding {
	return model.Rule{
		ID:         ruleID,
		Title:      "sample",
		Severity:   model.SeverityMedium,
		Confidence: model.ConfidenceHigh,
		Category:   model.CategoryPermissions,
	}.Finding(path).WithDescription("sample finding")
}

func TestDefaultRegistryCoversEveryDetector(t *testing.T) {
	registry := DefaultRegistry()

	want := []string{
		"permissions", "sensitive-permissions", "ssh-keys", "suid", "ownership",
		"systemd", "cron", "shell-profiles", "init", "ld-preload",
		"persistence-content", "sshd-config", "sudoers", "secrets",
		"temp-executables", "masquerade",
	}

	got := registry.Names()
	if len(got) != len(want) {
		t.Fatalf("registry holds %d detectors (%v), want %d", len(got), got, len(want))
	}
	for i, name := range want {
		if got[i] != name {
			t.Errorf("detector %d = %q, want %q", i, got[i], name)
		}
	}
	if registry.Len() != len(want) {
		t.Errorf("Len() = %d, want %d", registry.Len(), len(want))
	}
}

func TestRegistryNamesAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, name := range DefaultRegistry().Names() {
		if seen[name] {
			t.Errorf("duplicate detector name %q", name)
		}
		seen[name] = true
	}
}

func TestRegistrySelect(t *testing.T) {
	registry := DefaultRegistry()

	all, err := registry.Select(nil)
	if err != nil {
		t.Fatalf("Select(nil) returned error: %v", err)
	}
	if all.Len() != registry.Len() {
		t.Errorf("Select(nil) changed the detector count to %d", all.Len())
	}

	some, err := registry.Select([]string{"suid", "cron"})
	if err != nil {
		t.Fatalf("Select returned error: %v", err)
	}
	if got := some.Names(); len(got) != 2 || got[0] != "suid" || got[1] != "cron" {
		t.Errorf("Select produced %v, want [suid cron]", got)
	}

	if _, err := registry.Select([]string{"nope"}); err == nil {
		t.Error("Select accepted an unknown detector name")
	} else {
		message := err.Error()
		if !strings.Contains(message, "nope") || !strings.Contains(message, "available") {
			t.Errorf("error %q should name the unknown detector and list available ones", message)
		}
	}
}

func TestEmptyRegistryIsUsable(t *testing.T) {
	engine, err := NewEngine(Options{Detectors: []string{}})
	if err == nil {
		engine, err = NewEngine(Options{})
	}
	engine.registry = NewRegistry()

	if got := engine.DetectorNames(); len(got) != 0 {
		t.Errorf("empty registry reports detectors %v", got)
	}
	findings := engine.Process(entryAt(t, "/etc/hosts", 0o644))
	if len(findings) != 0 {
		t.Errorf("empty registry produced %v, want no findings", ruleIDs(findings))
	}
	if stats := engine.Stats(); stats.EntriesProcessed != 1 || stats.DetectorCalls != 0 {
		t.Errorf("stats = %+v, want one entry and zero detector calls", stats)
	}
}

func TestEngineRejectsUnknownDetectorSelection(t *testing.T) {
	if _, err := NewEngine(Options{Detectors: []string{"does-not-exist"}}); err == nil {
		t.Error("NewEngine accepted an unknown detector name")
	}
}

func TestEngineIsolatesPanics(t *testing.T) {
	good := &stubDetector{name: "good", findings: []model.Finding{sampleFinding("TEST-001", "/etc/hosts")}}
	bad := newPanickingDetector("bad")
	alsoGood := &stubDetector{name: "also-good", findings: []model.Finding{sampleFinding("TEST-002", "/etc/passwd")}}

	engine := newTestEngine(t, good, bad, alsoGood)
	findings := engine.Process(entryAt(t, "/etc/hosts", 0o644))

	if len(findings) != 2 {
		t.Fatalf("a panicking detector changed the result: got %v, want findings from both healthy detectors", ruleIDs(findings))
	}
	if findings[0].RuleID != "TEST-001" || findings[1].RuleID != "TEST-002" {
		t.Errorf("findings = %v, want TEST-001 and TEST-002 in detector order", ruleIDs(findings))
	}

	stats := engine.Stats()
	if stats.DetectorFailures["bad"] != 1 {
		t.Errorf("DetectorFailures = %v, want one failure recorded for bad", stats.DetectorFailures)
	}
	if stats.DetectorFailures["good"] != 0 {
		t.Errorf("DetectorFailures = %v, want no failures for healthy detectors", stats.DetectorFailures)
	}
	if stats.DetectorCalls != 3 {
		t.Errorf("DetectorCalls = %d, want 3", stats.DetectorCalls)
	}
	if stats.Findings != 2 {
		t.Errorf("Findings = %d, want 2", stats.Findings)
	}
	if bad.callCount() != 1 || good.callCount() != 1 || alsoGood.callCount() != 1 {
		t.Errorf("detector call counts = %d/%d/%d, want one each",
			good.callCount(), bad.callCount(), alsoGood.callCount())
	}
}

func TestEngineFailureCountersAccumulate(t *testing.T) {
	bad := newPanickingDetector("bad")
	engine := newTestEngine(t, bad)

	for i := 0; i < 3; i++ {
		engine.Process(entryAt(t, "/etc/hosts", 0o644))
	}
	if got := engine.Stats().DetectorFailures["bad"]; got != 3 {
		t.Errorf("DetectorFailures[bad] = %d, want 3", got)
	}
}

func TestEngineDoesNotLeakSecretsThroughFailurePaths(t *testing.T) {
	bad := newPanickingDetector("bad")
	engine := newTestEngine(t, bad)
	engine.Process(entryAt(t, "/etc/hosts", 0o644))

	for name, count := range engine.Stats().DetectorFailures {
		if strings.Contains(name, canaryPassword) {
			t.Errorf("failure key %q leaks a secret", name)
		}
		if count < 0 {
			t.Errorf("failure count for %q is negative", name)
		}
	}
}

func TestEngineStatsSnapshotIsIndependent(t *testing.T) {
	bad := newPanickingDetector("bad")
	engine := newTestEngine(t, bad)

	engine.Process(entryAt(t, "/etc/hosts", 0o644))
	first := engine.Stats()

	bad.panics.Store(false)
	engine.Process(entryAt(t, "/etc/hosts", 0o644))
	second := engine.Stats()

	if first.DetectorFailures["bad"] != 1 {
		t.Errorf("the earlier snapshot mutated: %v", first.DetectorFailures)
	}
	if second.DetectorFailures["bad"] != 1 {
		t.Errorf("second snapshot = %v, want one failure", second.DetectorFailures)
	}
	second.DetectorFailures["injected"] = 99
	if _, mutated := engine.Stats().DetectorFailures["injected"]; mutated {
		t.Error("mutating a snapshot changed engine state")
	}
}

func TestEngineStampsMissingTimestamps(t *testing.T) {
	unstamped := sampleFinding("TEST-001", "/etc/hosts")
	unstamped.DetectedAt = time.Time{}

	detector := &stubDetector{name: "unstamped", findings: []model.Finding{unstamped}}
	engine := newTestEngine(t, detector)

	findings := engine.Process(entryAt(t, "/etc/hosts", 0o644))
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want one", ruleIDs(findings))
	}
	if findings[0].DetectedAt.IsZero() {
		t.Error("the engine did not stamp a zero detection timestamp")
	}
	if !findings[0].DetectedAt.Equal(engine.opts.Now) {
		t.Errorf("DetectedAt = %v, want the configured clock %v", findings[0].DetectedAt, engine.opts.Now)
	}
}

func TestEnginePreservesExistingTimestamps(t *testing.T) {
	stamped := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	finding := sampleFinding("TEST-001", "/etc/hosts")
	finding.DetectedAt = stamped

	engine := newTestEngine(t, &stubDetector{name: "stamped", findings: []model.Finding{finding}})
	got := engine.Process(entryAt(t, "/etc/hosts", 0o644))
	if !got[0].DetectedAt.Equal(stamped) {
		t.Errorf("DetectedAt = %v, want the detector supplied %v", got[0].DetectedAt, stamped)
	}
}

func TestEngineProcessesEntriesConcurrentlySafely(t *testing.T) {
	detector := &stubDetector{name: "counting"}
	engine := newTestEngine(t, detector)

	entries := make([]fsscan.Entry, 0, 64)
	for i := 0; i < 64; i++ {
		entries = append(entries, entryAt(t, "/etc/hosts", 0o644))
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, entry := range entries {
				engine.Process(entry)
			}
		}()
	}
	wg.Wait()

	stats := engine.Stats()
	if stats.EntriesProcessed != int64(len(entries)*16) {
		t.Errorf("EntriesProcessed = %d, want %d", stats.EntriesProcessed, len(entries)*16)
	}
	if stats.DetectorCalls != int64(len(entries)*16) {
		t.Errorf("DetectorCalls = %d, want %d", stats.DetectorCalls, len(entries)*16)
	}
}

func TestEngineRunsEveryDetectorOverAWholeTree(t *testing.T) {
	engine, err := NewEngine(Options{Identity: testIdentity(t), Now: fixedNow})
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	entry := entryAt(t, "/usr/bin/sudo", os.FileMode(0o4755))
	findings := engine.Process(entry)
	if len(findings) == 0 {
		t.Fatal("a setuid system binary produced no findings from the full registry")
	}
	assertValid(t, findings)
	assertNoDuplicateRulePaths(t, findings)

	stats := engine.Stats()
	if stats.DetectorCalls != int64(engine.registry.Len()) {
		t.Errorf("DetectorCalls = %d, want one per registered detector (%d)", stats.DetectorCalls, engine.registry.Len())
	}
	if len(stats.DetectorFailures) != 0 {
		t.Errorf("DetectorFailures = %v, want none", stats.DetectorFailures)
	}
}

func newPanickingDetector(name string) *stubDetector {
	detector := &stubDetector{name: name}
	detector.panics.Store(true)
	return detector
}

func newTestEngine(t *testing.T, detectors ...Detector) *Engine {
	t.Helper()
	engine, err := NewEngine(Options{Identity: emptyIdentity(), Now: fixedNow})
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	engine.registry = NewRegistry(detectors...)
	return engine
}
