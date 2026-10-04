package detectors

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"lisa/internal/model"
)

func suidFindings(t *testing.T, path string, mode os.FileMode, enabled bool) []model.Finding {
	t.Helper()
	entry := entryAt(t, path, mode)
	ctx := testContext(entry, nil)
	ctx.GTFOBins = enabled
	return suidDetector{}.Detect(ctx)
}

func TestGtfoEnrichesMatchedSetuidBinary(t *testing.T) {
	findings := suidFindings(t, "/usr/bin/find", os.FileMode(0o755)|os.ModeSetuid, true)
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want one", ruleIDs(findings))
	}

	reference := findings[0].Reference
	if reference == nil {
		t.Fatal("a curated SUID binary produced no reference context")
	}
	if reference.Source != "gtfobins-curated" {
		t.Errorf("Source = %q", reference.Source)
	}
	if reference.Binary != "find" {
		t.Errorf("Binary = %q, want find", reference.Binary)
	}
	if reference.Category != "filesystem" {
		t.Errorf("Category = %q, want filesystem", reference.Category)
	}
	if reference.Summary == "" {
		t.Error("Summary is empty")
	}
	if reference.Caveat == "" {
		t.Error("Caveat is empty")
	}
	if !strings.Contains(reference.Caveat, "does not indicate") {
		t.Errorf("Caveat %q should state that a match proves nothing", reference.Caveat)
	}
	if !strings.Contains(reference.Attribution, "GTFOBins") {
		t.Errorf("Attribution %q should credit the source project", reference.Attribution)
	}
	if err := findings[0].Validate(); err != nil {
		t.Errorf("enriched finding is invalid: %v", err)
	}
}

func TestGtfoEnrichesMatchedSetgidBinary(t *testing.T) {
	findings := suidFindings(t, "/usr/bin/tar", os.FileMode(0o755)|os.ModeSetgid, true)
	finding, ok := findingByRule(findings, "LS-PRIV-002")
	if !ok {
		t.Fatalf("LS-PRIV-002 missing, got %v", ruleIDs(findings))
	}
	if finding.Reference == nil {
		t.Fatal("a curated SGID binary produced no reference context")
	}
	if finding.Reference.Binary != "tar" {
		t.Errorf("Binary = %q, want tar", finding.Reference.Binary)
	}
}

func TestGtfoEnrichesPrivilegeRuleOutsideSystemDirectories(t *testing.T) {
	findings := suidFindings(t, "/home/alice/.local/bin/sudo", os.FileMode(0o755)|os.ModeSetuid, true)
	finding, ok := findingByRule(findings, "LS-PRIV-003")
	if !ok {
		t.Fatalf("LS-PRIV-003 missing, got %v", ruleIDs(findings))
	}
	if finding.Reference == nil || finding.Reference.Binary != "sudo" {
		t.Errorf("privilege-related rule was not enriched: %+v", finding.Reference)
	}
}

func TestGtfoMatchesFullPathsByBaseName(t *testing.T) {
	for _, path := range []string{
		"/usr/bin/find", "/bin/find", "/usr/local/bin/find", "/opt/tool/bin/find",
	} {
		findings := suidFindings(t, path, os.FileMode(0o755)|os.ModeSetuid, true)
		if len(findings) != 1 || findings[0].Reference == nil {
			t.Errorf("%s was not enriched", path)
			continue
		}
		if findings[0].Reference.Binary != "find" {
			t.Errorf("%s matched %q", path, findings[0].Reference.Binary)
		}
		if findings[0].Path != path {
			t.Errorf("Path changed from %q to %q", path, findings[0].Path)
		}
	}
}

func TestGtfoDoesNotMatchSubstringsOrPrefixes(t *testing.T) {
	for _, name := range []string{
		"findutils", "xfind", "ind", "findx", "notsudo", "sudoku",
		"bashrc", "envsubst", "vimdiff", "tarball",
	} {
		findings := suidFindings(t, "/usr/bin/"+name, os.FileMode(0o755)|os.ModeSetuid, true)
		for _, finding := range findings {
			if finding.Reference != nil {
				t.Errorf("%q was enriched via %q; only exact base names may match",
					name, finding.Reference.Binary)
			}
		}
	}
}

func TestGtfoLeavesUnknownBinariesUnchanged(t *testing.T) {
	findings := suidFindings(t, "/usr/lib/our-app-helper", os.FileMode(0o755)|os.ModeSetuid, true)
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want one", ruleIDs(findings))
	}
	if findings[0].Reference != nil {
		t.Errorf("an unlisted binary was enriched: %+v", findings[0].Reference)
	}
	if findings[0].RuleID != "LS-PRIV-001" {
		t.Errorf("RuleID = %q, want the standard system binary rule", findings[0].RuleID)
	}
	if len(findings[0].Evidence) != 3 {
		t.Errorf("Evidence = %v, want the original three entries unchanged", findings[0].Evidence)
	}
}

func TestGtfoDisabledLeavesFindingsUntouched(t *testing.T) {
	enabled := suidFindings(t, "/usr/bin/find", os.FileMode(0o755)|os.ModeSetuid, true)
	disabled := suidFindings(t, "/usr/bin/find", os.FileMode(0o755)|os.ModeSetuid, false)

	if len(disabled) != len(enabled) {
		t.Fatalf("finding count changed: %d enabled, %d disabled", len(enabled), len(disabled))
	}
	for _, finding := range disabled {
		if finding.Reference != nil {
			t.Errorf("%s was enriched while the feature is disabled", finding.RuleID)
		}
	}
	if len(disabled[0].Evidence) != 3 {
		t.Errorf("disabled evidence = %v, want the original three entries", disabled[0].Evidence)
	}
	if disabled[0].Severity != enabled[0].Severity {
		t.Errorf("severity changed: %v enabled, %v disabled", enabled[0].Severity, disabled[0].Severity)
	}
}

func TestGtfoDoesNotChangeSeverityOrConfidence(t *testing.T) {
	enabled := suidFindings(t, "/usr/bin/find", os.FileMode(0o755)|os.ModeSetuid, true)
	disabled := suidFindings(t, "/usr/bin/find", os.FileMode(0o755)|os.ModeSetuid, false)

	if enabled[0].Severity != disabled[0].Severity {
		t.Errorf("severity inflated by enrichment: %v then %v", disabled[0].Severity, enabled[0].Severity)
	}
	if enabled[0].Confidence != disabled[0].Confidence {
		t.Errorf("confidence changed by enrichment: %v then %v", disabled[0].Confidence, enabled[0].Confidence)
	}
	if enabled[0].Category != disabled[0].Category {
		t.Errorf("category changed by enrichment: %q then %q", disabled[0].Category, enabled[0].Category)
	}
	if enabled[0].RuleID != disabled[0].RuleID {
		t.Errorf("rule id changed by enrichment: %q then %q", disabled[0].RuleID, enabled[0].RuleID)
	}
	if enabled[0].ID != disabled[0].ID {
		t.Errorf("finding id changed by enrichment")
	}
}

func TestGtfoPreservesOriginalFindingFields(t *testing.T) {
	findings := suidFindings(t, "/usr/bin/find", os.FileMode(0o755)|os.ModeSetuid, true)
	finding := findings[0]

	if finding.Path != "/usr/bin/find" {
		t.Errorf("Path = %q", finding.Path)
	}
	if finding.Title != ruleSetuidOutsideSystemDirectories.Title && finding.Title == "" {
		t.Error("Title was lost")
	}
	if finding.Remediation == "" {
		t.Error("Remediation was lost")
	}
	if finding.Mode == nil || *finding.Mode != 0o4755 {
		t.Errorf("Mode = %v, want 4755", finding.PermissionString())
	}
	if finding.DetectedAt.IsZero() {
		t.Error("DetectedAt was lost")
	}
	if finding.OwnerName() == "" {
		t.Error("Owner was lost")
	}
	if err := finding.Validate(); err != nil {
		t.Errorf("enriched finding is invalid: %v", err)
	}
}

func TestGtfoAppendsEvidenceWithoutDiscardingOriginal(t *testing.T) {
	findings := suidFindings(t, "/usr/bin/find", os.FileMode(0o755)|os.ModeSetuid, true)
	evidence := strings.Join(findings[0].Evidence, " | ")

	for _, original := range []string{"mode=4755", "setuid=yes", "privilege is inherited"} {
		if !strings.Contains(evidence, original) {
			t.Errorf("original evidence %q was lost", original)
		}
	}
	for _, added := range []string{"curated binary=find", "curated category=filesystem", "curated context:"} {
		if !strings.Contains(evidence, added) {
			t.Errorf("expected supplemental evidence %q", added)
		}
	}
	if !strings.Contains(evidence, "Recursive file walker") {
		t.Errorf("supplemental evidence lacks the curated summary: %s", evidence)
	}
}

func TestGtfoEnrichesBothBitsWithoutDuplication(t *testing.T) {
	mode := os.FileMode(0o755) | os.ModeSetuid | os.ModeSetgid
	findings := suidFindings(t, "/usr/bin/find", mode, true)

	if len(findings) != 2 {
		t.Fatalf("findings = %v, want one per set bit", ruleIDs(findings))
	}
	for _, finding := range findings {
		if finding.Reference == nil {
			t.Fatalf("%s was not enriched", finding.RuleID)
		}
		if finding.Reference.Binary != "find" {
			t.Errorf("%s matched %q", finding.RuleID, finding.Reference.Binary)
		}
	}
	if findings[0].ID == findings[1].ID {
		t.Error("setuid and setgid findings share an identifier")
	}
	assertNoDuplicateRulePaths(t, findings)
}

func TestGtfoIsStableRegardlessOfEnrichmentOrder(t *testing.T) {
	paths := []string{"/usr/bin/find", "/usr/bin/sudo", "/usr/bin/wget", "/usr/bin/tar"}

	first := collectReferences(t, paths, true)
	second := collectReferences(t, reverse(paths), true)

	if len(first) != len(second) {
		t.Fatalf("reference counts differ: %d then %d", len(first), len(second))
	}
	for path, reference := range first {
		other, ok := second[path]
		if !ok {
			t.Fatalf("%s missing from the reversed run", path)
		}
		if reference != other {
			t.Errorf("%s reference differs by input order", path)
		}
	}
}

func collectReferences(t *testing.T, paths []string, enabled bool) map[string]model.ReferenceContext {
	t.Helper()
	collected := map[string]model.ReferenceContext{}
	for _, path := range paths {
		for _, finding := range suidFindings(t, path, os.FileMode(0o755)|os.ModeSetuid, enabled) {
			if finding.Reference != nil {
				collected[path] = *finding.Reference
			}
		}
	}
	return collected
}

func reverse(values []string) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[len(values)-1-i] = value
	}
	return out
}

func TestGtfoDoesNotEnrichUnrelatedFindingTypes(t *testing.T) {
	cases := []struct {
		name     string
		detector Detector
		path     string
		mode     os.FileMode
	}{
		{"world writable file", worldWritableDetector{}, "/etc/find", os.FileMode(0o666)},
		{"world writable directory", worldWritableDetector{}, "/etc/wget", os.FileMode(0o777)},
		{"temporary executable", temporaryExecutableDetector{}, "/tmp/sudo", os.FileMode(0o755)},
		{"world writable in temp", worldWritableDetector{}, "/tmp/tar", os.FileMode(0o666)},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			entry := entryAt(t, testCase.path, testCase.mode)
			ctx := testContext(entry, nil)
			ctx.GTFOBins = true

			for _, finding := range testCase.detector.Detect(ctx) {
				if finding.Reference != nil {
					t.Errorf("%s produced GTFOBins reference %q; only SUID and SGID findings are eligible",
						caseName(testCase.detector), finding.Reference.Binary)
				}
			}
		})
	}
}

func caseName(detector Detector) string {
	switch detector.(type) {
	case worldWritableDetector:
		return "permissions"
	case temporaryExecutableDetector:
		return "temp-executables"
	}
	return detector.Name()
}

func TestGtfoDoesNotEnrichNonSetuidFiles(t *testing.T) {
	findings := suidFindings(t, "/usr/bin/find", os.FileMode(0o755), true)
	if len(findings) != 0 {
		t.Errorf("an ordinary binary produced %v", ruleIDs(findings))
	}
}

func TestGtfoEnrichmentThroughTheEngine(t *testing.T) {
	buildEngine := func(enabled bool) *Engine {
		engine, err := NewEngine(Options{Identity: testIdentity(t), Now: fixedNow, GTFOBins: enabled})
		if err != nil {
			t.Fatalf("NewEngine failed: %v", err)
		}
		return engine
	}

	entry := entryAt(t, "/usr/bin/find", os.FileMode(0o755)|os.ModeSetuid)

	enabled := buildEngine(true).Process(entry)
	disabled := buildEngine(false).Process(entry)

	if len(enabled) != len(disabled) {
		t.Fatalf("finding counts differ: %d enabled, %d disabled", len(enabled), len(disabled))
	}

	enriched := 0
	for _, finding := range enabled {
		if finding.Reference != nil {
			enriched++
		}
	}
	if enriched == 0 {
		t.Fatal("the engine produced no enriched findings")
	}
	for _, finding := range disabled {
		if finding.Reference != nil {
			t.Errorf("%s was enriched through the engine while disabled", finding.RuleID)
		}
	}
}

func TestGtfoReferenceSerializesAsAStructuredField(t *testing.T) {
	findings := suidFindings(t, "/usr/bin/find", os.FileMode(0o755)|os.ModeSetuid, true)
	data, err := json.Marshal(findings[0])
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
	for _, key := range []string{"source", "binary", "category", "summary", "severity", "caveat"} {
		if _, present := reference[key]; !present {
			t.Errorf("reference JSON is missing %q", key)
		}
	}
	if reference["source"] != "gtfobins-curated" {
		t.Errorf("source = %v", reference["source"])
	}
}

func TestGtfoReferenceIsOmittedForUnmatchedFindings(t *testing.T) {
	findings := suidFindings(t, "/usr/lib/our-helper", os.FileMode(0o755)|os.ModeSetuid, true)
	data, err := json.Marshal(findings[0])
	if err != nil {
		t.Fatalf("marshalling failed: %v", err)
	}
	if strings.Contains(string(data), "reference") {
		t.Errorf("unmatched finding JSON should omit the reference field: %s", data)
	}
}

func TestGtfoEvidenceContainsNoSensitiveContent(t *testing.T) {
	findings := suidFindings(t, "/usr/bin/find", os.FileMode(0o755)|os.ModeSetuid, true)
	serialized, err := json.Marshal(findings)
	if err != nil {
		t.Fatalf("marshalling failed: %v", err)
	}
	text := string(serialized)

	if strings.Contains(text, canaryPassword) {
		t.Error("supplemental content leaked a secret")
	}
	for _, forbidden := range []string{"BEGIN RSA PRIVATE KEY", "/etc/shadow", "root:"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("supplemental content contains %q", forbidden)
		}
	}
}

func TestGtfoEnrichmentIsIdempotent(t *testing.T) {
	findings := suidFindings(t, "/usr/bin/find", os.FileMode(0o755)|os.ModeSetuid, true)
	original := *findings[0].Reference

	for i := 0; i < 3; i++ {
		findings = suidFindings(t, "/usr/bin/find", os.FileMode(0o755)|os.ModeSetuid, true)
		if *findings[0].Reference != original {
			t.Fatal("repeated detection produced a different reference")
		}
		if len(findings[0].Evidence) != 7 {
			t.Fatalf("evidence accumulated across runs: %d entries", len(findings[0].Evidence))
		}
	}
}
