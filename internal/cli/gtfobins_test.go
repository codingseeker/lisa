package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lisa/internal/config"
	"lisa/internal/model"
	"lisa/internal/report"
)

func suidTree(t *testing.T, name string) string {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, []byte("#!/bin/false\n"), 0o755); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	if err := os.Chmod(path, 0o755|os.ModeSetuid); err != nil {
		t.Skipf("the filesystem does not retain the setuid bit for test fixtures: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat failed: %v", err)
	}
	if info.Mode()&os.ModeSetuid == 0 {
		t.Skip("the setuid bit was cleared; this filesystem cannot host the fixture")
	}
	return root
}

func decodeReport(t *testing.T, stdout string) report.Document {
	t.Helper()
	var document report.Document
	if err := json.Unmarshal([]byte(stdout), &document); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
	return document
}

func privilegeFindings(document report.Document) []model.Finding {
	var out []model.Finding
	for _, finding := range document.Findings {
		if strings.HasPrefix(finding.RuleID, "LS-PRIV-") {
			out = append(out, finding)
		}
	}
	return out
}

func scanSuidTree(t *testing.T, root string, extra ...string) (report.Document, string) {
	t.Helper()
	args := append([]string{"scan", root, "--format", "json", "--detector", "suid"}, extra...)
	result := exec(t, args...)
	if result.code != ExitFindings && result.code != ExitOK {
		t.Fatalf("%v exit = %d (stderr=%q)", args, result.code, result.stderr)
	}
	return decodeReport(t, result.stdout), result.stdout
}

func TestScanGtfoBinsOffByDefault(t *testing.T) {
	if config.Default().GTFOBins {
		t.Fatal("GTFOBins enrichment is enabled by default; the documented default is off")
	}
	document, raw := scanSuidTree(t, suidTree(t, "find"))
	privilege := privilegeFindings(document)
	if len(privilege) != 1 {
		t.Fatalf("privilege findings = %d, want one\n%s", len(privilege), raw)
	}
	if privilege[0].Reference != nil {
		t.Errorf("reference context attached without the flag: %+v", privilege[0].Reference)
	}
	if strings.Contains(raw, "gtfobins-curated") {
		t.Errorf("enrichment ran without the flag:\n%s", raw)
	}
}

func TestScanGtfoBinsEnrichesWhenEnabled(t *testing.T) {
	root := suidTree(t, "find")
	result := exec(t, "scan", root, "--format", "json", "--detector", "suid", "--gtfobins")

	if result.code != ExitFindings {
		t.Fatalf("exit code = %d, want %d (stderr=%q)", result.code, ExitFindings, result.stderr)
	}
	document := decodeReport(t, result.stdout)
	privilege := privilegeFindings(document)
	if len(privilege) != 1 {
		t.Fatalf("privilege findings = %d, want one\n%s", len(privilege), result.stdout)
	}

	finding := privilege[0]
	if finding.Reference == nil {
		t.Fatalf("no reference context:\n%s", result.stdout)
	}
	if finding.Reference.Source != "gtfobins-curated" {
		t.Errorf("source = %q", finding.Reference.Source)
	}
	if finding.Reference.Binary != "find" {
		t.Errorf("binary = %q, want find", finding.Reference.Binary)
	}
	if finding.Reference.Category != "filesystem" {
		t.Errorf("category = %q, want filesystem", finding.Reference.Category)
	}
	if finding.Reference.Summary == "" {
		t.Error("summary is empty")
	}
	if !strings.Contains(finding.Reference.Caveat, "does not indicate") {
		t.Errorf("caveat does not disclaim compromise: %q", finding.Reference.Caveat)
	}
	if !strings.Contains(finding.Reference.Attribution, "GTFOBins") {
		t.Errorf("attribution = %q", finding.Reference.Attribution)
	}
	if !strings.Contains(result.stdout, "Recursive file walker") {
		t.Errorf("supplemental summary missing from the JSON report:\n%s", result.stdout)
	}
}

func TestScanGtfoBinsPreservesTheOriginalDetection(t *testing.T) {
	root := suidTree(t, "find")
	plain, _ := scanSuidTree(t, root)
	enriched, _ := scanSuidTree(t, root, "--gtfobins")

	before := privilegeFindings(plain)
	after := privilegeFindings(enriched)
	if len(before) != len(after) || len(before) != 1 {
		t.Fatalf("privilege finding counts differ: %d then %d", len(before), len(after))
	}
	if after[0].Reference == nil {
		t.Fatal("the enriched run produced no reference context")
	}
	if before[0].ID != after[0].ID {
		t.Errorf("finding id changed: %q then %q", before[0].ID, after[0].ID)
	}
	if before[0].RuleID != after[0].RuleID {
		t.Errorf("rule id changed: %q then %q", before[0].RuleID, after[0].RuleID)
	}
	if before[0].Severity != after[0].Severity {
		t.Errorf("severity changed: %v then %v", before[0].Severity, after[0].Severity)
	}
	if before[0].Confidence != after[0].Confidence {
		t.Errorf("confidence changed: %v then %v", before[0].Confidence, after[0].Confidence)
	}
	if before[0].Category != after[0].Category {
		t.Errorf("category changed: %q then %q", before[0].Category, after[0].Category)
	}
	if before[0].Path != after[0].Path {
		t.Errorf("path changed: %q then %q", before[0].Path, after[0].Path)
	}
	if before[0].Remediation != after[0].Remediation {
		t.Errorf("remediation changed: %q then %q", before[0].Remediation, after[0].Remediation)
	}
	if before[0].Title != after[0].Title {
		t.Errorf("title changed: %q then %q", before[0].Title, after[0].Title)
	}
	if after[0].PermissionString() != "4755" {
		t.Errorf("mode = %q, want 4755", after[0].PermissionString())
	}
}

func TestScanGtfoBinsLeavesUnknownBinariesUnchanged(t *testing.T) {
	root := suidTree(t, "our-internal-helper")
	result := exec(t, "scan", root, "--format", "json", "--detector", "suid", "--gtfobins")
	document := decodeReport(t, result.stdout)

	privilege := privilegeFindings(document)
	if len(privilege) != 1 {
		t.Fatalf("privilege findings = %d, want one", len(privilege))
	}
	if privilege[0].Reference != nil {
		t.Errorf("an unlisted binary was enriched: %+v", privilege[0].Reference)
	}
	if strings.Contains(result.stdout, "reference") {
		t.Errorf("unmatched finding emitted a reference field:\n%s", result.stdout)
	}
}

func TestScanGtfoBinsCanBeDisabledExplicitly(t *testing.T) {
	root := suidTree(t, "find")
	result := exec(t, "scan", root, "--format", "json", "--detector", "suid", "--gtfobins=false")

	if result.code != ExitFindings {
		t.Fatalf("exit = %d, want %d (stderr=%q)", result.code, ExitFindings, result.stderr)
	}
	if strings.Contains(result.stdout, "gtfobins-curated") {
		t.Errorf("enriched while explicitly disabled:\n%s", result.stdout)
	}
	if len(privilegeFindings(decodeReport(t, result.stdout))) != 1 {
		t.Error("disabling the feature changed the finding count")
	}
}

func TestScanGtfoBinsRejectsInvalidValue(t *testing.T) {
	for _, value := range []string{"maybe", "1", "yes", "-"} {
		result := exec(t, "scan", suidTree(t, "find"), "--gtfobins", value)
		if result.code != ExitUsage {
			t.Errorf("--gtfobins %s exit = %d, want %d", value, result.code, ExitUsage)
		}
		if !strings.Contains(result.stderr, "gtfobins") {
			t.Errorf("--gtfobins %s stderr = %q, should name the flag", value, result.stderr)
		}
		if result.stdout != "" {
			t.Errorf("--gtfobins %s wrote %q to stdout", value, result.stdout)
		}
	}
}

func TestScanGtfoBinsTerminalReportShowsContext(t *testing.T) {
	result := exec(t, "scan", suidTree(t, "find"), "--detector", "suid", "--gtfobins")
	for _, want := range []string{
		"gtfo      : find, filesystem",
		"context   : Recursive file walker",
		"note      : Contextual risk information",
		"require analyst review",
	} {
		if !strings.Contains(result.stdout, want) {
			t.Errorf("terminal output is missing %q\n%s", want, result.stdout)
		}
	}
}

func TestScanGtfoBinsTerminalReportOmitsContextByDefault(t *testing.T) {
	result := exec(t, "scan", suidTree(t, "find"), "--detector", "suid")
	for _, unwanted := range []string{"gtfo      :", "context   :"} {
		if strings.Contains(result.stdout, unwanted) {
			t.Errorf("terminal output rendered %q without the flag:\n%s", unwanted, result.stdout)
		}
	}
}

func TestScanGtfoBinsIsDeterministic(t *testing.T) {
	root := suidTree(t, "find")
	first, _ := scanSuidTree(t, root, "--gtfobins")
	second, _ := scanSuidTree(t, root, "--gtfobins")

	left := privilegeFindings(first)
	right := privilegeFindings(second)
	if len(left) != len(right) || len(left) != 1 {
		t.Fatalf("privilege finding counts differ: %d then %d", len(left), len(right))
	}
	if left[0].ID != right[0].ID {
		t.Errorf("finding id differs: %q then %q", left[0].ID, right[0].ID)
	}
	if left[0].Reference == nil || right[0].Reference == nil {
		t.Fatal("enrichment was lost between runs")
	}
	if *left[0].Reference != *right[0].Reference {
		t.Errorf("reference context differs between runs:\n%+v\n%+v", left[0].Reference, right[0].Reference)
	}
	if len(left[0].Evidence) != len(right[0].Evidence) {
		t.Errorf("evidence length differs: %d then %d", len(left[0].Evidence), len(right[0].Evidence))
	}
}

func TestScanGtfoBinsHelpDocumentsTheFlag(t *testing.T) {
	result := exec(t, "scan", "--help")
	if result.code != ExitOK {
		t.Fatalf("exit code = %d, want %d", result.code, ExitOK)
	}
	for _, want := range []string{"--gtfobins", "curated GTFOBins subset", "off by default"} {
		if !strings.Contains(result.stdout, want) {
			t.Errorf("scan usage is missing %q\n%s", want, result.stdout)
		}
	}
	for _, args := range [][]string{
		{"baseline", "create", "--help"},
		{"baseline", "compare", "--help"},
	} {
		usage := exec(t, args...)
		if usage.code != ExitOK {
			t.Fatalf("%v exit = %d, want %d", args, usage.code, ExitOK)
		}
		if !strings.Contains(usage.stdout, "--gtfobins") {
			t.Errorf("%v usage does not document the flag:\n%s", args, usage.stdout)
		}
	}
}

func TestScanGtfoBinsDoesNotAffectNonPrivilegeFindings(t *testing.T) {
	root := t.TempDir()
	loose := filepath.Join(root, "notes.txt")
	if err := os.WriteFile(loose, []byte("data"), 0o600); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if err := os.Chmod(loose, 0o666); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}

	result := exec(t, "scan", root, "--format", "json", "--gtfobins")
	document := decodeReport(t, result.stdout)
	if len(document.Findings) == 0 {
		t.Fatal("the world-writable fixture produced no finding")
	}
	for _, finding := range document.Findings {
		if finding.Reference != nil {
			t.Errorf("non privilege finding %s was enriched: %+v", finding.RuleID, finding.Reference)
		}
	}
	if strings.Contains(result.stdout, "gtfobins-curated") {
		t.Errorf("non privilege findings produced supplemental context:\n%s", result.stdout)
	}
}

func TestScanGtfoBinsOutputStaysFreeOfDiagnostics(t *testing.T) {
	result := exec(t, "scan", suidTree(t, "find"), "--format", "json", "--gtfobins", "--verbose")
	if strings.Contains(result.stdout, "level=") || strings.Contains(result.stdout, "gtfobins=true") {
		t.Errorf("diagnostics reached stdout:\n%s", result.stdout)
	}
	if !strings.Contains(result.stderr, "gtfobins=true") {
		t.Errorf("verbose logging should record the feature state: %q", result.stderr)
	}
	decodeReport(t, result.stdout)
}

func TestScanGtfoBinsCoexistsWithOtherDetectors(t *testing.T) {
	root := suidTree(t, "find")
	result := exec(t, "scan", root, "--format", "json", "--gtfobins")
	document := decodeReport(t, result.stdout)

	privilege := privilegeFindings(document)
	if len(privilege) != 1 {
		t.Fatalf("privilege findings = %d, want one\n%s", len(privilege), result.stdout)
	}
	if privilege[0].Reference == nil {
		t.Error("enrichment did not survive running the full detector set")
	}
	for _, finding := range document.Findings {
		if strings.HasPrefix(finding.RuleID, "LS-PRIV-") {
			continue
		}
		if finding.Reference != nil {
			t.Errorf("unrelated rule %s was enriched", finding.RuleID)
		}
	}
}
