package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lisa/internal/report"
)

const e2eSecret = "E2E-CANARY-SECRET-9f8e7d"

type cliRun struct {
	code   int
	stdout string
	stderr string
}

func exec(t *testing.T, args ...string) cliRun {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(args, &stdout, &stderr)
	return cliRun{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

func labDir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	dir := filepath.Join(root, "etc")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}

	loose := filepath.Join(root, "loose.txt")
	if err := os.WriteFile(loose, []byte("data"), 0o600); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if err := os.Chmod(loose, 0o666); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}

	nested := filepath.Join(root, "vendor", "nested.txt")
	if err := os.MkdirAll(filepath.Dir(nested), 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	if err := os.WriteFile(nested, []byte("data"), 0o644); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	return root
}

func TestScanCleanTreeExitsZero(t *testing.T) {
	root := t.TempDir()
	result := exec(t, "scan", root, "--format", "json")

	if result.code != ExitOK {
		t.Errorf("exit code = %d, want %d (stderr=%q)", result.code, ExitOK, result.stderr)
	}

	var document report.Document
	if err := json.Unmarshal([]byte(result.stdout), &document); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, result.stdout)
	}
	if len(document.Findings) != 0 {
		t.Errorf("clean tree produced %d findings", len(document.Findings))
	}
	if document.Scan.Status != "complete" {
		t.Errorf("status = %q, want complete", document.Scan.Status)
	}
}

func TestScanWithFindingsExitsOne(t *testing.T) {
	root := labDir(t)
	result := exec(t, "scan", root, "--format", "json")

	if result.code != ExitFindings {
		t.Errorf("exit code = %d, want %d (stderr=%q)", result.code, ExitFindings, result.stderr)
	}
	if len(result.stderr) != 0 {
		t.Errorf("findings exit wrote %q to stderr, want nothing", result.stderr)
	}

	var document report.Document
	if err := json.Unmarshal([]byte(result.stdout), &document); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	if len(document.Findings) == 0 {
		t.Error("expected at least one finding")
	}
}

func TestScanJSONStdoutIsNotContaminated(t *testing.T) {
	root := labDir(t)

	for _, args := range [][]string{
		{"scan", root, "--format", "json"},
		{"scan", root, "--format", "json", "--verbose"},
		{"scan", root, "--format", "json", "--quiet"},
	} {
		result := exec(t, args...)
		if strings.Contains(result.stdout, "level=") ||
			strings.Contains(result.stdout, "lisa:") {
			t.Errorf("%v leaked diagnostics into stdout", args)
		}
		var document map[string]any
		if err := json.Unmarshal([]byte(result.stdout), &document); err != nil {
			t.Errorf("%v produced invalid JSON on stdout: %v", args, err)
		}
	}
}

func TestScanVerboseLogsOnlyToStderr(t *testing.T) {
	root := labDir(t)
	result := exec(t, "scan", root, "--verbose")

	if !strings.Contains(result.stderr, "target=") {
		t.Errorf("verbose mode did not log to stderr: %q", result.stderr)
	}
	if strings.Contains(result.stdout, "target=") {
		t.Error("verbose diagnostics leaked into stdout")
	}
}

func TestScanQuietSuppressesDiagnostics(t *testing.T) {
	root := labDir(t)
	result := exec(t, "scan", root, "--quiet")

	if strings.Contains(result.stderr, "target=") {
		t.Errorf("quiet mode logged to stderr: %q", result.stderr)
	}
	if !strings.Contains(result.stdout, "lisa") {
		t.Error("quiet mode should still write the report to stdout")
	}
}

func TestScanTextReportIsHumanReadable(t *testing.T) {
	root := labDir(t)
	result := exec(t, "scan", root)

	if result.code != ExitFindings {
		t.Errorf("exit code = %d, want %d", result.code, ExitFindings)
	}
	for _, want := range []string{"lisa", "Status:", "SEVERITY SUMMARY", "FINDINGS", "require analyst review"} {
		if !strings.Contains(result.stdout, want) {
			t.Errorf("text report missing %q\n%s", want, result.stdout)
		}
	}
}

func TestScanWritesToOutputFile(t *testing.T) {
	root := labDir(t)
	target := filepath.Join(t.TempDir(), "report.json")

	result := exec(t, "scan", root, "--format", "json", "--output", target)
	if result.code != ExitFindings {
		t.Errorf("exit code = %d, want %d", result.code, ExitFindings)
	}
	if result.stdout != "" {
		t.Errorf("stdout = %q, want nothing when --output is used", result.stdout)
	}

	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("reading report failed: %v", err)
	}
	var document report.Document
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("written report is not valid JSON: %v", err)
	}
	if document.Schema != report.Schema {
		t.Errorf("schema = %q", document.Schema)
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("report mode = %04o, want 0600", info.Mode().Perm())
	}
}

func TestScanDetectorSelection(t *testing.T) {
	root := labDir(t)

	all := exec(t, "scan", root, "--format", "json")
	limited := exec(t, "scan", root, "--format", "json", "--detector", "suid")

	if all.code != ExitFindings {
		t.Fatalf("unfiltered scan exit = %d", all.code)
	}
	if limited.code != ExitOK {
		t.Errorf("suid-only scan exit = %d, want %d", limited.code, ExitOK)
	}

	var document report.Document
	if err := json.Unmarshal([]byte(limited.stdout), &document); err != nil {
		t.Fatalf("decoding failed: %v", err)
	}
	if len(document.Findings) != 0 {
		t.Errorf("suid-only scan produced %d findings", len(document.Findings))
	}
}

func TestScanUnknownDetectorIsUsageError(t *testing.T) {
	result := exec(t, "scan", t.TempDir(), "--detector", "does-not-exist")
	if result.code != ExitUsage {
		t.Errorf("exit code = %d, want %d", result.code, ExitUsage)
	}
	if !strings.Contains(result.stderr, "does-not-exist") {
		t.Errorf("stderr should name the unknown detector: %q", result.stderr)
	}
	if result.stdout != "" {
		t.Errorf("usage error wrote to stdout: %q", result.stdout)
	}
}

func TestScanExclusions(t *testing.T) {
	root := labDir(t)
	vendor := filepath.Join(root, "vendor")

	withVendor := exec(t, "scan", root, "--format", "json", "--detector", "permissions")
	withoutVendor := exec(t, "scan", root, "--format", "json", "--detector", "permissions",
		"--exclude", vendor)

	var first, second report.Document
	if err := json.Unmarshal([]byte(withVendor.stdout), &first); err != nil {
		t.Fatalf("decoding failed: %v", err)
	}
	if err := json.Unmarshal([]byte(withoutVendor.stdout), &second); err != nil {
		t.Fatalf("decoding failed: %v", err)
	}

	if len(first.Findings) == 0 {
		t.Fatal("the unfiltered scan produced no findings")
	}
	for _, finding := range second.Findings {
		if strings.HasPrefix(finding.Path, vendor) {
			t.Errorf("excluded subtree produced finding %s at %s", finding.RuleID, finding.Path)
		}
	}
}

func TestScanWorkerLimitIsAccepted(t *testing.T) {
	root := labDir(t)
	for _, workers := range []string{"1", "2", "16", "256"} {
		result := exec(t, "scan", root, "--format", "json", "--workers", workers)
		if result.code != ExitFindings && result.code != ExitOK {
			t.Errorf("workers=%s exit = %d", workers, result.code)
		}
		var document report.Document
		if err := json.Unmarshal([]byte(result.stdout), &document); err != nil {
			t.Errorf("workers=%s produced invalid JSON", workers)
		}
	}
}

func TestScanRejectsInvalidWorkerCount(t *testing.T) {
	for _, workers := range []string{"0", "-1", "257", "abc"} {
		result := exec(t, "scan", t.TempDir(), "--workers", workers)
		if result.code != ExitUsage {
			t.Errorf("workers=%s exit = %d, want %d", workers, result.code, ExitUsage)
		}
	}
}

func TestScanDepthAndEntryLimits(t *testing.T) {
	root := t.TempDir()
	deep := root
	for i := 0; i < 4; i++ {
		deep = filepath.Join(deep, "level")
		if err := os.MkdirAll(deep, 0o755); err != nil {
			t.Fatalf("mkdir failed: %v", err)
		}
		if err := os.WriteFile(filepath.Join(deep, "f.txt"), []byte("x"), 0o666); err != nil {
			t.Fatalf("write failed: %v", err)
		}
	}

	full := exec(t, "scan", root, "--format", "json")
	limited := exec(t, "scan", root, "--format", "json", "--max-depth", "2")

	var fullDoc, limitedDoc report.Document
	if err := json.Unmarshal([]byte(full.stdout), &fullDoc); err != nil {
		t.Fatalf("decoding failed: %v", err)
	}
	if err := json.Unmarshal([]byte(limited.stdout), &limitedDoc); err != nil {
		t.Fatalf("decoding failed: %v", err)
	}
	if limitedDoc.Files.Entries >= fullDoc.Files.Entries {
		t.Errorf("max-depth did not reduce coverage: %d vs %d", limitedDoc.Files.Entries, fullDoc.Files.Entries)
	}

	capped := exec(t, "scan", root, "--format", "json", "--max-entries", "3")
	var cappedDoc report.Document
	if err := json.Unmarshal([]byte(capped.stdout), &cappedDoc); err != nil {
		t.Fatalf("decoding failed: %v", err)
	}
	if !cappedDoc.Warnings.LimitsReached {
		t.Error("hitting the entry limit did not raise a warning")
	}
	if cappedDoc.Scan.Status != "partial" {
		t.Errorf("status = %q, want partial when limits are reached", cappedDoc.Scan.Status)
	}
}

func TestScanRejectsInvalidLimits(t *testing.T) {
	root := t.TempDir()
	if result := exec(t, "scan", root, "--max-depth", "-1"); result.code != ExitUsage {
		t.Errorf("negative max-depth exit = %d, want %d", result.code, ExitUsage)
	}
	if result := exec(t, "scan", root, "--max-entries", "0"); result.code != ExitUsage {
		t.Errorf("zero max-entries exit = %d, want %d", result.code, ExitUsage)
	}
}

func TestScanMinSeverityFiltersFindings(t *testing.T) {
	root := labDir(t)

	all := exec(t, "scan", root, "--format", "json")
	criticalOnly := exec(t, "scan", root, "--format", "json", "--min-severity", "critical")

	var allDoc, criticalDoc report.Document
	if err := json.Unmarshal([]byte(all.stdout), &allDoc); err != nil {
		t.Fatalf("decoding failed: %v", err)
	}
	if err := json.Unmarshal([]byte(criticalOnly.stdout), &criticalDoc); err != nil {
		t.Fatalf("decoding failed: %v", err)
	}
	if len(allDoc.Findings) == 0 {
		t.Fatal("unfiltered scan produced no findings")
	}
	if len(criticalDoc.Findings) != 0 {
		t.Errorf("min-severity critical kept %d findings", len(criticalDoc.Findings))
	}
	if criticalOnly.code != ExitOK {
		t.Errorf("exit = %d, want %d when nothing is reportable", criticalOnly.code, ExitOK)
	}
}

func TestScanRedactsSecretsEndToEnd(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "app.conf")
	body := "host=localhost\npassword = " + e2eSecret + "\napi_key=" + e2eSecret + "-api\n"
	if err := os.WriteFile(config, []byte(body), 0o600); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if err := os.Chmod(config, 0o644); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}

	for _, format := range []string{"json", "text"} {
		result := exec(t, "scan", root, "--format", format)
		combined := result.stdout + result.stderr
		if strings.Contains(combined, e2eSecret) {
			t.Errorf("%s output leaked the secret:\n%s", format, combined)
		}
	}
}

func TestScanSecretRedactionIsAppliedToRealConfigPaths(t *testing.T) {
	target := t.TempDir()
	config := filepath.Join(target, "app.conf")
	body := "host=localhost\npassword = " + e2eSecret + "\n"
	if err := os.WriteFile(config, []byte(body), 0o644); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	result := exec(t, "scan", target, "--format", "json", "--detector", "secrets")
	combined := result.stdout + result.stderr
	if strings.Contains(combined, e2eSecret) {
		t.Errorf("secret leaked:\n%s", combined)
	}
	t.Logf("secrets detector inspected %s (a config outside /etc is not a secret-scanning target)", config)
}

func TestScanDoesNotFollowSymlinksByDefault(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	loose := filepath.Join(outside, "loose.txt")
	if err := os.WriteFile(loose, []byte("x"), 0o600); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if err := os.Chmod(loose, 0o666); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	result := exec(t, "scan", root, "--format", "json")
	if strings.Contains(result.stdout, outside) {
		t.Errorf("the scan escaped the root:\n%s", result.stdout)
	}
}

func TestScanUnavailableFormatIsOperationalError(t *testing.T) {
	for _, format := range []string{"csv", "html"} {
		result := exec(t, "scan", t.TempDir(), "--format", format)
		if result.code != ExitOperational {
			t.Errorf("format=%s exit = %d, want %d", format, result.code, ExitOperational)
		}
		if !strings.Contains(result.stderr, "not available") {
			t.Errorf("format=%s stderr = %q, should explain the limitation", format, result.stderr)
		}
	}
}

func TestScanMissingTargetIsUsageError(t *testing.T) {
	if result := exec(t, "scan"); result.code != ExitUsage {
		t.Errorf("exit = %d, want %d", result.code, ExitUsage)
	}
	missing := filepath.Join(t.TempDir(), "absent")
	if result := exec(t, "scan", missing); result.code != ExitUsage {
		t.Errorf("missing target exit = %d, want %d", result.code, ExitUsage)
	}
}

func TestScanIsRepeatableAndDeterministic(t *testing.T) {
	root := labDir(t)

	first := exec(t, "scan", root, "--format", "json")
	second := exec(t, "scan", root, "--format", "json")

	if first.code != second.code {
		t.Errorf("exit codes differ: %d then %d", first.code, second.code)
	}

	var a, b report.Document
	if err := json.Unmarshal([]byte(first.stdout), &a); err != nil {
		t.Fatalf("decoding failed: %v", err)
	}
	if err := json.Unmarshal([]byte(second.stdout), &b); err != nil {
		t.Fatalf("decoding failed: %v", err)
	}
	if len(a.Findings) != len(b.Findings) {
		t.Fatalf("finding counts differ: %d then %d", len(a.Findings), len(b.Findings))
	}
	for i := range a.Findings {
		if a.Findings[i].ID != b.Findings[i].ID {
			t.Errorf("finding %d differs between runs: %s then %s", i, a.Findings[i].ID, b.Findings[i].ID)
		}
	}
}

func TestExitCodeContract(t *testing.T) {
	cases := []struct {
		name string
		run  cliRun
		want int
	}{
		{"version", exec(t, "version"), ExitOK},
		{"help", exec(t, "help"), ExitOK},
		{"no command", exec(t), ExitUsage},
		{"unknown command", exec(t, "frobnicate"), ExitUsage},
		{"scan without target", exec(t, "scan"), ExitUsage},
		{"clean scan", exec(t, "scan", t.TempDir()), ExitOK},
		{"scan with findings", exec(t, "scan", labDir(t)), ExitFindings},
		{"unavailable format", exec(t, "scan", t.TempDir(), "--format", "csv"), ExitOperational},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if testCase.run.code != testCase.want {
				t.Errorf("exit = %d, want %d (stderr=%q)", testCase.run.code, testCase.want, testCase.run.stderr)
			}
		})
	}
}
