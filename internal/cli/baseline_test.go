package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func recordBaseline(t *testing.T, target, path string, args ...string) {
	t.Helper()
	full := append([]string{"baseline", "create", target, "--baseline", path, "--quiet"}, args...)
	result := run(t, full...)
	if result.code != ExitOK {
		t.Fatalf("baseline create exited %d, want %d; stderr = %q", result.code, ExitOK, result.stderr)
	}
}

func worldWritable(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat %s: %v", path, err)
	}
	if err := os.Chmod(path, info.Mode().Perm()|0o002); err != nil {
		t.Fatalf("Chmod %s: %v", path, err)
	}
}

func writeWorldWritable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile %s: %v", path, err)
	}
	worldWritable(t, path)
}

func TestBaselineCompareReportsNoChangesForAnUnchangedTree(t *testing.T) {
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "config"), []byte("value\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	path := filepath.Join(t.TempDir(), "baseline.json")
	recordBaseline(t, target, path)

	result := run(t, "baseline", "compare", target, "--baseline", path, "--quiet")
	if result.code != ExitOK {
		t.Fatalf("exit code = %d, want %d; stderr = %q", result.code, ExitOK, result.stderr)
	}
	if !strings.Contains(result.stdout, "nothing changed") {
		t.Errorf("stdout %q should say nothing changed", result.stdout)
	}
}

func TestBaselineCompareReportsANewFinding(t *testing.T) {
	target := t.TempDir()
	path := filepath.Join(t.TempDir(), "baseline.json")
	recordBaseline(t, target, path)

	writeWorldWritable(t, filepath.Join(target, "newfile"), "x\n")

	result := run(t, "baseline", "compare", target, "--baseline", path, "--quiet")
	if result.code != ExitFindings {
		t.Errorf("exit code = %d, want %d when something changed", result.code, ExitFindings)
	}
	if !strings.Contains(result.stdout, "NEW") {
		t.Errorf("stdout %q should mark the finding as new", result.stdout)
	}
}

func TestBaselineCompareReportsAResolvedFinding(t *testing.T) {
	target := t.TempDir()
	exposed := filepath.Join(target, "exposed")
	writeWorldWritable(t, exposed, "x\n")
	path := filepath.Join(t.TempDir(), "baseline.json")
	recordBaseline(t, target, path)

	if err := os.Chmod(exposed, 0o600); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	result := run(t, "baseline", "compare", target, "--baseline", path, "--quiet")
	if !strings.Contains(result.stdout, "RESOLVED") {
		t.Errorf("stdout %q should mark the finding as resolved", result.stdout)
	}
}

func TestBaselineCompareReportsAChangedFinding(t *testing.T) {
	target := t.TempDir()

	secret := filepath.Join(target, "secret")
	writeWorldWritable(t, secret, "x\n")
	path := filepath.Join(t.TempDir(), "baseline.json")
	recordBaseline(t, target, path)

	if err := os.Chmod(secret, 0o666); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	result := run(t, "baseline", "compare", target, "--baseline", path, "--quiet")
	if !strings.Contains(result.stdout, "CHANGED") {
		t.Errorf("stdout %q should mark the finding as changed", result.stdout)
	}
	if !strings.Contains(result.stdout, "mode") {
		t.Errorf("stdout %q should name the attribute that changed", result.stdout)
	}
}

func TestBaselineCompareEmitsJSON(t *testing.T) {
	target := t.TempDir()
	path := filepath.Join(t.TempDir(), "baseline.json")
	recordBaseline(t, target, path)

	writeWorldWritable(t, filepath.Join(target, "added"), "x\n")

	result := run(t, "baseline", "compare", target, "--baseline", path, "--format", "json", "--quiet")
	if result.code != ExitFindings {
		t.Errorf("exit code = %d, want %d", result.code, ExitFindings)
	}

	var document struct {
		Schema  string `json:"schema"`
		Summary struct {
			New         int `json:"new"`
			ChangeCount int `json:"change_count"`
		} `json:"summary"`
		Changes []struct {
			RuleID string `json:"rule_id"`
			Path   string `json:"path"`
			Status string `json:"status"`
		} `json:"changes"`
		Reliability struct {
			Reliable bool `json:"reliable"`
		} `json:"reliability"`
	}
	if err := json.Unmarshal([]byte(result.stdout), &document); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, result.stdout)
	}
	if document.Schema != "lisa/baseline-comparison/v1" {
		t.Errorf("schema = %q, want the comparison schema", document.Schema)
	}
	if document.Summary.New == 0 || len(document.Changes) == 0 {
		t.Errorf("expected a new finding in the JSON report, got %+v", document.Summary)
	}
	if !document.Reliability.Reliable {
		t.Error("a complete scan of a test tree should be reliable")
	}
}

func TestBaselineCreateRefusesToOverwrite(t *testing.T) {
	target := t.TempDir()
	path := filepath.Join(t.TempDir(), "baseline.json")
	recordBaseline(t, target, path)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	writeWorldWritable(t, filepath.Join(target, "added"), "x\n")

	result := run(t, "baseline", "create", target, "--baseline", path, "--quiet")
	if result.code != ExitUsage {
		t.Errorf("exit code = %d, want %d for a refused overwrite", result.code, ExitUsage)
	}
	if !strings.Contains(result.stderr, "--overwrite") {
		t.Errorf("stderr %q should point at the overwrite flag", result.stderr)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(before) != string(after) {
		t.Error("the refused overwrite still replaced the baseline")
	}
}

func TestBaselineCreateOverwritesWhenAsked(t *testing.T) {
	target := t.TempDir()
	path := filepath.Join(t.TempDir(), "baseline.json")
	recordBaseline(t, target, path)

	writeWorldWritable(t, filepath.Join(target, "added"), "x\n")
	result := run(t, "baseline", "create", target, "--baseline", path, "--overwrite", "--quiet")
	if result.code != ExitOK {
		t.Fatalf("exit code = %d, want %d; stderr = %q", result.code, ExitOK, result.stderr)
	}

	comparison := run(t, "baseline", "compare", target, "--baseline", path, "--quiet")
	if !strings.Contains(comparison.stdout, "nothing changed") {
		t.Errorf("stdout %q should show the overwritten baseline matching the tree", comparison.stdout)
	}
}

func TestBaselineCompareWritesToAnOutputFile(t *testing.T) {
	target := t.TempDir()
	path := filepath.Join(t.TempDir(), "baseline.json")
	recordBaseline(t, target, path)

	output := filepath.Join(t.TempDir(), "report.json")
	result := run(t, "baseline", "compare", target, "--baseline", path,
		"--format", "json", "--output", output, "--quiet")
	if result.code != ExitOK {
		t.Fatalf("exit code = %d, want %d; stderr = %q", result.code, ExitOK, result.stderr)
	}
	if result.stdout != "" {
		t.Errorf("stdout %q should be empty when writing to a file", result.stdout)
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("output permissions = %04o, want 0600", got)
	}
}

func TestBaselineCreateAndCompareAgreeAcrossRuns(t *testing.T) {
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "file"), []byte("x\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	path := filepath.Join(t.TempDir(), "baseline.json")

	first := run(t, "baseline", "create", target, "--baseline", path, "--quiet")
	if first.code != ExitOK {
		t.Fatalf("create exited %d: %q", first.code, first.stderr)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	forward := run(t, "baseline", "compare", target, "--baseline", path, "--quiet")
	if forward.code != ExitOK || !strings.Contains(forward.stdout, "nothing changed") {
		t.Errorf("first comparison reported %d: %q", forward.code, forward.stdout)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(before) != string(after) {
		t.Error("comparing must not modify the baseline")
	}
}

func TestBaselineCompareHonoursTheDetectorFlag(t *testing.T) {
	target := t.TempDir()
	path := filepath.Join(t.TempDir(), "baseline.json")
	recordBaseline(t, target, path)

	writeWorldWritable(t, filepath.Join(target, "added"), "x\n")

	result := run(t, "baseline", "compare", target, "--baseline", path,
		"--detector", "permissions", "--quiet")
	if !strings.Contains(result.stdout, "RELIABILITY") {
		t.Errorf("stdout %q should report that fewer detectors ran", result.stdout)
	}
	if !strings.Contains(result.stdout, "did not run detectors") {
		t.Errorf("stdout %q should name the skipped detectors", result.stdout)
	}
}

func TestBaselineRejectsUnknownDetectorNames(t *testing.T) {
	target := t.TempDir()
	path := filepath.Join(t.TempDir(), "baseline.json")
	recordBaseline(t, target, path)

	for _, args := range [][]string{
		{"baseline", "create", target, "--baseline", path, "--detector", "nonexistent"},
		{"baseline", "compare", target, "--baseline", path, "--detector", "nonexistent"},
	} {
		result := run(t, args...)
		if result.code != ExitUsage {
			t.Errorf("%v exited %d, want %d", args, result.code, ExitUsage)
		}
		if !strings.Contains(result.stderr, "unknown detector") {
			t.Errorf("%v stderr %q should name the unknown detector", args, result.stderr)
		}
	}
}

func TestBaselineRejectsUnavailableFormats(t *testing.T) {
	target := t.TempDir()
	path := filepath.Join(t.TempDir(), "baseline.json")

	for _, format := range []string{"csv", "html"} {
		result := run(t, "baseline", "create", target, "--baseline", path, "--format", format)
		if result.code != ExitOperational {
			t.Errorf("--format %s exited %d, want %d", format, result.code, ExitOperational)
		}
		if !strings.Contains(result.stderr, "not available in this build") {
			t.Errorf("--format %s stderr %q should explain the format is unavailable", format, result.stderr)
		}
	}
}

func TestOverwriteIsRejectedOutsideBaselineCreate(t *testing.T) {
	target := t.TempDir()
	result := run(t, "scan", target, "--overwrite")
	if result.code != ExitUsage {
		t.Errorf("exit code = %d, want %d", result.code, ExitUsage)
	}
	if !strings.Contains(result.stderr, "--overwrite") {
		t.Errorf("stderr %q should explain the flag does not apply to scan", result.stderr)
	}
}

func TestBaselineCompareRejectsATamperedBaseline(t *testing.T) {
	target := t.TempDir()
	writeWorldWritable(t, filepath.Join(target, "exposed"), "x\n")
	path := filepath.Join(t.TempDir(), "baseline.json")
	recordBaseline(t, target, path)

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	tampered := strings.Replace(string(content), `"path": "`, `"path": "/tampered`, 1)
	if tampered == string(content) {
		t.Fatal("the fixture did not contain the expected path field")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	result := run(t, "baseline", "compare", target, "--baseline", path, "--quiet")
	if result.code != ExitUsage {
		t.Errorf("exit code = %d, want %d for a baseline that no longer validates", result.code, ExitUsage)
	}
	if !strings.Contains(result.stderr, "does not match its identity") {
		t.Errorf("stderr %q should explain the record failed validation", result.stderr)
	}
}

func TestBaselineCompareRejectsAFutureSchema(t *testing.T) {
	target := t.TempDir()
	path := filepath.Join(t.TempDir(), "baseline.json")
	recordBaseline(t, target, path)

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	future := strings.Replace(string(content), `"version": 1`, `"version": 99`, 1)
	if future == string(content) {
		t.Fatal("the fixture did not contain the expected version field")
	}
	if err := os.WriteFile(path, []byte(future), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	result := run(t, "baseline", "compare", target, "--baseline", path, "--quiet")
	if result.code != ExitUsage {
		t.Errorf("exit code = %d, want %d for an unsupported version", result.code, ExitUsage)
	}
	if !strings.Contains(result.stderr, "not supported") {
		t.Errorf("stderr %q should say the schema is unsupported", result.stderr)
	}
}

func TestBaselineUsageMentionsTheOverwriteFlag(t *testing.T) {
	result := run(t, "baseline", "create", "--help")
	if !strings.Contains(result.stdout, "--overwrite") {
		t.Errorf("baseline create usage should document --overwrite, got:\n%s", result.stdout)
	}
}

func TestBaselineCreateHonoursOutputAndFormat(t *testing.T) {
	t.Run("text summary to a file", func(t *testing.T) {
		target := t.TempDir()
		writeWorldWritable(t, filepath.Join(target, "loose"), "x\n")

		baselinePath := filepath.Join(t.TempDir(), "baseline.json")
		summaryPath := filepath.Join(t.TempDir(), "summary.txt")
		result := run(t, "baseline", "create", target, "--baseline", baselinePath,
			"--output", summaryPath, "--quiet")
		if result.code != ExitOK {
			t.Fatalf("exit code = %d, want %d; stderr = %q", result.code, ExitOK, result.stderr)
		}
		if result.stdout != "" {
			t.Errorf("stdout = %q, want it empty when writing to a file", result.stdout)
		}

		summary, err := os.ReadFile(summaryPath)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		if !strings.Contains(string(summary), "Recorded 1 finding(s)") {
			t.Errorf("summary = %q, want it to record the finding count", summary)
		}
		info, err := os.Stat(summaryPath)
		if err != nil {
			t.Fatalf("Stat: %v", err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("summary permissions = %04o, want 0600", got)
		}
	})

	t.Run("json to stdout matches the file", func(t *testing.T) {
		target := t.TempDir()
		writeWorldWritable(t, filepath.Join(target, "loose"), "x\n")

		baselinePath := filepath.Join(t.TempDir(), "baseline.json")
		result := run(t, "baseline", "create", target, "--baseline", baselinePath,
			"--format", "json", "--quiet")
		if result.code != ExitOK {
			t.Fatalf("exit code = %d, want %d; stderr = %q", result.code, ExitOK, result.stderr)
		}

		written, err := os.ReadFile(baselinePath)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}

		if got, want := result.stdout, string(written)+"\n"; got != want {
			t.Errorf("stdout does not match the recorded baseline.\n got: %q\nwant: %q", got, want)
		}
		var decoded map[string]any
		if err := json.Unmarshal([]byte(result.stdout), &decoded); err != nil {
			t.Fatalf("creation output is not valid JSON: %v", err)
		}
		if decoded["schema"] != "lisa/baseline/v1" {
			t.Errorf("schema = %v, want the baseline schema", decoded["schema"])
		}
	})
}
