package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lisa/internal/model"
)

func scanConfig(t *testing.T) Config {
	t.Helper()
	cfg := Default()
	cfg.Command = CommandScan
	cfg.Target = t.TempDir()
	return cfg
}

func TestDefaultIsUsableForScan(t *testing.T) {
	cfg := scanConfig(t)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default scan configuration is invalid: %v", err)
	}
}

func TestDefaultWorkerBounds(t *testing.T) {
	workers := Default().Workers
	if workers < 1 || workers > DefaultWorkers {
		t.Errorf("default workers = %d, want between 1 and %d", workers, DefaultWorkers)
	}
}

func TestDefaultRecentWindowIsPositive(t *testing.T) {
	if Default().RecentWindow != DefaultRecentWindow {
		t.Errorf("default recent window = %s, want %s", Default().RecentWindow, DefaultRecentWindow)
	}
	if DefaultRecentWindow != 7*24*time.Hour {
		t.Errorf("DefaultRecentWindow = %s, want 168h", DefaultRecentWindow)
	}
}

func TestCommandUsage(t *testing.T) {
	cases := map[Command]string{
		CommandScan:            "scan",
		CommandBaselineCreate:  "baseline create",
		CommandBaselineCompare: "baseline compare",
		CommandVersion:         "version",
	}
	for command, expected := range cases {
		if got := command.Usage(); got != expected {
			t.Errorf("Command(%q).Usage() = %q, want %q", command, got, expected)
		}
	}
	if Command("nonsense").IsValid() {
		t.Error("unknown command reported as valid")
	}
	if !CommandScan.IsValid() {
		t.Error("scan command reported as invalid")
	}
}

func TestParseFormat(t *testing.T) {
	for _, name := range []string{"text", "JSON", " csv ", "html"} {
		if _, err := ParseFormat(name); err != nil {
			t.Errorf("ParseFormat(%q) returned error: %v", name, err)
		}
	}
	if _, err := ParseFormat("pdf"); err == nil {
		t.Error("ParseFormat(\"pdf\") returned no error, want error")
	}
}

func TestValidateRejectsUnknownCommand(t *testing.T) {
	cfg := scanConfig(t)
	cfg.Command = "audit"
	if err := cfg.Validate(); err == nil {
		t.Error("Validate accepted an unknown command")
	}
}

func TestValidateRejectsWorkerBounds(t *testing.T) {
	for _, workers := range []int{0, -1, MaxWorkers + 1} {
		cfg := scanConfig(t)
		cfg.Workers = workers
		if err := cfg.Validate(); err == nil {
			t.Errorf("Validate accepted workers = %d", workers)
		}
	}
}

func TestValidateAcceptsWorkerUpperBound(t *testing.T) {
	cfg := scanConfig(t)
	cfg.Workers = MaxWorkers
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate rejected workers = %d: %v", MaxWorkers, err)
	}
}

func TestValidateRejectsVerboseWithQuiet(t *testing.T) {
	cfg := scanConfig(t)
	cfg.Verbose = true
	cfg.Quiet = true
	if err := cfg.Validate(); err == nil {
		t.Error("Validate accepted verbose together with quiet")
	}
}

func TestValidateRequiresExistingTargetDirectory(t *testing.T) {
	cfg := scanConfig(t)
	cfg.Target = ""
	if err := cfg.Validate(); err == nil {
		t.Error("Validate accepted an empty target")
	}

	cfg.Target = filepath.Join(t.TempDir(), "absent")
	if err := cfg.Validate(); err == nil {
		t.Error("Validate accepted a target that does not exist")
	}

	file := filepath.Join(t.TempDir(), "regular")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("writing fixture failed: %v", err)
	}
	cfg.Target = file
	if err := cfg.Validate(); err == nil {
		t.Error("Validate accepted a regular file as target")
	}
}

func TestValidateVersionNeedsNoTarget(t *testing.T) {
	cfg := Default()
	cfg.Command = CommandVersion
	if err := cfg.Validate(); err != nil {
		t.Errorf("version configuration rejected: %v", err)
	}
}

func TestValidateRejectsDuplicateAndEmptyNames(t *testing.T) {
	cfg := scanConfig(t)
	cfg.Detectors = []string{"perms", "perms"}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate accepted duplicate detector names")
	}
	cfg.Detectors = []string{"  "}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate accepted a blank detector name")
	}
	cfg.Detectors = nil
	cfg.Excludes = []string{"/tmp", "/tmp"}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate accepted duplicate excluded paths")
	}
}

func TestValidateBaselineCompareRequiresBaseline(t *testing.T) {
	cfg := scanConfig(t)
	cfg.Command = CommandBaselineCompare
	if err := cfg.Validate(); err == nil {
		t.Error("Validate accepted baseline compare without a baseline path")
	}

	baseline := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(baseline, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatalf("writing baseline fixture failed: %v", err)
	}
	cfg.BaselinePath = baseline
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate rejected a readable baseline: %v", err)
	}
}

func TestValidateBaselineCompareRejectsMissingBaseline(t *testing.T) {
	cfg := scanConfig(t)
	cfg.Command = CommandBaselineCompare
	cfg.BaselinePath = filepath.Join(t.TempDir(), "absent.json")
	if err := cfg.Validate(); err == nil {
		t.Error("Validate accepted a baseline file that does not exist")
	}
}

func TestValidateBaselineCreateDoesNotRequireExistingFile(t *testing.T) {
	cfg := scanConfig(t)
	cfg.Command = CommandBaselineCreate
	cfg.BaselinePath = filepath.Join(t.TempDir(), "new-baseline.json")
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate rejected a baseline that does not exist yet: %v", err)
	}
}

func TestValidateRejectsBaselineEqualToOutput(t *testing.T) {
	dir := t.TempDir()
	shared := filepath.Join(dir, "report.json")
	cfg := scanConfig(t)
	cfg.BaselinePath = shared
	cfg.OutputPath = shared
	if err := cfg.Validate(); err == nil {
		t.Error("Validate accepted baseline and output pointing at the same file")
	}
}

func TestValidateRejectsDirectoryOutput(t *testing.T) {
	dir := t.TempDir()
	cfg := scanConfig(t)
	cfg.OutputPath = dir
	if err := cfg.Validate(); err == nil {
		t.Error("Validate accepted a directory as output path")
	}
}

func TestValidateRejectsMissingOutputDirectory(t *testing.T) {
	cfg := scanConfig(t)
	cfg.OutputPath = filepath.Join(t.TempDir(), "absent-dir", "report.json")
	if err := cfg.Validate(); err == nil {
		t.Error("Validate accepted an output path whose parent directory is missing")
	}
}

func TestValidateRejectsInvalidSeverityAndFormat(t *testing.T) {
	cfg := scanConfig(t)
	cfg.MinSeverity = model.Severity(77)
	if err := cfg.Validate(); err == nil {
		t.Error("Validate accepted an invalid minimum severity")
	}
	cfg = scanConfig(t)
	cfg.Format = "xml"
	if err := cfg.Validate(); err == nil {
		t.Error("Validate accepted an unknown format")
	}
}

func TestValidateRejectsNonPositiveRecentWindow(t *testing.T) {
	cfg := scanConfig(t)
	cfg.Recent = true
	cfg.RecentWindow = 0
	if err := cfg.Validate(); err == nil {
		t.Error("Validate accepted a zero recent window while recent is enabled")
	}
}

func TestNormalizeCleansPathsAndDeduplicatesExcludes(t *testing.T) {
	cfg := scanConfig(t)
	cfg.Target = "/tmp/../tmp/scanme/"
	cfg.Excludes = []string{"/tmp/a/", "/tmp/a", "/tmp//b", "  /tmp/c  "}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize returned error: %v", err)
	}
	if cfg.Target != "/tmp/scanme" {
		t.Errorf("Target = %q, want %q", cfg.Target, "/tmp/scanme")
	}
	want := []string{"/tmp/a", "/tmp/b", "/tmp/c"}
	if len(cfg.Excludes) != len(want) {
		t.Fatalf("Excludes = %v, want %v", cfg.Excludes, want)
	}
	for i, expected := range want {
		if cfg.Excludes[i] != expected {
			t.Errorf("Excludes[%d] = %q, want %q", i, cfg.Excludes[i], expected)
		}
	}
}

func TestNormalizeRejectsInvalidExcludes(t *testing.T) {
	cfg := scanConfig(t)
	cfg.Excludes = []string{"/tmp", ""}
	if err := cfg.Normalize(); err == nil {
		t.Error("Normalize accepted a blank excluded path")
	}
}

func TestNormalizeLeavesUnsetPathsEmpty(t *testing.T) {
	cfg := scanConfig(t)
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize returned error: %v", err)
	}
	if cfg.BaselinePath != "" || cfg.OutputPath != "" {
		t.Errorf("Normalize invented paths: baseline=%q output=%q", cfg.BaselinePath, cfg.OutputPath)
	}
}

func TestValidationErrorsAreDescriptive(t *testing.T) {
	cfg := scanConfig(t)
	cfg.Workers = 0
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate returned no error")
	}
	if !strings.Contains(err.Error(), "workers") {
		t.Errorf("error %q should mention the offending field", err)
	}
}
