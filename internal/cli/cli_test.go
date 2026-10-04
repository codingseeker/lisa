package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type runResult struct {
	code   int
	stdout string
	stderr string
}

func run(t *testing.T, args ...string) runResult {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(args, &stdout, &stderr)
	return runResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

func tempFile(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("writing fixture %s failed: %v", name, err)
	}
	return path
}

func TestExitCodesAreDistinct(t *testing.T) {
	codes := map[string]int{
		"ExitOK":          ExitOK,
		"ExitFindings":    ExitFindings,
		"ExitUsage":       ExitUsage,
		"ExitOperational": ExitOperational,
	}
	seen := map[int]string{}
	for name, code := range codes {
		if previous, duplicate := seen[code]; duplicate {
			t.Errorf("%s and %s share exit code %d", name, previous, code)
		}
		seen[code] = name
	}
	if ExitOK != 0 || ExitFindings != 1 || ExitUsage != 2 || ExitOperational != 3 {
		t.Errorf("exit codes drifted from the documented contract: %v", codes)
	}
}

func TestExitCodeFor(t *testing.T) {
	if got := ExitCodeFor(nil); got != ExitOK {
		t.Errorf("ExitCodeFor(nil) = %d, want %d", got, ExitOK)
	}
	if got := ExitCodeFor(usageErrorf("bad flag")); got != ExitUsage {
		t.Errorf("ExitCodeFor(usage) = %d, want %d", got, ExitUsage)
	}
	if got := ExitCodeFor(operationalErrorf("engine offline")); got != ExitOperational {
		t.Errorf("ExitCodeFor(operational) = %d, want %d", got, ExitOperational)
	}
	if got := ExitCodeFor(errors.New("plain")); got != ExitOperational {
		t.Errorf("ExitCodeFor(plain error) = %d, want %d", got, ExitOperational)
	}
	wrapped := fmt.Errorf("context: %w", usageErrorf("bad flag"))
	if got := ExitCodeFor(wrapped); got != ExitUsage {
		t.Errorf("ExitCodeFor(wrapped usage error) = %d, want %d", got, ExitUsage)
	}
}

func TestErrorMessageIncludesCause(t *testing.T) {
	cause := errors.New("permission denied")
	err := &Error{Code: ExitOperational, Message: "cannot open target", Err: cause}
	if !strings.Contains(err.Error(), "cannot open target") {
		t.Errorf("Error() = %q, want it to contain the message", err.Error())
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("Error() = %q, want it to contain the cause", err.Error())
	}
	if !errors.Is(err, cause) {
		t.Error("errors.Is should unwrap to the cause")
	}
}

func TestNoArgumentsIsUsageError(t *testing.T) {
	result := run(t)
	if result.code != ExitUsage {
		t.Errorf("exit code = %d, want %d", result.code, ExitUsage)
	}
	if result.stderr == "" {
		t.Error("usage error should explain itself on stderr")
	}
	if result.stdout != "" {
		t.Errorf("usage error wrote %q to stdout, want nothing", result.stdout)
	}
}

func TestUnknownCommandIsUsageError(t *testing.T) {
	result := run(t, "audit", "/tmp")
	if result.code != ExitUsage {
		t.Errorf("exit code = %d, want %d", result.code, ExitUsage)
	}
	if !strings.Contains(result.stderr, "audit") {
		t.Errorf("stderr %q should name the unknown command", result.stderr)
	}
	if !strings.Contains(result.stderr, "Usage:") {
		t.Errorf("stderr %q should include usage", result.stderr)
	}
}

func TestVersionSucceedsOnStdout(t *testing.T) {
	for _, arg := range []string{"version", "--version", "-V"} {
		result := run(t, arg)
		if result.code != ExitOK {
			t.Errorf("%s exit code = %d, want %d", arg, result.code, ExitOK)
		}
		if !strings.Contains(result.stdout, Version) {
			t.Errorf("%s stdout %q should contain version %q", arg, result.stdout, Version)
		}
		if result.stderr != "" {
			t.Errorf("%s wrote %q to stderr, want nothing", arg, result.stderr)
		}
	}
}

func TestHelpSucceedsOnStdout(t *testing.T) {
	for _, arg := range []string{"help", "--help", "-h"} {
		result := run(t, arg)
		if result.code != ExitOK {
			t.Errorf("%s exit code = %d, want %d", arg, result.code, ExitOK)
		}
		if !strings.Contains(result.stdout, "Exit codes:") {
			t.Errorf("%s stdout should document exit codes", arg)
		}
		if !strings.Contains(result.stdout, "baseline compare") {
			t.Errorf("%s stdout should list the available commands", arg)
		}
	}
}

func TestCommandHelpSucceedsOnStdout(t *testing.T) {
	cases := map[string][]string{
		"scan":             {"scan", "--help"},
		"baseline create":  {"baseline", "create", "--help"},
		"baseline compare": {"baseline", "compare", "--help"},
	}
	for name, args := range cases {
		result := run(t, args...)
		if result.code != ExitOK {
			t.Errorf("%s --help exit code = %d, want %d", name, result.code, ExitOK)
		}
		if !strings.Contains(result.stdout, "Usage: lisa "+name) {
			t.Errorf("%s --help stdout %q should start with its usage line", name, result.stdout)
		}
		if !strings.Contains(result.stdout, "Defaults:") {
			t.Errorf("%s --help stdout should document defaults", name)
		}
	}
}

func TestScanAcceptsValidConfiguration(t *testing.T) {
	target := t.TempDir()
	result := run(t, "scan", target, "--workers", "4")
	if result.code != ExitOK && result.code != ExitFindings {
		t.Errorf("exit code = %d, want %d or %d (stderr=%q)", result.code, ExitOK, ExitFindings, result.stderr)
	}
	if result.stdout == "" {
		t.Error("a completed scan should write a report")
	}
}

func TestScanAcceptsPositionalTargetAfterFlags(t *testing.T) {
	target := t.TempDir()
	result := run(t, "scan", "--min-severity", "high", target, "--format", "json")
	if result.code != ExitOK && result.code != ExitFindings {
		t.Errorf("exit code = %d, want %d or %d (stderr=%q)", result.code, ExitOK, ExitFindings, result.stderr)
	}
}

func TestScanAcceptsPathFlag(t *testing.T) {
	result := run(t, "scan", "--path", t.TempDir())
	if result.code != ExitOK && result.code != ExitFindings {
		t.Errorf("exit code = %d, want %d or %d (stderr=%q)", result.code, ExitOK, ExitFindings, result.stderr)
	}
}

func TestScanRejectsMissingTarget(t *testing.T) {
	result := run(t, "scan")
	if result.code != ExitUsage {
		t.Errorf("exit code = %d, want %d", result.code, ExitUsage)
	}
	if !strings.Contains(result.stderr, "requires a target directory") {
		t.Errorf("stderr %q should explain the missing target", result.stderr)
	}
}

func TestScanRejectsTwoTargets(t *testing.T) {
	dir := t.TempDir()
	result := run(t, "scan", dir, dir)
	if result.code != ExitUsage {
		t.Errorf("exit code = %d, want %d", result.code, ExitUsage)
	}
	if !strings.Contains(result.stderr, "only one target") {
		t.Errorf("stderr %q should explain the duplicate target", result.stderr)
	}
}

func TestScanRejectsTargetGivenTwice(t *testing.T) {
	dir := t.TempDir()
	result := run(t, "scan", "--path", dir, dir)
	if result.code != ExitUsage {
		t.Errorf("exit code = %d, want %d", result.code, ExitUsage)
	}
	if !strings.Contains(result.stderr, "target given twice") {
		t.Errorf("stderr %q should explain the duplicate target", result.stderr)
	}
}

func TestScanRejectsInvalidFlagValue(t *testing.T) {
	result := run(t, "scan", t.TempDir(), "--workers", "0")
	if result.code != ExitUsage {
		t.Errorf("exit code = %d, want %d", result.code, ExitUsage)
	}
	if !strings.Contains(result.stderr, "workers") {
		t.Errorf("stderr %q should name the invalid flag", result.stderr)
	}
}

func TestScanRejectsUnknownFlag(t *testing.T) {
	result := run(t, "scan", t.TempDir(), "--turbo")
	if result.code != ExitUsage {
		t.Errorf("exit code = %d, want %d", result.code, ExitUsage)
	}
	if !strings.Contains(result.stderr, "turbo") {
		t.Errorf("stderr %q should name the unknown flag", result.stderr)
	}
}

func TestScanRejectsInvalidSeverityAndFormat(t *testing.T) {
	dir := t.TempDir()
	severity := run(t, "scan", dir, "--min-severity", "extreme")
	if severity.code != ExitUsage {
		t.Errorf("invalid severity exit code = %d, want %d", severity.code, ExitUsage)
	}
	format := run(t, "scan", dir, "--format", "pdf")
	if format.code != ExitUsage {
		t.Errorf("invalid format exit code = %d, want %d", format.code, ExitUsage)
	}
	if !strings.Contains(format.stderr, "format") {
		t.Errorf("stderr %q should name the invalid format", format.stderr)
	}
}

func TestScanRejectsVerboseWithQuiet(t *testing.T) {
	result := run(t, "scan", t.TempDir(), "--verbose", "--quiet")
	if result.code != ExitUsage {
		t.Errorf("exit code = %d, want %d", result.code, ExitUsage)
	}
	if !strings.Contains(result.stderr, "mutually exclusive") {
		t.Errorf("stderr %q should explain the conflict", result.stderr)
	}
}

func TestScanRejectsInaccessibleTarget(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")
	result := run(t, "scan", missing)
	if result.code != ExitUsage {
		t.Errorf("exit code = %d, want %d", result.code, ExitUsage)
	}
	if !strings.Contains(result.stderr, "not accessible") {
		t.Errorf("stderr %q should explain the inaccessible target", result.stderr)
	}
}

func TestVerboseLogsToStderrOnly(t *testing.T) {
	result := run(t, "scan", t.TempDir(), "--format", "json", "--verbose")
	if strings.Contains(result.stdout, "target=") {
		t.Errorf("stdout = %q, verbose diagnostics must not reach the report", result.stdout)
	}
	if !strings.Contains(result.stderr, "target=") {
		t.Errorf("stderr %q should carry verbose diagnostics", result.stderr)
	}
	if !strings.Contains(result.stdout, `"schema"`) {
		t.Errorf("stdout should still be a JSON report, got %q", result.stdout)
	}
}

func TestQuietSuppressesDiagnostics(t *testing.T) {
	result := run(t, "scan", t.TempDir(), "--verbose", "--quiet")
	if result.code != ExitUsage {
		t.Fatalf("exit code = %d, want %d for the flag conflict", result.code, ExitUsage)
	}
	if strings.Contains(result.stderr, "target=") {
		t.Errorf("stderr %q should not carry verbose diagnostics in quiet mode", result.stderr)
	}
}

func TestBaselineWithoutSubcommandIsUsageError(t *testing.T) {
	result := run(t, "baseline")
	if result.code != ExitUsage {
		t.Errorf("exit code = %d, want %d", result.code, ExitUsage)
	}
	if !strings.Contains(result.stderr, "create") {
		t.Errorf("stderr %q should list the valid subcommands", result.stderr)
	}
}

func TestBaselineUnknownSubcommandIsUsageError(t *testing.T) {
	result := run(t, "baseline", "destroy")
	if result.code != ExitUsage {
		t.Errorf("exit code = %d, want %d", result.code, ExitUsage)
	}
	if !strings.Contains(result.stderr, "destroy") {
		t.Errorf("stderr %q should name the unknown subcommand", result.stderr)
	}
}

func TestBaselineCreateRequiresBaselineFlag(t *testing.T) {
	result := run(t, "baseline", "create", t.TempDir())
	if result.code != ExitUsage {
		t.Errorf("exit code = %d, want %d", result.code, ExitUsage)
	}
	if !strings.Contains(result.stderr, "--baseline is required") {
		t.Errorf("stderr %q should explain the missing baseline flag", result.stderr)
	}
}

func TestBaselineCreateWritesAFile(t *testing.T) {
	target := t.TempDir()
	path := filepath.Join(t.TempDir(), "baseline.json")

	result := run(t, "baseline", "create", target, "--baseline", path)
	if result.code != ExitOK {
		t.Fatalf("exit code = %d, want %d; stderr = %q", result.code, ExitOK, result.stderr)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("permissions = %04o, want 0600", got)
	}
	if !strings.Contains(result.stdout, "Recorded") {
		t.Errorf("stdout %q should report what was recorded", result.stdout)
	}
}

func TestBaselineCompareRequiresExistingBaseline(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.json")
	result := run(t, "baseline", "compare", t.TempDir(), "--baseline", missing)
	if result.code != ExitUsage {
		t.Errorf("exit code = %d, want %d", result.code, ExitUsage)
	}
	if !strings.Contains(result.stderr, "not accessible") {
		t.Errorf("stderr %q should explain the missing baseline", result.stderr)
	}
}

func TestBaselineCompareRejectsAFileThatIsNotABaseline(t *testing.T) {
	path := tempFile(t, "baseline.json")
	result := run(t, "baseline", "compare", t.TempDir(), "--baseline", path)
	if result.code != ExitUsage {
		t.Errorf("exit code = %d, want %d for an unreadable baseline", result.code, ExitUsage)
	}
	if !strings.Contains(result.stderr, "baseline") {
		t.Errorf("stderr %q should explain the baseline could not be used", result.stderr)
	}
}

func TestHelpRequestedIsRecognised(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"--help"}, {"-help"}, {"--help", t.TempDir()}} {
		if !helpRequested(args) {
			t.Errorf("helpRequested(%v) = false, want true", args)
		}
	}
	if helpRequested([]string{"-verbose"}) {
		t.Error("helpRequested must not treat -verbose as help")
	}
}

func TestStringListSetAccumulates(t *testing.T) {
	var list stringList
	for _, value := range []string{"a", "b"} {
		if err := list.Set(value); err != nil {
			t.Fatalf("Set(%q) returned error: %v", value, err)
		}
	}
	if list.String() != "a,b" {
		t.Errorf("String() = %q, want %q", list.String(), "a,b")
	}
}
