package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func buildBinary(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "lisa")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the binary failed: %v\n%s", err, output)
	}
	return binary
}

func execute(t *testing.T, binary string, args ...string) (int, string, string) {
	t.Helper()
	command := exec.Command(binary, args...)
	var stdout, stderr strings.Builder
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	exitCode := 0
	if exitError, ok := err.(*exec.ExitError); ok {
		exitCode = exitError.ExitCode()
	} else if err != nil {
		t.Fatalf("running %v failed: %v", args, err)
	}
	return exitCode, stdout.String(), stderr.String()
}

func TestBinaryExitCodes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping build based integration test in short mode")
	}
	binary := buildBinary(t)

	cases := []struct {
		name     string
		args     []string
		wantCode int
	}{
		{"version succeeds", []string{"version"}, 0},
		{"help succeeds", []string{"help"}, 0},
		{"missing command is a usage error", nil, 2},
		{"unknown command is a usage error", []string{"audit"}, 2},
		{"scan without a target is a usage error", []string{"scan"}, 2},
		{"scan of a clean target finds nothing", []string{"scan", t.TempDir()}, 0},
		{"scan with an unsupported format is operational", []string{"scan", t.TempDir(), "--format", "csv"}, 3},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			code, stdout, stderr := execute(t, binary, testCase.args...)
			if code != testCase.wantCode {
				t.Errorf("exit code = %d, want %d (stdout=%q stderr=%q)", code, testCase.wantCode, stdout, stderr)
			}
		})
	}
}

func TestBinaryKeepsStdoutCleanForMachineOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping build based integration test in short mode")
	}
	binary := buildBinary(t)

	_, stdout, _ := execute(t, binary, "version")
	if !strings.Contains(stdout, "lisa") {
		t.Errorf("version stdout = %q, want it on stdout", stdout)
	}

	_, stdout, stderr := execute(t, binary, "audit")
	if stdout != "" {
		t.Errorf("usage error stdout = %q, want nothing", stdout)
	}
	if stderr == "" {
		t.Error("usage error should write to stderr")
	}
}

func TestBinaryEmitsValidJSONOnStdout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping build based integration test in short mode")
	}
	binary := buildBinary(t)

	code, stdout, _ := execute(t, binary, "scan", t.TempDir(), "--format", "json", "--verbose")
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}

	var document map[string]any
	if err := json.Unmarshal([]byte(stdout), &document); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
	if document["schema"] != "lisa/report/v1" {
		t.Errorf("schema = %v, want lisa/report/v1", document["schema"])
	}
	if strings.Contains(stdout, "level=") {
		t.Error("verbose diagnostics leaked into the JSON report")
	}
}

func TestBinaryExitCodeOneOnFindings(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping build based integration test in short mode")
	}
	binary := buildBinary(t)

	root := t.TempDir()
	loose := filepath.Join(root, "loose.txt")
	if err := os.WriteFile(loose, []byte("data"), 0o600); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if err := os.Chmod(loose, 0o666); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}

	code, stdout, _ := execute(t, binary, "scan", root)
	if code != 1 {
		t.Errorf("exit code = %d, want 1 when findings are present", code)
	}
	if !strings.Contains(stdout, "FINDINGS") {
		t.Errorf("stdout should contain the findings section, got %q", stdout)
	}
}
