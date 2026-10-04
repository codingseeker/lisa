package baseline

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"lisa/internal/model"
)

func syscallUmask(mask int) int {
	return syscall.Umask(mask)
}

func mustCreate(t *testing.T, paths ...string) *Document {
	t.Helper()
	document, err := Create(completeResult(paths...), testCreateOptions())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return document
}

func writeBaseline(t *testing.T, document *Document) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := Write(document, path, WriteOptions{}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return path
}

func TestWriteProducesAnOwnerOnlyFile(t *testing.T) {
	path := writeBaseline(t, mustCreate(t, "/etc/passwd"))

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("permissions = %04o, want 0600 so the baseline is not world readable", got)
	}
}

func TestWriteIsOwnerOnlyUnderAPermissiveUmask(t *testing.T) {
	previous := syscallUmask(0o000)
	defer syscallUmask(previous)

	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := Write(mustCreate(t, "/etc/passwd"), path, WriteOptions{}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("permissions = %04o with umask 000, want 0600", got)
	}
}

func TestWriteLeavesNoTemporaryFilesBehind(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "baseline.json")
	if err := Write(mustCreate(t, "/etc/passwd"), path, WriteOptions{}); err != nil {
		t.Fatalf("Write: %v", err)
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "baseline.json" {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Errorf("directory holds %v, want only baseline.json", names)
	}
}

func TestWriteRefusesToOverwriteByDefault(t *testing.T) {
	path := writeBaseline(t, mustCreate(t, "/etc/passwd"))

	replacement := mustCreate(t, "/etc/passwd", "/etc/shadow")
	err := Write(replacement, path, WriteOptions{})
	if !errors.Is(err, ErrExists) {
		t.Fatalf("Write error = %v, want ErrExists", err)
	}

	loaded, err := Load(path, LoadOptions{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded.Findings) != 1 {
		t.Errorf("the refused write still replaced the baseline: %d findings", len(loaded.Findings))
	}
}

func TestWriteOverwritesWhenAsked(t *testing.T) {
	path := writeBaseline(t, mustCreate(t, "/etc/passwd"))

	if err := Write(mustCreate(t, "/etc/passwd", "/etc/shadow"), path, WriteOptions{Overwrite: true}); err != nil {
		t.Fatalf("Write with overwrite: %v", err)
	}
	loaded, err := Load(path, LoadOptions{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded.Findings) != 2 {
		t.Errorf("findings = %d, want 2", len(loaded.Findings))
	}
}

func TestWriteRejectsUnusablePaths(t *testing.T) {
	for _, path := range []string{"", "   ", "baseline\x00.json"} {
		if err := Write(mustCreate(t, "/etc/passwd"), path, WriteOptions{}); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("Write(%q) error = %v, want ErrUnsafePath", path, err)
		}
	}
}

func TestWriteRefusesAnInvalidDocument(t *testing.T) {
	document := mustCreate(t, "/etc/passwd")
	document.Findings[0].Severity = model.Severity(42)

	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := Write(document, path, WriteOptions{}); !errors.Is(err, ErrInvalidDocument) {
		t.Errorf("Write error = %v, want ErrInvalidDocument", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Error("Write created a file for an invalid document")
	}
}

func TestLoadRoundTrips(t *testing.T) {
	path := writeBaseline(t, mustCreate(t, "/etc/passwd", "/usr/bin/su"))

	loaded, err := Load(path, LoadOptions{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Schema != Schema || loaded.Version != Version {
		t.Errorf("schema/version = %s/%d, want %s/%d", loaded.Schema, loaded.Version, Schema, Version)
	}
	if len(loaded.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(loaded.Findings))
	}
}

func TestLoadReportsMissingAndUnreadablePaths(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent.json"), LoadOptions{}); !errors.Is(err, ErrNotFound) {
		t.Errorf("Load error = %v, want ErrNotFound", err)
	}
	if _, err := Load(t.TempDir(), LoadOptions{}); err == nil {
		t.Error("Load accepted a directory")
	}
	if _, err := Load("", LoadOptions{}); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("Load error = %v, want ErrUnsafePath", err)
	}
}

func TestLoadRefusesAnOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, make([]byte, 128), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := Load(path, LoadOptions{MaxBytes: 16}); !errors.Is(err, ErrSchema) {
		t.Errorf("Load error = %v, want ErrSchema for an oversized file", err)
	}
}

func TestParseRejectsUnsupportedSchema(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"empty", ""},
		{"malformed", `{"schema": "lisa/baseline/v1",`},
		{"not json", "this is not json"},
		{"array", `[]`},
		{"wrong schema", `{"schema": "lisa/baseline/v2", "version": 2}`},
		{"wrong version", `{"schema": "lisa/baseline/v1", "version": 99}`},
		{"no schema", `{"version": 1}`},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := Parse([]byte(testCase.content)); err == nil {
				t.Error("Parse accepted an unsupported document")
			}
		})
	}
}

func TestParseErrorsDoNotEchoUntrustedContent(t *testing.T) {
	content := []byte(`{"schema": "lisa/baseline/v1", "version": 1, ` +
		`"tool": {"name": "SECRET-CANARY", "version": "1"}, "created_at": "2026-03-04T05:06:07Z", ` +
		`"min_severity": "info", "roots": [], "coverage": {"scan_status": "complete", "complete": true}, ` +
		`"summary": {"findings": 1, "by_severity": {}}, "findings": [not json}`)

	_, err := Parse(content)
	if err == nil {
		t.Fatal("Parse accepted malformed trailing content")
	}
	if strings.Contains(err.Error(), "SECRET-CANARY") {
		t.Errorf("error message echoed untrusted content: %q", err)
	}
}

func TestParseRejectsRecordsThatFailValidation(t *testing.T) {
	valid := mustCreate(t, "/etc/passwd")

	cases := []struct {
		name    string
		mutate  func(*Document)
		mustErr string
	}{
		{"duplicate identifiers", func(d *Document) {
			d.Findings = append(d.Findings, d.Findings[0])
			d.Summary.Findings = 2
		}, "repeats the identity"},
		{"empty findings with a stale summary", func(d *Document) {
			d.Findings = nil
		}, "summary counts"},
		{"summary mismatch", func(d *Document) { d.Summary.Findings = 99 }, "summary counts"},
		{"invalid entry", func(d *Document) { d.Findings[0].ID = "tampered" }, "does not match its identity"},
		{"no tool name", func(d *Document) { d.Tool.Name = "" }, "tool.name is required"},
		{"bad min severity", func(d *Document) { d.MinSeverity = "extreme" }, "unknown severity"},
		{"bad timestamp", func(d *Document) { d.CreatedAt = "last tuesday" }, "RFC 3339"},
		{"relative root", func(d *Document) { d.Roots = []string{"etc"} }, "must be absolute"},
		{"unknown scan status", func(d *Document) { d.Coverage.ScanStatus = "weird" }, "is not one of"},
		{"coverage disagreement", func(d *Document) {
			d.Coverage.ScanStatus = "partial"
		}, "disagrees with scan_status"},
		{"relative inaccessible path", func(d *Document) {
			d.Coverage.InaccessiblePaths = []string{"root"}
		}, "must be absolute"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			document := *valid
			document.Findings = append([]Entry(nil), valid.Findings...)
			document.Summary = valid.Summary
			document.Coverage = valid.Coverage
			testCase.mutate(&document)

			_, err := Parse(mustMarshal(t, &document))
			if err == nil {
				t.Fatalf("Parse accepted a document with %s", testCase.name)
			}
			if !strings.Contains(err.Error(), testCase.mustErr) {
				t.Errorf("Parse error = %q, want it to mention %q", err, testCase.mustErr)
			}
		})
	}
}

func TestParseRejectsDuplicateIdentitiesWithDifferentContent(t *testing.T) {
	document := mustCreate(t, "/etc/passwd", "/etc/shadow")
	document.Findings[1].Path = document.Findings[0].Path
	document.Findings[1].ID = document.Findings[0].ID

	_, err := Parse(mustMarshal(t, document))
	if err == nil {
		t.Fatal("Parse accepted two records with the same identity")
	}
	if !errors.Is(err, ErrAmbiguousIdentity) {
		t.Errorf("error = %v, want ErrAmbiguousIdentity", err)
	}
}

func TestParseAcceptsABaselineOfACleanHost(t *testing.T) {
	document := mustCreate(t)
	if len(document.Findings) != 0 {
		t.Fatalf("fixture holds %d findings, want none", len(document.Findings))
	}
	if _, err := Parse(mustMarshal(t, document)); err != nil {
		t.Errorf("Parse rejected a baseline of a clean host: %v", err)
	}
}

func TestParseIgnoresUnknownFields(t *testing.T) {
	document := mustCreate(t, "/etc/passwd")
	content := mustMarshal(t, document)

	var generic map[string]any
	if err := json.Unmarshal(content, &generic); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	generic["a_field_from_the_future"] = "value"
	extended, err := json.Marshal(generic)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	if _, err := Parse(extended); err != nil {
		t.Errorf("Parse rejected a document with an unknown field: %v", err)
	}
}

func TestWrittenFileIsStableAcrossReloads(t *testing.T) {
	document := mustCreate(t, "/etc/shadow", "/etc/passwd")
	path := writeBaseline(t, document)

	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	loaded, err := Load(path, LoadOptions{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	second, err := loaded.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(first) != string(second) {
		t.Error("re-encoding a loaded baseline did not reproduce the file byte for byte")
	}
}

func mustMarshal(t *testing.T, document *Document) []byte {
	t.Helper()
	content, err := document.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return content
}
