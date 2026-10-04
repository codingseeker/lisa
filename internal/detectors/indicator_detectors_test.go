package detectors

import (
	"os"
	"strings"
	"testing"

	"lisa/internal/model"
)

func TestTemporaryExecutableDetector(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		mode    os.FileMode
		wantHit bool
	}{
		{"executable in tmp", "/tmp/updater", os.FileMode(0o755), true},
		{"executable in var tmp", "/var/tmp/payload", os.FileMode(0o755), true},
		{"executable in dev shm", "/dev/shm/loader", os.FileMode(0o777), true},
		{"non-executable in tmp", "/tmp/notes.txt", os.FileMode(0o644), false},
		{"executable outside temporary storage", "/usr/local/bin/updater", os.FileMode(0o755), false},
		{"path merely starting with tmp", "/tmpdata/tool", os.FileMode(0o755), false},
		{"home tmp directory is not temporary storage", "/home/alice/tmp/tool", os.FileMode(0o755), false},
	}

	detector := temporaryExecutableDetector{}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			findings := runDetectorOn(t, detector, entryAt(t, testCase.path, testCase.mode), nil)
			_, found := findingByRule(findings, "LS-IND-001")
			if found != testCase.wantHit {
				t.Errorf("LS-IND-001 present = %v, want %v (findings %v)", found, testCase.wantHit, ruleIDs(findings))
			}
			if found {
				finding, _ := findingByRule(findings, "LS-IND-001")
				if finding.Severity != model.SeverityMedium {
					t.Errorf("Severity = %v, want medium", finding.Severity)
				}
				if finding.Confidence != model.ConfidenceHigh {
					t.Errorf("Confidence = %v, want high", finding.Confidence)
				}
				if finding.Category != model.CategoryIndicator {
					t.Errorf("Category = %q, want indicator", finding.Category)
				}
			}
			assertValid(t, findings)
		})
	}
}

func TestMasqueradeDetector(t *testing.T) {
	const (
		elf    = "\x7fELF\x02\x01\x01\x00rest of the binary"
		script = "#!/bin/sh\necho hello\n"
		plain  = "%PDF-1.4\nthis is a real document\n"
	)

	cases := []struct {
		name     string
		path     string
		body     string
		wantRule string
		wantSev  model.Severity
	}{
		{"elf as document", "/home/alice/Documents/invoice.pdf", elf, "LS-IND-002", model.SeverityHigh},
		{"elf as image", "/home/alice/Downloads/photo.png", elf, "LS-IND-002", model.SeverityHigh},
		{"elf as text", "/srv/logs/payload.txt", elf, "LS-IND-003", model.SeverityMedium},
		{"elf as config", "/etc/app/loader.conf", elf, "LS-IND-003", model.SeverityMedium},
		{"script as document", "/home/alice/Documents/report.docx", script, "LS-IND-002", model.SeverityHigh},
		{"script as image", "/home/alice/Downloads/avatar.gif", script, "LS-IND-002", model.SeverityHigh},
		{"script as text", "/srv/notes/notes.txt", script, "LS-IND-003", model.SeverityMedium},
		{"elf without extension in downloads", "/home/alice/Downloads/invoice", elf, "LS-IND-005", model.SeverityMedium},
		{"script with non-script extension in downloads", "/home/alice/Downloads/setup", script, "LS-IND-004", model.SeverityMedium},
		{"genuine document", "/home/alice/Documents/report.pdf", plain, "", 0},
		{"genuine text file", "/srv/logs/app.log", "plain log line\n", "", 0},
		{"legitimate script with script extension", "/usr/local/bin/deploy.sh", script, "", 0},
		{"legitimate binary with binary extension", "/usr/local/bin/tool.bin", elf, "", 0},
		{"extensionless file outside user folders", "/srv/bin/tool", elf, "", 0},
		{"empty file", "/home/alice/Documents/empty.pdf", "", "", 0},
		{"text with document extension in system path", "/usr/share/doc/pkg/readme.pdf", plain, "", 0},
	}

	detector := masqueradeDetector{}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			reader := newStubReader(map[string]string{testCase.path: testCase.body})
			findings := runDetectorOn(t, detector, entryAt(t, testCase.path, os.FileMode(0o755)), reader)

			if testCase.wantRule == "" {
				if len(findings) != 0 {
					t.Errorf("benign content produced %v, want no findings", ruleIDs(findings))
				}
				return
			}
			finding, found := findingByRule(findings, testCase.wantRule)
			if !found {
				t.Fatalf("%s missing, got %v", testCase.wantRule, ruleIDs(findings))
			}
			if finding.Severity != testCase.wantSev {
				t.Errorf("Severity = %v, want %v", finding.Severity, testCase.wantSev)
			}
			evidence := strings.Join(finding.Evidence, " ")
			if !strings.Contains(evidence, "content=") {
				t.Errorf("Evidence = %v, should record the detected content type", finding.Evidence)
			}
			assertValid(t, findings)
		})
	}
}

func TestMasqueradeDetectorRespectsHeaderBudget(t *testing.T) {
	const body = "\x7fELF\x02\x01"
	reader := newStubReader(map[string]string{"/home/alice/Documents/a.pdf": body})

	entry := entryAt(t, "/home/alice/Documents/a.pdf", os.FileMode(0o755))
	budget := int64(0)
	ctx := testContext(entry, reader)
	ctx.headerBudget = &budget

	findings := masqueradeDetector{}.Detect(ctx)
	if len(findings) != 0 {
		t.Errorf("an exhausted header budget produced %v, want no findings", ruleIDs(findings))
	}
}

func TestMasqueradeDetectorBudgetIsConsumedOncePerEntry(t *testing.T) {
	const body = "\x7fELF\x02\x01"
	reader := newStubReader(map[string]string{"/home/alice/Documents/a.pdf": body})

	entry := entryAt(t, "/home/alice/Documents/a.pdf", os.FileMode(0o755))
	budget := int64(1)
	ctx := testContext(entry, reader)
	ctx.headerBudget = &budget

	firstCall := masqueradeDetector{}.Detect(ctx)
	if len(firstCall) != 1 {
		t.Fatalf("first call produced %v, want one finding", ruleIDs(firstCall))
	}
	if budget != 0 {
		t.Errorf("budget = %d after one header read, want 0", budget)
	}
	secondCall := masqueradeDetector{}.Detect(ctx)
	if len(secondCall) != 0 {
		t.Errorf("second call produced %v despite an exhausted budget", ruleIDs(secondCall))
	}
}

func TestExecutableKind(t *testing.T) {
	cases := []struct {
		header string
		want   string
	}{
		{"\x7fELF\x02\x01\x01", "an ELF binary"},
		{"#!/bin/sh\n", "an interpreted script"},
		{"#!/usr/bin/env python3\n", "an interpreted script"},
		{"%PDF-1.4", ""},
		{"", ""},
		{"MZ\x90\x00", ""},
	}
	for _, testCase := range cases {
		if got := executableKind([]byte(testCase.header)); got != testCase.want {
			t.Errorf("executableKind(%q) = %q, want %q", testCase.header, got, testCase.want)
		}
	}
}

func TestMasqueradeDetectorIgnoresDirectories(t *testing.T) {
	findings := runDetectorOn(t, masqueradeDetector{},
		dirEntryAt(t, "/home/alice/Documents", os.FileMode(0o755)), nil)
	if len(findings) != 0 {
		t.Errorf("directory produced %v, want no findings", ruleIDs(findings))
	}
}
