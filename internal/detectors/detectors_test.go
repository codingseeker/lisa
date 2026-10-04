package detectors

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lisa/internal/fsscan"
	"lisa/internal/model"
)

var fixedNow = time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)

const testPasswd = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
messagebus:x:100:101::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
alice:x:1000:1000::/home/alice:/bin/bash
bob:x:1001:1001::/home/bob:/bin/bash
`

const testGroup = `root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:
messagebus:x:101:
sshd:x:65534:
alice:x:1000:
bob:x:1001:
`

func testIdentity(t *testing.T) *Identity {
	t.Helper()
	identity, err := LoadIdentity(strings.NewReader(testPasswd), strings.NewReader(testGroup))
	if err != nil {
		t.Fatalf("LoadIdentity failed: %v", err)
	}
	return identity
}

func emptyIdentity() *Identity {
	identity, err := LoadIdentity(strings.NewReader(""), strings.NewReader(""))
	if err != nil {
		panic(err)
	}
	return identity
}

func entryAt(t *testing.T, syntheticPath string, mode os.FileMode) fsscan.Entry {
	t.Helper()
	real := filepath.Join(t.TempDir(), "carrier")
	if err := os.WriteFile(real, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("writing carrier failed: %v", err)
	}
	if err := os.Chmod(real, mode); err != nil {
		t.Skipf("cannot set mode %v: %v", mode, err)
	}
	info, err := os.Lstat(real)
	if err != nil {
		t.Fatalf("lstat failed: %v", err)
	}
	return fsscan.Entry{Path: syntheticPath, Root: "/", Info: info}
}

func dirEntryAt(t *testing.T, syntheticPath string, mode os.FileMode) fsscan.Entry {
	t.Helper()
	real := filepath.Join(t.TempDir(), "carrierdir")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatalf("creating carrier dir failed: %v", err)
	}
	if err := os.Chmod(real, mode); err != nil {
		t.Skipf("cannot set mode %v: %v", mode, err)
	}
	info, err := os.Lstat(real)
	if err != nil {
		t.Fatalf("lstat failed: %v", err)
	}
	return fsscan.Entry{Path: syntheticPath, Root: "/", Info: info}
}

type stubReader struct {
	content map[string]string
	fail    map[string]bool
	calls   []string
}

func newStubReader(content map[string]string) *stubReader {
	return &stubReader{content: content, fail: map[string]bool{}}
}

func (s *stubReader) Read(path string, limit int64) ([]byte, error) {
	s.calls = append(s.calls, path)
	if s.fail[path] {
		return nil, os.ErrPermission
	}
	body, ok := s.content[path]
	if !ok {
		return nil, nil
	}
	if limit > 0 && int64(len(body)) > limit {
		body = body[:limit]
	}
	return []byte(body), nil
}

func (s *stubReader) readPaths() []string {
	return append([]string(nil), s.calls...)
}

func testContext(entry fsscan.Entry, reader FileReader) Context {
	ctx := newContext(entry, Options{
		Identity: emptyIdentity(),
		ReadFile: reader,
		Now:      fixedNow,
	})
	return ctx
}

func runDetectorOn(t *testing.T, detector Detector, entry fsscan.Entry, reader FileReader) []model.Finding {
	t.Helper()
	if reader == nil {
		reader = newLimitedFileReader(256*1024, 8*1024*1024)
	}
	return detector.Detect(testContext(entry, reader))
}

func findingByRule(findings []model.Finding, ruleID string) (model.Finding, bool) {
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return finding, true
		}
	}
	return model.Finding{}, false
}

func ruleIDs(findings []model.Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		ids = append(ids, finding.RuleID)
	}
	return ids
}

func assertNoRule(t *testing.T, findings []model.Finding, ruleID string) {
	t.Helper()
	if _, found := findingByRule(findings, ruleID); found {
		t.Errorf("unexpected finding %s in %v", ruleID, ruleIDs(findings))
	}
}

func assertValid(t *testing.T, findings []model.Finding) {
	t.Helper()
	for _, finding := range findings {
		if err := finding.Validate(); err != nil {
			t.Errorf("finding %s is invalid: %v", finding.RuleID, err)
		}
		if finding.DetectedAt.IsZero() {
			t.Errorf("finding %s has a zero detection timestamp", finding.RuleID)
		}
	}
}

func marshalFinding(t *testing.T, finding model.Finding) string {
	t.Helper()
	data, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("marshalling finding failed: %v", err)
	}
	return string(data)
}

func assertNoDuplicateRulePaths(t *testing.T, findings []model.Finding) {
	t.Helper()
	seen := map[string]struct{}{}
	for _, finding := range findings {
		key := finding.RuleID + "\x00" + finding.Path
		if _, duplicate := seen[key]; duplicate {
			t.Errorf("duplicate finding for rule %s on path %s", finding.RuleID, finding.Path)
		}
		seen[key] = struct{}{}
	}
}
func fsscanEntry(path string, info os.FileInfo) fsscan.Entry {
	return fsscan.Entry{Path: path, Root: "/", Info: info}
}

func itoaTest(value int) string {
	if value == 0 {
		return "0"
	}
	digits := ""
	for value > 0 {
		digits = string(rune('0'+value%10)) + digits
		value /= 10
	}
	return digits
}
