package detectors

import (
	"os"
	"strings"
	"testing"

	"lisa/internal/model"
)

func TestSSHDConfigDetector(t *testing.T) {
	const path = "/etc/ssh/sshd_config"

	cases := []struct {
		name     string
		body     string
		wantRule string
		wantSev  model.Severity
	}{
		{"permit root login yes", "PermitRootLogin yes\n", "LS-SENS-001", model.SeverityHigh},
		{"permit root login no", "PermitRootLogin no\n", "", 0},
		{"permit root login without-password", "PermitRootLogin prohibit-password\n", "", 0},
		{"empty passwords yes", "PermitEmptyPasswords yes\n", "LS-SENS-002", model.SeverityHigh},
		{"empty passwords no", "PermitEmptyPasswords no\n", "", 0},
		{"user environment yes", "PermitUserEnvironment yes\n", "LS-SENS-003", model.SeverityMedium},
		{"password authentication yes", "PasswordAuthentication yes\n", "LS-SENS-004", model.SeverityLow},
		{"password authentication no", "PasswordAuthentication no\n", "", 0},
		{"equals separator", "PermitRootLogin=yes\n", "LS-SENS-001", model.SeverityHigh},
		{"mixed case key", "permitrootlogin YES\n", "LS-SENS-001", model.SeverityHigh},
		{"leading whitespace", "   PermitRootLogin   yes   \n", "LS-SENS-001", model.SeverityHigh},
		{"commented out is ignored", "#PermitRootLogin yes\n", "", 0},
		{"first occurrence wins", "PermitRootLogin yes\nPermitRootLogin no\n", "LS-SENS-001", model.SeverityHigh},
		{"first occurrence wins the other way", "PermitRootLogin no\nPermitRootLogin yes\n", "", 0},
		{"multiple directives", "Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\n", "LS-SENS-001", model.SeverityHigh},
		{"benign configuration", "Port 22\nProtocol 2\nBanner /etc/issue.net\n", "", 0},
		{"empty file", "", "", 0},
	}

	detector := sshdConfigDetector{}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			reader := newStubReader(map[string]string{path: testCase.body})
			findings := runDetectorOn(t, detector, entryAt(t, path, os.FileMode(0o644)), reader)

			if testCase.wantRule == "" {
				if len(findings) != 0 {
					t.Errorf("configuration produced %v, want no findings", ruleIDs(findings))
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
			if finding.Category != model.CategorySensitiveConfig {
				t.Errorf("Category = %q, want sensitive-config", finding.Category)
			}
			if joined := strings.Join(finding.Evidence, " | "); !strings.Contains(joined, "first matching directive wins") {
				t.Errorf("Evidence = %v, should explain sshd precedence", finding.Evidence)
			}
			assertValid(t, findings)
		})
	}
}

func TestSSHDConfigDetectorOnlyReadsTheRealConfigPath(t *testing.T) {
	detector := sshdConfigDetector{}
	for _, path := range []string{"/etc/ssh/sshd_config.d/override.conf", "/etc/ssh/ssh_config", "/home/alice/.ssh/config"} {
		reader := newStubReader(map[string]string{path: "PermitRootLogin yes\n"})
		findings := runDetectorOn(t, detector, entryAt(t, path, os.FileMode(0o644)), reader)
		if len(findings) != 0 {
			t.Errorf("%s produced %v, want no findings", path, ruleIDs(findings))
		}
		if len(reader.readPaths()) != 0 {
			t.Errorf("%s must not be read by the sshd config detector", path)
		}
	}
}

func TestSSHDConfigDetectorUnreadableFile(t *testing.T) {
	const path = "/etc/ssh/sshd_config"
	reader := newStubReader(map[string]string{path: "PermitRootLogin yes\n"})
	reader.fail[path] = true

	findings := runDetectorOn(t, sshdConfigDetector{}, entryAt(t, path, os.FileMode(0o644)), reader)
	if len(findings) != 0 {
		t.Errorf("unreadable config produced %v, want no findings", ruleIDs(findings))
	}
}

func TestParseSSHDDirectives(t *testing.T) {
	directives := parseSSHDDirectives(strings.Join([]string{
		"# comment",
		"",
		"Port 22",
		"Port=2222",
		"PermitRootLogin   yes",
		"  Banner  /etc/issue  ",
	}, "\n"))

	if directives["port"] != "22" {
		t.Errorf("port = %q, want the first occurrence 22", directives["port"])
	}
	if directives["permitrootlogin"] != "yes" {
		t.Errorf("permitrootlogin = %q, want yes", directives["permitrootlogin"])
	}
	if directives["banner"] != "/etc/issue" {
		t.Errorf("banner = %q, want /etc/issue", directives["banner"])
	}
	if _, present := directives["# comment"]; present {
		t.Error("comments must not become directives")
	}
}

func TestSudoersDetector(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		body    string
		wantHit bool
	}{
		{"nopasswd in sudoers", "/etc/sudoers", "alice ALL=(ALL) NOPASSWD: ALL\n", true},
		{"nopasswd dropin", "/etc/sudoers.d/90-deploy", "deploy ALL=(ALL) NOPASSWD: /usr/bin/deploy\n", true},
		{"lowercase nopasswd", "/etc/sudoers", "bob all=(all) nopasswd: all\n", true},
		{"password required", "/etc/sudoers", "alice ALL=(ALL:ALL) ALL\n", false},
		{"commented nopasswd", "/etc/sudoers", "# alice ALL=(ALL) NOPASSWD: ALL\n", false},
		{"empty sudoers", "/etc/sudoers", "", false},
		{"unrelated path ignored", "/opt/app/sudoers.md", "NOPASSWD: ALL\n", false},
	}

	detector := sudoersDetector{}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			reader := newStubReader(map[string]string{testCase.path: testCase.body})
			findings := runDetectorOn(t, detector, entryAt(t, testCase.path, os.FileMode(0o440)), reader)
			_, found := findingByRule(findings, "LS-SENS-005")
			if found != testCase.wantHit {
				t.Errorf("LS-SENS-005 present = %v, want %v (findings %v)", found, testCase.wantHit, ruleIDs(findings))
			}
			if found {
				finding, _ := findingByRule(findings, "LS-SENS-005")
				if finding.Severity != model.SeverityMedium {
					t.Errorf("Severity = %v, want medium", finding.Severity)
				}
				if finding.Confidence != model.ConfidenceMedium {
					t.Errorf("Confidence = %v, want medium; sudoers parsing is heuristic", finding.Confidence)
				}
			}
			assertValid(t, findings)
		})
	}
}

func TestSudoersDetectorOnlyReadsSudoersPaths(t *testing.T) {
	detector := sudoersDetector{}
	for _, path := range []string{"/etc/sudoers.bak", "/etc/sudoers.d", "/home/alice/.sudoers"} {
		reader := newStubReader(map[string]string{path: "NOPASSWD: ALL\n"})
		findings := runDetectorOn(t, detector, entryAt(t, path, os.FileMode(0o440)), reader)
		if len(findings) != 0 {
			t.Errorf("%s produced %v, want no findings", path, ruleIDs(findings))
		}
		if len(reader.readPaths()) != 0 {
			t.Errorf("%s must not be read by the sudoers detector", path)
		}
	}
}
