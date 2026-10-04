package detectors

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lisa/internal/model"
)

func TestPermissionsDetectorWorldWritableRegularFile(t *testing.T) {
	entry := entryAt(t, "/srv/data/report.txt", os.FileMode(0o666))
	findings := runDetectorOn(t, worldWritableDetector{}, entry, nil)

	if len(findings) != 1 {
		t.Fatalf("findings = %v, want exactly one", ruleIDs(findings))
	}
	finding := findings[0]
	if finding.RuleID != "LS-PERM-001" {
		t.Errorf("RuleID = %q, want LS-PERM-001", finding.RuleID)
	}
	if finding.Severity != model.SeverityMedium {
		t.Errorf("Severity = %v, want medium", finding.Severity)
	}
	if finding.Confidence != model.ConfidenceHigh {
		t.Errorf("Confidence = %v, want high", finding.Confidence)
	}
	if finding.Category != model.CategoryPermissions {
		t.Errorf("Category = %q, want permissions", finding.Category)
	}
	if finding.Path != "/srv/data/report.txt" {
		t.Errorf("Path = %q, want the synthetic path", finding.Path)
	}
	if finding.PermissionString() != "0666" {
		t.Errorf("PermissionString = %q, want 0666", finding.PermissionString())
	}
	if len(finding.Evidence) == 0 || !strings.Contains(finding.Evidence[0], "0666") {
		t.Errorf("Evidence = %v, want the mode recorded", finding.Evidence)
	}
	assertValid(t, findings)
}

func TestPermissionsDetectorEscalatesForSystemDirectories(t *testing.T) {
	cases := []struct {
		path     string
		wantRule string
		wantSev  model.Severity
	}{
		{"/usr/bin/tool", "LS-PERM-007", model.SeverityHigh},
		{"/etc/ld.so.conf", "LS-PERM-007", model.SeverityHigh},
		{"/boot/vmlinuz", "LS-PERM-007", model.SeverityHigh},
		{"/tmp/staged.bin", "LS-PERM-008", model.SeverityMedium},
		{"/var/tmp/staged.bin", "LS-PERM-008", model.SeverityMedium},
		{"/dev/shm/staged.bin", "LS-PERM-008", model.SeverityMedium},
		{"/home/alice/notes.txt", "LS-PERM-001", model.SeverityMedium},
		{"/opt/app/data.json", "LS-PERM-001", model.SeverityMedium},
	}
	for _, testCase := range cases {
		t.Run(testCase.path, func(t *testing.T) {
			findings := runDetectorOn(t, worldWritableDetector{}, entryAt(t, testCase.path, os.FileMode(0o666)), nil)
			if len(findings) != 1 {
				t.Fatalf("findings = %v, want exactly one", ruleIDs(findings))
			}
			if findings[0].RuleID != testCase.wantRule {
				t.Errorf("RuleID = %q, want %q", findings[0].RuleID, testCase.wantRule)
			}
			if findings[0].Severity != testCase.wantSev {
				t.Errorf("Severity = %v, want %v", findings[0].Severity, testCase.wantSev)
			}
		})
	}
}

func TestPermissionsDetectorDirectories(t *testing.T) {
	sticky := runDetectorOn(t, worldWritableDetector{}, dirEntryAt(t, "/srv/shared", os.FileMode(0o777)|os.ModeSticky), nil)
	if len(sticky) != 1 || sticky[0].RuleID != "LS-PERM-003" {
		t.Fatalf("sticky directory findings = %v, want LS-PERM-003", ruleIDs(sticky))
	}
	if sticky[0].Severity != model.SeverityInfo {
		t.Errorf("sticky directory Severity = %v, want info", sticky[0].Severity)
	}

	plain := runDetectorOn(t, worldWritableDetector{}, dirEntryAt(t, "/srv/shared", os.FileMode(0o777)), nil)
	if len(plain) != 1 || plain[0].RuleID != "LS-PERM-002" {
		t.Fatalf("plain world-writable directory findings = %v, want LS-PERM-002", ruleIDs(plain))
	}
	if plain[0].Severity != model.SeverityMedium {
		t.Errorf("Severity = %v, want medium", plain[0].Severity)
	}
	assertValid(t, append(sticky, plain...))
}

func TestPermissionsDetectorIgnoresSafeModes(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o600, 0o755, 0o750, 0o640} {
		findings := runDetectorOn(t, worldWritableDetector{}, entryAt(t, "/srv/data/file", mode), nil)
		if len(findings) != 0 {
			t.Errorf("mode %04o produced %v, want no findings", mode.Perm(), ruleIDs(findings))
		}
	}
}

func TestPermissionsDetectorIgnoresNonRegularWorldWritableFiles(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "pipe")
	if err := mkfifo(fifo); err != nil {
		t.Skipf("cannot create a FIFO: %v", err)
	}
	info, err := os.Lstat(fifo)
	if err != nil {
		t.Fatalf("lstat failed: %v", err)
	}
	entry := fsscanEntry("/tmp/pipe", info)
	findings := runDetectorOn(t, worldWritableDetector{}, entry, nil)
	if len(findings) != 0 {
		t.Errorf("a world-writable FIFO produced %v, want no findings", ruleIDs(findings))
	}
}

func TestSensitivePermissionDetector(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		mode    os.FileMode
		wantHit bool
		wantSev model.Severity
	}{
		{"shadow group readable", "/etc/shadow", os.FileMode(0o640), true, model.SeverityHigh},
		{"shadow world readable", "/etc/shadow", os.FileMode(0o644), true, model.SeverityHigh},
		{"shadow correctly restricted", "/etc/shadow", os.FileMode(0o600), false, 0},
		{"shadow root owned 0640 still group readable", "/etc/shadow", os.FileMode(0o640), true, model.SeverityHigh},
		{"gshadow world readable", "/etc/gshadow", os.FileMode(0o604), true, model.SeverityHigh},
		{"sudoers world writable", "/etc/sudoers", os.FileMode(0o666), true, model.SeverityHigh},
		{"sudoers group writable", "/etc/sudoers", os.FileMode(0o660), true, model.SeverityHigh},
		{"sudoers correct", "/etc/sudoers", os.FileMode(0o440), false, 0},
		{"sudoers dropin world writable", "/etc/sudoers.d/90-local", os.FileMode(0o666), true, model.SeverityMedium},
		{"sshd_config world writable", "/etc/ssh/sshd_config", os.FileMode(0o666), true, model.SeverityMedium},
		{"passwd world writable", "/etc/passwd", os.FileMode(0o666), true, model.SeverityLow},
		{"fstab group writable is tolerated", "/etc/fstab", os.FileMode(0o660), false, 0},
		{"unrelated file ignored", "/etc/hosts", os.FileMode(0o666), false, 0},
		{"similar name ignored", "/etc/shadow.bak", os.FileMode(0o666), false, 0},
	}

	detector := sensitivePermissionDetector{}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			findings := runDetectorOn(t, detector, entryAt(t, testCase.path, testCase.mode), nil)
			finding, found := findingByRule(findings, "LS-PERM-004")
			if found != testCase.wantHit {
				t.Fatalf("LS-PERM-004 present = %v, want %v (findings %v)", found, testCase.wantHit, ruleIDs(findings))
			}
			if found && finding.Severity != testCase.wantSev {
				t.Errorf("Severity = %v, want %v", finding.Severity, testCase.wantSev)
			}
			if found && finding.Category != model.CategorySensitiveConfig {
				t.Errorf("Category = %q, want sensitive-config", finding.Category)
			}
			assertValid(t, findings)
		})
	}
}

func TestSensitivePermissionDetectorNonRootOwnership(t *testing.T) {
	entry := entryAt(t, "/etc/shadow", os.FileMode(0o600))
	ctx := testContext(entry, nil)
	ctx.UID = 1000
	ctx.GID = 1000
	ctx.User = "alice"
	ctx.Group = "alice"
	ctx.HaveOwner = true

	findings := sensitivePermissionDetector{}.Detect(ctx)
	finding, found := findingByRule(findings, "LS-OWN-001")
	if !found {
		t.Fatalf("LS-OWN-001 missing, got %v", ruleIDs(findings))
	}
	if finding.Severity != model.SeverityHigh {
		t.Errorf("Severity = %v, want high", finding.Severity)
	}
	if finding.OwnerName() != "alice" {
		t.Errorf("Owner = %q, want alice", finding.OwnerName())
	}
	if !strings.Contains(finding.Description, "alice") {
		t.Errorf("Description %q should name the owning account", finding.Description)
	}
	assertValid(t, findings)
}

func TestSensitivePermissionDetectorRootOwnershipIsClean(t *testing.T) {
	entry := entryAt(t, "/etc/shadow", os.FileMode(0o600))
	ctx := testContext(entry, nil)
	ctx.UID = 0
	ctx.GID = 0
	ctx.User = "root"
	ctx.Group = "root"
	ctx.HaveOwner = true

	findings := sensitivePermissionDetector{}.Detect(ctx)
	assertNoRule(t, findings, "LS-OWN-001")
}

func TestSSHKeyDetectorPrivateKeys(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		mode    os.FileMode
		wantHit bool
	}{
		{"user key world readable", "/home/alice/.ssh/id_rsa", os.FileMode(0o644), true},
		{"user key group readable", "/home/alice/.ssh/id_ed25519", os.FileMode(0o640), true},
		{"user key correct", "/home/alice/.ssh/id_rsa", os.FileMode(0o600), false},
		{"root key correct", "/root/.ssh/id_rsa", os.FileMode(0o600), false},
		{"root key exposed", "/root/.ssh/id_rsa", os.FileMode(0o644), true},
		{"host key correct", "/etc/ssh/ssh_host_ed25519_key", os.FileMode(0o600), false},
		{"host key exposed", "/etc/ssh/ssh_host_rsa_key", os.FileMode(0o644), true},
		{"public key ignored", "/home/alice/.ssh/id_rsa.pub", os.FileMode(0o644), false},
		{"unrelated ssh file ignored", "/home/alice/.ssh/known_hosts", os.FileMode(0o644), false},
	}

	detector := sshKeyDetector{}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			findings := runDetectorOn(t, detector, entryAt(t, testCase.path, testCase.mode), nil)
			_, found := findingByRule(findings, "LS-PERM-005")
			if found != testCase.wantHit {
				t.Errorf("LS-PERM-005 present = %v, want %v (findings %v)", found, testCase.wantHit, ruleIDs(findings))
			}
			assertValid(t, findings)
		})
	}
}

func TestSSHKeyDetectorAuthorizedKeys(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		mode    os.FileMode
		wantHit bool
		wantSev model.Severity
	}{
		{"correctly restricted", "/home/alice/.ssh/authorized_keys", os.FileMode(0o600), false, 0},
		{"world readable", "/home/alice/.ssh/authorized_keys", os.FileMode(0o644), true, model.SeverityMedium},
		{"group readable", "/root/.ssh/authorized_keys", os.FileMode(0o640), true, model.SeverityMedium},
		{"world writable", "/home/bob/.ssh/authorized_keys", os.FileMode(0o666), true, model.SeverityMedium},
		{"authorized_keys2 also covered", "/home/bob/.ssh/authorized_keys2", os.FileMode(0o644), true, model.SeverityMedium},
		{"similarly named file ignored", "/home/bob/.ssh/authorized_keys.old", os.FileMode(0o644), false, 0},
	}

	detector := sshKeyDetector{}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			findings := runDetectorOn(t, detector, entryAt(t, testCase.path, testCase.mode), nil)
			finding, found := findingByRule(findings, "LS-PERM-006")
			if found != testCase.wantHit {
				t.Fatalf("LS-PERM-006 present = %v, want %v (findings %v)", found, testCase.wantHit, ruleIDs(findings))
			}
			if found {
				if finding.Severity != testCase.wantSev {
					t.Errorf("Severity = %v, want %v", finding.Severity, testCase.wantSev)
				}
				if finding.Technique == nil || finding.Technique.ID != "T1552.001" {
					t.Errorf("Technique = %v, want T1552.001", finding.Technique)
				}
			}
			assertValid(t, findings)
		})
	}
}
