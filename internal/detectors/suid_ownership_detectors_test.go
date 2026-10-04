package detectors

import (
	"os"
	"strings"
	"testing"

	"lisa/internal/model"
)

func TestSuidDetectorSetuidAndSetgid(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		mode     os.FileMode
		wantRule string
		wantSev  model.Severity
	}{
		{"setuid in a standard binary directory", "/usr/bin/passwd",
			os.FileMode(0o755) | os.ModeSetuid, "LS-PRIV-001", model.SeverityLow},
		{"setuid outside system directories", "/home/alice/.local/bin/helper",
			os.FileMode(0o755) | os.ModeSetuid, "LS-PRIV-003", model.SeverityMedium},
		{"setgid in a standard binary directory", "/usr/bin/wall",
			os.FileMode(0o755) | os.ModeSetgid, "LS-PRIV-002", model.SeverityLow},
		{"setgid outside system directories", "/opt/tools/backup",
			os.FileMode(0o755) | os.ModeSetgid, "LS-PRIV-002", model.SeverityLow},
		{"setuid in a temporary directory", "/tmp/rootshell",
			os.FileMode(0o755) | os.ModeSetuid, "LS-PRIV-003", model.SeverityMedium},
	}

	detector := suidDetector{}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			findings := runDetectorOn(t, detector, entryAt(t, testCase.path, testCase.mode), nil)
			finding, found := findingByRule(findings, testCase.wantRule)
			if !found {
				t.Fatalf("%s missing, got %v", testCase.wantRule, ruleIDs(findings))
			}
			if finding.Severity != testCase.wantSev {
				t.Errorf("Severity = %v, want %v", finding.Severity, testCase.wantSev)
			}
			if finding.Category != model.CategoryIndicator {
				t.Errorf("Category = %q, want indicator", finding.Category)
			}
			leading := finding.PermissionString()[0:1]
			if leading != "2" && leading != "4" && leading != "6" {
				t.Errorf("PermissionString = %q, want a setuid or setgid mode", finding.PermissionString())
			}
			assertValid(t, findings)
		})
	}
}

func TestSuidDetectorReportsBothBits(t *testing.T) {
	mode := os.FileMode(0o755) | os.ModeSetuid | os.ModeSetgid
	findings := runDetectorOn(t, suidDetector{}, entryAt(t, "/usr/bin/both", mode), nil)

	if _, ok := findingByRule(findings, "LS-PRIV-001"); !ok {
		t.Errorf("LS-PRIV-001 missing for a setuid+setgid binary, got %v", ruleIDs(findings))
	}
	if _, ok := findingByRule(findings, "LS-PRIV-002"); !ok {
		t.Errorf("LS-PRIV-002 missing for a setuid+setgid binary, got %v", ruleIDs(findings))
	}
	assertNoDuplicateRulePaths(t, findings)
}

func TestSuidDetectorIgnoresOrdinaryFiles(t *testing.T) {
	for _, path := range []string{"/usr/bin/plain", "/usr/local/bin/tool", "/opt/app/daemon"} {
		for _, mode := range []os.FileMode{0o755, 0o777, 0o700, 0o4755 &^ os.ModeSetuid} {
			findings := runDetectorOn(t, suidDetector{}, entryAt(t, path, mode), nil)
			if len(findings) != 0 {
				t.Errorf("%s at %04o produced %v, want no findings", path, mode.Perm(), ruleIDs(findings))
			}
		}
	}
}

func TestSuidDetectorIgnoresDirectories(t *testing.T) {
	findings := runDetectorOn(t, suidDetector{},
		dirEntryAt(t, "/usr/bin", os.FileMode(0o755)|os.ModeSetuid), nil)
	if len(findings) != 0 {
		t.Errorf("a setuid directory produced %v, want no findings", ruleIDs(findings))
	}
}

func TestOwnershipDetectorOrphanedUser(t *testing.T) {
	entry := entryAt(t, "/srv/data/report.txt", os.FileMode(0o644))
	ctx := testContext(entry, nil)
	ctx.Identity = testIdentity(t)
	ctx.UID = 4242
	ctx.GID = 1000
	ctx.Group = "alice"
	ctx.HaveOwner = true

	findings := ownershipDetector{}.Detect(ctx)
	finding, found := findingByRule(findings, "LS-OWN-002")
	if !found {
		t.Fatalf("LS-OWN-002 missing, got %v", ruleIDs(findings))
	}
	if finding.Severity != model.SeverityMedium {
		t.Errorf("Severity = %v, want medium", finding.Severity)
	}
	if finding.Confidence != model.ConfidenceMedium {
		t.Errorf("Confidence = %v, want medium; orphan detection depends on the passwd file", finding.Confidence)
	}
	if !strings.Contains(finding.Description, "4242") {
		t.Errorf("Description %q should record the orphaned uid", finding.Description)
	}
	assertValid(t, findings)
}

func TestOwnershipDetectorOrphanedGroup(t *testing.T) {
	entry := entryAt(t, "/srv/data/report.txt", os.FileMode(0o644))
	ctx := testContext(entry, nil)
	ctx.Identity = testIdentity(t)
	ctx.UID = 1000
	ctx.User = "alice"
	ctx.GID = 7777
	ctx.HaveOwner = true

	findings := ownershipDetector{}.Detect(ctx)
	finding, found := findingByRule(findings, "LS-OWN-003")
	if !found {
		t.Fatalf("LS-OWN-003 missing, got %v", ruleIDs(findings))
	}
	if finding.Severity != model.SeverityLow {
		t.Errorf("Severity = %v, want low", finding.Severity)
	}
	assertValid(t, findings)
}

func TestOwnershipDetectorKnownIDsAreClean(t *testing.T) {
	entry := entryAt(t, "/srv/data/report.txt", os.FileMode(0o644))
	ctx := testContext(entry, nil)
	ctx.Identity = testIdentity(t)
	ctx.UID = 1000
	ctx.User = "alice"
	ctx.GID = 1000
	ctx.Group = "alice"
	ctx.HaveOwner = true

	findings := ownershipDetector{}.Detect(ctx)
	assertNoRule(t, findings, "LS-OWN-002")
	assertNoRule(t, findings, "LS-OWN-003")
	assertNoRule(t, findings, "LS-OWN-004")
}

func TestOwnershipDetectorSkippedWithoutIdentityData(t *testing.T) {
	entry := entryAt(t, "/etc/hosts", os.FileMode(0o644))
	ctx := testContext(entry, nil)
	ctx.Identity = emptyIdentity()
	ctx.UID = 9999
	ctx.GID = 9999
	ctx.HaveOwner = true

	findings := ownershipDetector{}.Detect(ctx)
	assertNoRule(t, findings, "LS-OWN-002")
	assertNoRule(t, findings, "LS-OWN-003")
}

func TestOwnershipDetectorWithoutOwnershipMetadata(t *testing.T) {
	entry := entryAt(t, "/usr/bin/tool", os.FileMode(0o644))
	ctx := testContext(entry, nil)
	ctx.UID = 0
	ctx.GID = 0
	ctx.User = ""
	ctx.Group = ""
	ctx.HaveOwner = false

	findings := ownershipDetector{}.Detect(ctx)
	if len(findings) != 0 {
		t.Errorf("entry without ownership metadata produced %v, want no findings", ruleIDs(findings))
	}
}

func TestOwnershipDetectorUnprivilegedOwnerInSystemDirectory(t *testing.T) {
	cases := []struct {
		path    string
		wantHit bool
	}{
		{"/usr/bin/owned-by-user", true},
		{"/etc/owned-by-user", true},
		{"/boot/owned-by-user", true},
		{"/usr/local/bin/owned-by-user", true},
		{"/home/alice/owned-by-user", false},
		{"/srv/www/owned-by-user", false},
		{"/opt/app/owned-by-user", false},
	}

	detector := ownershipDetector{}
	for _, testCase := range cases {
		t.Run(testCase.path, func(t *testing.T) {
			entry := entryAt(t, testCase.path, os.FileMode(0o644))
			ctx := testContext(entry, nil)
			ctx.Identity = testIdentity(t)
			ctx.UID = 1001
			ctx.User = "bob"
			ctx.GID = 1001
			ctx.Group = "bob"
			ctx.HaveOwner = true

			findings := detector.Detect(ctx)
			_, found := findingByRule(findings, "LS-OWN-004")
			if found != testCase.wantHit {
				t.Errorf("LS-OWN-004 present = %v, want %v (findings %v)", found, testCase.wantHit, ruleIDs(findings))
			}
		})
	}
}

func TestOwnershipDetectorIgnoresSystemAccounts(t *testing.T) {
	entry := entryAt(t, "/usr/bin/owned-by-daemon", os.FileMode(0o644))
	ctx := testContext(entry, nil)
	ctx.Identity = testIdentity(t)
	ctx.UID = 1
	ctx.User = "daemon"
	ctx.GID = 1
	ctx.Group = "daemon"
	ctx.HaveOwner = true

	findings := ownershipDetector{}.Detect(ctx)
	assertNoRule(t, findings, "LS-OWN-004")
}

func TestOwnershipDetectorIgnoresDirectories(t *testing.T) {
	dirFindings := ownershipDetector{}.Detect(testContext(dirEntryAt(t, "/usr/bin", os.FileMode(0o755)), nil))
	if len(dirFindings) != 0 {
		t.Errorf("directory produced %v, want no findings", ruleIDs(dirFindings))
	}

}

func TestRuleCatalogueHasUniqueIdentifiers(t *testing.T) {
	seen := map[string]bool{}
	for _, rule := range allRules() {
		if err := rule.Validate(); err != nil {
			t.Errorf("rule %s is invalid: %v", rule.ID, err)
		}
		if seen[rule.ID] {
			t.Errorf("duplicate rule id %s", rule.ID)
		}
		seen[rule.ID] = true
	}
	if len(seen) < 30 {
		t.Errorf("rule catalogue holds %d rules, expected the full documented set", len(seen))
	}
}
