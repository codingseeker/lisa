package correlation

import (
	"strings"
	"testing"
	"time"

	"lisa/internal/attack"
	"lisa/internal/model"
	"lisa/internal/scan"
)

var fixedInstant = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

func ruleFinding(ruleID, path string, mode uint32, owner string, category model.Category) model.Finding {
	finding := model.Rule{
		ID:         ruleID,
		Title:      ruleID + " title",
		Severity:   model.SeverityMedium,
		Confidence: model.ConfidenceHigh,
		Category:   category,
	}.Finding(path)
	finding = finding.WithMode(mode)
	if owner != "" {
		finding = finding.WithOwner(owner).WithGroup("group")
	}
	finding.DetectedAt = fixedInstant
	return finding
}

func resultWith(findings ...model.Finding) *scan.Result {
	return &scan.Result{
		Status:      scan.StatusComplete,
		Findings:    findings,
		MinSeverity: model.SeverityInfo,
		StartedAt:   fixedInstant,
		FinishedAt:  fixedInstant,
	}
}

func analyse(t *testing.T, result *scan.Result) []model.Correlation {
	t.Helper()
	return Analyse(result, Options{Attack: attack.Dataset()})
}

func findRecord(t *testing.T, records []model.Correlation, ruleID string) model.Correlation {
	t.Helper()
	for _, record := range records {
		if record.RuleID == ruleID {
			return record
		}
	}
	t.Fatalf("no record for %s in %d record(s)", ruleID, len(records))
	return model.Correlation{}
}

func ruleIDsOfRecords(records []model.Correlation) []string {
	ids := make([]string, len(records))
	for i, record := range records {
		ids[i] = record.RuleID
	}
	return ids
}

func TestWritablePersistenceEntryCorrelatesWithItsPermissionsFinding(t *testing.T) {
	persistence := ruleFinding("LS-PERS-001", "/etc/cron.d/job", 0o666, "root", model.CategoryPersistence)
	permissions := ruleFinding("LS-PERM-001", "/etc/cron.d/job", 0o666, "root", model.CategoryPermissions)

	records := analyse(t, resultWith(persistence, permissions))
	if len(records) != 1 {
		t.Fatalf("got %d record(s) %v, want one", len(records), ruleIDsOfRecords(records))
	}

	record := findRecord(t, records, "LS-COR-001")
	if record.Confidence != model.CorrelationHigh {
		t.Errorf("Confidence = %q, want high", record.Confidence)
	}
	if len(record.FindingIDs) != 2 {
		t.Errorf("FindingIDs = %v, want both findings", record.FindingIDs)
	}
	if !strings.Contains(record.Explanation, "/etc/cron.d/job") {
		t.Errorf("the explanation does not name the file: %q", record.Explanation)
	}
	if err := record.Validate(); err != nil {
		t.Errorf("the record is not valid: %v", err)
	}
}

func TestPersistenceCorrelationRequiresTheSamePath(t *testing.T) {
	records := analyse(t, resultWith(
		ruleFinding("LS-PERS-001", "/etc/cron.d/a", 0o666, "root", model.CategoryPersistence),
		ruleFinding("LS-PERM-001", "/etc/cron.d/b", 0o666, "root", model.CategoryPermissions),
	))
	if len(records) != 0 {
		t.Errorf("correlated two different files: %v", ruleIDsOfRecords(records))
	}
}

func TestPersistenceCorrelationRequiresWriteAccess(t *testing.T) {
	records := analyse(t, resultWith(
		ruleFinding("LS-PERS-001", "/etc/cron.d/job", 0o644, "root", model.CategoryPersistence),
		ruleFinding("LS-PERM-001", "/etc/cron.d/job", 0o644, "root", model.CategoryPermissions),
	))
	if len(records) != 0 {
		t.Errorf("correlated a file nobody can write to: %v", ruleIDsOfRecords(records))
	}
}

func TestPersistenceCorrelationAcceptsGroupWrite(t *testing.T) {
	records := analyse(t, resultWith(
		ruleFinding("LS-PERS-002", "/etc/cron.d/job", 0o664, "root", model.CategoryPersistence),
		ruleFinding("LS-PERM-001", "/etc/cron.d/job", 0o664, "root", model.CategoryPermissions),
	))

	if len(records) != 1 || records[0].RuleID != "LS-COR-001" {
		t.Errorf("records = %v, want one LS-COR-001", ruleIDsOfRecords(records))
	}
	if !strings.Contains(records[0].Explanation, "owning group") {
		t.Errorf("the explanation should name the group, not other users: %q", records[0].Explanation)
	}
}

func TestPrivilegedBinaryWithUntrustedOwnershipCorrelates(t *testing.T) {
	records := analyse(t, resultWith(
		ruleFinding("LS-PRIV-003", "/opt/bin/tool", 0o4755, "app", model.CategoryIndicator),
		ruleFinding("LS-OWN-004", "/opt/bin/tool", 0o4755, "app", model.CategoryOwnership),
	))
	if len(records) != 1 {
		t.Fatalf("got %d record(s) %v, want one", len(records), ruleIDsOfRecords(records))
	}

	record := findRecord(t, records, "LS-COR-002")
	if !strings.Contains(record.Explanation, "app") {
		t.Errorf("the explanation does not name the owner: %q", record.Explanation)
	}
	if !strings.Contains(record.Explanation, "did not execute") {
		t.Errorf("the explanation should state the binary was not run: %q", record.Explanation)
	}
}

func TestSetgidCountsAsAPrivilegeBit(t *testing.T) {
	for _, mode := range []uint32{0o2755, 0o6755} {
		records := analyse(t, resultWith(
			ruleFinding("LS-PRIV-002", "/opt/bin/tool", mode, "app", model.CategoryIndicator),
			ruleFinding("LS-OWN-004", "/opt/bin/tool", mode, "app", model.CategoryOwnership),
		))
		if len(records) != 1 {
			t.Errorf("mode %04o produced %d record(s), want one", mode, len(records))
		}
	}
}

func TestPrivilegedBinaryOwnedByRootIsNotCorrelated(t *testing.T) {
	records := analyse(t, resultWith(
		ruleFinding("LS-PRIV-001", "/usr/bin/sudo", 0o4755, "root", model.CategoryIndicator),
		ruleFinding("LS-OWN-001", "/usr/bin/sudo", 0o4755, "root", model.CategoryOwnership),
	))

	if len(records) != 1 {
		t.Fatalf("records = %v, want the ownership pair to match", ruleIDsOfRecords(records))
	}

	alone := analyse(t, resultWith(
		ruleFinding("LS-PRIV-001", "/usr/bin/sudo", 0o4755, "root", model.CategoryIndicator),
	))
	if len(alone) != 0 {
		t.Errorf("a lone setuid binary produced %v", ruleIDsOfRecords(alone))
	}
}

func TestPrivilegeCorrelationNeedsARecordedMode(t *testing.T) {
	finding := ruleFinding("LS-PRIV-003", "/opt/bin/tool", 0o4755, "app", model.CategoryIndicator)
	finding.Mode = nil

	records := analyse(t, resultWith(
		finding,
		ruleFinding("LS-OWN-004", "/opt/bin/tool", 0o4755, "app", model.CategoryOwnership),
	))
	if len(records) != 0 {
		t.Errorf("correlated without a recorded mode: %v", ruleIDsOfRecords(records))
	}
}

func TestStagedPayloadShapedFileCorrelates(t *testing.T) {
	records := analyse(t, resultWith(
		ruleFinding("LS-IND-001", "/tmp/stage/dropper", 0o755, "app", model.CategoryIndicator),
		ruleFinding("LS-IND-004", "/tmp/stage/dropper", 0o755, "app", model.CategoryIndicator),
	))
	if len(records) != 1 {
		t.Fatalf("got %d record(s) %v, want one", len(records), ruleIDsOfRecords(records))
	}
	record := findRecord(t, records, "LS-COR-003")
	if !strings.Contains(record.Explanation, "not classified as malicious") {
		t.Errorf("the explanation should say the file was not called malicious: %q", record.Explanation)
	}
}

func TestEveryPayloadShapeRuleParticipates(t *testing.T) {
	for _, ruleID := range []string{"LS-IND-002", "LS-IND-003", "LS-IND-004", "LS-IND-005"} {
		records := analyse(t, resultWith(
			ruleFinding("LS-IND-001", "/tmp/stage/x", 0o755, "app", model.CategoryIndicator),
			ruleFinding(ruleID, "/tmp/stage/x", 0o755, "app", model.CategoryIndicator),
		))
		if len(records) != 1 {
			t.Errorf("%s with LS-IND-001 produced %d record(s), want one", ruleID, len(records))
		}
	}
}

func TestIndicatorsInTheSameDirectoryAreNotCorrelated(t *testing.T) {
	records := analyse(t, resultWith(
		ruleFinding("LS-IND-001", "/tmp/stage/a", 0o755, "app", model.CategoryIndicator),
		ruleFinding("LS-IND-004", "/tmp/stage/b", 0o755, "app", model.CategoryIndicator),
	))
	if len(records) != 0 {
		t.Errorf("correlated two different files in one directory: %v", ruleIDsOfRecords(records))
	}
}

func TestUnrelatedFindingsAreNotCorrelated(t *testing.T) {
	records := analyse(t, resultWith(
		ruleFinding("LS-PERM-002", "/tmp/world-writable", 0o777, "root", model.CategoryPermissions),
		ruleFinding("LS-OWN-003", "/opt/bin/other", 0o755, "ghost", model.CategoryOwnership),
		ruleFinding("LS-SENS-004", "/etc/ssh/sshd_config", 0o644, "root", model.CategorySensitiveConfig),
	))
	if len(records) != 0 {
		t.Errorf("correlated unrelated findings: %v", ruleIDsOfRecords(records))
	}
}

func TestWeakenedSSHPolicyCorrelatesWithBroadKeyPermissions(t *testing.T) {
	records := analyse(t, resultWith(
		ruleFinding("LS-SENS-001", "/etc/ssh/sshd_config", 0o644, "root", model.CategorySensitiveConfig),
		ruleFinding("LS-PERM-005", "/root/.ssh/id_rsa", 0o644, "root", model.CategoryPermissions),
	))
	if len(records) != 1 {
		t.Fatalf("got %d record(s) %v, want one", len(records), ruleIDsOfRecords(records))
	}

	record := findRecord(t, records, "LS-COR-004")
	if record.Confidence != model.CorrelationMedium {
		t.Errorf("Confidence = %q, want medium because no path links the findings", record.Confidence)
	}
	if !strings.Contains(record.Explanation, "cannot show") {
		t.Errorf("the explanation should state what the tool cannot show: %q", record.Explanation)
	}
}

func TestSSHCorrelationPairsEachKeyFindingSeparately(t *testing.T) {
	records := analyse(t, resultWith(
		ruleFinding("LS-SENS-002", "/etc/ssh/sshd_config", 0o644, "root", model.CategorySensitiveConfig),
		ruleFinding("LS-PERM-005", "/root/.ssh/id_rsa", 0o644, "root", model.CategoryPermissions),
		ruleFinding("LS-PERM-006", "/root/.ssh/authorized_keys", 0o644, "root", model.CategoryPermissions),
	))
	if len(records) != 2 {
		t.Fatalf("got %d record(s), want one per key finding", len(records))
	}
	for _, record := range records {
		if len(record.FindingIDs) != 2 {
			t.Errorf("record %s references %v, want exactly two findings", record.ID, record.FindingIDs)
		}
	}
	if records[0].ID == records[1].ID {
		t.Error("two different relationships produced the same identifier")
	}
}

func TestSSHCorrelationNeedsBothSides(t *testing.T) {
	policyOnly := analyse(t, resultWith(
		ruleFinding("LS-SENS-001", "/etc/ssh/sshd_config", 0o644, "root", model.CategorySensitiveConfig),
	))
	if len(policyOnly) != 0 {
		t.Errorf("a policy finding alone produced %v", ruleIDsOfRecords(policyOnly))
	}

	keysOnly := analyse(t, resultWith(
		ruleFinding("LS-PERM-005", "/root/.ssh/id_rsa", 0o644, "root", model.CategoryPermissions),
	))
	if len(keysOnly) != 0 {
		t.Errorf("a key finding alone produced %v", ruleIDsOfRecords(keysOnly))
	}
}

func TestSSHCorrelationExcludesUnrelatedSSHSettings(t *testing.T) {
	records := analyse(t, resultWith(
		ruleFinding("LS-SENS-004", "/etc/ssh/sshd_config", 0o644, "root", model.CategorySensitiveConfig),
		ruleFinding("LS-PERM-005", "/root/.ssh/id_rsa", 0o644, "root", model.CategoryPermissions),
	))
	if len(records) != 0 {
		t.Errorf("correlated on a setting that does not weaken access control: %v", ruleIDsOfRecords(records))
	}
}

func TestCorrelationIdentifiersAreStable(t *testing.T) {
	first := CorrelationID("LS-COR-001", []string{"b", "a"})
	second := CorrelationID("LS-COR-001", []string{"a", "b"})
	if first != second {
		t.Errorf("the identifier depends on input order: %s vs %s", first, second)
	}
	if !strings.HasPrefix(first, "LS-COR-001-") {
		t.Errorf("identifier %q does not carry its rule", first)
	}
	if other := CorrelationID("LS-COR-002", []string{"a", "b"}); other == first {
		t.Error("two rules over the same findings produced the same identifier")
	}
	if len(first) != len("LS-COR-001-")+12 {
		t.Errorf("identifier %q has an unexpected length", first)
	}
}

func TestAnalyseIsDeterministicAndOrderIndependent(t *testing.T) {
	findings := []model.Finding{
		ruleFinding("LS-IND-001", "/tmp/stage/x", 0o755, "app", model.CategoryIndicator),
		ruleFinding("LS-IND-004", "/tmp/stage/x", 0o755, "app", model.CategoryIndicator),
		ruleFinding("LS-PRIV-003", "/opt/bin/tool", 0o4755, "app", model.CategoryIndicator),
		ruleFinding("LS-OWN-004", "/opt/bin/tool", 0o4755, "app", model.CategoryOwnership),
		ruleFinding("LS-PERS-001", "/etc/cron.d/job", 0o666, "root", model.CategoryPersistence),
		ruleFinding("LS-PERM-001", "/etc/cron.d/job", 0o666, "root", model.CategoryPermissions),
		ruleFinding("LS-SENS-001", "/etc/ssh/sshd_config", 0o644, "root", model.CategorySensitiveConfig),
		ruleFinding("LS-PERM-005", "/root/.ssh/id_rsa", 0o644, "root", model.CategoryPermissions),
	}

	baseline := analyse(t, resultWith(findings...))
	if len(baseline) != 4 {
		t.Fatalf("got %d record(s), want one per rule", len(baseline))
	}

	for shift := 1; shift < len(findings); shift++ {
		rotated := append(append([]model.Finding(nil), findings[shift:]...), findings[:shift]...)
		records := analyse(t, resultWith(rotated...))
		if len(records) != len(baseline) {
			t.Fatalf("rotation by %d produced %d record(s), want %d", shift, len(records), len(baseline))
		}
		for i := range records {
			if records[i].ID != baseline[i].ID {
				t.Fatalf("rotation by %d changed record %d from %s to %s",
					shift, i, baseline[i].ID, records[i].ID)
			}
		}
	}
}

func TestRecordsAreSortedAndDeduplicated(t *testing.T) {

	duplicate := ruleFinding("LS-IND-001", "/tmp/stage/x", 0o755, "app", model.CategoryIndicator)
	shape := ruleFinding("LS-IND-004", "/tmp/stage/x", 0o755, "app", model.CategoryIndicator)

	records := analyse(t, resultWith(duplicate, shape, duplicate, shape))
	if len(records) != 1 {
		t.Fatalf("duplicated findings produced %d record(s), want one", len(records))
	}

	all := analyse(t, resultWith(
		ruleFinding("LS-SENS-001", "/etc/ssh/sshd_config", 0o644, "root", model.CategorySensitiveConfig),
		ruleFinding("LS-PERM-005", "/root/.ssh/id_rsa", 0o644, "root", model.CategoryPermissions),
		ruleFinding("LS-IND-001", "/tmp/stage/x", 0o755, "app", model.CategoryIndicator),
		ruleFinding("LS-IND-004", "/tmp/stage/x", 0o755, "app", model.CategoryIndicator),
	))
	seen := map[string]bool{}
	var previous string
	for i, record := range all {
		if seen[record.ID] {
			t.Errorf("record %s appears twice", record.ID)
		}
		seen[record.ID] = true
		if i > 0 && previous > record.RuleID {
			t.Errorf("records are not sorted by rule: %s then %s", previous, record.RuleID)
		}
		previous = record.RuleID
	}
}

func TestRecordsNeverReferenceAFindingTwice(t *testing.T) {
	records := analyse(t, resultWith(
		ruleFinding("LS-IND-001", "/tmp/stage/x", 0o755, "app", model.CategoryIndicator),
		ruleFinding("LS-IND-001", "/tmp/stage/x", 0o755, "app", model.CategoryIndicator),
		ruleFinding("LS-IND-004", "/tmp/stage/x", 0o755, "app", model.CategoryIndicator),
	))
	if len(records) != 1 {
		t.Fatalf("got %d record(s), want one", len(records))
	}
	seen := map[string]bool{}
	for _, id := range records[0].FindingIDs {
		if seen[id] {
			t.Errorf("record %s references %s twice: %v", records[0].ID, id, records[0].FindingIDs)
		}
		seen[id] = true
	}
	if err := records[0].Validate(); err != nil {
		t.Errorf("a record with duplicated input findings is not valid: %v", err)
	}
}

func TestEveryRuleMapsToADefensibleTechnique(t *testing.T) {
	set := attack.Dataset()
	records := analyse(t, resultWith(
		ruleFinding("LS-PERS-001", "/etc/cron.d/job", 0o666, "root", model.CategoryPersistence),
		ruleFinding("LS-PERM-001", "/etc/cron.d/job", 0o666, "root", model.CategoryPermissions),
		ruleFinding("LS-PRIV-003", "/opt/bin/tool", 0o4755, "app", model.CategoryIndicator),
		ruleFinding("LS-OWN-004", "/opt/bin/tool", 0o4755, "app", model.CategoryOwnership),
		ruleFinding("LS-IND-001", "/tmp/stage/x", 0o755, "app", model.CategoryIndicator),
		ruleFinding("LS-IND-004", "/tmp/stage/x", 0o755, "app", model.CategoryIndicator),
		ruleFinding("LS-SENS-001", "/etc/ssh/sshd_config", 0o644, "root", model.CategorySensitiveConfig),
		ruleFinding("LS-PERM-005", "/root/.ssh/id_rsa", 0o644, "root", model.CategoryPermissions),
	))
	if len(records) != 4 {
		t.Fatalf("got %d record(s), want four", len(records))
	}

	for _, record := range records {
		if record.Technique == nil {
			t.Errorf("%s has no technique", record.RuleID)
			continue
		}
		if record.AttackRelevance == "" {
			t.Errorf("%s has no relevance explanation", record.RuleID)
		}
		if err := record.Validate(); err != nil {
			t.Errorf("%s is not a valid record: %v", record.RuleID, err)
		}
		if _, ok := set.Lookup(record.RuleID); !ok {
			t.Errorf("%s produced a record but has no curated mapping", record.RuleID)
		}
	}
}

func TestEveryRuleHasACuratedMapping(t *testing.T) {
	set := attack.Dataset()
	for _, rule := range Rules() {
		if _, ok := set.Lookup(rule.ID); !ok {
			t.Errorf("rule %s has no curated ATT&CK mapping", rule.ID)
		}
	}
}

func TestDisablingAttackKeepsCorrelations(t *testing.T) {
	result := resultWith(
		ruleFinding("LS-IND-001", "/tmp/stage/x", 0o755, "app", model.CategoryIndicator),
		ruleFinding("LS-IND-004", "/tmp/stage/x", 0o755, "app", model.CategoryIndicator),
	)

	withMapping := Analyse(result, Options{Attack: attack.Dataset()})
	withoutMapping := Analyse(result, Options{})

	if len(withoutMapping) != len(withMapping) {
		t.Fatalf("disabling the mapping changed the record count from %d to %d",
			len(withMapping), len(withoutMapping))
	}
	if len(withoutMapping) != 1 {
		t.Fatalf("got %d record(s), want one", len(withoutMapping))
	}
	record := withoutMapping[0]
	if record.Technique != nil || record.AttackRelevance != "" {
		t.Error("a record carries ATT&CK context although mapping was disabled")
	}
	if record.ID != withMapping[0].ID {
		t.Error("the mapping changed the correlation identifier")
	}
	if err := record.Validate(); err != nil {
		t.Errorf("an unmapped record should still be valid: %v", err)
	}
}

func TestScopeIsCompleteForAFullScan(t *testing.T) {
	records := analyse(t, resultWith(
		ruleFinding("LS-IND-001", "/tmp/stage/x", 0o755, "app", model.CategoryIndicator),
		ruleFinding("LS-IND-004", "/tmp/stage/x", 0o755, "app", model.CategoryIndicator),
	))
	if !records[0].Scope.Complete {
		t.Errorf("a complete scan produced scope %+v", records[0].Scope)
	}
	if records[0].Scope.Note != "" {
		t.Errorf("a complete scope carries a note: %q", records[0].Scope.Note)
	}
}

func TestIncompleteScanRecordsWhyTheRecordMayBeIncomplete(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(*scan.Result)
		mustErr string
	}{
		{"cancelled", func(r *scan.Result) { r.Status = scan.StatusCancelled }, "cancelled"},
		{"partial", func(r *scan.Result) { r.Status = scan.StatusPartial }, "covered only part"},
		{"entry limit", func(r *scan.Result) { r.Files.EntryLimitHit = true }, "traversal limit"},
		{"depth limit", func(r *scan.Result) { r.Files.DepthLimitHit = true }, "traversal limit"},
		{
			"detector failure",
			func(r *scan.Result) {
				r.Detectors.DetectorFailures = map[string]int64{"persistence": 3}
			},
			"persistence failed",
		},
		{
			"inaccessible path",
			func(r *scan.Result) {
				r.Files.Inaccessible = []string{"/root (permission denied)"}
			},
			"could not be read",
		},
		{
			"narrow detector selection",
			func(r *scan.Result) {
				r.Detectors.Selected = []string{"indicator", "permissions"}
			},
			"detectors ran",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			result := resultWith(
				ruleFinding("LS-IND-001", "/tmp/stage/x", 0o755, "app", model.CategoryIndicator),
				ruleFinding("LS-IND-004", "/tmp/stage/x", 0o755, "app", model.CategoryIndicator),
			)
			testCase.prepare(result)

			records := analyse(t, result)
			if len(records) != 1 {
				t.Fatalf("got %d record(s), want the observed relationship still reported", len(records))
			}
			record := records[0]
			if record.Scope.Complete {
				t.Error("the record claims complete coverage although the scan was incomplete")
			}
			if !strings.Contains(record.Scope.Note, testCase.mustErr) {
				t.Errorf("scope note %q does not mention %q", record.Scope.Note, testCase.mustErr)
			}

			if err := record.Validate(); err != nil {
				t.Errorf("the record is not valid: %v", err)
			}
		})
	}
}

func TestIncompleteScanNeverAssertsAbsence(t *testing.T) {
	result := resultWith(
		ruleFinding("LS-IND-001", "/tmp/stage/x", 0o755, "app", model.CategoryIndicator),
	)
	result.Status = scan.StatusPartial
	result.Files.Inaccessible = []string{"/tmp/stage (permission denied)"}

	records := analyse(t, result)
	for _, record := range records {
		for _, forbidden := range []string{"no relationship", "not correlated", "absent", "clean"} {
			if strings.Contains(strings.ToLower(record.Explanation), forbidden) {
				t.Errorf("the explanation asserts absence: %q", record.Explanation)
			}
		}
	}
}

func TestCorrelationDoesNotReadOrChangeRisk(t *testing.T) {
	withRisk := ruleFinding("LS-IND-001", "/tmp/stage/x", 0o755, "app", model.CategoryIndicator)
	withRisk.Risk = &model.Risk{
		Score: 99, Band: model.RiskBandCritical, Severity: model.SeverityMedium, Base: 42,
		Factors:     []model.RiskFactor{{Name: "severity-base", Points: 42, Reason: "r"}},
		Explanation: "x",
	}

	records := analyse(t, resultWith(
		withRisk,
		ruleFinding("LS-IND-004", "/tmp/stage/x", 0o755, "app", model.CategoryIndicator),
	))
	if len(records) != 1 {
		t.Fatalf("got %d record(s), want one", len(records))
	}

	record := records[0]
	if strings.Contains(record.Explanation, "99") || strings.Contains(record.Explanation, "critical") {
		t.Errorf("the explanation quotes a risk score: %q", record.Explanation)
	}

	if withRisk.Risk == nil || withRisk.Risk.Score != 99 {
		t.Error("correlation changed the risk of a finding")
	}
}

func TestEveryRuleIsDocumentedAndComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, rule := range Rules() {
		if rule.ID == "" || rule.Title == "" || rule.Assumption == "" {
			t.Errorf("rule %+v is missing an identifier, title or assumption", rule)
		}
		if !strings.HasPrefix(rule.ID, "LS-COR-") {
			t.Errorf("rule %s is outside the LS-COR-* namespace", rule.ID)
		}
		if seen[rule.ID] {
			t.Errorf("rule %s is defined twice", rule.ID)
		}
		seen[rule.ID] = true

		if rule.Match == nil {
			t.Errorf("rule %s has no match function", rule.ID)
		}
		if rule.Explain == nil {
			t.Errorf("rule %s has no explanation function", rule.ID)
		}
		if rule.Confidence != model.CorrelationHigh && rule.Confidence != model.CorrelationMedium {
			t.Errorf("rule %s has confidence %q; only high and medium rules are produced",
				rule.ID, rule.Confidence)
		}
		if rule.Assumption == "" {
			t.Errorf("rule %s does not record what it assumes", rule.ID)
		}
	}
}

func TestRuleByID(t *testing.T) {
	rule, ok := RuleByID("LS-COR-001")
	if !ok {
		t.Fatal("RuleByID did not find LS-COR-001")
	}
	if rule.Title == "" {
		t.Error("RuleByID returned a rule without a title")
	}
	if _, ok := RuleByID("LS-COR-999"); ok {
		t.Error("RuleByID invented a rule")
	}
}

func TestExplanationsDoNotAssertAdversaryActivity(t *testing.T) {

	forbidden := []string{
		"attacker", "adversary ", "was exploited", "was used to", "compromised",
		"was executed", "was planted", "backdoor", "intrusion", "proves",
	}
	for _, rule := range Rules() {
		related := []model.Finding{
			ruleFinding("LS-IND-001", "/tmp/stage/x", 0o755, "app", model.CategoryIndicator),
			ruleFinding("LS-IND-004", "/tmp/stage/x", 0o755, "app", model.CategoryIndicator),
			ruleFinding("LS-SENS-001", "/etc/ssh/sshd_config", 0o644, "root", model.CategorySensitiveConfig),
			ruleFinding("LS-PERM-005", "/root/.ssh/id_rsa", 0o644, "root", model.CategoryPermissions),
		}
		explanation := strings.ToLower(rule.Explain(related))
		for _, phrase := range forbidden {
			if strings.Contains(explanation, phrase) {
				t.Errorf("rule %s explanation asserts adversary activity (%q): %s",
					rule.ID, phrase, explanation)
			}
		}
	}
}

func TestAnalyseHandlesDegenerateInput(t *testing.T) {
	if records := Analyse(nil, Options{Attack: attack.Dataset()}); records != nil {
		t.Errorf("Analyse(nil) = %v, want nil", records)
	}
	if records := analyse(t, resultWith()); len(records) != 0 {
		t.Errorf("an empty scan produced %v", ruleIDsOfRecords(records))
	}
	single := analyse(t, resultWith(
		ruleFinding("LS-IND-001", "/tmp/stage/x", 0o755, "app", model.CategoryIndicator),
	))
	if len(single) != 0 {
		t.Errorf("a single finding produced %v", ruleIDsOfRecords(single))
	}
}

func TestFindingsWithoutIdentifiersAreIgnored(t *testing.T) {
	broken := ruleFinding("LS-IND-001", "/tmp/stage/x", 0o755, "app", model.CategoryIndicator)
	broken.ID = ""
	other := ruleFinding("LS-IND-004", "/tmp/stage/x", 0o755, "app", model.CategoryIndicator)

	if records := analyse(t, resultWith(broken, other)); len(records) != 0 {
		t.Errorf("correlated a finding with no identifier: %v", ruleIDsOfRecords(records))
	}
}

func TestAnalyseDoesNotModifyFindings(t *testing.T) {
	original := ruleFinding("LS-IND-001", "/tmp/stage/x", 0o755, "app", model.CategoryIndicator)
	before := original

	result := resultWith(original,
		ruleFinding("LS-IND-004", "/tmp/stage/x", 0o755, "app", model.CategoryIndicator))
	_ = analyse(t, result)

	if original.ID != before.ID || original.Path != before.Path ||
		original.RuleID != before.RuleID || original.Severity != before.Severity {
		t.Error("Analyse modified a finding")
	}
	if original.Risk != nil {
		t.Error("Analyse attached risk metadata to a finding")
	}
}
