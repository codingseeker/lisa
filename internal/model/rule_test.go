package model

import "testing"

func validRule() Rule {
	return Rule{
		ID:          "LS-PERM-001",
		Title:       "World-writable regular file",
		Severity:    SeverityMedium,
		Confidence:  ConfidenceHigh,
		Category:    CategoryPermissions,
		Remediation: "Restrict the mode to 0644 or stricter.",
	}
}

func TestRuleValidateAcceptsCompleteRule(t *testing.T) {
	rule := validRule()
	if err := rule.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
}

func TestRuleValidateRejectsIncompleteRule(t *testing.T) {
	cases := map[string]func(*Rule){
		"missing id":          func(r *Rule) { r.ID = "" },
		"missing title":       func(r *Rule) { r.Title = "" },
		"invalid severity":    func(r *Rule) { r.Severity = Severity(42) },
		"invalid confidence":  func(r *Rule) { r.Confidence = Confidence(42) },
		"unknown category":    func(r *Rule) { r.Category = "made-up" },
		"malformed technique": func(r *Rule) { r.Technique = &Technique{ID: "nope", Name: "Nope"} },
	}
	for name, mutate := range cases {
		rule := validRule()
		mutate(&rule)
		if err := rule.Validate(); err == nil {
			t.Errorf("%s: Validate returned no error, want error", name)
		}
	}
}

func TestRuleFindingCopiesRuleMetadata(t *testing.T) {
	rule := validRule()
	rule.Technique = &Technique{ID: "T1222.002", Name: "File and Directory Permissions Modification", Tactic: "Defense Evasion"}

	finding := rule.Finding("/tmp/payload")

	if finding.RuleID != rule.ID {
		t.Errorf("RuleID = %q, want %q", finding.RuleID, rule.ID)
	}
	if finding.Title != rule.Title {
		t.Errorf("Title = %q, want %q", finding.Title, rule.Title)
	}
	if finding.Severity != rule.Severity {
		t.Errorf("Severity = %v, want %v", finding.Severity, rule.Severity)
	}
	if finding.Confidence != rule.Confidence {
		t.Errorf("Confidence = %v, want %v", finding.Confidence, rule.Confidence)
	}
	if finding.Category != rule.Category {
		t.Errorf("Category = %q, want %q", finding.Category, rule.Category)
	}
	if finding.Remediation != rule.Remediation {
		t.Errorf("Remediation = %q, want %q", finding.Remediation, rule.Remediation)
	}
	if finding.Path != "/tmp/payload" {
		t.Errorf("Path = %q, want %q", finding.Path, "/tmp/payload")
	}
	if finding.Technique == nil || finding.Technique.ID != "T1222.002" {
		t.Errorf("Technique was not copied from the rule")
	}
}

func TestRuleFindingIsIndependentOfRuleMutation(t *testing.T) {
	rule := validRule()
	finding := rule.Finding("/tmp/payload")
	rule.Title = "mutated"
	rule.Severity = SeverityInfo
	if finding.Title == rule.Title {
		t.Error("finding title should not track later rule mutation")
	}
	if finding.Severity == rule.Severity {
		t.Error("finding severity should not track later rule mutation")
	}
}
