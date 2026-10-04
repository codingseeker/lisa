package model

import (
	"strings"
	"testing"
)

func validCorrelation() Correlation {
	return Correlation{
		ID:              "LS-COR-001-abcdef123456",
		RuleID:          "LS-COR-001",
		Title:           "Automatically executed configuration is writable by other users",
		FindingIDs:      []string{"LS-PERM-001-aaa", "LS-PERS-001-bbb"},
		Confidence:      CorrelationHigh,
		Explanation:     "The file runs automatically and its mode allows other users to write to it.",
		Technique:       &Technique{ID: "T1543.002", Name: "Systemd Service", Tactic: "Persistence"},
		AttackRelevance: "A unit another user can rewrite is a documented way to gain persistence.",
		Scope:           CorrelationScope{Complete: true},
	}
}

func TestCorrelationConfidenceIsValid(t *testing.T) {
	for _, confidence := range CorrelationConfidences() {
		if !confidence.IsValid() {
			t.Errorf("confidence %q should be valid", confidence)
		}
	}
	for _, invalid := range []CorrelationConfidence{"", "High", "certain", "MEDIUM"} {
		if invalid.IsValid() {
			t.Errorf("confidence %q should not be valid", invalid)
		}
	}
}

func TestCorrelationValidate(t *testing.T) {
	record := validCorrelation()
	if err := record.Validate(); err != nil {
		t.Fatalf("a well formed correlation was rejected: %v", err)
	}
}

func TestCorrelationValidateRejectsInconsistentRecords(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Correlation)
		mustErr string
	}{
		{"no id", func(c *Correlation) { c.ID = "" }, "requires an id"},
		{"no rule", func(c *Correlation) { c.RuleID = "" }, "requires a rule id"},
		{"no title", func(c *Correlation) { c.Title = "" }, "requires a title"},
		{"unknown confidence", func(c *Correlation) { c.Confidence = "certain" }, "unknown confidence"},
		{"no explanation", func(c *Correlation) { c.Explanation = "" }, "requires an explanation"},
		{"one finding", func(c *Correlation) { c.FindingIDs = []string{"only"} }, "at least two"},
		{"no findings", func(c *Correlation) { c.FindingIDs = nil }, "at least two"},
		{"empty finding id", func(c *Correlation) {
			c.FindingIDs = []string{"", "b"}
		}, "empty finding identifier"},
		{"repeated finding", func(c *Correlation) {
			c.FindingIDs = []string{"a", "a"}
		}, "more than once"},
		{"unsorted finding ids", func(c *Correlation) {
			c.FindingIDs = []string{"z", "a"}
		}, "not sorted"},
		{"relevance without a technique", func(c *Correlation) {
			c.Technique = nil
		}, "explains a technique it does not name"},
		{"technique without relevance", func(c *Correlation) { c.AttackRelevance = "" },
			"without explaining its relevance"},
		{"complete scope with a note", func(c *Correlation) {
			c.Scope.Note = "something"
		}, "complete scope and a note"},
		{"incomplete scope without a note", func(c *Correlation) {
			c.Scope = CorrelationScope{Complete: false}
		}, "incomplete scope and no note"},
		{"invalid technique", func(c *Correlation) {
			c.Technique = &Technique{ID: "nope", Name: "x"}
		}, "not a valid ATT&CK identifier"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			record := validCorrelation()
			testCase.mutate(&record)
			err := record.Validate()
			if err == nil {
				t.Fatalf("Validate accepted a correlation with %s", testCase.name)
			}
			if !strings.Contains(err.Error(), testCase.mustErr) {
				t.Errorf("Validate error = %q, want it to mention %q", err, testCase.mustErr)
			}
		})
	}
}

func TestCorrelationWithoutATTACKContextIsValid(t *testing.T) {
	record := validCorrelation()
	record.Technique = nil
	record.AttackRelevance = ""
	if err := record.Validate(); err != nil {
		t.Errorf("an unmapped correlation should be valid: %v", err)
	}
}

func TestSortCorrelationsIsTotal(t *testing.T) {
	records := []Correlation{
		{ID: "b", RuleID: "LS-COR-002"},
		{ID: "a", RuleID: "LS-COR-002"},
		{ID: "z", RuleID: "LS-COR-001"},
	}
	SortCorrelations(records)
	want := []string{"z", "a", "b"}
	for i, record := range records {
		if record.ID != want[i] {
			t.Fatalf("order = %v, want %v", ids(records), want)
		}
	}
}

func ids(records []Correlation) []string {
	out := make([]string, len(records))
	for i, record := range records {
		out[i] = record.ID
	}
	return out
}
