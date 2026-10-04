package model

import (
	"strings"
	"testing"
	"time"
)

func validRisk() Risk {
	return Risk{
		Score:    72,
		Band:     RiskBandHigh,
		Severity: SeverityHigh,
		Base:     60,
		Factors: []RiskFactor{
			{Name: "severity-base", Points: 60, Reason: "the detector rates this finding high"},
			{Name: "world-writable", Points: 12, Reason: "the recorded mode grants write permission to other users"},
		},
		Explanation: "Base 60 from detector severity high; +12 world-writable.",
	}
}

func TestRiskBandIsValid(t *testing.T) {
	for _, band := range RiskBands() {
		if !band.IsValid() {
			t.Errorf("band %q should be valid", band)
		}
	}
	if RiskBand("severe").IsValid() {
		t.Error("an invented band should not be valid")
	}
	if RiskBand("").IsValid() {
		t.Error("the empty band should not be valid")
	}
}

func TestNilRiskIsValid(t *testing.T) {
	var assessment *Risk
	if err := assessment.Validate(); err != nil {
		t.Errorf("a nil risk assessment should validate: %v", err)
	}
}

func TestRiskValidate(t *testing.T) {
	assessment := validRisk()
	if err := assessment.Validate(); err != nil {
		t.Fatalf("a well formed risk assessment was rejected: %v", err)
	}
}

func TestRiskValidateRejectsInconsistentAssessments(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Risk)
		mustErr string
	}{
		{"score below the scale", func(r *Risk) { r.Score = -1; r.Factors[0].Points = -61 },
			"outside the"},
		{"score above the scale", func(r *Risk) { r.Score = 101 }, "outside the"},
		{"unknown band", func(r *Risk) { r.Band = "severe" }, "not a known band"},
		{"no factors", func(r *Risk) { r.Factors = nil }, "at least one factor"},
		{"unnamed factor", func(r *Risk) { r.Factors[0].Name = "" }, "requires a name"},
		{"unexplained factor", func(r *Risk) { r.Factors[0].Reason = "" }, "requires a reason"},
		{"repeated factor", func(r *Risk) {
			r.Factors = append(r.Factors, RiskFactor{Name: "world-writable", Points: 1, Reason: "again"})
		}, "counted more than once"},
		{"factors that do not sum to the score", func(r *Risk) { r.Factors[0].Points = 1 },
			"but the score is"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			assessment := validRisk()
			testCase.mutate(&assessment)
			err := assessment.Validate()
			if err == nil {
				t.Fatalf("Validate accepted a risk assessment with %s", testCase.name)
			}
			if !strings.Contains(err.Error(), testCase.mustErr) {
				t.Errorf("Validate error = %q, want it to mention %q", err, testCase.mustErr)
			}
		})
	}
}

func TestRiskSum(t *testing.T) {
	if got := validRisk().Sum(); got != 72 {
		t.Errorf("Sum() = %d, want 72", got)
	}
	if got := (Risk{}).Sum(); got != 0 {
		t.Errorf("Sum() on an empty assessment = %d, want 0", got)
	}
}

func TestRiskSumIncludesTheCap(t *testing.T) {
	assessment := Risk{
		Score: 100, Band: RiskBandCritical, Severity: SeverityCritical, Base: 80,
		Factors: []RiskFactor{
			{Name: "severity-base", Points: 80, Reason: "base"},
			{Name: "score-cap", Points: 20, Reason: "capped"},
		},
	}
	if got := assessment.Sum(); got != assessment.Score {
		t.Errorf("Sum() = %d, want the score %d", got, assessment.Score)
	}
	if err := assessment.Validate(); err != nil {
		t.Errorf("a capped assessment should validate: %v", err)
	}
}

func TestFindingValidateChecksRisk(t *testing.T) {
	finding := Finding{
		ID: "LS-PERM-001-abc", RuleID: "LS-PERM-001", Title: "t",
		Severity: SeverityHigh, Confidence: ConfidenceHigh, Category: CategoryPermissions,
		Path: "/srv/app", DetectedAt: time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC),
	}
	if err := finding.Validate(); err != nil {
		t.Fatalf("a finding without risk should validate: %v", err)
	}

	assessment := validRisk()
	finding.Risk = &assessment
	if err := finding.Validate(); err != nil {
		t.Errorf("a finding with a valid assessment was rejected: %v", err)
	}

	broken := validRisk()
	broken.Score = 999
	finding.Risk = &broken
	if err := finding.Validate(); err == nil {
		t.Error("a finding with an out of range score was accepted")
	}
}
