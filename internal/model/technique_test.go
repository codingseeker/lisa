package model

import "testing"

func TestTechniqueValidate(t *testing.T) {
	valid := []*Technique{
		nil,
		{ID: "T1059", Name: "Command and Scripting Interpreter", Tactic: "Execution"},
		{ID: "T1548.001", Name: "Setuid and Setgid", Tactic: "Privilege Escalation"},
	}
	for _, technique := range valid {
		if err := technique.Validate(); err != nil {
			t.Errorf("Validate(%+v) returned error: %v", technique, err)
		}
	}
}

func TestTechniqueValidateRejectsMalformed(t *testing.T) {
	invalid := []*Technique{
		{ID: "", Name: "No ID", Tactic: "Execution"},
		{ID: "1059", Name: "Missing prefix", Tactic: "Execution"},
		{ID: "TA0001", Name: "Tactic not technique", Tactic: "Execution"},
		{ID: "T1059.1", Name: "Wrong subtechnique arity", Tactic: "Execution"},
		{ID: "T1059", Name: "", Tactic: "Execution"},
	}
	for _, technique := range invalid {
		if err := technique.Validate(); err == nil {
			t.Errorf("Validate(%+v) returned no error, want error", technique)
		}
	}
}

func TestTechniqueIDPatternAcceptsKnownIDs(t *testing.T) {
	for _, id := range []string{"T1053", "T1053.003", "T1546.004", "T1036.005"} {
		if !techniqueIDPattern.MatchString(id) {
			t.Errorf("technique id %q should be accepted", id)
		}
	}
	for _, id := range []string{"T1053.03", "T1053.0033", "t1053", "1053", "T1053.", ""} {
		if techniqueIDPattern.MatchString(id) {
			t.Errorf("technique id %q should be rejected", id)
		}
	}
}
