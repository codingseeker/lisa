package config

import "testing"

func TestCorrelationAndAttackAreOnByDefault(t *testing.T) {
	defaults := Default()
	if !defaults.Correlate {
		t.Error("correlation should be enabled by default")
	}
	if !defaults.Attack {
		t.Error("ATT&CK context should be enabled by default")
	}
}

func TestCorrelationAndAttackCanBeDisabledIndependently(t *testing.T) {
	cases := []struct {
		name              string
		correlate, attack bool
	}{
		{"both on", true, true},
		{"both off", false, false},
		{"correlation off, attack on", false, true},
		{"correlation on, attack off", true, false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := Default()
			cfg.Command = CommandScan
			cfg.Target = t.TempDir()
			cfg.Correlate = testCase.correlate
			cfg.Attack = testCase.attack

			if err := cfg.Validate(); err != nil {
				t.Errorf("the combination should be valid: %v", err)
			}
		})
	}
}
