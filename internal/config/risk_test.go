package config

import (
	"strings"
	"testing"

	"lisa/internal/model"
)

func TestRiskScoringIsOnByDefault(t *testing.T) {
	if !Default().RiskEnabled {
		t.Error("risk scoring should be enabled by default")
	}
	if Default().SortByRisk {
		t.Error("risk ordering should be opt in, so the default finding order is unchanged")
	}
}

func TestSortByRiskRequiresScoring(t *testing.T) {
	cfg := Default()
	cfg.Command = CommandScan
	cfg.Target = t.TempDir()
	cfg.RiskEnabled = false
	cfg.SortByRisk = true

	err := cfg.Validate()
	if err == nil {
		t.Fatal("ordering by risk was accepted with scoring disabled")
	}
	if !strings.Contains(err.Error(), "--sort-risk") {
		t.Errorf("Validate error = %q, want it to name the conflicting option", err)
	}
}

func TestRiskOptionsAreValidTogether(t *testing.T) {
	cfg := Default()
	cfg.Command = CommandScan
	cfg.Target = t.TempDir()
	cfg.SortByRisk = true

	if err := cfg.Validate(); err != nil {
		t.Errorf("scoring with risk ordering should be valid: %v", err)
	}
}

func TestRiskScoringCanBeDisabled(t *testing.T) {
	cfg := Default()
	cfg.Command = CommandScan
	cfg.Target = t.TempDir()
	cfg.RiskEnabled = false

	if err := cfg.Validate(); err != nil {
		t.Errorf("scoring disabled should be valid: %v", err)
	}
	if cfg.MinSeverity != model.SeverityInfo {
		t.Error("disabling scoring changed the severity threshold")
	}
}
