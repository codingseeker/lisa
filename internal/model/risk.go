package model

import (
	"errors"
	"fmt"
)

type RiskBand string

const (
	RiskBandInformational RiskBand = "informational"
	RiskBandLow           RiskBand = "low"
	RiskBandMedium        RiskBand = "medium"
	RiskBandHigh          RiskBand = "high"
	RiskBandCritical      RiskBand = "critical"
)

func RiskBands() []RiskBand {
	return []RiskBand{
		RiskBandInformational, RiskBandLow, RiskBandMedium,
		RiskBandHigh, RiskBandCritical,
	}
}

func (b RiskBand) IsValid() bool {
	for _, known := range RiskBands() {
		if b == known {
			return true
		}
	}
	return false
}

type RiskFactor struct {
	Name string `json:"name"`

	Points int `json:"points"`

	Reason string `json:"reason"`
}

type Risk struct {
	Score int `json:"score"`

	Band RiskBand `json:"band"`

	Severity Severity `json:"severity"`

	Base int `json:"base"`

	Factors []RiskFactor `json:"factors"`

	Explanation string `json:"explanation"`
}

const (
	MinRiskScore = 0
	MaxRiskScore = 100
)

func (r Risk) Sum() int {
	total := 0
	for _, factor := range r.Factors {
		total += factor.Points
	}
	return total
}

func (r *Risk) Validate() error {
	if r == nil {
		return nil
	}
	if r.Score < MinRiskScore || r.Score > MaxRiskScore {
		return fmt.Errorf("model: risk score %d is outside the %d to %d scale", r.Score, MinRiskScore, MaxRiskScore)
	}
	if !r.Band.IsValid() {
		return fmt.Errorf("model: risk band %q is not a known band", string(r.Band))
	}
	if len(r.Factors) == 0 {
		return errors.New("model: risk assessment requires at least one factor")
	}
	if err := r.ValidateFactors(); err != nil {
		return err
	}
	if sum := r.Sum(); sum != r.Score {
		return fmt.Errorf("model: risk factors total %d but the score is %d", sum, r.Score)
	}
	return nil
}

func (r Risk) ValidateFactors() error {
	seen := make(map[string]struct{}, len(r.Factors))
	for _, factor := range r.Factors {
		if factor.Name == "" {
			return errors.New("model: risk factor requires a name")
		}
		if factor.Reason == "" {
			return fmt.Errorf("model: risk factor %s requires a reason", factor.Name)
		}
		if _, duplicate := seen[factor.Name]; duplicate {
			return fmt.Errorf("model: risk factor %s is counted more than once", factor.Name)
		}
		seen[factor.Name] = struct{}{}
	}
	return nil
}
