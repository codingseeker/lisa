package model

import (
	"errors"
	"fmt"
)

type Rule struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	Severity    Severity   `json:"severity"`
	Confidence  Confidence `json:"confidence"`
	Category    Category   `json:"category"`
	Remediation string     `json:"remediation,omitempty"`
	Technique   *Technique `json:"technique,omitempty"`
}

func (r Rule) Validate() error {
	if r.ID == "" {
		return errors.New("rule id is required")
	}
	if r.Title == "" {
		return fmt.Errorf("rule %s requires a title", r.ID)
	}
	if !r.Severity.IsValid() {
		return fmt.Errorf("rule %s has invalid severity %d", r.ID, int(r.Severity))
	}
	if !r.Confidence.IsValid() {
		return fmt.Errorf("rule %s has invalid confidence %d", r.ID, int(r.Confidence))
	}
	if !r.Category.IsValid() {
		return fmt.Errorf("rule %s has unknown category %q", r.ID, string(r.Category))
	}
	return r.Technique.Validate()
}

func (r Rule) Finding(path string) Finding {
	return Finding{
		ID:          FindingID(r.ID, path),
		RuleID:      r.ID,
		Title:       r.Title,
		Severity:    r.Severity,
		Confidence:  r.Confidence,
		Category:    r.Category,
		Remediation: r.Remediation,
		Technique:   r.Technique,
		Path:        path,
	}
}
