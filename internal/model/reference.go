package model

import (
	"errors"
	"fmt"
)

type ReferenceContext struct {
	Source      string   `json:"source"`
	Binary      string   `json:"binary"`
	Category    string   `json:"category"`
	Summary     string   `json:"summary"`
	Attribution string   `json:"attribution,omitempty"`
	Severity    Severity `json:"severity"`
	Caveat      string   `json:"caveat"`
}

func (r *ReferenceContext) Validate() error {
	if r == nil {
		return nil
	}
	if r.Source == "" {
		return errors.New("model: reference context requires a source")
	}
	if r.Binary == "" {
		return fmt.Errorf("model: reference context from %s requires a binary name", r.Source)
	}
	if r.Category == "" {
		return fmt.Errorf("model: reference context for %s requires a category", r.Binary)
	}
	if r.Summary == "" {
		return fmt.Errorf("model: reference context for %s requires a summary", r.Binary)
	}
	if !r.Severity.IsValid() {
		return fmt.Errorf("model: reference context for %s has invalid severity %d", r.Binary, int(r.Severity))
	}
	if r.Caveat == "" {
		return fmt.Errorf("model: reference context for %s requires a caveat", r.Binary)
	}
	return nil
}
