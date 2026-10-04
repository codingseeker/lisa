package model

import (
	"errors"
	"fmt"
	"regexp"
)

var techniqueIDPattern = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

type Technique struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Tactic string `json:"tactic"`
}

func (t *Technique) Validate() error {
	if t == nil {
		return nil
	}
	if t.ID == "" {
		return errors.New("technique id is required")
	}
	if !techniqueIDPattern.MatchString(t.ID) {
		return fmt.Errorf("technique id %q is not a valid ATT&CK identifier", t.ID)
	}
	if t.Name == "" {
		return fmt.Errorf("technique %s requires a name", t.ID)
	}
	return nil
}
