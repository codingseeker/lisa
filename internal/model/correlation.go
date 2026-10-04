package model

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

type CorrelationConfidence string

const (
	CorrelationHigh CorrelationConfidence = "high"

	CorrelationMedium CorrelationConfidence = "medium"

	CorrelationLow CorrelationConfidence = "low"
)

func CorrelationConfidences() []CorrelationConfidence {
	return []CorrelationConfidence{CorrelationHigh, CorrelationMedium, CorrelationLow}
}

func (c CorrelationConfidence) IsValid() bool {
	for _, known := range CorrelationConfidences() {
		if c == known {
			return true
		}
	}
	return false
}

type CorrelationScope struct {
	Complete bool `json:"complete"`

	Note string `json:"note,omitempty"`
}

type Correlation struct {
	ID string `json:"id"`

	RuleID string `json:"rule_id"`

	Title string `json:"title"`

	FindingIDs []string `json:"finding_ids"`

	Confidence CorrelationConfidence `json:"confidence"`

	Explanation string `json:"explanation"`

	Technique *Technique `json:"technique,omitempty"`

	AttackRelevance string `json:"attack_relevance,omitempty"`

	Scope CorrelationScope `json:"scope"`
}

func SortCorrelations(records []Correlation) {
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].RuleID != records[j].RuleID {
			return records[i].RuleID < records[j].RuleID
		}
		return records[i].ID < records[j].ID
	})
}

func (c Correlation) Validate() error {
	if c.ID == "" {
		return errors.New("model: correlation requires an id")
	}
	if c.RuleID == "" {
		return errors.New("model: correlation requires a rule id")
	}
	if c.Title == "" {
		return fmt.Errorf("model: correlation %s requires a title", c.ID)
	}
	if !c.Confidence.IsValid() {
		return fmt.Errorf("model: correlation %s has unknown confidence %q",
			c.ID, string(c.Confidence))
	}
	if c.Explanation == "" {
		return fmt.Errorf("model: correlation %s requires an explanation", c.ID)
	}
	if err := c.validateFindingIDs(); err != nil {
		return err
	}
	if err := c.Technique.Validate(); err != nil {
		return err
	}
	if c.Technique == nil && c.AttackRelevance != "" {
		return fmt.Errorf("model: correlation %s explains a technique it does not name", c.ID)
	}
	if c.Technique != nil && strings.TrimSpace(c.AttackRelevance) == "" {
		return fmt.Errorf("model: correlation %s names technique %s without explaining its relevance",
			c.ID, c.Technique.ID)
	}
	if c.Scope.Complete && c.Scope.Note != "" {
		return fmt.Errorf("model: correlation %s has a complete scope and a note", c.ID)
	}
	if !c.Scope.Complete && strings.TrimSpace(c.Scope.Note) == "" {
		return fmt.Errorf("model: correlation %s has an incomplete scope and no note", c.ID)
	}
	return nil
}

func (c Correlation) validateFindingIDs() error {
	if len(c.FindingIDs) < 2 {
		return fmt.Errorf("model: correlation %s references %d finding(s); a relationship needs at least two",
			c.ID, len(c.FindingIDs))
	}
	for i, id := range c.FindingIDs {
		if id == "" {
			return fmt.Errorf("model: correlation %s has an empty finding identifier at position %d", c.ID, i)
		}
		if i > 0 {
			if id == c.FindingIDs[i-1] {
				return fmt.Errorf("model: correlation %s references %s more than once", c.ID, id)
			}
			if id < c.FindingIDs[i-1] {
				return fmt.Errorf("model: correlation %s finding identifiers are not sorted", c.ID)
			}
		}
	}
	return nil
}
