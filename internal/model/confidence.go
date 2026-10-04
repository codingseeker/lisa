package model

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Confidence int

const (
	ConfidenceLow Confidence = iota
	ConfidenceMedium
	ConfidenceHigh
)

var confidenceNames = map[Confidence]string{
	ConfidenceLow:    "low",
	ConfidenceMedium: "medium",
	ConfidenceHigh:   "high",
}

func Confidences() []Confidence {
	return []Confidence{ConfidenceLow, ConfidenceMedium, ConfidenceHigh}
}

func (c Confidence) String() string {
	if name, ok := confidenceNames[c]; ok {
		return name
	}
	return fmt.Sprintf("confidence(%d)", int(c))
}

func (c Confidence) IsValid() bool {
	_, ok := confidenceNames[c]
	return ok
}

func (c Confidence) MarshalJSON() ([]byte, error) {
	if !c.IsValid() {
		return nil, fmt.Errorf("cannot marshal invalid confidence %d", int(c))
	}
	return json.Marshal(c.String())
}

func (c *Confidence) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err != nil {
		return fmt.Errorf("confidence must be a JSON string: %w", err)
	}
	parsed, err := ParseConfidence(name)
	if err != nil {
		return err
	}
	*c = parsed
	return nil
}

func ParseConfidence(name string) (Confidence, error) {
	normalized := strings.ToLower(strings.TrimSpace(name))
	for confidence, candidate := range confidenceNames {
		if candidate == normalized {
			return confidence, nil
		}
	}
	return ConfidenceLow, fmt.Errorf("unknown confidence %q, expected one of low, medium, high", name)
}
