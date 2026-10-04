package model

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityInfo:     "info",
	SeverityLow:      "low",
	SeverityMedium:   "medium",
	SeverityHigh:     "high",
	SeverityCritical: "critical",
}

func Severities() []Severity {
	return []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
}

func (s Severity) String() string {
	if name, ok := severityNames[s]; ok {
		return name
	}
	return fmt.Sprintf("severity(%d)", int(s))
}

func (s Severity) IsValid() bool {
	_, ok := severityNames[s]
	return ok
}

func (s Severity) AtLeast(minimum Severity) bool {
	return s >= minimum
}

func (s Severity) MarshalJSON() ([]byte, error) {
	if !s.IsValid() {
		return nil, fmt.Errorf("cannot marshal invalid severity %d", int(s))
	}
	return json.Marshal(s.String())
}

func (s *Severity) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err != nil {
		return fmt.Errorf("severity must be a JSON string: %w", err)
	}
	parsed, err := ParseSeverity(name)
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

func ParseSeverity(name string) (Severity, error) {
	normalized := strings.ToLower(strings.TrimSpace(name))
	for severity, candidate := range severityNames {
		if candidate == normalized {
			return severity, nil
		}
	}
	return SeverityInfo, fmt.Errorf("unknown severity %q, expected one of info, low, medium, high, critical", name)
}
