package attack

import (
	_ "embed"
	"fmt"
	"sort"
	"strings"

	"lisa/internal/model"
)

const DatasetName = "lisa-attack-curated"

const Framework = "MITRE ATT&CK"

const Attribution = "Technique names and tactics (c) The MITRE Corporation, MITRE ATT&CK, " +
	"Apache License 2.0. Mapping choices and relevance notes are original."

//go:embed data/techniques.tsv
var dataset string

type Mapping struct {
	CorrelationRule string
	Technique       model.Technique

	Reference string

	Relevance string
}

type Set struct {
	mappings   []Mapping
	byRule     map[string]Mapping
	techniques map[string]model.Technique
	version    string
}

func (s *Set) Version() string {
	if s == nil {
		return ""
	}
	return s.version
}

func Dataset() *Set {
	set, err := Parse(dataset)
	if err != nil {
		return &Set{byRule: map[string]Mapping{}, techniques: map[string]model.Technique{}}
	}
	return set
}

func Parse(content string) (*Set, error) {
	mappings := make([]Mapping, 0, 16)
	byRule := make(map[string]Mapping, 16)
	techniques := make(map[string]model.Technique, 16)
	seenLines := map[string]int{}
	version := ""

	for index, raw := range strings.Split(content, "\n") {
		lineNumber := index + 1
		line := strings.TrimRight(raw, "\r")

		if strings.HasPrefix(strings.TrimSpace(line), "#") {

			if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "# dataset_version:") {
				version = strings.TrimSpace(strings.TrimPrefix(trimmed, "# dataset_version:"))
			}
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.Split(line, "\t")
		if len(fields) != 6 {
			return nil, fmt.Errorf("attack: line %d: expected 6 tab-separated fields, found %d",
				lineNumber, len(fields))
		}

		rule := strings.TrimSpace(fields[0])
		name := strings.TrimSpace(fields[2])
		tactic := strings.TrimSpace(fields[3])
		reference := strings.TrimSpace(fields[4])
		relevance := strings.TrimSpace(fields[5])

		if rule == "" {
			return nil, fmt.Errorf("attack: line %d: empty correlation rule", lineNumber)
		}
		if !strings.HasPrefix(rule, "LS-COR-") {
			return nil, fmt.Errorf("attack: line %d: %q is not an LS-COR-* correlation rule",
				lineNumber, rule)
		}
		technique := model.Technique{ID: strings.TrimSpace(fields[1]), Name: name, Tactic: tactic}
		if err := technique.Validate(); err != nil {
			return nil, fmt.Errorf("attack: line %d: %w", lineNumber, err)
		}
		if err := validateReference(reference, technique.ID, rule, lineNumber); err != nil {
			return nil, err
		}
		if relevance == "" {
			return nil, fmt.Errorf("attack: line %d: %s has no relevance explanation", lineNumber, rule)
		}
		if len(relevance) > 400 {
			return nil, fmt.Errorf("attack: line %d: %s has a relevance note longer than 400 characters",
				lineNumber, rule)
		}
		if previous, duplicate := seenLines[rule]; duplicate {
			return nil, fmt.Errorf("attack: line %d: duplicate mapping for %s, already defined on line %d",
				lineNumber, rule, previous)
		}
		seenLines[rule] = lineNumber

		mapping := Mapping{
			CorrelationRule: rule,
			Technique:       technique,
			Reference:       reference,
			Relevance:       relevance,
		}
		mappings = append(mappings, mapping)
		byRule[rule] = mapping
		techniques[technique.ID] = technique
	}

	if len(mappings) == 0 {
		return nil, fmt.Errorf("attack: dataset contains no mappings")
	}
	if version == "" {
		return nil, fmt.Errorf("attack: dataset does not record a dataset_version")
	}

	sort.Slice(mappings, func(i, j int) bool {
		return mappings[i].CorrelationRule < mappings[j].CorrelationRule
	})

	return &Set{mappings: mappings, byRule: byRule, techniques: techniques, version: version}, nil
}

const techniqueReferencePrefix = "https://attack.mitre.org/techniques/"

func validateReference(reference, techniqueID, rule string, lineNumber int) error {
	if reference == "" {
		return fmt.Errorf("attack: line %d: %s has no technique reference", lineNumber, rule)
	}
	want := techniqueReferencePrefix + strings.ReplaceAll(techniqueID, ".", "/") + "/"
	if reference != want {
		return fmt.Errorf("attack: line %d: %s reference %q does not match technique %s, want %q",
			lineNumber, rule, reference, techniqueID, want)
	}
	return nil
}

func (s *Set) Lookup(correlationRule string) (Mapping, bool) {
	if s == nil || correlationRule == "" {
		return Mapping{}, false
	}
	mapping, ok := s.byRule[correlationRule]
	return mapping, ok
}

func (s *Set) Mappings() []Mapping {
	if s == nil {
		return nil
	}
	return append([]Mapping(nil), s.mappings...)
}

func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.mappings)
}

func (s *Set) Techniques() []model.Technique {
	if s == nil {
		return nil
	}
	out := make([]model.Technique, 0, len(s.techniques))
	for _, technique := range s.techniques {
		out = append(out, technique)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
