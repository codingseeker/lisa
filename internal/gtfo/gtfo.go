package gtfo

import (
	_ "embed"
	"fmt"
	"path"
	"sort"
	"strings"
)

const SourceName = "gtfobins-curated"

const Attribution = "Concept: GTFOBins (https://github.com/GTFOBins/GTFOBins, MIT licence). Independent curated subset; descriptions are original."

//go:embed data/gtfobins.tsv
var dataset string

type Entry struct {
	Binary   string
	Category string
	Summary  string
}

type Set struct {
	entries []Entry
	byName  map[string]Entry
}

func Parse(content string) (*Set, error) {
	entries := make([]Entry, 0, 64)
	byName := make(map[string]Entry, 64)
	seenLines := map[string]int{}

	for index, raw := range strings.Split(content, "\n") {
		lineNumber := index + 1
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			return nil, fmt.Errorf("gtfo: line %d: expected 3 tab-separated fields, found %d", lineNumber, len(fields))
		}

		name := strings.TrimSpace(fields[0])
		category := strings.TrimSpace(fields[1])
		summary := strings.TrimSpace(fields[2])

		if err := validateName(name, lineNumber); err != nil {
			return nil, err
		}
		if category == "" {
			return nil, fmt.Errorf("gtfo: line %d: %s has an empty category", lineNumber, name)
		}
		if summary == "" {
			return nil, fmt.Errorf("gtfo: line %d: %s has an empty summary", lineNumber, name)
		}
		if len(summary) > 240 {
			return nil, fmt.Errorf("gtfo: line %d: %s has a summary longer than 240 characters", lineNumber, name)
		}
		if previous, duplicate := seenLines[name]; duplicate {
			return nil, fmt.Errorf("gtfo: line %d: duplicate binary %q, already defined on line %d", lineNumber, name, previous)
		}
		seenLines[name] = lineNumber

		entry := Entry{Binary: name, Category: category, Summary: summary}
		entries = append(entries, entry)
		byName[name] = entry
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("gtfo: dataset contains no entries")
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Binary < entries[j].Binary })

	return &Set{entries: entries, byName: byName}, nil
}

func validateName(name string, lineNumber int) error {
	if name == "" {
		return fmt.Errorf("gtfo: line %d: empty binary name", lineNumber)
	}
	if strings.ContainsAny(name, "/\\ \t") {
		return fmt.Errorf("gtfo: line %d: binary name %q must not contain path separators or whitespace", lineNumber, name)
	}
	if name != strings.ToLower(name) {
		return fmt.Errorf("gtfo: line %d: binary name %q must be lower case", lineNumber, name)
	}
	return nil
}

func Default() *Set {
	set, err := Parse(dataset)
	if err != nil {
		return &Set{byName: map[string]Entry{}}
	}
	return set
}

func (s *Set) Lookup(candidate string) (Entry, bool) {
	if s == nil || candidate == "" {
		return Entry{}, false
	}
	name := path.Base(strings.TrimSpace(candidate))
	if name == "" || name == "." || name == "/" {
		return Entry{}, false
	}
	entry, ok := s.byName[name]
	return entry, ok
}

func (s *Set) Entries() []Entry {
	if s == nil {
		return nil
	}
	return append([]Entry(nil), s.entries...)
}

func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.entries)
}

func (s *Set) Categories() []string {
	if s == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(s.entries))
	for _, entry := range s.entries {
		seen[entry.Category] = struct{}{}
	}
	categories := make([]string, 0, len(seen))
	for category := range seen {
		categories = append(categories, category)
	}
	sort.Strings(categories)
	return categories
}
