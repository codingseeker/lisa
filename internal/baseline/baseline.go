package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"lisa/internal/model"
	"lisa/internal/scan"
)

type Document struct {
	Schema      string   `json:"schema"`
	Version     int      `json:"version"`
	Tool        Tool     `json:"tool"`
	CreatedAt   string   `json:"created_at"`
	Roots       []string `json:"roots"`
	MinSeverity string   `json:"min_severity"`
	GTFOBins    bool     `json:"gtfobins"`
	Coverage    Coverage `json:"coverage"`
	Summary     Summary  `json:"summary"`
	Findings    []Entry  `json:"findings"`
}

type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Summary struct {
	Findings   int            `json:"findings"`
	BySeverity map[string]int `json:"by_severity"`
	Duplicates int            `json:"duplicates_collapsed"`
}

type Coverage struct {
	ScanStatus        string   `json:"scan_status"`
	Complete          bool     `json:"complete"`
	Detectors         []string `json:"detectors"`
	FailedDetectors   []string `json:"failed_detectors,omitempty"`
	InaccessiblePaths []string `json:"inaccessible_paths,omitempty"`
	LimitsReached     bool     `json:"limits_reached"`
	Notes             []string `json:"notes,omitempty"`
}

type CreateOptions struct {
	Tool        Tool
	MinSeverity model.Severity

	GTFOBins bool

	CreatedAt time.Time
}

func Create(result *scan.Result, opts CreateOptions) (*Document, error) {
	if result == nil {
		return nil, fmt.Errorf("baseline: a scan result is required")
	}
	if strings.TrimSpace(opts.Tool.Name) == "" {
		return nil, fmt.Errorf("baseline: a tool name is required")
	}
	if !opts.MinSeverity.IsValid() {
		return nil, fmt.Errorf("baseline: invalid minimum severity %d", int(opts.MinSeverity))
	}
	if opts.CreatedAt.IsZero() {
		return nil, fmt.Errorf("baseline: a creation timestamp is required")
	}

	created, duplicates, err := entriesOf(result.Findings)
	if err != nil {
		return nil, err
	}

	document := &Document{
		Schema:      Schema,
		Version:     Version,
		Tool:        opts.Tool,
		CreatedAt:   opts.CreatedAt.UTC().Format(time.RFC3339),
		Roots:       sortedCopy(result.Roots),
		MinSeverity: opts.MinSeverity.String(),
		GTFOBins:    opts.GTFOBins,
		Coverage:    coverageOf(result),
		Findings:    created,
	}
	document.Summary = summarise(created, duplicates)
	return document, nil
}

func entriesOf(findings []model.Finding) ([]Entry, int, error) {
	entries := make([]Entry, 0, len(findings))
	index := make(map[string]int, len(findings))
	duplicates := 0

	for position, finding := range findings {
		entry := EntryOf(finding)
		if err := entry.Validate(position); err != nil {
			return nil, 0, fmt.Errorf("baseline: %w", err)
		}
		if previous, seen := index[entry.ID]; seen {
			duplicates++
			if entries[previous] != entry {
				return nil, 0, fmt.Errorf("baseline: %w: %s at %s conflicts with an earlier finding on the same path",
					ErrAmbiguousIdentity, entry.RuleID, entry.Path)
			}
			continue
		}
		index[entry.ID] = len(entries)
		entries = append(entries, entry)
	}

	sortEntries(entries)
	return entries, duplicates, nil
}

func sortEntries(entries []Entry) {
	sort.Slice(entries, func(i, j int) bool {
		left, right := entries[i], entries[j]
		if left.Path != right.Path {
			return left.Path < right.Path
		}
		if left.RuleID != right.RuleID {
			return left.RuleID < right.RuleID
		}
		return left.Category < right.Category
	})
}

func coverageOf(result *scan.Result) Coverage {
	files := result.Files
	coverage := Coverage{
		ScanStatus:        string(result.Status),
		Complete:          result.Status == scan.StatusComplete,
		Detectors:         sortedCopy(result.Detectors.Selected),
		FailedDetectors:   sortedCounts(result.Detectors.DetectorFailures),
		InaccessiblePaths: sortedCopy(files.Inaccessible),
		LimitsReached:     files.EntryLimitHit || files.DepthLimitHit,
	}
	if !coverage.Complete {
		coverage.Notes = append(coverage.Notes,
			"the baseline was recorded from a scan that did not complete; resolved classifications against it are unreliable")
	}
	if len(coverage.FailedDetectors) > 0 {
		coverage.Notes = append(coverage.Notes,
			"one or more detectors failed during the baseline scan")
	}
	if len(coverage.InaccessiblePaths) > 0 {
		coverage.Notes = append(coverage.Notes,
			"one or more paths could not be read during the baseline scan")
	}
	if coverage.LimitsReached {
		coverage.Notes = append(coverage.Notes,
			"the baseline scan hit a configured traversal limit")
	}
	return coverage
}

func summarise(entries []Entry, duplicates int) Summary {
	summary := Summary{Findings: len(entries), Duplicates: duplicates, BySeverity: map[string]int{}}
	for _, severity := range model.Severities() {
		summary.BySeverity[severity.String()] = 0
	}
	for _, entry := range entries {
		summary.BySeverity[entry.Severity.String()]++
	}
	return summary
}

func sortedCopy(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func sortedCounts(counts map[string]int64) []string {
	if len(counts) == 0 {
		return nil
	}
	names := make([]string, 0, len(counts))
	for name, count := range counts {
		if count > 0 {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func (d *Document) Digest() string {
	digest := sha256.New()
	for _, entry := range d.Findings {
		digest.Write([]byte(entry.ID))
		digest.Write([]byte{0})
		digest.Write([]byte(entry.comparisonKey()))
		digest.Write([]byte{0})
	}
	return hex.EncodeToString(digest.Sum(nil))[:identityDigestLength]
}

func (e Entry) comparisonKey() string {
	reference := ""
	if e.Reference != nil {
		reference = strings.Join([]string{
			e.Reference.Source, e.Reference.Binary, e.Reference.Category,
			e.Reference.Summary, e.Reference.Severity.String(),
		}, "\x1f")
	}
	fields := []string{
		e.Severity.String(),
		e.Confidence.String(),
		e.Mode,
		e.Owner,
		e.Group,
		reference,
	}
	var builder strings.Builder
	for _, field := range fields {
		fmt.Fprintf(&builder, "%d:%s\x1e", len(field), field)
	}
	return builder.String()
}

func (d *Document) Marshal() ([]byte, error) {
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("baseline: encoding failed: %w", err)
	}
	return append(data, '\n'), nil
}
