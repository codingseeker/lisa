package baseline

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"lisa/internal/detectors"
	"lisa/internal/model"
	"lisa/internal/scan"
)

type Status string

const (
	StatusNew Status = "new"

	StatusResolved Status = "resolved"

	StatusUnchanged Status = "unchanged"

	StatusChanged Status = "changed"

	StatusUnverified Status = "unverified"
)

var statusOrder = map[Status]int{
	StatusNew: 0, StatusChanged: 1, StatusUnverified: 2, StatusResolved: 3, StatusUnchanged: 4,
}

type Change struct {
	Attribute string `json:"attribute"`
	Baseline  string `json:"baseline,omitempty"`
	Current   string `json:"current,omitempty"`
}

func (c Change) String() string {
	switch {
	case c.Baseline == "":
		return fmt.Sprintf("%s added (%s)", c.Attribute, c.Current)
	case c.Current == "":
		return fmt.Sprintf("%s removed (was %s)", c.Attribute, c.Baseline)
	default:
		return fmt.Sprintf("%s %s -> %s", c.Attribute, c.Baseline, c.Current)
	}
}

type Item struct {
	ID       string         `json:"id"`
	RuleID   string         `json:"rule_id"`
	Category model.Category `json:"category"`
	Path     string         `json:"path"`
	Title    string         `json:"title"`
	Status   Status         `json:"status"`
	Baseline *Entry         `json:"baseline,omitempty"`
	Current  *Entry         `json:"current,omitempty"`
	Changes  []Change       `json:"changes,omitempty"`
}

type Counts struct {
	New         int `json:"new"`
	Changed     int `json:"changed"`
	Resolved    int `json:"resolved"`
	Unverified  int `json:"unverified"`
	Unchanged   int `json:"unchanged"`
	ChangeCount int `json:"change_count"`
}

type Comparison struct {
	BaselinePath   string      `json:"-"`
	BaselineSchema string      `json:"baseline_schema"`
	BaselineTool   Tool        `json:"baseline_tool"`
	BaselineAt     string      `json:"baseline_created_at"`
	ComparedAt     string      `json:"compared_at"`
	ScanStatus     string      `json:"scan_status"`
	MinSeverity    string      `json:"min_severity"`
	GTFOBins       bool        `json:"gtfobins"`
	Counts         Counts      `json:"counts"`
	Reliability    Reliability `json:"reliability"`
	Duplicates     int         `json:"duplicates_collapsed"`
	Items          []Item      `json:"items"`
}

func (c *Comparison) Marshal() ([]byte, error) {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("baseline: encoding the comparison failed: %w", err)
	}
	return append(data, '\n'), nil
}

func (c *Comparison) Changes() []Item {
	out := make([]Item, 0, len(c.Items))
	for _, item := range c.Items {
		if item.Status != StatusUnchanged {
			out = append(out, item)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if statusOrder[out[i].Status] != statusOrder[out[j].Status] {
			return statusOrder[out[i].Status] < statusOrder[out[j].Status]
		}
		return itemLess(out[i], out[j])
	})
	return out
}

type CompareOptions struct {
	BaselinePath string

	Current CurrentScan

	CurrentMinSeverity model.Severity
	CurrentGTFOBins    bool

	ComparedAt time.Time

	IncludeUnchanged bool
}

func Compare(document *Document, findings []model.Finding, opts CompareOptions) (*Comparison, error) {
	if document == nil {
		return nil, fmt.Errorf("baseline: a document is required")
	}
	if err := document.Validate(); err != nil {
		return nil, err
	}
	if opts.ComparedAt.IsZero() {
		return nil, fmt.Errorf("baseline: a comparison timestamp is required")
	}

	currentEntries, duplicates, err := entriesOf(findings)
	if err != nil {
		return nil, err
	}

	policy := Policy(document.Coverage, document.MinSeverity, document.GTFOBins,
		opts.Current, opts.CurrentMinSeverity, opts.CurrentGTFOBins)
	reliability := policy.resolve(document.Findings)

	baselineByID := make(map[string]Entry, len(document.Findings))
	for _, entry := range document.Findings {
		baselineByID[entry.ID] = entry
	}
	currentByID := make(map[string]Entry, len(currentEntries))
	for _, entry := range currentEntries {
		currentByID[entry.ID] = entry
	}

	items := make([]Item, 0, len(document.Findings)+len(currentEntries))
	for _, entry := range document.Findings {
		now, present := currentByID[entry.ID]
		switch {
		case present:
			before, after := entry, now
			item := Item{
				ID: entry.ID, RuleID: entry.RuleID, Category: entry.Category, Path: entry.Path,
				Title: entry.Title, Baseline: &before, Current: &after,
			}
			if changes := differences(entry, now); len(changes) > 0 {
				item.Status = StatusChanged
				item.Changes = changes
			} else {
				item.Status = StatusUnchanged
			}
			items = append(items, item)
		case reliability.MayResolve(entry.ID):
			before := entry
			items = append(items, Item{
				ID: entry.ID, RuleID: entry.RuleID, Category: entry.Category, Path: entry.Path,
				Title: entry.Title, Status: StatusResolved, Baseline: &before,
			})
		default:
			before := entry
			items = append(items, Item{
				ID: entry.ID, RuleID: entry.RuleID, Category: entry.Category, Path: entry.Path,
				Title: entry.Title, Status: StatusUnverified, Baseline: &before,
			})
		}
	}

	for _, entry := range currentEntries {
		if _, present := baselineByID[entry.ID]; present {
			continue
		}
		after := entry
		items = append(items, Item{
			ID: entry.ID, RuleID: entry.RuleID, Category: entry.Category, Path: entry.Path,
			Title: entry.Title, Status: StatusNew, Current: &after,
		})
	}

	comparison := &Comparison{
		BaselinePath:   opts.BaselinePath,
		BaselineSchema: document.Schema,
		BaselineTool:   document.Tool,
		BaselineAt:     document.CreatedAt,
		ComparedAt:     opts.ComparedAt.UTC().Format(time.RFC3339),
		ScanStatus:     string(opts.Current.Status),
		MinSeverity:    opts.CurrentMinSeverity.String(),
		GTFOBins:       opts.CurrentGTFOBins,
		Reliability:    reliability,
		Duplicates:     duplicates,
		Items:          items,
	}
	comparison.sort()
	comparison.count()
	if !opts.IncludeUnchanged {
		comparison.Items = filtered(comparison.Items)
	}
	return comparison, nil
}

func differences(before, after Entry) []Change {
	var changes []Change
	changes = appendChange(changes, "severity", before.Severity.String(), after.Severity.String())
	changes = appendChange(changes, "confidence", before.Confidence.String(), after.Confidence.String())
	changes = appendChange(changes, "mode", before.Mode, after.Mode)
	changes = appendChange(changes, "owner", before.Owner, after.Owner)
	changes = appendChange(changes, "group", before.Group, after.Group)
	changes = appendReferenceChanges(changes, before.Reference, after.Reference)
	return changes
}

var comparedReferenceAttributes = []struct {
	name  string
	value func(*Reference) string
}{
	{"reference.source", func(r *Reference) string { return r.Source }},
	{"reference.binary", func(r *Reference) string { return r.Binary }},
	{"reference.category", func(r *Reference) string { return r.Category }},
	{"reference.severity", func(r *Reference) string { return r.Severity.String() }},
	{"reference.summary", func(r *Reference) string { return r.Summary }},
}

func appendReferenceChanges(changes []Change, before, after *Reference) []Change {
	for _, attribute := range comparedReferenceAttributes {
		var beforeValue, afterValue string
		if before != nil {
			beforeValue = attribute.value(before)
		}
		if after != nil {
			afterValue = attribute.value(after)
		}
		changes = appendChange(changes, attribute.name, beforeValue, afterValue)
	}
	return changes
}

func appendChange(changes []Change, attribute, before, after string) []Change {
	if before == after {
		return changes
	}
	return append(changes, Change{Attribute: attribute, Baseline: before, Current: after})
}

func (c *Comparison) sort() {
	sort.SliceStable(c.Items, func(i, j int) bool {
		left, right := c.Items[i], c.Items[j]
		if statusOrder[left.Status] != statusOrder[right.Status] {
			return statusOrder[left.Status] < statusOrder[right.Status]
		}
		return itemLess(left, right)
	})
}

func (c *Comparison) count() {
	c.Counts = Counts{}
	for _, item := range c.Items {
		switch item.Status {
		case StatusNew:
			c.Counts.New++
		case StatusChanged:
			c.Counts.Changed++
		case StatusResolved:
			c.Counts.Resolved++
		case StatusUnverified:
			c.Counts.Unverified++
		case StatusUnchanged:
			c.Counts.Unchanged++
		}
	}
	c.Counts.ChangeCount = c.Counts.New + c.Counts.Changed
}

func itemLess(left, right Item) bool {
	if left.Path != right.Path {
		return left.Path < right.Path
	}
	if left.RuleID != right.RuleID {
		return left.RuleID < right.RuleID
	}
	if left.Category != right.Category {
		return left.Category < right.Category
	}
	return left.ID < right.ID
}

func filtered(items []Item) []Item {
	out := make([]Item, 0, len(items))
	for _, item := range items {
		if item.Status != StatusUnchanged {
			out = append(out, item)
		}
	}
	return out
}

func ScanCurrent(result *scan.Result) CurrentScan {
	return CurrentScanOf(result)
}

func allDetectorNames() []string {
	names := detectors.DefaultRegistry().Names()
	sort.Strings(names)
	return names
}
