package scan

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"time"

	"lisa/internal/detectors"
	"lisa/internal/fsscan"
	"lisa/internal/model"
)

type Status string

const (
	StatusComplete  Status = "complete"
	StatusPartial   Status = "partial"
	StatusCancelled Status = "cancelled"
)

type Options struct {
	Roots                  []string
	Workers                int
	Excludes               []string
	Detectors              []string
	MinSeverity            model.Severity
	Identity               *detectors.Identity
	GTFOBins               bool
	Now                    time.Time
	MaxDepth               int
	MaxEntries             int
	FollowSymlinks         bool
	SkipVirtualFilesystems bool
	OnProgress             func(fsscan.Stats)
}

type Result struct {
	Status      Status
	Findings    []model.Finding
	Files       fsscan.Stats
	Detectors   detectors.Stats
	Roots       []string
	MinSeverity model.Severity
	StartedAt   time.Time
	FinishedAt  time.Time
	Duplicates  int
}

func (r Result) Duration() time.Duration {
	if r.StartedAt.IsZero() || r.FinishedAt.IsZero() {
		return 0
	}
	return r.FinishedAt.Sub(r.StartedAt)
}

func (r Result) Reportable() []model.Finding {
	return r.Findings
}

func (r Result) DetectorFailureCount() int64 {
	var total int64
	for _, count := range r.Detectors.DetectorFailures {
		total += count
	}
	return total
}

func Run(ctx context.Context, opts Options) (*Result, error) {
	if len(opts.Roots) == 0 {
		return nil, fmt.Errorf("scan: at least one root is required")
	}
	if opts.Workers == 0 {
		opts.Workers = defaultWorkers()
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}

	engine, err := detectors.NewEngine(detectors.Options{
		Detectors: opts.Detectors,
		Identity:  opts.Identity,
		GTFOBins:  opts.GTFOBins,
		Now:       opts.Now,
	})
	if err != nil {
		return nil, err
	}

	walker, err := fsscan.New(fsscan.Options{
		Roots:                  opts.Roots,
		Workers:                opts.Workers,
		Excludes:               opts.Excludes,
		MaxDepth:               opts.MaxDepth,
		MaxEntries:             opts.MaxEntries,
		FollowSymlinks:         opts.FollowSymlinks,
		SkipVirtualFilesystems: opts.SkipVirtualFilesystems,
		OnProgress:             opts.OnProgress,
	})
	if err != nil {
		return nil, err
	}

	collector := newCollector(opts.MinSeverity)

	started := time.Now().UTC()
	walkErr := walker.Walk(ctx, func(entry fsscan.Entry) {
		collector.add(engine.Process(entry))
	})
	finished := time.Now().UTC()

	files := walker.Stats()
	result := &Result{
		Findings:    collector.sorted(),
		Files:       files,
		Detectors:   engine.Stats(),
		Roots:       files.Roots,
		MinSeverity: opts.MinSeverity,
		StartedAt:   started,
		FinishedAt:  finished,
		Duplicates:  collector.duplicates,
	}
	result.Status = classify(result, ctx, walkErr)

	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if walkErr != nil {
		return result, walkErr
	}
	return result, nil
}

func classify(result *Result, ctx context.Context, walkErr error) Status {
	if ctx.Err() != nil {
		return StatusCancelled
	}
	if walkErr != nil {
		return StatusPartial
	}
	files := result.Files
	if files.Cancelled || files.EntryLimitHit || files.DepthLimitHit ||
		files.Errors > 0 || files.PermissionDenied > 0 || result.DetectorFailureCount() > 0 {
		return StatusPartial
	}
	return StatusComplete
}

type collector struct {
	minSeverity model.Severity
	byID        map[string]model.Finding
	duplicates  int
}

func newCollector(minSeverity model.Severity) *collector {
	if !minSeverity.IsValid() {
		minSeverity = model.SeverityInfo
	}
	return &collector{minSeverity: minSeverity, byID: map[string]model.Finding{}}
}

func (c *collector) add(findings []model.Finding) {
	for _, finding := range findings {
		if finding.Severity < c.minSeverity {
			continue
		}
		if err := finding.Validate(); err != nil {
			continue
		}
		if _, exists := c.byID[finding.ID]; exists {
			c.duplicates++
			continue
		}
		c.byID[finding.ID] = finding
	}
}

func (c *collector) sorted() []model.Finding {
	findings := make([]model.Finding, 0, len(c.byID))
	for _, finding := range c.byID {
		findings = append(findings, finding)
	}
	SortFindings(findings)
	return findings
}

func SortFindings(findings []model.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		left, right := findings[i], findings[j]
		if left.Severity != right.Severity {
			return left.Severity > right.Severity
		}
		if left.Path != right.Path {
			return left.Path < right.Path
		}
		return left.RuleID < right.RuleID
	})
}

func defaultWorkers() int {
	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}
	if workers < 1 {
		workers = 1
	}
	return workers
}
