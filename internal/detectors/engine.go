package detectors

import (
	"fmt"
	"sync"
	"time"

	"lisa/internal/fsscan"
	"lisa/internal/model"
)

type Options struct {
	Detectors            []string
	Identity             *Identity
	ReadFile             FileReader
	Now                  time.Time
	GTFOBins             bool
	MaxContentBytes      int64
	MaxReadableFileBytes int64
	MaxHeaderReads       int
	headerBudget         *int64
}

func (o *Options) applyDefaults() {
	if o.Now.IsZero() {
		o.Now = time.Now().UTC()
	}
	if o.MaxContentBytes <= 0 {
		o.MaxContentBytes = 256 * 1024
	}
	if o.MaxReadableFileBytes <= 0 {
		o.MaxReadableFileBytes = 8 * 1024 * 1024
	}
	if o.MaxHeaderReads <= 0 {
		o.MaxHeaderReads = DefaultMaxHeaderReads
	}
	if o.headerBudget == nil {
		budget := int64(o.MaxHeaderReads)
		o.headerBudget = &budget
	}
	if o.ReadFile == nil {
		o.ReadFile = newLimitedFileReader(o.MaxContentBytes, o.MaxReadableFileBytes)
	}
	if o.Identity == nil {
		o.Identity = &Identity{users: map[uint32]string{}, groups: map[uint32]string{}}
	}
}

const DefaultMaxHeaderReads = 200_000

type Stats struct {
	EntriesProcessed int64            `json:"entries_processed"`
	DetectorCalls    int64            `json:"detector_calls"`
	DetectorFailures map[string]int64 `json:"detector_failures,omitempty"`
	Findings         int64            `json:"findings"`
	ContentReads     int64            `json:"content_reads"`
	HeaderBudget     int64            `json:"header_budget"`

	Selected []string `json:"-"`
}

type Engine struct {
	registry *Registry
	opts     Options
	mu       sync.Mutex
	stats    Stats
}

func NewEngine(opts Options) (*Engine, error) {
	opts.applyDefaults()
	registry, err := DefaultRegistry().Select(opts.Detectors)
	if err != nil {
		return nil, err
	}
	return &Engine{
		registry: registry,
		opts:     opts,
		stats:    Stats{DetectorFailures: map[string]int64{}},
	}, nil
}

func (e *Engine) DetectorNames() []string {
	return e.registry.Names()
}

func (e *Engine) Stats() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	snapshot := e.stats
	snapshot.DetectorFailures = map[string]int64{}
	for name, count := range e.stats.DetectorFailures {
		snapshot.DetectorFailures[name] = count
	}
	snapshot.Selected = append([]string(nil), e.registry.Names()...)
	return snapshot
}

func (e *Engine) Process(entry fsscan.Entry) []model.Finding {
	ctx := newContext(entry, e.opts)
	var findings []model.Finding

	e.mu.Lock()
	e.stats.EntriesProcessed++
	e.mu.Unlock()

	for _, detector := range e.registry.detectors {
		e.mu.Lock()
		e.stats.DetectorCalls++
		e.mu.Unlock()

		produced, failure := runDetector(detector, ctx)
		if failure != nil {
			e.recordFailure(detector.Name(), failure)
			continue
		}
		for i := range produced {
			findings = append(findings, normalizeFinding(produced[i], ctx))
		}
	}

	e.mu.Lock()
	e.stats.Findings += int64(len(findings))
	e.mu.Unlock()

	return findings
}

func normalizeFinding(finding model.Finding, ctx Context) model.Finding {
	if finding.DetectedAt.IsZero() {
		finding.DetectedAt = ctx.Now
	}
	return finding
}

func (e *Engine) recordFailure(name string, failure error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stats.DetectorFailures[name]++
}

func runDetector(detector Detector, ctx Context) (findings []model.Finding, failure error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			findings = nil
			failure = fmt.Errorf("detector %s panicked: %v", detector.Name(), recovered)
		}
	}()
	return detector.Detect(ctx), nil
}
