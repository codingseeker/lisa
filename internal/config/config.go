package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"lisa/internal/model"
)

const (
	DefaultWorkers      = 16
	MaxWorkers          = 256
	DefaultRecentWindow = 7 * 24 * time.Hour
	DefaultMaxEntries   = 4_000_000
)

type Command string

const (
	CommandScan            Command = "scan"
	CommandBaselineCreate  Command = "baseline-create"
	CommandBaselineCompare Command = "baseline-compare"
	CommandVersion         Command = "version"
)

func (c Command) Usage() string {
	switch c {
	case CommandBaselineCreate:
		return "baseline create"
	case CommandBaselineCompare:
		return "baseline compare"
	default:
		return string(c)
	}
}

func (c Command) IsValid() bool {
	switch c {
	case CommandScan, CommandBaselineCreate, CommandBaselineCompare, CommandVersion:
		return true
	}
	return false
}

type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
	FormatCSV  Format = "csv"
	FormatHTML Format = "html"
)

func Formats() []Format {
	return []Format{FormatText, FormatJSON, FormatCSV, FormatHTML}
}

func (f Format) IsValid() bool {
	for _, known := range Formats() {
		if f == known {
			return true
		}
	}
	return false
}

func ParseFormat(name string) (Format, error) {
	normalized := Format(strings.ToLower(strings.TrimSpace(name)))
	if normalized.IsValid() {
		return normalized, nil
	}
	return FormatText, fmt.Errorf("unknown output format %q, expected one of text, json, csv, html", name)
}

type Config struct {
	Command      Command
	Target       string
	Workers      int
	Excludes     []string
	Detectors    []string
	MinSeverity  model.Severity
	BaselinePath string
	OutputPath   string
	Format       Format
	Recent       bool
	RecentWindow time.Duration
	Verbose      bool
	Quiet        bool

	MaxDepth               int
	MaxEntries             int
	FollowSymlinks         bool
	SkipVirtualFilesystems bool
	GTFOBins               bool
	Overwrite              bool

	RiskEnabled bool

	SortByRisk bool

	Correlate bool

	Attack bool
}

func Default() Config {
	return Config{
		Command:                "",
		Workers:                defaultWorkers(),
		MinSeverity:            model.SeverityInfo,
		Format:                 FormatText,
		RecentWindow:           DefaultRecentWindow,
		MaxEntries:             DefaultMaxEntries,
		SkipVirtualFilesystems: true,
		RiskEnabled:            true,
		Correlate:              true,
		Attack:                 true,
	}
}

func defaultWorkers() int {
	workers := runtime.NumCPU()
	if workers > DefaultWorkers {
		workers = DefaultWorkers
	}
	if workers < 1 {
		workers = 1
	}
	return workers
}

func (c *Config) Validate() error {
	if !c.Command.IsValid() {
		return fmt.Errorf("unknown command %q", string(c.Command))
	}
	if c.Workers < 1 || c.Workers > MaxWorkers {
		return fmt.Errorf("workers must be between 1 and %d, got %d", MaxWorkers, c.Workers)
	}
	if !c.MinSeverity.IsValid() {
		return fmt.Errorf("invalid minimum severity %d", int(c.MinSeverity))
	}
	if !c.Format.IsValid() {
		return fmt.Errorf("unknown output format %q", string(c.Format))
	}
	if c.Verbose && c.Quiet {
		return errors.New("verbose and quiet are mutually exclusive")
	}
	if c.SortByRisk && !c.RiskEnabled {
		return errors.New("--sort-risk requires risk scoring, which --no-risk disables")
	}
	if c.MaxDepth < 0 {
		return fmt.Errorf("max depth must not be negative, got %d", c.MaxDepth)
	}
	if c.MaxEntries < 1 {
		return fmt.Errorf("max entries must be positive, got %d", c.MaxEntries)
	}
	if c.Recent && c.RecentWindow <= 0 {
		return fmt.Errorf("recent window must be positive, got %s", c.RecentWindow)
	}
	if err := validateNames(c.Detectors, "detector"); err != nil {
		return err
	}
	if c.Command == CommandVersion {
		return nil
	}
	if err := c.validateTarget(); err != nil {
		return err
	}
	return c.validatePaths()
}

func (c *Config) validateTarget() error {
	if c.Command == CommandVersion {
		return nil
	}
	if strings.TrimSpace(c.Target) == "" {
		return fmt.Errorf("%s requires a target directory", c.Command.Usage())
	}
	info, err := os.Stat(c.Target)
	if err != nil {
		return fmt.Errorf("target %q is not accessible: %w", c.Target, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("target %q is not a directory", c.Target)
	}
	return nil
}

func (c *Config) validatePaths() error {
	if _, err := normalizeNames(c.Excludes, "excluded path"); err != nil {
		return err
	}
	if c.Command == CommandBaselineCompare && strings.TrimSpace(c.BaselinePath) == "" {
		return errors.New("baseline compare requires --baseline")
	}
	if c.BaselinePath != "" {
		if c.Command != CommandBaselineCreate {
			info, err := os.Stat(c.BaselinePath)
			if err != nil {
				return fmt.Errorf("baseline %q is not accessible: %w", c.BaselinePath, err)
			}
			if info.IsDir() {
				return fmt.Errorf("baseline %q is a directory", c.BaselinePath)
			}
		}
		if c.BaselinePath == c.OutputPath {
			return errors.New("baseline and output paths must differ")
		}
	}
	if c.Overwrite && c.Command != CommandBaselineCreate {
		return errors.New("--overwrite is only meaningful for baseline create")
	}
	if c.OutputPath != "" {
		if info, err := os.Stat(c.OutputPath); err == nil && info.IsDir() {
			return fmt.Errorf("output %q is a directory", c.OutputPath)
		}
		parent := filepath.Dir(c.OutputPath)
		if _, err := os.Stat(parent); err != nil {
			return fmt.Errorf("output directory %q is not accessible: %w", parent, err)
		}
	}
	return nil
}

func validateNames(names []string, label string) error {
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			return fmt.Errorf("empty %s name is not allowed", label)
		}
		if _, duplicate := seen[trimmed]; duplicate {
			return fmt.Errorf("duplicate %s %q", label, trimmed)
		}
		seen[trimmed] = struct{}{}
	}
	return nil
}

func normalizeNames(names []string, label string) ([]string, error) {
	if err := validateNames(names, label); err != nil {
		return nil, err
	}
	normalized := make([]string, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		cleaned := filepath.Clean(strings.TrimSpace(name))
		if _, duplicate := seen[cleaned]; duplicate {
			continue
		}
		seen[cleaned] = struct{}{}
		normalized = append(normalized, cleaned)
	}
	return normalized, nil
}

func (c *Config) Normalize() error {
	excludes, err := normalizeNames(c.Excludes, "excluded path")
	if err != nil {
		return err
	}
	c.Excludes = excludes
	if c.Target != "" {
		c.Target = filepath.Clean(c.Target)
	}
	if c.BaselinePath != "" {
		c.BaselinePath = filepath.Clean(c.BaselinePath)
	}
	if c.OutputPath != "" {
		c.OutputPath = filepath.Clean(c.OutputPath)
	}
	return nil
}
