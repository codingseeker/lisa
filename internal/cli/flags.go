package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"lisa/internal/config"
	"lisa/internal/model"
)

type stringList []string

func (l *stringList) String() string {
	return strings.Join(*l, ",")
}

func (l *stringList) Set(value string) error {
	*l = append(*l, value)
	return nil
}

type options struct {
	path         string
	workers      int
	excludes     stringList
	detectors    stringList
	minSeverity  string
	baseline     string
	output       string
	format       string
	recent       bool
	recentWindow time.Duration
	verbose      bool
	quiet        bool

	maxDepth               int
	maxEntries             int
	followSymlinks         bool
	skipVirtualFilesystems bool
	gtfobins               bool
	overwrite              bool
	risk                   bool
	sortRisk               bool
	correlate              bool
	attack                 bool
}

func (o *options) register(fs *flag.FlagSet, defaults config.Config) {
	fs.StringVar(&o.path, "path", "", "directory to scan")
	fs.IntVar(&o.workers, "workers", defaults.Workers, "maximum concurrent filesystem workers")
	fs.Var(&o.excludes, "exclude", "path to exclude, repeatable")
	fs.Var(&o.detectors, "detector", "detector to enable, repeatable (default: all)")
	fs.StringVar(&o.minSeverity, "min-severity", defaults.MinSeverity.String(), "lowest severity to report: info, low, medium, high, critical")
	fs.StringVar(&o.baseline, "baseline", "", "baseline file to create or compare against")
	fs.StringVar(&o.output, "output", "", "write the report to this file instead of stdout")
	fs.StringVar(&o.format, "format", string(defaults.Format), "output format: text, json, csv, html")
	fs.BoolVar(&o.recent, "recent", defaults.Recent, "include a clearly labelled recent activity section")
	fs.DurationVar(&o.recentWindow, "recent-window", defaults.RecentWindow, "window covered by the recent activity section")
	fs.BoolVar(&o.verbose, "verbose", defaults.Verbose, "enable debug logging on stderr")
	fs.BoolVar(&o.quiet, "quiet", defaults.Quiet, "suppress all logging on stderr")
	fs.IntVar(&o.maxDepth, "max-depth", defaults.MaxDepth, "maximum directory depth to descend, 0 for unlimited")
	fs.IntVar(&o.maxEntries, "max-entries", defaults.MaxEntries, "maximum number of entries to visit")
	fs.BoolVar(&o.followSymlinks, "follow-symlinks", defaults.FollowSymlinks, "follow symlinks that resolve inside the scan root")
	fs.BoolVar(&o.skipVirtualFilesystems, "skip-virtual", defaults.SkipVirtualFilesystems, "skip /proc and /sys during traversal")
	fs.BoolVar(&o.gtfobins, "gtfobins", defaults.GTFOBins, "enrich SUID and SGID findings with curated GTFOBins context")
	fs.BoolVar(&o.overwrite, "overwrite", defaults.Overwrite, "replace an existing baseline file instead of refusing")
	fs.BoolVar(&o.risk, "risk", defaults.RiskEnabled, "score findings for review priority; --risk=false omits the score")
	fs.BoolVar(&o.sortRisk, "sort-risk", defaults.SortByRisk, "order findings by descending risk instead of by severity")
	fs.BoolVar(&o.correlate, "correlate", defaults.Correlate, "infer relationships between findings; --correlate=false omits them")
	fs.BoolVar(&o.attack, "attack", defaults.Attack, "add ATT&CK technique context to correlations; --attack=false omits it")
}

func (o *options) build(command config.Command, positional []string) (config.Config, error) {
	severity, err := model.ParseSeverity(o.minSeverity)
	if err != nil {
		return config.Config{}, err
	}
	format, err := config.ParseFormat(o.format)
	if err != nil {
		return config.Config{}, err
	}
	target, err := resolveTarget(o.path, positional)
	if err != nil {
		return config.Config{}, err
	}
	return config.Config{
		Command:      command,
		Target:       target,
		Workers:      o.workers,
		Excludes:     o.excludes,
		Detectors:    o.detectors,
		MinSeverity:  severity,
		BaselinePath: o.baseline,
		OutputPath:   o.output,
		Format:       format,
		Recent:       o.recent,
		RecentWindow: o.recentWindow,
		Verbose:      o.verbose,
		Quiet:        o.quiet,

		MaxDepth:               o.maxDepth,
		MaxEntries:             o.maxEntries,
		FollowSymlinks:         o.followSymlinks,
		SkipVirtualFilesystems: o.skipVirtualFilesystems,
		GTFOBins:               o.gtfobins,
		Overwrite:              o.overwrite,
		RiskEnabled:            o.risk,
		SortByRisk:             o.sortRisk,
		Correlate:              o.correlate,
		Attack:                 o.attack,
	}, nil
}

func resolveTarget(pathFlag string, positional []string) (string, error) {
	switch {
	case len(positional) > 1:
		return "", fmt.Errorf("only one target directory may be given, received %d", len(positional))
	case pathFlag != "" && len(positional) == 1:
		return "", fmt.Errorf("target given twice, use either --path or a positional path")
	case pathFlag != "":
		return pathFlag, nil
	case len(positional) == 1:
		return positional[0], nil
	default:
		return "", nil
	}
}

func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	positional := []string{}
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		remaining := fs.Args()
		if len(remaining) == 0 {
			return positional, nil
		}
		positional = append(positional, remaining[0])
		args = remaining[1:]
	}
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	return fs
}
