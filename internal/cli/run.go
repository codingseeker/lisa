package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"lisa/internal/attack"
	"lisa/internal/baseline"
	"lisa/internal/config"
	"lisa/internal/detectors"
	"lisa/internal/logging"
	"lisa/internal/report"
	"lisa/internal/scan"
)

const Version = "0.1.0"

const rootUsage = `lisa - Linux host security auditing and forensic analysis

Usage:
  lisa <command> [flags] [target]

Commands:
  scan              audit a directory tree and report findings
  baseline create   record a baseline of file metadata and hashes
  baseline compare  compare the current state against a baseline
  version           print the version and exit
  help              print this help and exit

Run "lisa <command> --help" for command specific flags.

Exit codes:
  0  scan completed with no findings at or above the reporting threshold
  1  scan completed and reportable findings were detected
  2  invalid arguments or configuration
  3  operational failure
`

const scanUsage = `Usage: lisa scan [flags] <target>

Audits a directory tree and reports findings as structured records.

Flags:
  --path <dir>            target directory, may also be given positionally
  --workers <n>           maximum concurrent filesystem workers
  --exclude <path>        path to exclude, repeatable
  --detector <name>       detector to enable, repeatable, default all
  --min-severity <level>  lowest severity to report
  --baseline <file>       baseline to create or compare against
  --output <file>         write the report to a file instead of stdout
  --format <format>       text, json, csv or html
  --recent                include a clearly labelled recent activity section
  --recent-window <dur>   window covered by the recent activity section
  --gtfobins              annotate SUID and SGID findings whose basename is in
                          the curated GTFOBins subset; off by default
  --risk                  score each finding for review priority, on by
                          default; --risk=false omits the score
  --sort-risk             order findings by descending risk instead of severity
  --correlate             infer relationships between findings, on by default;
                          --correlate=false omits them
  --attack                add MITRE ATT&CK technique context to correlations, on
                          by default; --attack=false omits it
  --verbose               enable debug logging on stderr
  --quiet                 suppress logging on stderr
`

const baselineCreateUsage = `Usage: lisa baseline create [flags] <target>

Scans the target and records the findings it reports into a versioned baseline
file. The file holds only a stable identifier per finding and the attributes
needed to detect a later change: no file contents, no evidence lines and no
secrets. It is written atomically with owner-only permissions, and an existing
file is never replaced unless --overwrite is given.

A baseline recorded from a partial or cancelled scan says so in its coverage
record, and later comparisons withhold resolutions against it rather than
claiming that findings were fixed.

Flags:
  --path <dir>            target directory, may also be given positionally
  --baseline <file>       baseline file to write, required
  --overwrite             replace an existing baseline instead of refusing
  --workers <n>           maximum concurrent filesystem workers
  --exclude <path>        path to exclude, repeatable
  --detector <name>       detector to enable, repeatable (default: all)
  --min-severity <level>  lowest severity to record
  --output <file>         write the recorded baseline, or a summary of it, to
                          this file instead of stdout
  --format <format>       text, json, csv or html
  --gtfobins              record curated GTFOBins context for SUID and SGID
                          findings whose basename is in the curated subset;
                          off by default
  --verbose               enable debug logging on stderr
  --quiet                 suppress all logging on stderr
`

const baselineCompareUsage = `Usage: lisa baseline compare [flags] <target>

Scans the target and reports how it differs from a saved baseline: findings that
appeared, findings that disappeared, and findings whose attributes changed.

A finding is identified by its rule, category and path, so it keeps the same
identity across runs. Severity, confidence, mode, ownership and curated
reference context are the compared attributes, which means a rule tuning or a
curated dataset update is reported as a change rather than as a flood of new
findings.

A finding the scan no longer reports is only called resolved when the scan could
actually vouch for it. Cancellation, traversal limits, detector failures, an
unreadable directory, a raised severity threshold and a narrower detector
selection all suppress resolutions, and the reliability block says which applied.

Flags:
  --path <dir>            target directory, may also be given positionally
  --baseline <file>       baseline file to compare against, required
  --workers <n>           maximum concurrent filesystem workers
  --exclude <path>        path to exclude, repeatable
  --detector <name>       detector to enable, repeatable (default: all)
  --min-severity <level>  lowest severity to report
  --output <file>         write the report to a file instead of stdout
  --format <format>       text, json, csv or html
  --gtfobins              annotate SUID and SGID findings whose basename is in
                          the curated GTFOBins subset; off by default
  --verbose               enable debug logging on stderr
  --quiet                 suppress all logging on stderr
`

func Run(args []string, stdout, stderr io.Writer) int {
	err := dispatch(args, stdout, stderr)
	if err == nil {
		return ExitOK
	}

	var coded *Error
	if errors.As(err, &coded) {
		fmt.Fprintf(stderr, "lisa: %s\n", coded.Message)
		if coded.Usage != "" {
			fmt.Fprint(stderr, coded.Usage)
		}
		return coded.Code
	}

	var findings *FindingsError
	if errors.As(err, &findings) {
		return ExitFindings
	}

	fmt.Fprintf(stderr, "lisa: %v\n", err)
	return ExitOperational
}

func dispatch(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageErrorWithUsagef(rootUsage, "no command given")
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, rootUsage)
		return nil
	case "version", "-V", "--version":
		fmt.Fprintf(stdout, "lisa %s %s %s/%s\n", Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return nil
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "baseline":
		return runBaseline(args[1:], stdout, stderr)
	default:
		return usageErrorWithUsagef(rootUsage, "unknown command %q", args[0])
	}
}

func runScan(args []string, stdout, stderr io.Writer) error {
	cfg, err := buildConfig(config.CommandScan, "scan", args, stdout, stderr)
	if err != nil {
		return err
	}
	if cfg == nil {
		return nil
	}
	if len(cfg.Detectors) > 0 {
		if err := validateDetectorNames(cfg.Detectors); err != nil {
			return usageErrorf("%v", err)
		}
	}
	if cfg.Format != config.FormatText && cfg.Format != config.FormatJSON {
		return operationalErrorf("output format %q is not available in this build, use text or json", string(cfg.Format))
	}

	log := logging.New(stderr, logging.LevelFor(cfg.Verbose, cfg.Quiet))
	log.Debug("scan configuration accepted",
		"target", cfg.Target,
		"workers", cfg.Workers,
		"excludes", len(cfg.Excludes),
		"detectors", len(cfg.Detectors),
		"min_severity", cfg.MinSeverity.String(),
		"format", string(cfg.Format),
		"gtfobins", cfg.GTFOBins,
		"risk", cfg.RiskEnabled,
		"sort_risk", cfg.SortByRisk,
		"correlate", cfg.Correlate,
		"attack", cfg.Attack,
	)

	stopProgress := make(chan struct{})
	if cfg.Verbose && !cfg.Quiet {
		go reportProgress(stderr, stopProgress)
	}

	result, scanErr := scan.Run(context.Background(), scan.Options{
		Roots:                  []string{cfg.Target},
		Workers:                cfg.Workers,
		Excludes:               cfg.Excludes,
		Detectors:              cfg.Detectors,
		MinSeverity:            cfg.MinSeverity,
		Identity:               detectors.SystemIdentity(),
		MaxDepth:               cfg.MaxDepth,
		MaxEntries:             cfg.MaxEntries,
		FollowSymlinks:         cfg.FollowSymlinks,
		SkipVirtualFilesystems: cfg.SkipVirtualFilesystems,
		GTFOBins:               cfg.GTFOBins,
	})
	close(stopProgress)

	if result == nil {
		if scanErr != nil {
			return operationalErrorf("scan failed: %v", scanErr)
		}
		return operationalErrorf("scan produced no result")
	}

	var attackSet *attack.Set
	if cfg.Correlate && cfg.Attack {
		attackSet = attack.Dataset()
	}

	document := report.BuildWith(result, "lisa", Version, report.Options{
		Score:      cfg.RiskEnabled,
		SortByRisk: cfg.SortByRisk,
		Correlate:  cfg.Correlate,
		Attack:     attackSet,
	})
	if err := writeReport(document, cfg, stdout); err != nil {
		return operationalErrorf("%v", err)
	}

	if result.Status == scan.StatusPartial {
		fmt.Fprintln(stderr, "lisa: partial scan, coverage is incomplete; see the warnings section")
	}

	if len(document.Findings) > 0 {
		return &FindingsError{Count: len(document.Findings)}
	}
	if scanErr != nil {
		return operationalErrorf("scan failed: %v", scanErr)
	}
	return nil
}

type FindingsError struct {
	Count int
}

func (e *FindingsError) Error() string {
	return fmt.Sprintf("%d reportable finding(s) detected", e.Count)
}

func validateDetectorNames(names []string) error {
	available := detectors.DefaultRegistry().Names()
	known := make(map[string]struct{}, len(available))
	for _, name := range available {
		known[name] = struct{}{}
	}
	var unknown []string
	for _, name := range names {
		if _, ok := known[strings.TrimSpace(name)]; !ok {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		return fmt.Errorf("unknown detector(s): %s; available: %s",
			strings.Join(unknown, ", "), strings.Join(available, ", "))
	}
	return nil
}

func reportProgress(stderr io.Writer, stop <-chan struct{}) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			fmt.Fprintf(stderr, "lisa: scanning %s\n", "in progress")
		}
	}
}

func writeReport(document report.Document, cfg *config.Config, stdout io.Writer) error {
	var buffer bytes.Buffer
	switch cfg.Format {
	case config.FormatJSON:
		if err := report.WriteJSON(&buffer, document); err != nil {
			return err
		}
	default:
		if err := report.WriteText(&buffer, document); err != nil {
			return err
		}
	}

	if cfg.OutputPath == "" {
		if _, err := buffer.WriteTo(stdout); err != nil {
			return fmt.Errorf("writing report to stdout failed: %w", err)
		}
		return nil
	}

	content := buffer.Bytes()
	return writeBuffer(cfg.OutputPath, content)
}

func runBaseline(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageErrorWithUsagef(rootUsage, "baseline: expected a subcommand, create or compare")
	}
	var command config.Command
	switch args[0] {
	case "create":
		command = config.CommandBaselineCreate
	case "compare":
		command = config.CommandBaselineCompare
	default:
		return usageErrorf("baseline: unknown subcommand %q, expected create or compare", args[0])
	}
	cfg, err := buildConfig(command, command.Usage(), args[1:], stdout, stderr)
	if err != nil {
		return err
	}
	if cfg == nil {
		return nil
	}
	if command == config.CommandBaselineCreate && cfg.BaselinePath == "" {
		return usageErrorWithUsagef(baselineCreateUsage, "baseline create: --baseline is required")
	}
	if cfg.Format != config.FormatText && cfg.Format != config.FormatJSON {
		return operationalErrorf("output format %q is not available in this build, use text or json", string(cfg.Format))
	}
	if len(cfg.Detectors) > 0 {
		if err := validateDetectorNames(cfg.Detectors); err != nil {
			return usageErrorf("%v", err)
		}
	}

	log := logging.New(stderr, logging.LevelFor(cfg.Verbose, cfg.Quiet))
	log.Debug("baseline configuration accepted",
		"target", cfg.Target,
		"baseline", cfg.BaselinePath,
		"overwrite", cfg.Overwrite,
		"detectors", len(cfg.Detectors),
		"min_severity", cfg.MinSeverity.String(),
		"format", string(cfg.Format),
		"gtfobins", cfg.GTFOBins,
	)

	result, scanErr := scan.Run(context.Background(), scan.Options{
		Roots:                  []string{cfg.Target},
		Workers:                cfg.Workers,
		Excludes:               cfg.Excludes,
		Detectors:              cfg.Detectors,
		MinSeverity:            cfg.MinSeverity,
		Identity:               detectors.SystemIdentity(),
		MaxDepth:               cfg.MaxDepth,
		MaxEntries:             cfg.MaxEntries,
		FollowSymlinks:         cfg.FollowSymlinks,
		SkipVirtualFilesystems: cfg.SkipVirtualFilesystems,
		GTFOBins:               cfg.GTFOBins,
	})
	if result == nil {
		if scanErr != nil {
			return operationalErrorf("scan failed: %v", scanErr)
		}
		return operationalErrorf("scan produced no result")
	}
	if result.Status == scan.StatusPartial {
		fmt.Fprintln(stderr, "lisa: partial scan, coverage is incomplete; see the coverage record")
	}

	if command == config.CommandBaselineCreate {
		return createBaseline(cfg, result, stdout, stderr)
	}
	return compareBaseline(cfg, result, stdout, stderr)
}

func createBaseline(cfg *config.Config, result *scan.Result, stdout, stderr io.Writer) error {
	document, err := baseline.Create(result, baseline.CreateOptions{
		Tool:        baseline.Tool{Name: "lisa", Version: Version},
		MinSeverity: cfg.MinSeverity,
		GTFOBins:    cfg.GTFOBins,
		CreatedAt:   time.Now(),
	})
	if err != nil {
		return operationalErrorf("%v", err)
	}
	if err := baseline.Write(document, cfg.BaselinePath, baseline.WriteOptions{Overwrite: cfg.Overwrite}); err != nil {
		if errors.Is(err, baseline.ErrExists) {
			return usageErrorWithUsagef(baselineCreateUsage, "%v", err)
		}
		return operationalErrorf("%v", err)
	}

	var buffer bytes.Buffer
	if cfg.Format == config.FormatJSON {
		encoded, err := document.Marshal()
		if err != nil {
			return operationalErrorf("%v", err)
		}
		buffer.Write(encoded)
		buffer.WriteByte('\n')
	} else {
		fmt.Fprintf(&buffer, "Recorded %d finding(s) from %s into %s\n",
			document.Summary.Findings, cfg.Target, cfg.BaselinePath)
		if !document.Coverage.Complete {
			fmt.Fprintln(&buffer,
				"The baseline records an incomplete scan; comparisons against it will withhold resolutions")
		}
	}

	if cfg.OutputPath == "" {
		if _, err := buffer.WriteTo(stdout); err != nil {
			return operationalErrorf("writing the creation summary to stdout failed: %v", err)
		}
	} else if err := writeBuffer(cfg.OutputPath, buffer.Bytes()); err != nil {
		return operationalErrorf("%v", err)
	}
	return nil
}

func compareBaseline(cfg *config.Config, result *scan.Result, stdout, stderr io.Writer) error {
	document, err := baseline.Load(cfg.BaselinePath, baseline.LoadOptions{})
	if err != nil {
		if errors.Is(err, baseline.ErrNotFound) || errors.Is(err, baseline.ErrSchema) ||
			errors.Is(err, baseline.ErrInvalidDocument) {
			return usageErrorWithUsagef(baselineCompareUsage, "%v", err)
		}
		return operationalErrorf("%v", err)
	}

	comparison, err := baseline.Compare(document, result.Reportable(), baseline.CompareOptions{
		BaselinePath:       cfg.BaselinePath,
		Current:            baseline.ScanCurrent(result),
		CurrentMinSeverity: cfg.MinSeverity,
		CurrentGTFOBins:    cfg.GTFOBins,
		ComparedAt:         time.Now(),
	})
	if err != nil {
		return operationalErrorf("%v", err)
	}

	reported, err := report.BuildBaseline(comparison)
	if err != nil {
		return operationalErrorf("%v", err)
	}

	var buffer bytes.Buffer
	switch cfg.Format {
	case config.FormatJSON:
		err = report.WriteBaselineJSON(&buffer, reported)
	default:
		err = report.WriteBaselineText(&buffer, reported)
	}
	if err != nil {
		return operationalErrorf("%v", err)
	}

	if cfg.OutputPath == "" {
		if _, err := buffer.WriteTo(stdout); err != nil {
			return operationalErrorf("writing the comparison to stdout failed: %v", err)
		}
	} else if err := writeBuffer(cfg.OutputPath, buffer.Bytes()); err != nil {
		return operationalErrorf("%v", err)
	}

	if !comparison.Reliability.Reliable {
		fmt.Fprintln(stderr,
			"lisa: the scan could not confirm the absence of baseline findings; nothing is reported as resolved")
	}
	if comparison.Counts.ChangeCount > 0 {
		return &FindingsError{Count: comparison.Counts.ChangeCount}
	}
	return nil
}

func writeBuffer(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("opening output file %q failed: %w", path, err)
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		return fmt.Errorf("writing output file %q failed: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("closing output file %q failed: %w", path, err)
	}
	return nil
}

func usageFor(command config.Command) string {
	defaults := config.Default()
	footer := fmt.Sprintf("\nDefaults: workers=%d min-severity=%s format=%s recent-window=%s\n",
		defaults.Workers, defaults.MinSeverity, defaults.Format, defaults.RecentWindow)
	switch command {
	case config.CommandScan:
		return scanUsage + footer
	case config.CommandBaselineCreate:
		return baselineCreateUsage + footer
	case config.CommandBaselineCompare:
		return baselineCompareUsage + footer
	default:
		return rootUsage
	}
}

func buildConfig(command config.Command, name string, args []string, stdout, stderr io.Writer) (*config.Config, error) {
	usage := usageFor(command)
	if helpRequested(args) {
		fmt.Fprint(stdout, usage)
		return nil, nil
	}

	defaults := config.Default()
	opts := &options{}
	fs := newFlagSet(name)
	opts.register(fs, defaults)

	positional, err := parseInterspersed(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, usageErrorWithUsagef(usage, "%s: no arguments provided", name)
		}
		return nil, usageErrorWithUsagef(usage, "%s: %v", name, err)
	}

	cfg, err := opts.build(command, positional)
	if err != nil {
		return nil, usageErrorWithUsagef(usage, "%s: %v", name, err)
	}
	if err := cfg.Normalize(); err != nil {
		return nil, usageErrorWithUsagef(usage, "%s: %v", name, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, usageErrorWithUsagef(usage, "%s: %v", name, err)
	}
	return &cfg, nil
}

func helpRequested(args []string) bool {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" || arg == "-help" {
			return true
		}
	}
	return false
}
