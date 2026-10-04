package baseline

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"lisa/internal/fsscan"
	"lisa/internal/model"
	"lisa/internal/scan"
)

type Reliability struct {
	Complete bool `json:"complete"`

	Reliable bool `json:"reliable"`

	ResolutionsSuppressed bool `json:"resolutions_suppressed"`

	Suppressed []string `json:"suppressed,omitempty"`

	Reasons []string `json:"reasons,omitempty"`
}

type CurrentScan struct {
	Status      scan.Status
	MinSeverity model.Severity
	Detectors   []string
	Files       fsscan.Stats
	Failures    map[string]int64
}

func CurrentScanOf(result *scan.Result) CurrentScan {
	if result == nil {
		return CurrentScan{}
	}
	selected := result.Detectors.Selected
	if len(selected) == 0 {
		selected = allDetectorNames()
	}
	return CurrentScan{
		Status:      result.Status,
		MinSeverity: result.MinSeverity,
		Detectors:   selected,
		Files:       result.Files,
		Failures:    result.Detectors.DetectorFailures,
	}
}

func Policy(baselineCoverage Coverage, baselineMinSeverity string, baselineGTFOBins bool,
	current CurrentScan, currentMinSeverity model.Severity, currentGTFOBins bool) PolicyDecision {
	decision := PolicyDecision{baselineCoverage: baselineCoverage, current: current}
	decision.BlockingReasons, decision.AdvisoryReasons = reasons(
		baselineCoverage, baselineMinSeverity, baselineGTFOBins,
		current, currentMinSeverity, currentGTFOBins)
	decision.ScopedReasons = scopedReasons(current)

	if !decision.explained() && len(decision.BlockingReasons) == 0 && len(decision.ScopedReasons) == 0 {

		decision.BlockingReasons = append(decision.BlockingReasons,
			"the current scan completed only partially for an unrecorded reason")
	}
	return decision
}

func (d PolicyDecision) explained() bool {
	return d.current.Status != scan.StatusPartial
}

type PolicyDecision struct {
	baselineCoverage Coverage
	current          CurrentScan

	BlockingReasons []string

	AdvisoryReasons []string

	ScopedReasons []ScopedReason
}

type ScopedReason struct {
	Paths  []string
	Reason string
}

func reasons(baseline Coverage, baselineMinSeverity string, baselineGTFOBins bool,
	current CurrentScan, currentMinSeverity model.Severity, currentGTFOBins bool) (blocking, advisory []string) {

	switch current.Status {
	case scan.StatusCancelled:
		blocking = append(blocking, "the current scan was cancelled before it finished")
	case scan.StatusPartial, scan.StatusComplete:
	default:
		blocking = append(blocking, fmt.Sprintf("the current scan reported the unknown status %q", clip(string(current.Status))))
	}

	if current.Files.Cancelled {
		blocking = append(blocking, "the current scan stopped its filesystem walk early")
	}
	if current.Files.EntryLimitHit {
		blocking = append(blocking, "the current scan reached its configured entry limit, so some paths were never visited")
	}
	if current.Files.DepthLimitHit {
		blocking = append(blocking, "the current scan reached its configured depth limit, so some paths were never visited")
	}
	if unattributed := current.Files.Errors - current.Files.PermissionDenied; unattributed > 0 {
		blocking = append(blocking, fmt.Sprintf(
			"the current scan hit %d filesystem error(s) that were not permission denials and whose extent is not recorded, so missing coverage cannot be located",
			unattributed))
	}
	if current.Files.InaccessibleTruncated {

		blocking = append(blocking,
			fmt.Sprintf("the current scan stopped recording unreadable paths after %d, so unreadable areas may be missing",
				fsscan.DefaultMaxInaccessible))
	}

	if failed := sortedCounts(current.Failures); len(failed) > 0 {
		blocking = append(blocking, fmt.Sprintf(
			"detectors %s failed during the current scan, and the tool does not record which rules each detector owns, "+
				"so a finding they would have produced cannot be distinguished from one that was fixed",
			strings.Join(failed, ", ")))
	}

	if baselineMin, err := model.ParseSeverity(baselineMinSeverity); err == nil {
		if currentMinSeverity > baselineMin {
			blocking = append(blocking, fmt.Sprintf(
				"the current scan reports from %s but the baseline recorded findings from %s, so lower severity findings would look resolved",
				currentMinSeverity, baselineMin))
		}
	}
	if skipped := missingDetectors(baseline.Detectors, current.Detectors); len(skipped) > 0 {
		blocking = append(blocking, fmt.Sprintf(
			"the current scan did not run detectors %s, so their findings cannot be resolved",
			strings.Join(skipped, ", ")))
	}

	if !baseline.Complete {
		blocking = append(blocking,
			"the baseline was recorded from a scan that did not complete, so a finding it lacks may never have been inspected")
	}

	if baselineGTFOBins != currentGTFOBins {
		advisory = append(advisory, fmt.Sprintf(
			"supplemental GTFOBins context was %s for the current scan and %s for the baseline, so differences in it may reflect the flag rather than the host",
			enabledLabel(currentGTFOBins), enabledLabel(baselineGTFOBins)))
	}
	return blocking, advisory
}

func scopedReasons(current CurrentScan) []ScopedReason {
	var reasons []ScopedReason

	if !current.Files.InaccessibleTruncated {
		if paths := inaccessiblePaths(current.Files); len(paths) > 0 {
			reasons = append(reasons, ScopedReason{
				Paths: paths,
				Reason: fmt.Sprintf(
					"the current scan could not read %d path(s), so a finding recorded at or beneath them cannot be confirmed absent",
					len(paths)),
			})
		}
	}
	return reasons
}

func inaccessiblePaths(files fsscan.Stats) []string {
	paths := make([]string, 0, len(files.Inaccessible))
	for _, entry := range files.Inaccessible {
		path := strings.TrimSpace(entry)
		if index := strings.LastIndex(path, " ("); index > 0 && strings.HasSuffix(path, ")") {
			path = path[:index]
		}
		if path == "" || !filepath.IsAbs(path) {
			continue
		}
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func missingDetectors(baseline, current []string) []string {
	if len(baseline) == 0 {
		return nil
	}
	ran := make(map[string]bool, len(current))
	for _, name := range current {
		ran[name] = true
	}
	var missing []string
	for _, name := range baseline {
		if !ran[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	return missing
}

func enabledLabel(value bool) string {
	if value {
		return "enabled"
	}
	return "disabled"
}

func (d PolicyDecision) resolve(entries []Entry) Reliability {
	reliability := Reliability{
		Complete:   d.current.Status == scan.StatusComplete,
		Reliable:   len(d.BlockingReasons) == 0,
		Reasons:    append(append([]string(nil), d.BlockingReasons...), d.AdvisoryReasons...),
		Suppressed: nil,
	}

	for _, scoped := range d.ScopedReasons {
		for _, entry := range entries {
			if !withinAny(entry.Path, scoped.Paths) {
				continue
			}
			reliability.ResolutionsSuppressed = true
			reliability.Suppressed = append(reliability.Suppressed, entry.ID)
			reliability.Reasons = append(reliability.Reasons, scoped.Reason)
		}
	}

	if len(d.BlockingReasons) > 0 {
		for _, entry := range entries {
			if !contains(reliability.Suppressed, entry.ID) {
				reliability.Suppressed = append(reliability.Suppressed, entry.ID)
			}
		}
	}

	sort.Strings(reliability.Suppressed)
	reliability.Suppressed = dedupe(reliability.Suppressed)
	sort.Strings(reliability.Reasons)
	reliability.Reasons = dedupe(reliability.Reasons)
	return reliability
}

func (r Reliability) MayResolve(id string) bool {
	return !contains(r.Suppressed, id)
}

func withinAny(path string, prefixes []string) bool {
	cleaned := filepath.Clean(path)
	for _, prefix := range prefixes {
		root := filepath.Clean(prefix)
		if cleaned == root {
			return true
		}
		if strings.HasSuffix(root, string(filepath.Separator)) {
			if strings.HasPrefix(cleaned, root) {
				return true
			}
			continue
		}
		if strings.HasPrefix(cleaned, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func dedupe(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for i, value := range values {
		if i > 0 && value == values[i-1] {
			continue
		}
		out = append(out, value)
	}
	return out
}
