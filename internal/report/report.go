package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"lisa/internal/attack"
	"lisa/internal/correlation"
	"lisa/internal/detectors"
	"lisa/internal/model"
	"lisa/internal/risk"
	"lisa/internal/scan"
)

const Schema = "lisa/report/v1"

type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type ScanMeta struct {
	Roots       []string `json:"roots"`
	MinSeverity string   `json:"min_severity"`
	StartedAt   string   `json:"started_at"`
	FinishedAt  string   `json:"finished_at"`
	DurationMS  int64    `json:"duration_ms"`
	Status      string   `json:"status"`
}

type Counts struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	ByCategory map[string]int `json:"by_category"`

	ByRiskBand map[string]int `json:"by_risk_band,omitempty"`
}

type Files struct {
	Directories      int64 `json:"directories"`
	Files            int64 `json:"files"`
	Symlinks         int64 `json:"symlinks"`
	SpecialFiles     int64 `json:"special_files"`
	Entries          int64 `json:"entries"`
	Excluded         int64 `json:"excluded"`
	Errors           int64 `json:"errors"`
	PermissionDenied int64 `json:"permission_denied"`
	EntryLimitHit    bool  `json:"entry_limit_hit"`
	DepthLimitHit    bool  `json:"depth_limit_hit"`
	Inaccessible     int   `json:"inaccessible_count"`
}

type DetectorStats struct {
	EntriesProcessed int64            `json:"entries_processed"`
	DetectorCalls    int64            `json:"detector_calls"`
	Findings         int64            `json:"findings"`
	Duplicates       int              `json:"duplicate_findings"`
	Failures         map[string]int64 `json:"failures,omitempty"`
}

type Warnings struct {
	Partial          bool     `json:"partial"`
	LimitsReached    bool     `json:"limits_reached"`
	Inaccessible     bool     `json:"inaccessible_paths"`
	DetectorFailures bool     `json:"detector_failures"`
	Notes            []string `json:"notes,omitempty"`
}

type CorrelationSummary struct {
	Total int `json:"total"`

	ByConfidence map[string]int `json:"by_confidence,omitempty"`

	Mapped int `json:"mapped"`
}

type AttackContext struct {
	Framework string `json:"framework"`
	Dataset   string `json:"dataset"`
	Version   string `json:"version"`

	Attribution string `json:"attribution"`

	Caveat string `json:"caveat"`
}

type Document struct {
	Schema    string          `json:"schema"`
	Tool      Tool            `json:"tool"`
	Scan      ScanMeta        `json:"scan"`
	Summary   Counts          `json:"summary"`
	Files     Files           `json:"files"`
	Detectors DetectorStats   `json:"detectors"`
	Warnings  Warnings        `json:"warnings"`
	Findings  []model.Finding `json:"findings"`

	Correlations []model.Correlation `json:"correlations,omitempty"`

	CorrelationSummary *CorrelationSummary `json:"correlation_summary,omitempty"`

	Attack *AttackContext `json:"attack,omitempty"`
}

type Options struct {
	Score bool

	SortByRisk bool

	Correlate bool

	Attack *attack.Set
}

func Build(result *scan.Result, toolName, toolVersion string) Document {
	return BuildWith(result, toolName, toolVersion, Options{})
}

func BuildWith(result *scan.Result, toolName, toolVersion string, opts Options) Document {
	files := result.Files
	failures := map[string]int64{}
	for name, count := range result.Detectors.DetectorFailures {
		if count > 0 {
			failures[name] = count
		}
	}

	limitsReached := files.EntryLimitHit || files.DepthLimitHit
	partial := result.Status == scan.StatusPartial

	var notes []string
	if limitsReached {
		notes = append(notes, "configured scan limits were reached, coverage is incomplete")
	}
	if files.PermissionDenied > 0 {
		notes = append(notes, "some paths were unreadable and were recorded rather than scanned")
	}
	if len(failures) > 0 {
		notes = append(notes, "one or more detectors failed and were skipped for the remaining entries")
	}
	if result.Duplicates > 0 {
		notes = append(notes, "duplicate findings were collapsed by finding identifier")
	}

	document := Document{
		Schema: Schema,
		Tool:   Tool{Name: toolName, Version: toolVersion},
		Scan: ScanMeta{
			Roots:       result.Roots,
			MinSeverity: result.MinSeverity.String(),
			StartedAt:   result.StartedAt.UTC().Format(timeLayout),
			FinishedAt:  result.FinishedAt.UTC().Format(timeLayout),
			DurationMS:  result.Duration().Milliseconds(),
			Status:      string(result.Status),
		},
		Summary: summarise(result.Findings),
		Files: Files{Directories: files.Directories,
			Files:            files.Files,
			Symlinks:         files.Symlinks,
			SpecialFiles:     files.SpecialFiles,
			Entries:          files.Entries,
			Excluded:         files.Excluded,
			Errors:           files.Errors,
			PermissionDenied: files.PermissionDenied,
			EntryLimitHit:    files.EntryLimitHit,
			DepthLimitHit:    files.DepthLimitHit,
			Inaccessible:     len(files.Inaccessible),
		},
		Detectors: DetectorStats{
			EntriesProcessed: result.Detectors.EntriesProcessed,
			DetectorCalls:    result.Detectors.DetectorCalls,
			Findings:         result.Detectors.Findings,
			Duplicates:       result.Duplicates,
			Failures:         failures,
		},
		Warnings: Warnings{
			Partial:          partial,
			LimitsReached:    limitsReached,
			Inaccessible:     files.PermissionDenied > 0 || files.Errors > 0,
			DetectorFailures: len(failures) > 0,
			Notes:            notes,
		},
		Findings: result.Findings,
	}
	document.Findings = make([]model.Finding, 0, len(result.Findings))
	for _, finding := range result.Findings {
		document.Findings = append(document.Findings, redactFinding(finding))
	}
	if opts.Score {
		document.Findings = risk.Attach(document.Findings)
		document.Summary.ByRiskBand = risk.Summarise(document.Findings)
	}
	if opts.SortByRisk {
		risk.Sort(document.Findings)
	}
	if opts.Correlate {
		document.Correlations = correlation.Analyse(result, correlation.Options{Attack: opts.Attack})
		summary := summariseCorrelations(document.Correlations)
		document.CorrelationSummary = &summary
		if opts.Attack != nil {
			document.Attack = &AttackContext{
				Framework:   attack.Framework,
				Dataset:     attack.DatasetName,
				Version:     opts.Attack.Version(),
				Attribution: attack.Attribution,
				Caveat: "A technique mapping describes a documented behaviour this weakness is " +
					"relevant to. It is not evidence that the technique was attempted, that an " +
					"adversary is present, or that anything was exploited.",
			}
		}
	}
	return document
}

func summariseCorrelations(records []model.Correlation) CorrelationSummary {
	summary := CorrelationSummary{Total: len(records)}
	if len(records) == 0 {
		return summary
	}
	summary.ByConfidence = map[string]int{}
	for _, confidence := range model.CorrelationConfidences() {
		summary.ByConfidence[string(confidence)] = 0
	}
	for _, record := range records {
		summary.ByConfidence[string(record.Confidence)]++
		if record.Technique != nil {
			summary.Mapped++
		}
	}
	return summary
}

func redactFinding(finding model.Finding) model.Finding {
	finding.Description = detectors.RedactText(finding.Description)
	finding.Remediation = detectors.RedactText(finding.Remediation)
	if len(finding.Evidence) > 0 {
		evidence := make([]string, len(finding.Evidence))
		for i, line := range finding.Evidence {
			evidence[i] = detectors.RedactText(line)
		}
		finding.Evidence = evidence
	}
	return finding
}

func summarise(findings []model.Finding) Counts {
	counts := Counts{
		Total:      len(findings),
		BySeverity: map[string]int{},
		ByCategory: map[string]int{},
	}
	for _, severity := range model.Severities() {
		counts.BySeverity[severity.String()] = 0
	}
	for _, finding := range findings {
		counts.BySeverity[finding.Severity.String()]++
		counts.ByCategory[string(finding.Category)]++
	}
	return counts
}

func WriteJSON(w io.Writer, document Document) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(document); err != nil {
		return fmt.Errorf("report: encoding JSON failed: %w", err)
	}
	return nil
}

func WriteText(w io.Writer, document Document) error {
	var out strings.Builder

	fmt.Fprintf(&out, "%s %s\n", document.Tool.Name, document.Tool.Version)
	fmt.Fprintf(&out, "Status: %s", strings.ToUpper(string(document.Scan.Status)))
	if document.Warnings.Partial {
		out.WriteString(" (incomplete coverage)")
	}
	out.WriteString("\n")
	fmt.Fprintf(&out, "Roots: %s\n", strings.Join(document.Scan.Roots, ", "))
	fmt.Fprintf(&out, "Duration: %dms   Entries: %d   Findings: %d\n",
		document.Scan.DurationMS, document.Files.Entries, document.Summary.Total)

	if document.Warnings.Partial {
		out.WriteString("\nWARNINGS\n")
		for _, note := range document.Warnings.Notes {
			fmt.Fprintf(&out, "  ! %s\n", note)
		}
	}
	if len(document.Detectors.Failures) > 0 {
		out.WriteString("\nDETECTOR FAILURES\n")
		for _, name := range sortedKeys(document.Detectors.Failures) {
			fmt.Fprintf(&out, "  ! %s failed %d time(s)\n", name, document.Detectors.Failures[name])
		}
	}

	out.WriteString("\nSEVERITY SUMMARY\n")
	for _, severity := range model.Severities() {
		count := document.Summary.BySeverity[severity.String()]
		if count == 0 {
			continue
		}
		fmt.Fprintf(&out, "  %-8s %4d\n", strings.ToUpper(severity.String()), count)
	}
	if document.Summary.Total == 0 {
		out.WriteString("  no findings at or above the reporting threshold\n")
	}
	if len(document.Summary.ByRiskBand) > 0 {
		out.WriteString("\nRISK SUMMARY\n")
		for _, band := range model.RiskBands() {
			count := document.Summary.ByRiskBand[string(band)]
			if count == 0 {
				continue
			}
			fmt.Fprintf(&out, "  %-14s %4d\n", strings.ToUpper(string(band)), count)
		}
	}

	if len(document.Findings) > 0 {
		out.WriteString("\nFINDINGS\n")
		for _, finding := range document.Findings {
			writeFinding(&out, finding)
		}
	}

	writeCorrelations(&out, document)

	out.WriteString("\nFindings are indicators derived from filesystem metadata and configuration\n")
	out.WriteString("state. They are not proof of compromise and require analyst review.\n")
	if len(document.Summary.ByRiskBand) > 0 {
		out.WriteString("Risk scores rank findings for review using the measured attributes above;\n")
		out.WriteString("they are not probabilities and not evidence that anything was exploited.\n")
	}

	if _, err := io.WriteString(w, out.String()); err != nil {
		return fmt.Errorf("report: writing text failed: %w", err)
	}
	return nil
}

func writeFinding(out *strings.Builder, finding model.Finding) {
	fmt.Fprintf(out, "\n  [%s] %s  %s\n",
		strings.ToUpper(finding.Severity.String()), finding.RuleID, finding.Title)
	writeRisk(out, finding)
	fmt.Fprintf(out, "      path      : %s\n", singleLine(finding.Path))
	fmt.Fprintf(out, "      confidence: %s\n", finding.Confidence.String())
	if finding.Owner != nil || finding.Group != nil {
		fmt.Fprintf(out, "      owner     : %s:%s\n", orUnknown(finding.OwnerName()), orUnknown(finding.GroupName()))
	}
	if finding.Mode != nil {
		fmt.Fprintf(out, "      mode      : %04o\n", *finding.Mode)
	}
	if finding.Technique != nil {
		fmt.Fprintf(out, "      attack    : %s %s (%s)\n",
			finding.Technique.ID, singleLine(finding.Technique.Name), singleLine(finding.Technique.Tactic))
	}
	if finding.Description != "" {
		fmt.Fprintf(out, "      detail    : %s\n", truncate(singleLine(finding.Description), 200))
	}
	for _, line := range finding.Evidence {
		fmt.Fprintf(out, "      evidence  : %s\n", truncate(singleLine(line), 160))
	}
	if finding.Remediation != "" {
		fmt.Fprintf(out, "      fix       : %s\n", truncate(singleLine(finding.Remediation), 200))
	}
	writeReference(out, finding)
}

func writeCorrelations(out *strings.Builder, document Document) {
	if len(document.Correlations) == 0 {
		return
	}

	out.WriteString("\nCORRELATIONS\n")
	fmt.Fprintf(out, "  %d relationship(s) inferred between the findings above. These describe\n",
		len(document.Correlations))
	out.WriteString("  how observed weaknesses relate, not adversary activity.\n")

	if document.Attack != nil {
		fmt.Fprintf(out, "  ATT&CK %s, dataset %s: techniques are relevance context,\n",
			singleLine(document.Attack.Framework), singleLine(document.Attack.Version))
		out.WriteString("  not evidence that a technique was used.\n")
	}

	for _, record := range document.Correlations {
		fmt.Fprintf(out, "\n  %s [%s] %s\n",
			record.RuleID, strings.ToUpper(string(record.Confidence)), singleLine(record.Title))
		fmt.Fprintf(out, "      id       : %s\n", record.ID)
		fmt.Fprintf(out, "      findings : %s\n", strings.Join(record.FindingIDs, ", "))
		fmt.Fprintf(out, "      why      : %s\n", truncate(singleLine(record.Explanation), 300))
		if record.Technique != nil {
			fmt.Fprintf(out, "      attack   : %s %s (%s)\n",
				record.Technique.ID, singleLine(record.Technique.Name), singleLine(record.Technique.Tactic))
			fmt.Fprintf(out, "      relevance: %s\n", truncate(singleLine(record.AttackRelevance), 300))
		}
		if !record.Scope.Complete {
			fmt.Fprintf(out, "      coverage : %s\n", singleLine(record.Scope.Note))
		}
	}
}

func writeRisk(out *strings.Builder, finding model.Finding) {
	if finding.Risk == nil {
		return
	}
	fmt.Fprintf(out, "      risk      : %d/100 %s (detector severity %s)\n",
		finding.Risk.Score, strings.ToUpper(string(finding.Risk.Band)),
		finding.Risk.Severity)
	if names := riskFactorNames(*finding.Risk); len(names) > 0 {
		fmt.Fprintf(out, "      factors   : %s\n", strings.Join(names, ", "))
	}
}

func riskFactorNames(assessment model.Risk) []string {
	names := make([]string, 0, len(assessment.Factors))
	for _, factor := range assessment.Factors {
		if factor.Name == "severity-base" || factor.Name == "score-cap" {
			continue
		}
		names = append(names, factor.Name)
	}
	return names
}

func writeReference(out *strings.Builder, finding model.Finding) {
	reference := finding.Reference
	if reference == nil {
		return
	}
	fmt.Fprintf(out, "      gtfo      : %s, %s\n",
		singleLine(reference.Binary), singleLine(reference.Category))
	fmt.Fprintf(out, "      context   : %s\n", truncate(singleLine(reference.Summary), 160))
	fmt.Fprintf(out, "      note      : %s\n", truncate(singleLine(reference.Caveat), 160))
}

func sortedKeys(counts map[string]int64) []string {
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

func singleLine(value string) string {
	replacer := strings.NewReplacer("\r", " ", "\n", " ", "\t", " ")
	return strings.TrimSpace(stripControl(replacer.Replace(value)))
}

func stripControl(value string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}

func orUnknown(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}

const timeLayout = "2006-01-02T15:04:05Z07:00"
