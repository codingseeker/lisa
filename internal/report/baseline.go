package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"lisa/internal/baseline"
	"lisa/internal/model"
)

type BaselineDocument struct {
	Schema      string               `json:"schema"`
	Baseline    BaselineRef          `json:"baseline"`
	Scan        BaselineScanRef      `json:"scan"`
	Summary     baseline.Counts      `json:"summary"`
	Reliability baseline.Reliability `json:"reliability"`
	Changes     []BaselineChange     `json:"changes"`
	Unchanged   int                  `json:"unchanged"`
}

type BaselineRef struct {
	Path      string        `json:"path,omitempty"`
	Schema    string        `json:"schema"`
	Tool      baseline.Tool `json:"tool"`
	CreatedAt string        `json:"created_at"`
}

type BaselineScanRef struct {
	Status      string `json:"status"`
	ComparedAt  string `json:"compared_at"`
	MinSeverity string `json:"min_severity"`
	GTFOBins    bool   `json:"gtfobins"`
}

type BaselineChange struct {
	RuleID   string            `json:"rule_id"`
	Path     string            `json:"path"`
	Category model.Category    `json:"category"`
	Status   baseline.Status   `json:"status"`
	Severity model.Severity    `json:"severity"`
	Changes  []baseline.Change `json:"changes,omitempty"`
}

const BaselineSchema = "lisa/baseline-comparison/v1"

func BuildBaseline(comparison *baseline.Comparison) (BaselineDocument, error) {
	if comparison == nil {
		return BaselineDocument{}, fmt.Errorf("report: a comparison is required")
	}
	document := BaselineDocument{
		Schema: BaselineSchema,
		Baseline: BaselineRef{
			Path:      comparison.BaselinePath,
			Schema:    comparison.BaselineSchema,
			Tool:      comparison.BaselineTool,
			CreatedAt: comparison.BaselineAt,
		},
		Scan: BaselineScanRef{
			Status:      comparison.ScanStatus,
			ComparedAt:  comparison.ComparedAt,
			MinSeverity: comparison.MinSeverity,
			GTFOBins:    comparison.GTFOBins,
		},
		Summary:     comparison.Counts,
		Reliability: comparison.Reliability,
		Changes:     []BaselineChange{},
	}

	for _, item := range comparison.Changes() {
		severity := model.SeverityInfo
		if item.Baseline != nil {
			severity = item.Baseline.Severity
		}
		if item.Current != nil {
			severity = item.Current.Severity
		}
		document.Changes = append(document.Changes, BaselineChange{
			RuleID:   item.RuleID,
			Path:     item.Path,
			Category: item.Category,
			Status:   item.Status,
			Severity: severity,
			Changes:  item.Changes,
		})
	}
	document.Unchanged = comparison.Counts.Unchanged
	return document, nil
}

func WriteBaselineJSON(w io.Writer, document BaselineDocument) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(document); err != nil {
		return fmt.Errorf("report: encoding baseline JSON failed: %w", err)
	}
	return nil
}

func WriteBaselineText(w io.Writer, document BaselineDocument) error {
	var out strings.Builder

	fmt.Fprintf(&out, "%s\n", document.Schema)
	fmt.Fprintf(&out, "Baseline: %s %s recorded at %s\n",
		document.Baseline.Tool.Name, document.Baseline.Tool.Version, document.Baseline.CreatedAt)
	fmt.Fprintf(&out, "Scan:     %s compared at %s, reporting from %s\n",
		strings.ToUpper(document.Scan.Status), document.Scan.ComparedAt, document.Scan.MinSeverity)

	fmt.Fprintf(&out, "\nCHANGES\n")
	fmt.Fprintf(&out, "  %-11s %4d new, %4d changed, %4d resolved, %4d unverified, %4d unchanged\n",
		strings.ToUpper(document.Scan.Status),
		document.Summary.New, document.Summary.Changed, document.Summary.Resolved,
		document.Summary.Unverified, document.Summary.Unchanged)

	if len(document.Changes) == 0 {
		out.WriteString("\n  nothing changed since the baseline\n")
	}
	for _, change := range document.Changes {
		writeBaselineChange(&out, change)
	}

	if len(document.Reliability.Reasons) > 0 {
		out.WriteString("\nRELIABILITY\n")
		fmt.Fprintf(&out, "  %s\n", reliabilityLabel(document.Reliability))
		for _, reason := range document.Reliability.Reasons {
			fmt.Fprintf(&out, "  ! %s\n", singleLine(reason))
		}
	}

	out.WriteString("\nA resolved finding means the current scan did not report it. It does not prove\n")
	out.WriteString("the underlying condition is gone; read the reliability block before acting.\n")

	if _, err := io.WriteString(w, out.String()); err != nil {
		return fmt.Errorf("report: writing baseline text failed: %w", err)
	}
	return nil
}

func writeBaselineChange(out *strings.Builder, change BaselineChange) {
	fmt.Fprintf(out, "\n  %-11s [%s] %s\n",
		strings.ToUpper(string(change.Status)), strings.ToUpper(change.Severity.String()), change.RuleID)
	fmt.Fprintf(out, "      path: %s\n", singleLine(change.Path))
	for _, difference := range change.Changes {
		fmt.Fprintf(out, "      %s: %s -> %s\n",
			singleLine(difference.Attribute),
			orUnknown(singleLine(difference.Baseline)),
			orUnknown(singleLine(difference.Current)))
	}
}

func reliabilityLabel(reliability baseline.Reliability) string {
	switch {
	case !reliability.Reliable:
		return "no finding is reported as resolved"
	case reliability.ResolutionsSuppressed:
		return fmt.Sprintf("%d finding(s) withheld from the resolved set", len(reliability.Suppressed))
	default:
		return "resolutions are trustworthy, with the caveats below"
	}
}
