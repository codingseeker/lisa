package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"lisa/internal/model"
	"lisa/internal/scan"
)

func scoredResult(t *testing.T) *scan.Result {
	t.Helper()
	started := time.Date(2026, 6, 7, 8, 9, 10, 0, time.UTC)

	critical := model.Rule{ID: "LS-PERM-004", Title: "Unsafe permissions on sensitive file",
		Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh,
		Category: model.CategorySensitiveConfig}
	informational := model.Rule{ID: "LS-PERM-003", Title: "World-writable directory with sticky bit",
		Severity: model.SeverityInfo, Confidence: model.ConfidenceHigh,
		Category: model.CategoryPermissions}
	suid := model.Rule{ID: "LS-PRIV-001", Title: "SUID binary present",
		Severity: model.SeverityLow, Confidence: model.ConfidenceHigh,
		Category: model.CategoryIndicator}

	shadow := critical.Finding("/etc/shadow").WithDescription("unsafe permissions").
		WithMode(0o6666).WithOwner("nobody").WithGroup("nogroup")
	shadow.DetectedAt = started

	sticky := informational.Finding("/tmp/shared").WithDescription("sticky directory").
		WithMode(0o1777).WithOwner("root").WithGroup("root")
	sticky.DetectedAt = started

	privileged := suid.Finding("/usr/bin/sudo").WithDescription("setuid binary").
		WithMode(0o4755).WithOwner("root").WithGroup("root")
	privileged.DetectedAt = started

	findings := []model.Finding{shadow, sticky, privileged}
	scan.SortFindings(findings)

	return &scan.Result{
		Status:      scan.StatusComplete,
		Findings:    findings,
		Roots:       []string{"/target"},
		MinSeverity: model.SeverityInfo,
		StartedAt:   started,
		FinishedAt:  started.Add(time.Second),
	}
}

func scoredDocument(t *testing.T, opts Options) Document {
	t.Helper()
	return BuildWith(scoredResult(t), "lisa", "0.1.0", opts)
}

func TestBuildWithoutOptionsScoresNothing(t *testing.T) {
	document := Build(scoredResult(t), "lisa", "0.1.0")

	for _, finding := range document.Findings {
		if finding.Risk != nil {
			t.Errorf("%s carries a risk assessment although scoring was not requested", finding.RuleID)
		}
	}
	if document.Summary.ByRiskBand != nil {
		t.Error("the summary carries risk counts although scoring was not requested")
	}
}

func TestUnscoredReportIsUnchangedByThePresenceOfRiskSupport(t *testing.T) {
	result := scoredResult(t)
	before, err := json.Marshal(Build(result, "lisa", "0.1.0"))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	text := renderText(t, Build(result, "lisa", "0.1.0"))

	if strings.Contains(string(before), `"risk"`) {
		t.Errorf("an unscored report mentions risk: %s", before)
	}
	if strings.Contains(text, "risk") {
		t.Errorf("an unscored text report mentions risk:\n%s", text)
	}
}

func TestScoringAddsARiskObjectToEveryScoredFinding(t *testing.T) {
	document := scoredDocument(t, Options{Score: true})

	for _, finding := range document.Findings {
		if finding.Risk == nil {
			t.Fatalf("%s was not scored", finding.RuleID)
		}
		if err := finding.Risk.Validate(); err != nil {
			t.Errorf("%s carries an inconsistent assessment: %v", finding.RuleID, err)
		}
		if finding.Risk.Severity != finding.Severity {
			t.Errorf("%s risk reports severity %q but the finding is %q",
				finding.RuleID, finding.Risk.Severity, finding.Severity)
		}
		if finding.Severity == model.SeverityHigh && finding.Risk.Score == 0 {
			t.Errorf("%s scored zero despite a high severity", finding.RuleID)
		}
	}
}

func TestRiskSummaryCountsEveryBandThatIsPresent(t *testing.T) {
	document := scoredDocument(t, Options{Score: true})
	if len(document.Summary.ByRiskBand) != len(model.RiskBands()) {
		t.Errorf("risk summary has %d bands, want all %d",
			len(document.Summary.ByRiskBand), len(model.RiskBands()))
	}

	total := 0
	for _, count := range document.Summary.ByRiskBand {
		total += count
	}
	if total != len(document.Findings) {
		t.Errorf("risk summary counts %d findings but the report holds %d",
			total, len(document.Findings))
	}
}

func TestScoredReportIsDeterministic(t *testing.T) {
	first, err := json.Marshal(BuildWith(scoredResult(t), "lisa", "0.1.0",
		Options{Score: true, SortByRisk: true}))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for i := 0; i < 20; i++ {
		again, err := json.Marshal(BuildWith(scoredResult(t), "lisa", "0.1.0",
			Options{Score: true, SortByRisk: true}))
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if !bytes.Equal(first, again) {
			t.Fatalf("run %d produced a different document", i)
		}
	}
}

func TestSortByRiskOrdersDescendingWithTieBreakers(t *testing.T) {
	document := scoredDocument(t, Options{Score: true, SortByRisk: true})

	for i, finding := range document.Findings {
		if finding.Risk == nil {
			t.Fatalf("finding %d was not scored", i)
		}
		if i > 0 && document.Findings[i-1].Risk.Score < finding.Risk.Score {
			t.Fatalf("finding %d scores %d, above the previous %d",
				i, finding.Risk.Score, document.Findings[i-1].Risk.Score)
		}
	}

	plain := scoredDocument(t, Options{Score: true})
	for i := 1; i < len(plain.Findings); i++ {
		if plain.Findings[i-1].Severity < plain.Findings[i].Severity {
			t.Fatal("scoring alone changed the default finding order")
		}
	}
}

func TestScoringDoesNotMutateTheScanResult(t *testing.T) {
	result := scoredResult(t)
	before := make([]model.Finding, len(result.Findings))
	copy(before, result.Findings)

	_ = BuildWith(result, "lisa", "0.1.0", Options{Score: true, SortByRisk: true})

	for i, finding := range result.Findings {
		if finding.Risk != nil {
			t.Errorf("finding %d in the scan result was scored in place", i)
		}
		if finding.Path != before[i].Path || finding.Severity != before[i].Severity {
			t.Errorf("finding %d was changed by report building", i)
		}
	}
	if len(result.Findings) != len(before) {
		t.Errorf("the finding count changed from %d to %d", len(before), len(result.Findings))
	}
}

func TestTextReportShowsTheScoreAndItsFactors(t *testing.T) {
	text := renderText(t, scoredDocument(t, Options{Score: true}))

	if !strings.Contains(text, "RISK SUMMARY") {
		t.Errorf("the text report has no risk summary:\n%s", text)
	}
	if !strings.Contains(text, "risk      :") {
		t.Errorf("the text report does not show a risk line:\n%s", text)
	}
	if !strings.Contains(text, "factors   :") {
		t.Errorf("the text report does not show the contributing factors:\n%s", text)
	}
	if !strings.Contains(text, "not probabilities and not evidence that anything was exploited") {
		t.Errorf("the text report does not qualify what the score means:\n%s", text)
	}

	if !strings.Contains(text, "[HIGH] LS-PERM-004") {
		t.Errorf("the severity heading is missing:\n%s", text)
	}
	if !strings.Contains(text, "(detector severity high)") {
		t.Errorf("the report does not name the original severity alongside the score:\n%s", text)
	}
}

func TestTextReportOmitsRiskWhenScoringIsOff(t *testing.T) {
	text := renderText(t, scoredDocument(t, Options{}))
	for _, unwanted := range []string{"RISK SUMMARY", "risk      :", "factors   :"} {
		if strings.Contains(text, unwanted) {
			t.Errorf("an unscored text report contains %q:\n%s", unwanted, text)
		}
	}
}

func TestScoredTextReportStaysCompact(t *testing.T) {
	text := renderText(t, scoredDocument(t, Options{Score: true, SortByRisk: true}))
	lines := strings.Split(text, "\n")
	if len(lines) > 200 {
		t.Errorf("the scored text report is %d lines, which is no longer compact", len(lines))
	}
}

func TestScoredJSONCarriesTheDocumentedRiskShape(t *testing.T) {
	encoded, err := json.Marshal(scoredDocument(t, Options{Score: true}))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded struct {
		Summary struct {
			ByRiskBand map[string]int `json:"by_risk_band"`
		} `json:"summary"`
		Findings []struct {
			Risk *struct {
				Score       int    `json:"score"`
				Band        string `json:"band"`
				Severity    string `json:"severity"`
				Base        int    `json:"base"`
				Explanation string `json:"explanation"`
				Factors     []struct {
					Name   string `json:"name"`
					Points int    `json:"points"`
					Reason string `json:"reason"`
				} `json:"factors"`
			} `json:"risk"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if len(decoded.Summary.ByRiskBand) == 0 {
		t.Error("the JSON summary has no by_risk_band")
	}
	for _, finding := range decoded.Findings {
		if finding.Risk == nil {
			t.Fatalf("finding %+v has no risk object", finding)
		}
		if finding.Risk.Band == "" || finding.Risk.Explanation == "" {
			t.Errorf("the risk object is missing a band or an explanation: %+v", finding.Risk)
		}
		if finding.Risk.Severity == "" {
			t.Error("the risk object does not carry the original severity")
		}
		if len(finding.Risk.Factors) == 0 {
			t.Error("the risk object lists no factors")
		}
		for _, factor := range finding.Risk.Factors {
			if factor.Name == "" || factor.Reason == "" {
				t.Errorf("the risk object has an undescribed factor: %+v", factor)
			}
		}
	}
}

func renderText(t *testing.T, document Document) string {
	t.Helper()
	var buffer bytes.Buffer
	if err := WriteText(&buffer, document); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	return buffer.String()
}
