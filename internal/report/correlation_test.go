package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"lisa/internal/attack"
	"lisa/internal/model"
	"lisa/internal/scan"
)

var correlationInstant = time.Date(2026, 6, 7, 8, 9, 10, 0, time.UTC)

func correlatedResult(t *testing.T) *scan.Result {
	t.Helper()
	finding := func(ruleID, path string, mode uint32, owner string, category model.Category) model.Finding {
		built := model.Rule{
			ID: ruleID, Title: ruleID + " title", Severity: model.SeverityMedium,
			Confidence: model.ConfidenceHigh, Category: category,
		}.Finding(path).WithMode(mode).WithOwner(owner).WithGroup("group")
		built.DetectedAt = correlationInstant
		return built
	}

	findings := []model.Finding{
		finding("LS-IND-001", "/tmp/stage/dropper", 0o755, "app", model.CategoryIndicator),
		finding("LS-IND-004", "/tmp/stage/dropper", 0o755, "app", model.CategoryIndicator),
		finding("LS-PRIV-003", "/opt/bin/tool", 0o4755, "app", model.CategoryIndicator),
		finding("LS-OWN-004", "/opt/bin/tool", 0o4755, "app", model.CategoryOwnership),
		finding("LS-PERS-001", "/etc/cron.d/job", 0o666, "root", model.CategoryPersistence),
		finding("LS-PERM-001", "/etc/cron.d/job", 0o666, "root", model.CategoryPermissions),
		finding("LS-SENS-001", "/etc/ssh/sshd_config", 0o644, "root", model.CategorySensitiveConfig),
		finding("LS-PERM-005", "/root/.ssh/id_rsa", 0o644, "root", model.CategoryPermissions),
	}
	scan.SortFindings(findings)

	return &scan.Result{
		Status:      scan.StatusComplete,
		Findings:    findings,
		Roots:       []string{"/target"},
		MinSeverity: model.SeverityInfo,
		StartedAt:   correlationInstant,
		FinishedAt:  correlationInstant.Add(time.Second),
	}
}

func correlatedDocument(t *testing.T, opts Options) Document {
	t.Helper()
	if opts.Attack == nil && opts.Correlate {
		opts.Attack = attack.Dataset()
	}
	return BuildWith(correlatedResult(t), "lisa", "0.1.0", opts)
}

func TestCorrelationIsAbsentWhenNotRequested(t *testing.T) {
	document := Build(correlatedResult(t), "lisa", "0.1.0")

	if len(document.Correlations) != 0 {
		t.Errorf("a report without correlation carries %d record(s)", len(document.Correlations))
	}
	if document.CorrelationSummary != nil {
		t.Error("a report without correlation carries a summary")
	}
	if document.Attack != nil {
		t.Error("a report without correlation carries ATT&CK provenance")
	}

	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, unwanted := range []string{"correlations", "correlation_summary", "\"attack\""} {
		if strings.Contains(string(encoded), unwanted) {
			t.Errorf("an unrequested correlation field %q appears in the JSON", unwanted)
		}
	}
}

func TestCorrelationsAppearWithTheDocumentedShape(t *testing.T) {
	document := correlatedDocument(t, Options{Correlate: true})

	if len(document.Correlations) != 4 {
		t.Fatalf("got %d record(s), want one per rule", len(document.Correlations))
	}
	for _, record := range document.Correlations {
		if err := record.Validate(); err != nil {
			t.Errorf("%s is not a valid record: %v", record.RuleID, err)
		}
		if record.Technique == nil {
			t.Errorf("%s carries no technique", record.RuleID)
		}
		if record.AttackRelevance == "" {
			t.Errorf("%s carries no relevance explanation", record.RuleID)
		}
	}

	if document.CorrelationSummary == nil {
		t.Fatal("no correlation summary was produced")
	}
	summary := *document.CorrelationSummary
	if summary.Total != len(document.Correlations) {
		t.Errorf("summary total = %d, want %d", summary.Total, len(document.Correlations))
	}
	if summary.Mapped != len(document.Correlations) {
		t.Errorf("summary mapped = %d, want %d", summary.Mapped, len(document.Correlations))
	}
	if len(summary.ByConfidence) != len(model.CorrelationConfidences()) {
		t.Errorf("the summary lists %d confidence values, want all %d",
			len(summary.ByConfidence), len(model.CorrelationConfidences()))
	}
	if summary.ByConfidence[string(model.CorrelationHigh)] != 3 {
		t.Errorf("high confidence records = %d, want 3", summary.ByConfidence[string(model.CorrelationHigh)])
	}
	if summary.ByConfidence[string(model.CorrelationMedium)] != 1 {
		t.Errorf("medium confidence records = %d, want 1", summary.ByConfidence[string(model.CorrelationMedium)])
	}
}

func TestAttackProvenanceIsPublished(t *testing.T) {
	document := correlatedDocument(t, Options{Correlate: true})
	if document.Attack == nil {
		t.Fatal("no ATT&CK provenance was published")
	}
	if document.Attack.Framework != attack.Framework {
		t.Errorf("framework = %q, want %q", document.Attack.Framework, attack.Framework)
	}
	if document.Attack.Dataset != attack.DatasetName {
		t.Errorf("dataset = %q, want %q", document.Attack.Dataset, attack.DatasetName)
	}
	if document.Attack.Version == "" {
		t.Error("no dataset version was published")
	}
	if !strings.Contains(strings.ToLower(document.Attack.Caveat), "not evidence") {
		t.Errorf("the caveat does not qualify the mapping: %q", document.Attack.Caveat)
	}
	if !strings.Contains(document.Attack.Attribution, "MITRE") {
		t.Errorf("the attribution does not credit MITRE: %q", document.Attack.Attribution)
	}
}

func TestDisablingATTACKKeepsCorrelations(t *testing.T) {
	mapped := correlatedDocument(t, Options{Correlate: true})
	unmapped := BuildWith(correlatedResult(t), "lisa", "0.1.0", Options{Correlate: true})

	if len(unmapped.Correlations) != len(mapped.Correlations) {
		t.Fatalf("disabling ATT&CK changed the record count from %d to %d",
			len(mapped.Correlations), len(unmapped.Correlations))
	}
	for i, record := range unmapped.Correlations {
		if record.Technique != nil || record.AttackRelevance != "" {
			t.Errorf("record %s still carries ATT&CK context", record.RuleID)
		}
		if record.ID != mapped.Correlations[i].ID {
			t.Errorf("disabling ATT&CK changed the identifier of %s", record.RuleID)
		}
		if err := record.Validate(); err != nil {
			t.Errorf("an unmapped record is invalid: %v", err)
		}
	}
	if unmapped.Attack != nil {
		t.Error("ATT&CK provenance is published although mapping was disabled")
	}
	if unmapped.CorrelationSummary == nil || unmapped.CorrelationSummary.Mapped != 0 {
		t.Errorf("summary mapped = %v, want 0", unmapped.CorrelationSummary)
	}
}

func TestRiskAndCorrelationAreIndependent(t *testing.T) {
	scored := correlatedDocument(t, Options{Correlate: true, Score: true})
	plain := correlatedDocument(t, Options{Correlate: true})

	for i, finding := range scored.Findings {
		if finding.Risk == nil {
			t.Errorf("finding %d was not scored", i)
		}
	}
	for i, finding := range plain.Findings {
		if finding.Risk != nil {
			t.Errorf("finding %d was scored although scoring was off", i)
		}
	}

	if len(scored.Correlations) != len(plain.Correlations) {
		t.Fatalf("scoring changed the record count from %d to %d",
			len(plain.Correlations), len(scored.Correlations))
	}
	for i := range scored.Correlations {
		if scored.Correlations[i].ID != plain.Correlations[i].ID {
			t.Error("scoring changed a correlation identifier")
		}
		if scored.Correlations[i].Explanation != plain.Correlations[i].Explanation {
			t.Error("scoring changed a correlation explanation")
		}
	}

	unscored := BuildWith(correlatedResult(t), "lisa", "0.1.0", Options{Correlate: true})
	for _, finding := range unscored.Findings {
		if finding.Risk != nil {
			t.Errorf("correlation attached risk to %s", finding.RuleID)
		}
	}
}

func TestCorrelatedReportIsDeterministic(t *testing.T) {
	opts := Options{Correlate: true, Score: true, SortByRisk: true, Attack: attack.Dataset()}
	first, err := json.Marshal(BuildWith(correlatedResult(t), "lisa", "0.1.0", opts))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for i := 0; i < 20; i++ {
		again, err := json.Marshal(BuildWith(correlatedResult(t), "lisa", "0.1.0", opts))
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if !bytes.Equal(first, again) {
			t.Fatalf("run %d produced a different document", i)
		}
	}
}

func TestCorrelationTextSectionShowsEvidenceAndCaveats(t *testing.T) {
	text := renderText(t, correlatedDocument(t, Options{Correlate: true, Score: true}))

	if !strings.Contains(text, "CORRELATIONS") {
		t.Errorf("the text report has no correlation section:\n%s", text)
	}
	if !strings.Contains(text, "not adversary activity") {
		t.Errorf("the section does not separate inference from observation:\n%s", text)
	}
	for _, wanted := range []string{
		"LS-COR-001", "LS-COR-002", "LS-COR-003", "LS-COR-004",
		"HIGH", "MEDIUM", "findings :", "why      :", "attack   :", "relevance:",
	} {
		if !strings.Contains(text, wanted) {
			t.Errorf("the text report is missing %q:\n%s", wanted, text)
		}
	}
	if !strings.Contains(text, "not evidence that a technique was used") {
		t.Errorf("the section does not qualify the ATT&CK mapping:\n%s", text)
	}
}

func TestCorrelationTextOmitsTechniqueWhenUnmapped(t *testing.T) {
	text := renderText(t, BuildWith(correlatedResult(t), "lisa", "0.1.0",
		Options{Correlate: true}))

	if !strings.Contains(text, "CORRELATIONS") {
		t.Errorf("the text report has no correlation section:\n%s", text)
	}
	if strings.Contains(text, "attack   :") {
		t.Errorf("an unmapped report still prints technique lines:\n%s", text)
	}
}

func TestCorrelationTextShowsIncompleteCoverage(t *testing.T) {
	result := correlatedResult(t)
	result.Status = scan.StatusPartial
	result.Files.Inaccessible = []string{"/root (permission denied)"}

	text := renderText(t, BuildWith(result, "lisa", "0.1.0",
		Options{Correlate: true, Attack: attack.Dataset()}))

	if !strings.Contains(text, "coverage :") {
		t.Errorf("an incomplete scan does not qualify its correlations:\n%s", text)
	}
	if !strings.Contains(text, "could not be read") {
		t.Errorf("the coverage note does not explain what was missing:\n%s", text)
	}
}

func TestCorrelationSectionDoesNotRepeatFindings(t *testing.T) {
	text := renderText(t, correlatedDocument(t, Options{Correlate: true}))

	correlations := text[strings.Index(text, "CORRELATIONS"):]
	for _, line := range strings.Split(correlations, "\n") {
		if strings.HasPrefix(line, "      path") {
			t.Errorf("the correlation section repeats a full finding record: %q", line)
		}
	}
}

func TestReportWithNoCorrelationsStaysMeaningful(t *testing.T) {

	result := &scan.Result{
		Status:      scan.StatusComplete,
		MinSeverity: model.SeverityInfo,
		StartedAt:   correlationInstant,
		FinishedAt:  correlationInstant,
		Roots:       []string{"/target"},
		Findings: []model.Finding{
			func() model.Finding {
				f := model.Rule{ID: "LS-PERM-002", Title: "World-writable directory",
					Severity: model.SeverityMedium, Confidence: model.ConfidenceHigh,
					Category: model.CategoryPermissions}.Finding("/tmp/shared")
				f.DetectedAt = correlationInstant
				return f.WithMode(0o777).WithOwner("root")
			}(),
		},
	}

	text := renderText(t, BuildWith(result, "lisa", "0.1.0",
		Options{Correlate: true, Attack: attack.Dataset()}))
	if !strings.Contains(text, "FINDINGS") {
		t.Errorf("a report with no correlations lost its findings:\n%s", text)
	}
	if strings.Contains(text, "CORRELATIONS") {
		t.Errorf("an empty correlation section was printed:\n%s", text)
	}
}
