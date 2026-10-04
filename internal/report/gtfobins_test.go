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

func referenceFixture() *model.ReferenceContext {
	return &model.ReferenceContext{
		Source:      "gtfobins-curated",
		Binary:      "find",
		Category:    "filesystem",
		Summary:     "Recursive file walker that evaluates an expression supplied on the command line.",
		Attribution: "Concept: GTFOBins (MIT licence). Independent curated subset.",
		Severity:    model.SeverityMedium,
		Caveat:      "A match does not indicate exploitation or compromise.",
	}
}

func resultWithSuid(t *testing.T, binary string, withReference bool) *scan.Result {
	t.Helper()
	result := sampleResult(t)

	rule := model.Rule{ID: "LS-PRIV-001", Title: "SUID binary present",
		Severity: model.SeverityLow, Confidence: model.ConfidenceHigh,
		Category: model.CategoryIndicator, Remediation: "Remove the SUID bit."}

	finding := rule.Finding("/usr/bin/"+binary).
		WithDescription("File /usr/bin/"+binary+" carries the SUID bit (mode 4755).").
		WithEvidence("mode=4755", "setuid=yes").
		WithOwner("root").
		WithGroup("root").
		WithMode(0o4755)
	finding.DetectedAt = result.StartedAt
	if withReference {
		finding = finding.WithReference(referenceFixture())
		finding = finding.WithEvidence("curated binary="+binary, "curated category=filesystem")
	}

	result.Findings = []model.Finding{finding}
	return result
}

func TestJSONIncludesStructuredReferenceForMatchedFinding(t *testing.T) {
	document := Build(resultWithSuid(t, "find", true), "lisa", "0.1.0")

	var buffer bytes.Buffer
	if err := WriteJSON(&buffer, document); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	var decoded struct {
		Findings []struct {
			RuleID    string `json:"rule_id"`
			Severity  string `json:"severity"`
			Reference *struct {
				Source      string `json:"source"`
				Binary      string `json:"binary"`
				Category    string `json:"category"`
				Summary     string `json:"summary"`
				Attribution string `json:"attribution"`
				Severity    string `json:"severity"`
				Caveat      string `json:"caveat"`
			} `json:"reference"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buffer.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buffer.String())
	}
	if len(decoded.Findings) != 1 {
		t.Fatalf("decoded %d findings, want 1", len(decoded.Findings))
	}

	finding := decoded.Findings[0]
	if finding.Reference == nil {
		t.Fatalf("serialized JSON has no reference block:\n%s", buffer.String())
	}
	if finding.Reference.Source != "gtfobins-curated" {
		t.Errorf("source = %q", finding.Reference.Source)
	}
	if finding.Reference.Binary != "find" {
		t.Errorf("binary = %q", finding.Reference.Binary)
	}
	if finding.Reference.Category != "filesystem" {
		t.Errorf("category = %q", finding.Reference.Category)
	}
	if finding.Reference.Severity != "medium" {
		t.Errorf("reference severity = %q", finding.Reference.Severity)
	}
	if !strings.Contains(finding.Reference.Caveat, "does not indicate") {
		t.Errorf("caveat = %q", finding.Reference.Caveat)
	}
	if finding.Severity != "low" {
		t.Errorf("detection severity = %q, want the original low severity unchanged", finding.Severity)
	}
}

func TestJSONOmitsReferenceForUnmatchedFinding(t *testing.T) {
	document := Build(resultWithSuid(t, "our-helper", false), "lisa", "0.1.0")

	var buffer bytes.Buffer
	if err := WriteJSON(&buffer, document); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}
	if strings.Contains(buffer.String(), `"reference"`) {
		t.Errorf("unmatched finding should omit the reference field:\n%s", buffer.String())
	}
	if strings.Contains(buffer.String(), "gtfobins") {
		t.Errorf("unmatched report mentions gtfo:\n%s", buffer.String())
	}
}

func TestJSONShapeIsBackwardCompatible(t *testing.T) {
	withRef := Build(resultWithSuid(t, "find", true), "lisa", "0.1.0")
	withoutRef := Build(resultWithSuid(t, "our-helper", false), "lisa", "0.1.0")

	matched := decodeTopLevel(t, withRef)
	unmatched := decodeTopLevel(t, withoutRef)

	if len(matched) != len(unmatched) {
		t.Errorf("top-level key count differs: %d matched, %d unmatched", len(matched), len(unmatched))
	}
	for key := range unmatched {
		if _, present := matched[key]; !present {
			t.Errorf("matched report is missing top-level key %q", key)
		}
	}

	matchedFindings := matched["findings"].([]any)
	unmatchedFindings := unmatched["findings"].([]any)
	if len(matchedFindings) != 1 || len(unmatchedFindings) != 1 {
		t.Fatal("unexpected finding counts")
	}

	matchedKeys := fieldNames(t, matchedFindings[0])
	unmatchedKeys := fieldNames(t, unmatchedFindings[0])

	for key := range unmatchedKeys {
		if !matchedKeys[key] {
			t.Errorf("enrichment removed the %q field from findings", key)
		}
	}
	if len(matchedKeys) != len(unmatchedKeys)+1 {
		t.Errorf("enrichment changed the finding field count from %d to %d", len(unmatchedKeys), len(matchedKeys))
	}
	if !matchedKeys["reference"] {
		t.Error("matched finding JSON should carry a reference field")
	}
	if unmatchedKeys["reference"] {
		t.Error("unmatched finding JSON should not carry a reference field")
	}
}

func decodeTopLevel(t *testing.T, document Document) map[string]any {
	t.Helper()
	var buffer bytes.Buffer
	if err := WriteJSON(&buffer, document); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buffer.Bytes(), &decoded); err != nil {
		t.Fatalf("decoding failed: %v", err)
	}
	return decoded
}

func fieldNames(t *testing.T, value any) map[string]bool {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("expected a JSON object, got %T", value)
	}
	names := make(map[string]bool, len(object))
	for key := range object {
		names[key] = true
	}
	return names
}

func TestJSONReferenceIsDeterministic(t *testing.T) {
	document := Build(resultWithSuid(t, "find", true), "lisa", "0.1.0")

	var first, second bytes.Buffer
	if err := WriteJSON(&first, document); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}
	if err := WriteJSON(&second, document); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}
	if first.String() != second.String() {
		t.Error("two renders of the same document differ")
	}
}

func TestJSONReferenceExposesNoSensitiveData(t *testing.T) {
	document := Build(resultWithSuid(t, "find", true), "lisa", "0.1.0")
	var buffer bytes.Buffer
	if err := WriteJSON(&buffer, document); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	text := buffer.String()
	if strings.Contains(text, canarySecret) {
		t.Error("reference block leaked a secret")
	}
	for _, forbidden := range []string{"BEGIN RSA PRIVATE KEY", "passwd:", "shadow:"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("reference block contains %q", forbidden)
		}
	}
}

func TestTerminalShowsReferenceForMatchedFinding(t *testing.T) {
	document := Build(resultWithSuid(t, "find", true), "lisa", "0.1.0")

	var buffer bytes.Buffer
	if err := WriteText(&buffer, document); err != nil {
		t.Fatalf("WriteText failed: %v", err)
	}
	output := buffer.String()

	for _, want := range []string{
		"gtfo      : find, filesystem",
		"context   : Recursive file walker",
		"note      : A match does not indicate exploitation or compromise.",
		"LS-PRIV-001",
		"path      : /usr/bin/find",
		"fix       : Remove the SUID bit.",
		"[LOW]",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("terminal output is missing %q\n---\n%s", want, output)
		}
	}
	if !strings.Contains(output, "require analyst review") {
		t.Error("terminal output lost the standing disclaimer")
	}
}

func TestTerminalOmitsReferenceForUnmatchedFinding(t *testing.T) {
	document := Build(resultWithSuid(t, "our-helper", false), "lisa", "0.1.0")

	var buffer bytes.Buffer
	if err := WriteText(&buffer, document); err != nil {
		t.Fatalf("WriteText failed: %v", err)
	}
	output := buffer.String()

	if strings.Contains(output, "gtfo") {
		t.Errorf("unmatched finding should not render a gtfo line:\n%s", output)
	}
	if strings.Contains(output, "context   :") {
		t.Errorf("unmatched finding should not render a context line:\n%s", output)
	}
	for _, want := range []string{"LS-PRIV-001", "path      : /usr/bin/our-helper", "mode      : 4755"} {
		if !strings.Contains(output, want) {
			t.Errorf("terminal output lost %q\n---\n%s", want, output)
		}
	}
}

func TestTerminalReferenceIsDeterministic(t *testing.T) {
	document := Build(resultWithSuid(t, "find", true), "lisa", "0.1.0")

	var first, second bytes.Buffer
	if err := WriteText(&first, document); err != nil {
		t.Fatalf("WriteText failed: %v", err)
	}
	if err := WriteText(&second, document); err != nil {
		t.Fatalf("WriteText failed: %v", err)
	}
	if first.String() != second.String() {
		t.Error("two renders of the same document differ")
	}
}

func TestTerminalSanitisesReferenceContent(t *testing.T) {
	result := sampleResult(t)
	reference := referenceFixture()
	reference.Summary = "line one\nline two\x1b[31mred"
	reference.Binary = "b\x1bin"

	finding := model.Rule{ID: "LS-PRIV-001", Title: "t", Severity: model.SeverityLow,
		Confidence: model.ConfidenceHigh, Category: model.CategoryIndicator}.Finding("/usr/bin/x")
	finding.DetectedAt = result.StartedAt
	finding = finding.WithReference(reference)
	result.Findings = []model.Finding{finding}

	document := Build(result, "lisa", "0.1.0")
	var buffer bytes.Buffer
	if err := WriteText(&buffer, document); err != nil {
		t.Fatalf("WriteText failed: %v", err)
	}
	output := buffer.String()

	if strings.Contains(output, "\x1b[") {
		t.Error("terminal escape survived from the reference block")
	}
	if !strings.Contains(output, "line one line two") {
		t.Errorf("reference summary newlines were not collapsed:\n%s", output)
	}
}

func TestGtfoTimeImportUsed(t *testing.T) {
	result := sampleResult(t)
	document := Build(resultWithSuid(t, "find", true), "lisa", "0.1.0")
	for _, finding := range document.Findings {
		if err := finding.Validate(); err != nil {
			t.Errorf("finding %s is invalid: %v", finding.RuleID, err)
		}
	}
	_ = result
	_ = time.Now
}
