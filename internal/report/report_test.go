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

const canarySecret = "CANARY-SECRET-a1b2c3d4"

func sampleResult(t *testing.T) *scan.Result {
	t.Helper()
	started := time.Date(2026, 6, 7, 8, 9, 10, 0, time.UTC)

	rules := []model.Rule{
		{ID: "LS-PERM-004", Title: "Unsafe permissions on sensitive file",
			Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh,
			Category: model.CategorySensitiveConfig, Remediation: "chmod 0600 the file"},
		{ID: "LS-IND-001", Title: "Executable in temporary directory",
			Severity: model.SeverityMedium, Confidence: model.ConfidenceHigh,
			Category: model.CategoryIndicator, Remediation: "remove the file"},
		{ID: "LS-PRIV-001", Title: "SUID binary present",
			Severity: model.SeverityLow, Confidence: model.ConfidenceHigh,
			Category:  model.CategoryIndicator,
			Technique: &model.Technique{ID: "T1548.001", Name: "Setuid and Setgid", Tactic: "Privilege Escalation"}},
	}

	findings := make([]model.Finding, 0, len(rules))
	for i, rule := range rules {
		finding := rule.Finding([]string{"/etc/shadow", "/tmp/dropper", "/usr/bin/sudo"}[i]).
			WithDescription("description for " + rule.ID).
			WithMode(0o644)
		finding.DetectedAt = started
		if i == 0 {
			finding = finding.WithOwner("root").WithGroup("root").
				WithEvidence("mode=0644", "password = "+canarySecret+" [REDACTED]")
		}
		if i == 2 {
			finding = finding.WithOwner("root").WithGroup("root")
		}
		findings = append(findings, finding)
	}
	scan.SortFindings(findings)

	return &scan.Result{
		Status:      scan.StatusComplete,
		Findings:    findings,
		Roots:       []string{"/target"},
		MinSeverity: model.SeverityInfo,
		StartedAt:   started,
		FinishedAt:  started.Add(1500 * time.Millisecond),
	}
}

func TestBuildProducesStableSchema(t *testing.T) {
	document := Build(sampleResult(t), "lisa", "0.1.0")

	if document.Schema != Schema {
		t.Errorf("Schema = %q, want %q", document.Schema, Schema)
	}
	if document.Tool.Name != "lisa" || document.Tool.Version != "0.1.0" {
		t.Errorf("Tool = %+v", document.Tool)
	}
	if document.Scan.Status != "complete" {
		t.Errorf("Status = %q, want complete", document.Scan.Status)
	}
	if document.Scan.DurationMS != 1500 {
		t.Errorf("DurationMS = %d, want 1500", document.Scan.DurationMS)
	}
	if document.Summary.Total != 3 {
		t.Errorf("Summary.Total = %d, want 3", document.Summary.Total)
	}
	if document.Summary.BySeverity["high"] != 1 ||
		document.Summary.BySeverity["medium"] != 1 ||
		document.Summary.BySeverity["low"] != 1 {
		t.Errorf("BySeverity = %v", document.Summary.BySeverity)
	}
	if document.Summary.ByCategory["sensitive-config"] != 1 {
		t.Errorf("ByCategory = %v", document.Summary.ByCategory)
	}
	if document.Warnings.Partial {
		t.Error("Warnings.Partial = true for a complete scan")
	}
}

func TestJSONIsValidAndStable(t *testing.T) {
	document := Build(sampleResult(t), "lisa", "0.1.0")

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

	var decoded Document
	if err := json.Unmarshal(first.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if decoded.Schema != Schema {
		t.Errorf("decoded schema = %q", decoded.Schema)
	}
	if len(decoded.Findings) != 3 {
		t.Errorf("decoded %d findings, want 3", len(decoded.Findings))
	}
	for _, key := range []string{"schema", "tool", "scan", "summary", "files", "detectors", "warnings", "findings"} {
		if !strings.Contains(first.String(), `"`+key+`"`) {
			t.Errorf("JSON is missing the %q section", key)
		}
	}
}

func TestJSONFindingsCarryRuleMetadata(t *testing.T) {
	document := Build(sampleResult(t), "lisa", "0.1.0")
	var decoded Document

	var buffer bytes.Buffer
	if err := WriteJSON(&buffer, document); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}
	if err := json.Unmarshal(buffer.Bytes(), &decoded); err != nil {
		t.Fatalf("decoding failed: %v", err)
	}

	top := decoded.Findings[0]
	if top.RuleID != "LS-PERM-004" {
		t.Errorf("first finding rule = %q, want the highest severity rule first", top.RuleID)
	}
	if top.Severity != model.SeverityHigh {
		t.Errorf("Severity = %v, want high", top.Severity)
	}
	if top.Confidence != model.ConfidenceHigh {
		t.Errorf("Confidence = %v, want high", top.Confidence)
	}
	if top.Category != model.CategorySensitiveConfig {
		t.Errorf("Category = %q", top.Category)
	}
	if top.Path != "/etc/shadow" {
		t.Errorf("Path = %q", top.Path)
	}
	if top.ID == "" {
		t.Error("finding has no identifier")
	}

	var withTechnique bool
	for _, finding := range decoded.Findings {
		if finding.Technique != nil {
			withTechnique = true
			if finding.Technique.ID == "" || finding.Technique.Name == "" {
				t.Errorf("technique is incomplete: %+v", finding.Technique)
			}
		}
	}
	if !withTechnique {
		t.Error("the ATT&CK technique did not survive serialisation")
	}
}

func TestJSONNeverLeaksSecrets(t *testing.T) {
	document := Build(sampleResult(t), "lisa", "0.1.0")
	var buffer bytes.Buffer
	if err := WriteJSON(&buffer, document); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}
	if strings.Contains(buffer.String(), canarySecret) {
		t.Errorf("JSON report leaks a secret value:\n%s", buffer.String())
	}
}

func TestJSONHandlesEmptyFindings(t *testing.T) {
	result := sampleResult(t)
	result.Findings = nil

	document := Build(result, "lisa", "0.1.0")
	if document.Findings == nil {
		t.Fatal("Findings should be an empty slice, not nil")
	}
	if document.Summary.Total != 0 {
		t.Errorf("Summary.Total = %d, want 0", document.Summary.Total)
	}

	var buffer bytes.Buffer
	if err := WriteJSON(&buffer, document); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}
	var decoded Document
	if err := json.Unmarshal(buffer.Bytes(), &decoded); err != nil {
		t.Fatalf("empty report is not valid JSON: %v", err)
	}
	if !strings.Contains(buffer.String(), `"findings": []`) {
		t.Errorf("empty findings should serialise as [], got:\n%s", buffer.String())
	}
}

func TestJSONEscapesHTMLSensitiveCharacters(t *testing.T) {
	result := sampleResult(t)
	payload := `/tmp/<script>alert("x")</script>&\'' + string(rune(0x01))`
	finding := model.Rule{ID: "LS-TEST-1", Title: "payload", Severity: model.SeverityMedium,
		Confidence: model.ConfidenceHigh, Category: model.CategoryIndicator}.Finding(payload)
	finding.DetectedAt = result.StartedAt
	result.Findings = []model.Finding{finding}

	document := Build(result, "lisa", "0.1.0")
	var buffer bytes.Buffer
	if err := WriteJSON(&buffer, document); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}
	if strings.Contains(buffer.String(), "<script>") {
		t.Error("JSON output contains a raw script tag")
	}

	var decoded Document
	if err := json.Unmarshal(buffer.Bytes(), &decoded); err != nil {
		t.Fatalf("escaped output is not valid JSON: %v", err)
	}
	if decoded.Findings[0].Path != payload {
		t.Errorf("path did not survive escaping: %q", decoded.Findings[0].Path)
	}
}

func TestBuildMarksPartialScans(t *testing.T) {
	result := sampleResult(t)
	result.Status = scan.StatusPartial
	result.Files.Errors = 2
	result.Files.PermissionDenied = 2
	result.Files.EntryLimitHit = true
	result.Detectors.DetectorFailures = map[string]int64{"masquerade": 3}
	result.Duplicates = 1

	document := Build(result, "lisa", "0.1.0")

	if document.Scan.Status != "partial" {
		t.Errorf("Scan.Status = %q, want partial", document.Scan.Status)
	}
	if !document.Warnings.Partial {
		t.Error("Warnings.Partial = false")
	}
	if !document.Warnings.LimitsReached {
		t.Error("Warnings.LimitsReached = false")
	}
	if !document.Warnings.Inaccessible {
		t.Error("Warnings.Inaccessible = false")
	}
	if !document.Warnings.DetectorFailures {
		t.Error("Warnings.DetectorFailures = false")
	}
	if document.Detectors.Failures["masquerade"] != 3 {
		t.Errorf("Failures = %v", document.Detectors.Failures)
	}
	if document.Detectors.Duplicates != 1 {
		t.Errorf("Duplicates = %d, want 1", document.Detectors.Duplicates)
	}
	if len(document.Warnings.Notes) < 4 {
		t.Errorf("Notes = %v, want an explanation for each limitation", document.Warnings.Notes)
	}
	if document.Files.Inaccessible != 0 {
		t.Logf("note: Inaccessible counts recorded paths, got %d", document.Files.Inaccessible)
	}
}

func TestBuildOmitsZeroFailureMap(t *testing.T) {
	result := sampleResult(t)
	result.Detectors.DetectorFailures = map[string]int64{"masquerade": 0}

	document := Build(result, "lisa", "0.1.0")
	var buffer bytes.Buffer
	if err := WriteJSON(&buffer, document); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}
	if strings.Contains(buffer.String(), `"failures"`) {
		t.Error("a zero-valued failure map should be omitted")
	}
}

func TestTextReportContents(t *testing.T) {
	document := Build(sampleResult(t), "lisa", "0.1.0")

	var buffer bytes.Buffer
	if err := WriteText(&buffer, document); err != nil {
		t.Fatalf("WriteText failed: %v", err)
	}
	output := buffer.String()

	for _, want := range []string{
		"lisa 0.1.0",
		"Status: COMPLETE",
		"Roots: /target",
		"SEVERITY SUMMARY",
		"FINDINGS",
		"LS-PERM-004",
		"LS-PRIV-001",
		"path      : /etc/shadow",
		"confidence: high",
		"mode      : 0644",
		"T1548.001",
		"require analyst review",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("text report is missing %q\n---\n%s", want, output)
		}
	}
	if strings.Contains(output, canarySecret) {
		t.Error("text report leaks a secret value")
	}
}

func TestTextReportEmptyFindings(t *testing.T) {
	result := sampleResult(t)
	result.Findings = nil
	document := Build(result, "lisa", "0.1.0")

	var buffer bytes.Buffer
	if err := WriteText(&buffer, document); err != nil {
		t.Fatalf("WriteText failed: %v", err)
	}
	output := buffer.String()

	if !strings.Contains(output, "no findings at or above the reporting threshold") {
		t.Errorf("empty report should say so explicitly:\n%s", output)
	}
	if strings.Contains(output, "FINDINGS\n") {
		t.Error("empty report should not print a findings section")
	}
}

func TestTextReportShowsPartialWarnings(t *testing.T) {
	result := sampleResult(t)
	result.Status = scan.StatusPartial
	result.Files.EntryLimitHit = true
	result.Detectors.DetectorFailures = map[string]int64{"masquerade": 2}
	document := Build(result, "lisa", "0.1.0")

	var buffer bytes.Buffer
	if err := WriteText(&buffer, document); err != nil {
		t.Fatalf("WriteText failed: %v", err)
	}
	output := buffer.String()

	if !strings.Contains(output, "incomplete coverage") {
		t.Error("a partial scan should be labelled as incomplete")
	}
	if !strings.Contains(output, "WARNINGS") {
		t.Error("warnings section missing")
	}
	if !strings.Contains(output, "DETECTOR FAILURES") || !strings.Contains(output, "masquerade failed 2 time(s)") {
		t.Errorf("detector failures should be listed:\n%s", output)
	}
}

func TestTextReportSanitisesControlCharacters(t *testing.T) {
	result := sampleResult(t)
	finding := model.Rule{ID: "LS-TEST-1", Title: "t", Severity: model.SeverityMedium,
		Confidence: model.ConfidenceHigh, Category: model.CategoryIndicator}.
		Finding("/tmp/a\nb\tc\x1b[31mred")
	finding.DetectedAt = result.StartedAt
	finding = finding.WithDescription("line one\nline two")
	result.Findings = []model.Finding{finding}

	document := Build(result, "lisa", "0.1.0")
	var buffer bytes.Buffer
	if err := WriteText(&buffer, document); err != nil {
		t.Fatalf("WriteText failed: %v", err)
	}
	output := buffer.String()

	if strings.Contains(output, "\x1b[") {
		t.Error("terminal escape sequence survived into the text report")
	}
	if strings.Count(output, "line one line two") != 1 {
		t.Errorf("newlines in descriptions should be collapsed:\n%s", output)
	}
}

func TestTextReportTruncatesLongEvidence(t *testing.T) {
	result := sampleResult(t)
	long := strings.Repeat("A", 900)
	finding := model.Rule{ID: "LS-TEST-1", Title: "t", Severity: model.SeverityMedium,
		Confidence: model.ConfidenceHigh, Category: model.CategoryIndicator}.Finding("/tmp/a")
	finding.DetectedAt = result.StartedAt
	finding = finding.WithEvidence(long)
	result.Findings = []model.Finding{finding}

	document := Build(result, "lisa", "0.1.0")
	var buffer bytes.Buffer
	if err := WriteText(&buffer, document); err != nil {
		t.Fatalf("WriteText failed: %v", err)
	}
	if strings.Contains(buffer.String(), long) {
		t.Error("long evidence was not truncated for terminal output")
	}
	if !strings.Contains(buffer.String(), "...") {
		t.Error("truncated evidence should be marked")
	}
}

func TestTextReportIsDeterministic(t *testing.T) {
	document := Build(sampleResult(t), "lisa", "0.1.0")

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

func TestRedactionSafetyNetCoversUnredactedDetectorOutput(t *testing.T) {
	result := sampleResult(t)
	finding := model.Rule{ID: "LS-SENS-006", Title: "Credential-shaped value",
		Severity: model.SeverityHigh, Confidence: model.ConfidenceMedium,
		Category: model.CategorySensitiveConfig}.Finding("/etc/app.conf")
	finding.DetectedAt = result.StartedAt
	finding = finding.WithDescription("config contains password = " + canarySecret).
		WithEvidence("line 1: password = " + canarySecret).
		WithRemediation("rotate the key referenced by api_key=" + canarySecret)
	result.Findings = []model.Finding{finding}

	document := Build(result, "lisa", "0.1.0")

	for i, item := range document.Findings {
		for _, field := range []string{item.Description, item.Remediation} {
			if strings.Contains(field, canarySecret) {
				t.Errorf("finding %d leaks a secret in a text field: %q", i, field)
			}
		}
		for _, line := range item.Evidence {
			if strings.Contains(line, canarySecret) {
				t.Errorf("finding %d leaks a secret in evidence: %q", i, line)
			}
		}
	}

	var buffer bytes.Buffer
	if err := WriteJSON(&buffer, document); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}
	if strings.Contains(buffer.String(), canarySecret) {
		t.Error("the JSON safety net did not remove the secret")
	}
}

func TestRedactionDoesNotAlterBenignFindings(t *testing.T) {
	before := sampleResult(t)
	after := Build(before, "lisa", "0.1.0")

	if len(after.Findings) != len(before.Findings) {
		t.Fatalf("finding count changed from %d to %d", len(before.Findings), len(after.Findings))
	}
	for i := range before.Findings {
		if before.Findings[i].Path != after.Findings[i].Path ||
			before.Findings[i].RuleID != after.Findings[i].RuleID ||
			before.Findings[i].Title != after.Findings[i].Title {
			t.Errorf("finding %d identity changed", i)
		}
	}
}
