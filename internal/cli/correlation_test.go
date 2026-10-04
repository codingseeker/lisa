package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func correlatingTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	stage := filepath.Join(root, "stage")
	if err := os.Mkdir(stage, 0o777); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := os.Chmod(stage, 0o777); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	script := filepath.Join(stage, "payload")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return root
}

func correlatedScan(t *testing.T, args ...string) (map[string]any, string) {
	t.Helper()
	target := correlatingTree(t)
	return scanTree(t, target, args...)
}

func scanTree(t *testing.T, target string, args ...string) (map[string]any, string) {
	t.Helper()
	full := append([]string{"scan", target, "--format", "json", "--quiet"}, args...)
	result := run(t, full...)
	if result.code != ExitFindings {
		t.Fatalf("scan exited %d, want %d; stderr = %q", result.code, ExitFindings, result.stderr)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(result.stdout), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, result.stdout)
	}
	return decoded, result.stdout
}

func correlationRecords(t *testing.T, document map[string]any) []map[string]any {
	t.Helper()
	raw, present := document["correlations"].([]any)
	if !present {
		t.Fatalf("the report has no correlations field")
	}
	records := make([]map[string]any, 0, len(raw))
	for _, entry := range raw {
		record, ok := entry.(map[string]any)
		if !ok {
			t.Fatalf("correlation %v is not an object", entry)
		}
		records = append(records, record)
	}
	return records
}

func TestCorrelationIsOnByDefaultAndCarriesATTACKContext(t *testing.T) {
	document, _ := correlatedScan(t)

	records := correlationRecords(t, document)
	if len(records) == 0 {
		t.Fatal("a real scan produced no correlations")
	}

	for _, record := range records {
		for _, field := range []string{
			"id", "rule_id", "title", "finding_ids", "confidence", "explanation",
			"technique", "attack_relevance", "scope",
		} {
			if _, present := record[field]; !present {
				t.Errorf("correlation %v is missing the %q field", record["id"], field)
			}
		}
		if !strings.HasPrefix(record["rule_id"].(string), "LS-COR-") {
			t.Errorf("unexpected correlation rule %v", record["rule_id"])
		}
		ids, ok := record["finding_ids"].([]any)
		if !ok || len(ids) < 2 {
			t.Errorf("correlation %v references %v, want at least two findings", record["id"], record["finding_ids"])
		}
		if record["explanation"].(string) == "" {
			t.Error("a correlation carries an empty explanation")
		}
	}

	technique, ok := records[0]["technique"].(map[string]any)
	if !ok {
		t.Fatalf("the first correlation has no technique: %v", records[0]["technique"])
	}
	if technique["id"] == "" || technique["name"] == "" || technique["tactic"] == "" {
		t.Errorf("the technique is incomplete: %v", technique)
	}

	summary, ok := document["correlation_summary"].(map[string]any)
	if !ok {
		t.Fatal("the report has no correlation summary")
	}
	if int(summary["total"].(float64)) != len(records) {
		t.Errorf("summary total = %v, want %d", summary["total"], len(records))
	}
}

func TestATTACKProvenanceIsPublished(t *testing.T) {
	document, _ := correlatedScan(t)

	attackContext, ok := document["attack"].(map[string]any)
	if !ok {
		t.Fatal("the report publishes no ATT&CK provenance")
	}
	for _, field := range []string{"framework", "dataset", "version", "attribution", "caveat"} {
		if value, _ := attackContext[field].(string); value == "" {
			t.Errorf("the ATT&CK provenance has no %s", field)
		}
	}
	if !strings.Contains(attackContext["framework"].(string), "MITRE") {
		t.Errorf("framework = %v, want MITRE ATT&CK", attackContext["framework"])
	}
	if !strings.Contains(strings.ToLower(attackContext["caveat"].(string)), "not evidence") {
		t.Errorf("the caveat does not qualify the mapping: %v", attackContext["caveat"])
	}
}

func TestCorrelateCanBeDisabled(t *testing.T) {
	document, stdout := correlatedScan(t, "--correlate=false")

	if _, present := document["correlations"]; present {
		t.Error("correlations are present although correlation was disabled")
	}
	if _, present := document["correlation_summary"]; present {
		t.Error("a correlation summary is present although correlation was disabled")
	}
	if _, present := document["attack"]; present {
		t.Error("ATT&CK provenance is present although correlation was disabled")
	}

	if len(document["findings"].([]any)) == 0 {
		t.Errorf("disabling correlation removed the findings:\n%s", stdout)
	}
	if strings.Contains(stdout, "CORRELATIONS") {
		t.Errorf("a correlation section was printed although correlation was disabled:\n%s", stdout)
	}
}

func TestAttackCanBeDisabledWithoutDisablingCorrelation(t *testing.T) {
	target := correlatingTree(t)
	withMapping, _ := scanTree(t, target)
	withoutMapping, _ := scanTree(t, target, "--attack=false")

	mapped := correlationRecords(t, withMapping)
	unmapped := correlationRecords(t, withoutMapping)

	if len(unmapped) != len(mapped) {
		t.Fatalf("disabling ATT&CK changed the record count from %d to %d", len(mapped), len(unmapped))
	}
	for i, record := range unmapped {
		if _, present := record["technique"]; present {
			t.Errorf("record %v still carries a technique", record["id"])
		}
		if _, present := record["attack_relevance"]; present {
			t.Errorf("record %v still carries a relevance note", record["id"])
		}
		if record["id"] != mapped[i]["id"] {
			t.Errorf("disabling ATT&CK changed the identifier from %v to %v", mapped[i]["id"], record["id"])
		}
	}
	if _, present := withoutMapping["attack"]; present {
		t.Error("ATT&CK provenance is present although mapping was disabled")
	}
}

func TestCorrelationAndRiskAreIndependent(t *testing.T) {
	target := correlatingTree(t)
	scored, _ := scanTree(t, target)
	uncorrelated, _ := scanTree(t, target, "--risk=false")

	if len(uncorrelated["findings"].([]any)) != len(scored["findings"].([]any)) {
		t.Error("disabling risk scoring changed the finding count")
	}
	scoredRecords := correlationRecords(t, scored)
	plainRecords := correlationRecords(t, uncorrelated)
	if len(plainRecords) != len(scoredRecords) {
		t.Fatalf("disabling risk scoring changed the correlation count from %d to %d",
			len(scoredRecords), len(plainRecords))
	}
	for i := range scoredRecords {
		if scoredRecords[i]["id"] != plainRecords[i]["id"] {
			t.Error("disabling risk scoring changed a correlation identifier")
		}
	}
	for _, entry := range plainRecords {

		if strings.Contains(entry["explanation"].(string), "/100") {
			t.Errorf("a correlation explanation quotes a risk score: %v", entry["explanation"])
		}
	}
}

func TestCorrelationTextSectionIsRendered(t *testing.T) {
	target := correlatingTree(t)
	result := run(t, "scan", target, "--quiet")
	if result.code != ExitFindings {
		t.Fatalf("scan exited %d, want %d; stderr = %q", result.code, ExitFindings, result.stderr)
	}

	for _, wanted := range []string{
		"CORRELATIONS", "inferred between", "not adversary activity",
		"LS-COR-", "findings :", "why      :", "attack   :", "relevance:",
	} {
		if !strings.Contains(result.stdout, wanted) {
			t.Errorf("the text report is missing %q:\n%s", wanted, result.stdout)
		}
	}
}

func TestCorrelationIdentifiersAreStableAcrossRuns(t *testing.T) {
	target := correlatingTree(t)
	var previous string
	for attempt := 0; attempt < 5; attempt++ {
		result := run(t, "scan", target, "--format", "json", "--quiet")
		var decoded map[string]any
		if err := json.Unmarshal([]byte(result.stdout), &decoded); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		var ids []string
		for _, record := range correlationRecords(t, decoded) {
			ids = append(ids, record["id"].(string))
		}
		current := strings.Join(ids, ",")
		if attempt > 0 && current != previous {
			t.Fatalf("run %d produced identifiers %q, previous run produced %q",
				attempt, current, previous)
		}
		previous = current
	}
	if previous == "" {
		t.Error("no correlation identifiers were produced")
	}
}

func TestCorrelationDoesNotAffectBaselines(t *testing.T) {
	target := correlatingTree(t)
	dir := t.TempDir()

	withCorrelation := filepath.Join(dir, "with.json")
	withoutCorrelation := filepath.Join(dir, "without.json")
	if result := run(t, "baseline", "create", target, "--baseline", withCorrelation, "--quiet"); result.code != ExitOK {
		t.Fatalf("baseline create exited %d; stderr = %q", result.code, result.stderr)
	}
	if result := run(t, "baseline", "create", target, "--baseline", withoutCorrelation,
		"--correlate=false", "--quiet"); result.code != ExitOK {
		t.Fatalf("baseline create exited %d; stderr = %q", result.code, result.stderr)
	}

	first := readJSON(t, withCorrelation)
	second := readJSON(t, withoutCorrelation)
	delete(first, "created_at")
	delete(second, "created_at")
	if !sameJSON(t, first, second) {
		t.Error("correlation changed the recorded baseline")
	}
	for _, entry := range first["findings"].([]any) {
		finding := entry.(map[string]any)
		for _, unwanted := range []string{"risk", "correlation", "correlations"} {
			if _, present := finding[unwanted]; present {
				t.Errorf("baseline finding %v carries %q", finding["id"], unwanted)
			}
		}
	}
}

func TestScanUsageMentionsTheCorrelationFlags(t *testing.T) {
	result := run(t, "scan", "--help")
	if result.code != ExitOK {
		t.Fatalf("help exited %d", result.code)
	}
	for _, flag := range []string{"--correlate", "--attack"} {
		if !strings.Contains(result.stdout, flag) {
			t.Errorf("the scan usage does not document %s", flag)
		}
	}
}

func TestScanWithNoCorrelationsIsUnaffected(t *testing.T) {
	target := t.TempDir()
	result := run(t, "scan", target, "--format", "json", "--quiet")
	if result.code != ExitOK {
		t.Fatalf("scan exited %d, want %d; stderr = %q", result.code, ExitOK, result.stderr)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(result.stdout), &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if _, present := decoded["correlations"]; present {
		t.Error("a scan with no correlations emitted the field")
	}
	if decoded["findings"] == nil {
		t.Error("the report has no findings field")
	}
}

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(content, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	return decoded
}
