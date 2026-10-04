package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func riskTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	script := filepath.Join(root, "script")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(script, 0o0777); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	return root
}

func scanJSON(t *testing.T, target string, args ...string) map[string]any {
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
	return decoded
}

func TestRiskScoringIsOnByDefault(t *testing.T) {
	document := scanJSON(t, riskTree(t))

	summary, ok := document["summary"].(map[string]any)
	if !ok {
		t.Fatal("the report has no summary object")
	}
	if _, present := summary["by_risk_band"]; !present {
		t.Error("the summary has no by_risk_band although scoring is on by default")
	}

	findings, ok := document["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatal("the report has no findings")
	}
	for _, entry := range findings {
		finding, ok := entry.(map[string]any)
		if !ok {
			t.Fatalf("finding %v is not an object", entry)
		}
		risk, present := finding["risk"].(map[string]any)
		if !present {
			t.Fatalf("finding %v carries no risk object", finding["rule_id"])
		}
		if _, present := risk["score"]; !present {
			t.Error("the risk object has no score")
		}
		if _, present := risk["band"]; !present {
			t.Error("the risk object has no band")
		}
		if _, present := risk["severity"]; !present {
			t.Error("the risk object does not carry the original severity")
		}
		if _, present := risk["explanation"]; !present {
			t.Error("the risk object has no explanation")
		}
		factors, ok := risk["factors"].([]any)
		if !ok || len(factors) == 0 {
			t.Errorf("finding %v lists no contributing factors", finding["rule_id"])
		}
		if _, present := finding["severity"]; !present {
			t.Error("the finding lost its original severity")
		}
	}
}

func TestNoRiskOmitsScoringEntirely(t *testing.T) {
	target := riskTree(t)
	scored := scanJSON(t, target)
	plain := scanJSON(t, target, "--risk=false")

	plainSummary := plain["summary"].(map[string]any)
	if _, present := plainSummary["by_risk_band"]; present {
		t.Error("by_risk_band is present although scoring is disabled")
	}
	for _, entry := range plain["findings"].([]any) {
		finding := entry.(map[string]any)
		if _, present := finding["risk"]; present {
			t.Errorf("finding %v carries a risk object although scoring is disabled",
				finding["rule_id"])
		}
	}

	scoredFindings := scored["findings"].([]any)
	plainFindings := plain["findings"].([]any)
	if len(scoredFindings) != len(plainFindings) {
		t.Fatalf("disabling scoring changed the finding count from %d to %d",
			len(scoredFindings), len(plainFindings))
	}
	for i := range scoredFindings {
		scoredFinding := scoredFindings[i].(map[string]any)
		plainFinding := plainFindings[i].(map[string]any)
		delete(scoredFinding, "risk")

		delete(scoredFinding, "detected_at")
		delete(plainFinding, "detected_at")
		if !sameJSON(t, scoredFinding, plainFinding) {
			t.Errorf("finding %d differs between scored and unscored reports:\n scored: %v\n plain: %v",
				i, scoredFinding, plainFinding)
		}
	}
}

func sameJSON(t *testing.T, left, right any) bool {
	t.Helper()
	leftBytes, err := json.Marshal(left)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	rightBytes, err := json.Marshal(right)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return bytes.Equal(leftBytes, rightBytes)
}

func TestSortRiskOrdersTheReportByRisk(t *testing.T) {
	target := riskTree(t)
	document := scanJSON(t, target, "--sort-risk")

	findings := document["findings"].([]any)
	if len(findings) < 2 {
		t.Skip("the fixture produced fewer than two findings, so ordering cannot be shown")
	}
	previous := -1
	for i, entry := range findings {
		finding := entry.(map[string]any)
		risk, ok := finding["risk"].(map[string]any)
		if !ok {
			t.Fatalf("finding %d was not scored", i)
		}
		score, ok := risk["score"].(float64)
		if !ok {
			t.Fatalf("finding %d has a non numeric score", i)
		}
		if int(score) < previous {
			t.Fatalf("finding %d scores %v, below the previous %v", i, score, previous)
		}
		previous = int(score)
	}
}

func TestSortRiskIsRejectedWithoutScoring(t *testing.T) {
	target := riskTree(t)
	result := run(t, "scan", target, "--risk=false", "--sort-risk", "--quiet")
	if result.code != ExitUsage {
		t.Fatalf("exit code = %d, want %d; stderr = %q", result.code, ExitUsage, result.stderr)
	}
	if !strings.Contains(result.stderr, "sort-risk") {
		t.Errorf("stderr = %q, want it to name the conflicting option", result.stderr)
	}
}

func TestRiskTextReportShowsTheScore(t *testing.T) {
	target := riskTree(t)
	result := run(t, "scan", target, "--quiet")
	if result.code != ExitFindings {
		t.Fatalf("scan exited %d, want %d; stderr = %q", result.code, ExitFindings, result.stderr)
	}
	if !strings.Contains(result.stdout, "RISK SUMMARY") {
		t.Errorf("the text report has no risk summary:\n%s", result.stdout)
	}
	if !strings.Contains(result.stdout, "risk      :") {
		t.Errorf("the text report shows no risk line:\n%s", result.stdout)
	}

	plain := run(t, "scan", target, "--risk=false", "--quiet")
	if strings.Contains(plain.stdout, "RISK SUMMARY") {
		t.Errorf("the unscored report still shows a risk summary:\n%s", plain.stdout)
	}
}

func TestRiskScoringDoesNotChangeBaselines(t *testing.T) {
	target := riskTree(t)
	dir := t.TempDir()

	scored := filepath.Join(dir, "scored.json")
	plain := filepath.Join(dir, "plain.json")
	if result := run(t, "baseline", "create", target, "--baseline", scored, "--quiet"); result.code != ExitOK {
		t.Fatalf("baseline create exited %d; stderr = %q", result.code, result.stderr)
	}
	if result := run(t, "baseline", "create", target, "--baseline", plain,
		"--risk=false", "--quiet"); result.code != ExitOK {
		t.Fatalf("baseline create exited %d; stderr = %q", result.code, result.stderr)
	}

	scoredBytes, err := os.ReadFile(scored)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	plainBytes, err := os.ReadFile(plain)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var scoredDoc, plainDoc map[string]any
	if err := json.Unmarshal(scoredBytes, &scoredDoc); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if err := json.Unmarshal(plainBytes, &plainDoc); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	delete(scoredDoc, "created_at")
	delete(plainDoc, "created_at")
	if !sameJSON(t, scoredDoc, plainDoc) {
		t.Error("risk scoring changed the recorded baseline")
	}

	for _, entry := range scoredDoc["findings"].([]any) {
		finding := entry.(map[string]any)
		if _, present := finding["risk"]; present {
			t.Errorf("baseline finding %v carries risk metadata", finding["id"])
		}
	}
}

func TestScanUsageMentionsTheRiskFlags(t *testing.T) {
	result := run(t, "scan", "--help")
	if result.code != ExitOK {
		t.Fatalf("help exited %d", result.code)
	}
	for _, flag := range []string{"--risk", "--sort-risk"} {
		if !strings.Contains(result.stdout, flag) {
			t.Errorf("the scan usage does not document %s", flag)
		}
	}
}
