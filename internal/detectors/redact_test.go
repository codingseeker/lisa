package detectors

import (
	"encoding/json"
	"strings"
	"testing"

	"lisa/internal/model"
)

const (
	canaryPassword = "CANARY-PASSWORD-a1b2c3d4e5"
	canaryAPIKey   = "CANARY-API-KEY-9f8e7d6c5b"
	canaryToken    = "CANARY-TOKEN-1122334455"
	canaryAWSKey   = "AKIACANARY0123456789"
	canaryBearer   = "CANARYBEARERTOKEN0123456789"
)

func TestRedactLineCoversEveryPattern(t *testing.T) {
	cases := []struct {
		name     string
		line     string
		canaries []string
	}{
		{"password assignment", "password = " + canaryPassword, []string{canaryPassword}},
		{"password with quotes", `password="` + canaryPassword + `"`, []string{canaryPassword}},
		{"password single quoted", "passwd='" + canaryPassword + "'", []string{canaryPassword}},
		{"colon separated", "password:" + canaryPassword, []string{canaryPassword}},
		{"secret assignment", "secret = " + canaryAPIKey, []string{canaryAPIKey}},
		{"api key with underscore", "api_key = " + canaryAPIKey, []string{canaryAPIKey}},
		{"api key hyphenated", "api-key=" + canaryAPIKey, []string{canaryAPIKey}},
		{"access key", "access_key = " + canaryAPIKey, []string{canaryAPIKey}},
		{"auth token", "auth_token = " + canaryToken, []string{canaryToken}},
		{"bare token", "token=" + canaryToken, []string{canaryToken}},
		{"private key assignment", "private_key = " + canaryAPIKey, []string{canaryAPIKey}},
		{"client secret", "client_secret=" + canaryAPIKey, []string{canaryAPIKey}},
		{"aws access key id", "aws_access_key_id = " + canaryAWSKey, []string{canaryAWSKey}},
		{"aws secret access key", "AWS_SECRET_ACCESS_KEY=" + canaryPassword, []string{canaryPassword}},
		{"private key block", "-----BEGIN RSA PRIVATE KEY-----", []string{}},
		{"bearer token", "Authorization: Bearer " + canaryBearer, []string{canaryBearer}},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			redacted := redactLine(testCase.line)
			for _, canary := range testCase.canaries {
				if strings.Contains(redacted, canary) {
					t.Errorf("redacted line %q still contains the canary %q", redacted, canary)
				}
			}
			if testCase.canaries != nil && !strings.Contains(redacted, redactedMarker) {
				t.Errorf("redacted line %q should contain the redaction marker", redacted)
			}
			if testCase.name == "private key block" && redacted != "-----BEGIN [REDACTED] PRIVATE KEY-----" {
				t.Logf("private key block redacted to %q", redacted)
			}
		})
	}
}

func TestRedactLineMultipleSecretsOnOneLine(t *testing.T) {
	line := "password = " + canaryPassword + " api_key=" + canaryAPIKey + " token=" + canaryToken
	redacted := redactLine(line)

	for _, canary := range []string{canaryPassword, canaryAPIKey, canaryToken} {
		if strings.Contains(redacted, canary) {
			t.Errorf("redacted line %q leaks canary %q", redacted, canary)
		}
	}
	if strings.Count(redacted, redactedMarker) != 3 {
		t.Errorf("expected three redactions in %q, got %d", redacted, strings.Count(redacted, redactedMarker))
	}
}

func TestRedactLinePreservesSurroundingText(t *testing.T) {
	line := "[database] host=db.internal port=5432 password = " + canaryPassword + " sslmode=require"
	redacted := redactLine(line)

	for _, keep := range []string{"[database]", "host=db.internal", "port=5432", "sslmode=require", "password"} {
		if !strings.Contains(redacted, keep) {
			t.Errorf("redacted line %q dropped surrounding context %q", redacted, keep)
		}
	}
	if strings.Contains(redacted, canaryPassword) {
		t.Errorf("redacted line %q leaks the canary", redacted)
	}
}

func TestRedactLineLeavesBenignValuesAlone(t *testing.T) {
	benign := []string{
		"# database configuration",
		"host=db.internal",
		"port=5432",
		"sslmode=require",
		"max_connections=100",
		"[section]",
		"",
		"tokenizer=cl100k_base",
		"key=value",
		"passwd_expiry_days=90",
		"PATH=/usr/bin:/bin",
		"hostname=server01",
	}
	for _, line := range benign {
		if redacted := redactLine(line); redacted != line {
			t.Errorf("benign line %q was modified to %q", line, redacted)
		}
	}
}

func TestRedactLineHandlesPartialAndMalformedInput(t *testing.T) {
	cases := []string{
		"",
		"=",
		"password=",
		"password",
		"password = ",
		"   ",
		"api_key=",
		"secret==",
		"'",
		"\"unterminated",
		strings.Repeat("a=b ", 5000),
		"password = " + strings.Repeat("x", 10000),
		"\x00\x01\x02 password = " + canaryPassword,
		strings.Repeat("password = "+canaryPassword+"\n", 500),
	}
	for _, line := range cases {
		redacted := redactLine(line)
		if strings.Contains(redacted, canaryPassword) {
			t.Errorf("input of length %d leaked the canary: %q", len(line), redacted)
		}
		if strings.Contains(line, canaryPassword) && !strings.Contains(redacted, redactedMarker) {
			t.Errorf("input of length %d containing a secret produced no redaction marker", len(line))
		}
	}
}

func TestFindSecrets(t *testing.T) {
	content := strings.Join([]string{
		"# app config",
		"host=db.internal",
		"password = " + canaryPassword,
		"api_key=" + canaryAPIKey,
		"port=5432",
		"aws_access_key_id = " + canaryAWSKey,
	}, "\n")

	matches := findSecrets(content)
	if len(matches) == 0 {
		t.Fatal("findSecrets returned no matches")
	}

	lines := strings.Split(content, "\n")
	for _, match := range matches {
		if match.Line < 1 || match.Line > len(lines) {
			t.Fatalf("match reports line %d, outside the %d line input", match.Line, len(lines))
		}
		if match.Pattern == "" {
			t.Error("match has an empty pattern name")
		}
		if strings.Contains(lines[match.Line-1], canaryPassword) && match.Pattern != "aws secret access key" {
			continue
		}
	}
	if !containsLine(matches, 3) {
		t.Errorf("expected a match on line 3, got %+v", matches)
	}
	if !containsLine(matches, 4) {
		t.Errorf("expected a match on line 4, got %+v", matches)
	}
	if !containsLine(matches, 6) {
		t.Errorf("expected an AWS key match on line 6, got %+v", matches)
	}
	for _, match := range matches {
		if containsLine([]secretMatch{match}, 1) || containsLine([]secretMatch{match}, 2) || containsLine([]secretMatch{match}, 5) {
			t.Errorf("benign line %d reported as a secret", match.Line)
		}
	}
}

func TestFindSecretsOnBenignContent(t *testing.T) {
	for _, content := range []string{
		"", "nothing here", "[unit]\nDescription=test\n", "port=1234\n",
		strings.Repeat("key=value\n", 2000),
	} {
		if matches := findSecrets(content); len(matches) != 0 {
			t.Errorf("benign content produced %d matches", len(matches))
		}
	}
}

func TestSecretExposureDetectorRedactsFindings(t *testing.T) {
	const path = "/etc/app/config.yaml"
	body := strings.Join([]string{
		"host: db.internal",
		"password = " + canaryPassword,
		"api_key=" + canaryAPIKey,
	}, "\n")

	reader := newStubReader(map[string]string{path: body})
	findings := runDetectorOn(t, secretExposureDetector{}, entryAt(t, path, 0o644), reader)

	if len(findings) != 1 {
		t.Fatalf("expected one aggregated finding per file, got %d", len(findings))
	}

	serialized := serializeAll(t, findings)
	for _, canary := range []string{canaryPassword, canaryAPIKey} {
		if strings.Contains(serialized, canary) {
			t.Errorf("serialized findings leak canary %q:\n%s", canary, serialized)
		}
	}
	if !strings.Contains(serialized, redactedMarker) {
		t.Error("serialized findings should contain the redaction marker")
	}

	for _, finding := range findings {
		if finding.RuleID != "LS-SENS-006" {
			t.Errorf("RuleID = %q, want LS-SENS-006", finding.RuleID)
		}
		if finding.Severity != model.SeverityHigh {
			t.Errorf("Severity = %v, want high", finding.Severity)
		}
		if finding.Confidence != model.ConfidenceMedium {
			t.Errorf("Confidence = %v, want medium", finding.Confidence)
		}
		if finding.Category != model.CategorySensitiveConfig {
			t.Errorf("Category = %q, want sensitive-config", finding.Category)
		}
		if !strings.Contains(finding.Description, "redacted") {
			t.Errorf("Description %q should state that the value is redacted", finding.Description)
		}
		if finding.OwnerName() == "" {
			t.Logf("note: finding carries no owner label")
		}
		if finding.Technique == nil || finding.Technique.ID != "T1552.001" {
			t.Errorf("Technique = %v, want T1552.001", finding.Technique)
		}
		if err := finding.Validate(); err != nil {
			t.Errorf("finding is invalid: %v", err)
		}
	}
	assertNoDuplicateRulePaths(t, findings)
}

func TestSecretExposureDetectorIgnoresNonConfigPaths(t *testing.T) {
	detector := secretExposureDetector{}
	for _, path := range []string{
		"/etc/shadow", "/etc/gshadow", "/etc/ssh/ssh_host_rsa_key",
		"/home/alice/.ssh/id_rsa", "/home/alice/.ssh/authorized_keys",
		"/var/log/app.log", "/opt/app/main.go", "/etc/passwd",
	} {
		reader := newStubReader(map[string]string{path: "password = " + canaryPassword})
		findings := runDetectorOn(t, detector, entryAt(t, path, 0o644), reader)
		if len(findings) != 0 {
			t.Errorf("%s produced %v; sensitive and key material must never be read as config",
				path, ruleIDs(findings))
		}
		if len(reader.readPaths()) != 0 {
			t.Errorf("%s was read by the secrets detector; it must be skipped before any file access", path)
		}
	}
}

func TestSecretExposureDetectorAcceptedConfigPaths(t *testing.T) {
	detector := secretExposureDetector{}
	for _, path := range []string{
		"/etc/app.conf", "/etc/sysconfig/network", "/etc/default/grub",
		"/etc/environment", "/etc/docker/daemon.json", "/etc/xdg/app.ini",
	} {
		reader := newStubReader(map[string]string{path: "password = " + canaryPassword})
		findings := runDetectorOn(t, detector, entryAt(t, path, 0o644), reader)
		if len(findings) == 0 {
			t.Errorf("%s should be inspected for secrets", path)
		}
		if strings.Contains(serializeAll(t, findings), canaryPassword) {
			t.Errorf("%s leaked the canary", path)
		}
	}
}

func TestSecretExposureDetectorCapsFindingsPerFile(t *testing.T) {
	const path = "/etc/app/config.yaml"
	body := strings.Join([]string{
		"password = " + canaryPassword,
		"secret = " + canaryAPIKey,
		"AWS_SECRET_ACCESS_KEY=" + canaryToken,
		"aws_access_key_id = " + canaryAWSKey,
		"-----BEGIN RSA PRIVATE KEY-----",
		"Authorization: Bearer " + canaryBearer,
	}, "\n")

	if got := len(findSecrets(body)); got != len(secretPatterns) {
		t.Fatalf("fixture triggers %d distinct patterns, want all %d", got, len(secretPatterns))
	}

	findings := runDetectorOn(t, secretExposureDetector{}, entryAt(t, path, 0o644),
		newStubReader(map[string]string{path: body}))

	if len(findings) != 1 {
		t.Fatalf("expected one aggregated finding per file, got %d", len(findings))
	}
	if got := len(findings[0].Evidence) / 2; got > maxSecretHitsPerFile {
		t.Errorf("recorded %d pattern hits, want at most %d per file", got, maxSecretHitsPerFile)
	}
	if strings.Contains(serializeAll(t, findings), canaryPassword) {
		t.Error("capped output leaked a secret value")
	}
}

func TestSecretExposureDetectorDeduplicatesByPattern(t *testing.T) {
	const path = "/etc/app.conf"
	body := "password = " + canaryPassword + "\npassword = " + canaryAPIKey + "\n"

	findings := runDetectorOn(t, secretExposureDetector{}, entryAt(t, path, 0o644),
		newStubReader(map[string]string{path: body}))
	if len(findings) != 1 {
		t.Errorf("two password assignments produced %d findings, want one per pattern", len(findings))
	}
}

func TestSecretExposureDetectorBenignConfigIsSilent(t *testing.T) {
	const path = "/etc/app/config.yaml"
	body := "host: db.internal\nport: 5432\nsslmode: require\nmax_connections: 100\n"
	reader := newStubReader(map[string]string{path: body})

	findings := runDetectorOn(t, secretExposureDetector{}, entryAt(t, path, 0o644), reader)
	if len(findings) != 0 {
		t.Errorf("benign configuration produced %v, want no findings", ruleIDs(findings))
	}
}

func TestSecretExposureDetectorUnreadableFileIsSilent(t *testing.T) {
	const path = "/etc/app.conf"
	reader := newStubReader(map[string]string{path: "password = " + canaryPassword})
	reader.fail[path] = true

	findings := runDetectorOn(t, secretExposureDetector{}, entryAt(t, path, 0o644), reader)
	if len(findings) != 0 {
		t.Errorf("an unreadable file produced %v, want no findings", ruleIDs(findings))
	}
}

func serializeAll(t *testing.T, findings []model.Finding) string {
	t.Helper()
	data, err := json.Marshal(findings)
	if err != nil {
		t.Fatalf("marshalling findings failed: %v", err)
	}
	return string(data)
}

func containsLine(matches []secretMatch, line int) bool {
	for _, match := range matches {
		if match.Line == line {
			return true
		}
	}
	return false
}
