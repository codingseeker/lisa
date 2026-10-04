package detectors

import (
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	"lisa/internal/model"
)

const maxSecretHitsPerFile = 5

var nopasswdPattern = regexp.MustCompile(`(?i)\bNOPASSWD\s*:`)

type sshdConfigDetector struct{}

func (sshdConfigDetector) Name() string { return "sshd-config" }

func (sshdConfigDetector) Detect(ctx Context) []model.Finding {
	if ctx.Entry.Path != "/etc/ssh/sshd_config" || !ctx.Entry.IsRegular() {
		return nil
	}

	content, err := ctx.ReadFile.Read(ctx.Entry.Path, 0)
	if err != nil || len(content) == 0 {
		return nil
	}
	directives := parseSSHDDirectives(string(content))

	var findings []model.Finding
	for _, check := range []struct {
		directive string
		values    []string
		rule      model.Rule
	}{
		{"PermitRootLogin", []string{"yes"}, ruleSSHDPermitRootLogin},
		{"PermitEmptyPasswords", []string{"yes"}, ruleSSHDEmptyPasswords},
		{"PermitUserEnvironment", []string{"yes"}, ruleSSHDUserEnvironment},
		{"PasswordAuthentication", []string{"yes"}, ruleSSHDPasswordAuthentication},
	} {
		value, present := directives[strings.ToLower(check.directive)]
		if !present || !containsFold(check.values, value) {
			continue
		}
		findings = append(findings, ctx.base(check.rule).
			WithDescription(fmt.Sprintf("%s sets %s to %q in %s.", ctx.Entry.Path, check.directive, value, ctx.Entry.Path)).
			WithEvidence(
				fmt.Sprintf("%s %s", check.directive, value),
				"first matching directive wins in sshd, so this value is effective",
			))
	}

	return findings
}

func parseSSHDDirectives(content string) map[string]string {
	directives := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, value, found := strings.Cut(trimmed, "=")
		if !found {
			key, value, found = strings.Cut(trimmed, " ")
		}
		if !found {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if _, exists := directives[key]; exists {
			continue
		}
		directives[key] = strings.TrimSpace(value)
	}
	return directives
}

func containsFold(values []string, candidate string) bool {
	for _, value := range values {
		if strings.EqualFold(value, candidate) {
			return true
		}
	}
	return false
}

type sudoersDetector struct{}

func (sudoersDetector) Name() string { return "sudoers" }

func (sudoersDetector) Detect(ctx Context) []model.Finding {
	if !ctx.Entry.IsRegular() {
		return nil
	}
	if ctx.Entry.Path != "/etc/sudoers" && !isUnder(ctx.Entry.Path, "/etc/sudoers.d") {
		return nil
	}

	content, err := ctx.ReadFile.Read(ctx.Entry.Path, 0)
	if err != nil || len(content) == 0 {
		return nil
	}

	location, matched, ok := firstMatch(stripSudoersComments(string(content)), nopasswdPattern)
	if !ok {
		return nil
	}

	return []model.Finding{ctx.base(ruleSudoersNoPassword).
		WithDescription(fmt.Sprintf("Sudoers file %s grants a command without a password. Anyone who reaches that command path gains the granted privileges without authentication.", ctx.Entry.Path)).
		WithEvidence(
			fmt.Sprintf("line %d: %s", location, truncate(matched, 160)),
			"matched a NOPASSWD specification",
		)}
}

type secretExposureDetector struct{}

func (secretExposureDetector) Name() string { return "secrets" }

type secretHit struct {
	pattern  string
	line     int
	redacted string
}

func (secretExposureDetector) Detect(ctx Context) []model.Finding {
	if !ctx.Entry.IsRegular() || !isSecretScannableConfig(ctx.Entry.Path) {
		return nil
	}

	content, err := ctx.ReadFile.Read(ctx.Entry.Path, 0)
	if err != nil || len(content) == 0 {
		return nil
	}

	lines := strings.Split(string(content), "\n")
	var hits []secretHit
	seen := map[string]struct{}{}

	for _, match := range findSecrets(string(content)) {
		if len(hits) >= maxSecretHitsPerFile {
			break
		}
		if match.Line < 1 || match.Line > len(lines) {
			continue
		}
		if _, duplicate := seen[match.Pattern]; duplicate {
			continue
		}
		seen[match.Pattern] = struct{}{}
		hits = append(hits, secretHit{
			pattern:  match.Pattern,
			line:     match.Line,
			redacted: truncate(redactLine(lines[match.Line-1]), 160),
		})
	}

	if len(hits) == 0 {
		return nil
	}

	patterns := make([]string, 0, len(hits))
	numbers := make([]string, 0, len(hits))
	evidence := make([]string, 0, len(hits)*2+1)
	for _, hit := range hits {
		patterns = append(patterns, hit.pattern)
		numbers = append(numbers, strconv.Itoa(hit.line))
		evidence = append(evidence,
			fmt.Sprintf("line %d: %s", hit.line, hit.redacted),
			"pattern="+hit.pattern)
	}
	evidence = append(evidence, "values redacted by lisa")

	return []model.Finding{ctx.base(ruleExposedSecret).
		WithDescription(fmt.Sprintf("Configuration file %s contains %d value(s) matching credential patterns (%s) at line(s) %s. Values are redacted in this report and must be reviewed directly on the host.",
			ctx.Entry.Path, len(hits), strings.Join(patterns, ", "), strings.Join(numbers, ", "))).
		WithEvidence(evidence...)}
}

func stripSudoersComments(content string) string {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if index := strings.Index(line, "#"); index >= 0 {
			lines[i] = line[:index]
		}
	}
	return strings.Join(lines, "\n")
}

func isSecretScannableConfig(candidate string) bool {
	if !isUnder(candidate, "/etc") {
		return false
	}
	if isPrivateKeyFile(candidate) {
		return false
	}
	if _, _, sensitive := isSensitiveFile(candidate); sensitive {
		return false
	}
	switch extensionOf(path.Base(candidate)) {
	case ".conf", ".cfg", ".ini", ".env", ".yaml", ".yml", ".json", ".properties":
		return true
	}
	return strings.Count(candidate, "/") <= 3
}
