package detectors

import (
	"regexp"
	"strings"
)

const redactedMarker = "[REDACTED]"

type secretPattern struct {
	name    string
	pattern *regexp.Regexp
	value   int
}

var secretPatterns = []secretPattern{
	{"password assignment",
		regexp.MustCompile(`(?i)\b(pass(?:word|wd)?|pass)\b\s*[:=]\s*("[^"\n]*"|'[^'\n]*'|[^\s"';]+)`), 2},
	{"secret assignment",
		regexp.MustCompile(`(?i)\b(secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|token|private[_-]?key|client[_-]?secret)\b\s*[:=]\s*("[^"\n]*"|'[^'\n]*'|[^\s"';]+)`), 2},
	{"aws secret access key",
		regexp.MustCompile(`(?i)\baws_secret_access_key\b\s*[:=]\s*("[^"\n]*"|'[^'\n]*'|[^\s"';]+)`), 2},
	{"aws access key id",
		regexp.MustCompile(`\b((?:AKIA|ASIA)[0-9A-Z]{16})\b`), 1},
	{"private key block",
		regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`), 0},
	{"bearer token",
		regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._\-]{12,}`), 0},
}

type secretMatch struct {
	Pattern string
	Line    int
	Column  int
}

func findSecrets(content string) []secretMatch {
	var matches []secretMatch
	seen := map[secretMatch]struct{}{}
	for lineNumber, line := range strings.Split(content, "\n") {
		for _, candidate := range secretPatterns {
			location := candidate.pattern.FindStringIndex(line)
			if location == nil {
				continue
			}
			match := secretMatch{Pattern: candidate.name, Line: lineNumber + 1, Column: location[0]}
			if _, duplicate := seen[match]; duplicate {
				continue
			}
			seen[match] = struct{}{}
			matches = append(matches, match)
		}
	}
	return matches
}

func RedactText(line string) string {
	return redactLine(line)
}

func redactLine(line string) string {
	redacted := line
	for _, candidate := range secretPatterns {
		pattern := candidate
		redacted = candidate.pattern.ReplaceAllStringFunc(redacted, func(match string) string {
			return redactMatch(pattern, match)
		})
	}
	return redacted
}

func redactMatch(candidate secretPattern, match string) string {
	if candidate.value == 0 {
		return redactedMarker
	}
	groups := candidate.pattern.FindStringSubmatch(match)
	if len(groups) <= candidate.value || groups[candidate.value] == "" {
		return redactedMarker
	}
	return strings.Replace(match, groups[candidate.value], redactedMarker, 1)
}

func evidenceLocation(path string, line int) string {
	return path + ":" + itoa(uint32(line))
}
