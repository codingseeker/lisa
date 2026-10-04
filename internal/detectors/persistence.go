package detectors

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"lisa/internal/model"
)

var (
	temporaryReferencePattern = regexp.MustCompile(`/tmp/|/var/tmp/|/dev/shm/`)
	downloadPipeShellPattern  = regexp.MustCompile(`(?i)\b(curl|wget)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|k)?sh\b`)
	reverseShellPattern       = regexp.MustCompile(`(?i)/dev/(tcp|udp)/[0-9a-z.\-]+/[0-9]+|bash\s+-i\s*>&`)
	noopasswdPattern          = regexp.MustCompile(`(?i)\bNOPASSWD\s*:`)
)

const maxEvidenceLines = 3

type systemdDetector struct{}

func (systemdDetector) Name() string { return "systemd" }

func (systemdDetector) Detect(ctx Context) []model.Finding {
	if !ctx.Entry.IsRegular() {
		return nil
	}
	if !isInSystemdLocation(ctx.Entry.Path) && !isUserSystemdLocation(ctx.Entry.Path) {
		return nil
	}

	bits := ctx.Entry.PermissionBits()
	var findings []model.Finding

	if isWorldWritable(bits) {
		findings = append(findings, ctx.base(ruleSystemdWorldWritable).
			WithDescription(fmt.Sprintf("Systemd unit %s is world-writable (mode %04o). Any local user can change what the unit executes.", ctx.Entry.Path, bits)).
			WithEvidence(
				fmt.Sprintf("mode=%04o", bits),
				fmt.Sprintf("unit=%s", path.Base(ctx.Entry.Path)),
			))
	}

	if ctx.HaveOwner && ctx.UID != 0 && isInSystemdLocation(ctx.Entry.Path) {
		findings = append(findings, ctx.base(ruleSystemdOwnership).
			WithDescription(fmt.Sprintf("Systemd unit %s in a system directory is owned by %s instead of root.", ctx.Entry.Path, ctx.ownerLabel())).
			WithEvidence(
				fmt.Sprintf("uid=%d (%s)", ctx.UID, ctx.ownerLabel()),
				fmt.Sprintf("unit=%s", path.Base(ctx.Entry.Path)),
			))
	}

	return findings
}

type cronDetector struct{}

func (cronDetector) Name() string { return "cron" }

func (cronDetector) Detect(ctx Context) []model.Finding {
	if !ctx.Entry.IsRegular() || !isInCronLocation(ctx.Entry.Path) {
		return nil
	}

	bits := ctx.Entry.PermissionBits()
	var findings []model.Finding

	if isWorldWritable(bits) {
		findings = append(findings, ctx.base(ruleCronWorldWritable).
			WithDescription(fmt.Sprintf("Cron entry %s is world-writable (mode %04o). Any local user can schedule commands as root.", ctx.Entry.Path, bits)).
			WithEvidence(
				fmt.Sprintf("mode=%04o", bits),
				fmt.Sprintf("location=%s", path.Base(ctx.Entry.Path)),
			))
	}

	if ctx.HaveOwner && ctx.UID != 0 && !isCronSpoolFile(ctx.Entry.Path) {
		findings = append(findings, ctx.base(ruleCronOwnership).
			WithDescription(fmt.Sprintf("System cron entry %s is owned by %s instead of root.", ctx.Entry.Path, ctx.ownerLabel())).
			WithEvidence(
				fmt.Sprintf("uid=%d (%s)", ctx.UID, ctx.ownerLabel()),
				"system cron entries are executed with root privileges",
			))
	}

	return findings
}

type shellProfileDetector struct{}

func (shellProfileDetector) Name() string { return "shell-profiles" }

func (shellProfileDetector) Detect(ctx Context) []model.Finding {
	if !ctx.Entry.IsRegular() {
		return nil
	}

	isProfile := isShellProfileName(path.Base(ctx.Entry.Path))
	isAutostart := isInAutostartDirectory(ctx.Entry.Path) &&
		strings.HasSuffix(strings.ToLower(ctx.Entry.Path), ".desktop")
	if !isProfile && !isAutostart {
		return nil
	}

	bits := ctx.Entry.PermissionBits()
	if !isWorldWritable(bits) && !isGroupWritable(bits) {
		return nil
	}

	kind := "shell startup file"
	if isAutostart {
		kind = "desktop autostart entry"
	}
	return []model.Finding{ctx.base(ruleShellProfileWorldWritable).
		WithDescription(fmt.Sprintf("The %s %s is writable by group or other (mode %04o), so another local user can inject commands that run on next login.", kind, ctx.Entry.Path, bits)).
		WithEvidence(
			fmt.Sprintf("mode=%04o", bits),
			"the file is sourced or executed automatically at session start",
		)}
}

type initDetector struct{}

func (initDetector) Name() string { return "init" }

func (initDetector) Detect(ctx Context) []model.Finding {
	if !ctx.Entry.IsRegular() {
		return nil
	}

	rcLocal := isRcLocal(ctx.Entry.Path)
	if !rcLocal && !isInitScript(ctx.Entry.Path) {
		return nil
	}

	bits := ctx.Entry.PermissionBits()
	var findings []model.Finding

	if isWorldWritable(bits) {
		findings = append(findings, ctx.base(ruleInitWorldWritable).
			WithDescription(fmt.Sprintf("Init entry %s is world-writable (mode %04o). Any local user can change what runs at boot.", ctx.Entry.Path, bits)).
			WithEvidence(fmt.Sprintf("mode=%04o", bits)))
	}

	if rcLocal && !isExecutableMode(bits) {
		findings = append(findings, ctx.base(ruleRcLocalNotExecutable).
			WithDescription(fmt.Sprintf("%s exists but has no executable bit (mode %04o), so it will not run even if it is still used on this host.", ctx.Entry.Path, bits)).
			WithEvidence(fmt.Sprintf("mode=%04o", bits)))
	}

	return findings
}

type preloadDetector struct{}

func (preloadDetector) Name() string { return "ld-preload" }

func (preloadDetector) Detect(ctx Context) []model.Finding {
	if !ctx.Entry.IsRegular() || !isLdSoPreload(ctx.Entry.Path) {
		return nil
	}

	bits := ctx.Entry.PermissionBits()
	writable := isWorldWritable(bits) || isGroupWritable(bits)
	wrongOwner := ctx.HaveOwner && ctx.UID != 0
	if !writable && !wrongOwner {
		return nil
	}

	var evidence []string
	evidence = append(evidence, fmt.Sprintf("mode=%04o", bits))
	if wrongOwner {
		evidence = append(evidence, fmt.Sprintf("uid=%d (%s)", ctx.UID, ctx.ownerLabel()))
	}
	evidence = append(evidence, "every library listed here is loaded into every dynamically linked process")

	return []model.Finding{ctx.base(ruleLdSoPreloadUnsafe).
		WithDescription(fmt.Sprintf("%s is writable by group or other, or not owned by root. The dynamic linker loads the libraries listed in this file into every process, so write access here is equivalent to code execution as any user.", ctx.Entry.Path)).
		WithEvidence(evidence...)}
}

type persistenceContentDetector struct{}

func (persistenceContentDetector) Name() string { return "persistence-content" }

func (persistenceContentDetector) Detect(ctx Context) []model.Finding {
	if !ctx.Entry.IsRegular() || !isPersistenceContentTarget(ctx.Entry.Path) {
		return nil
	}

	content, err := ctx.ReadFile.Read(ctx.Entry.Path, 0)
	if err != nil || len(content) == 0 {
		return nil
	}
	text := string(content)

	var findings []model.Finding

	if location, matched, ok := firstMatch(text, temporaryReferencePattern); ok {
		findings = append(findings, ctx.base(rulePersistenceTemporaryReference).
			WithDescription(fmt.Sprintf("Persistence entry %s references a temporary directory. Temporary storage is writable by other users, so code placed there can be replaced before the entry runs.", ctx.Entry.Path)).
			WithEvidence(
				fmt.Sprintf("line %d: %s", location, truncate(matched, 160)),
				"matched a /tmp, /var/tmp or /dev/shm reference",
			))
	}

	if location, matched, ok := firstMatch(text, downloadPipeShellPattern); ok {
		findings = append(findings, ctx.base(rulePersistenceDownloadPipeShell).
			WithDescription(fmt.Sprintf("Persistence entry %s pipes network content into a shell, so every run executes code that was never reviewed.", ctx.Entry.Path)).
			WithEvidence(
				fmt.Sprintf("line %d: %s", location, truncate(matched, 160)),
				"matched a curl or wget pipeline into sh, bash, zsh or ksh",
			))
	}

	if location, matched, ok := firstMatch(text, reverseShellPattern); ok {
		findings = append(findings, ctx.base(rulePersistenceReverseShell).
			WithDescription(fmt.Sprintf("Persistence entry %s contains a reverse shell pattern, which connects to a remote endpoint for command execution.", ctx.Entry.Path)).
			WithEvidence(
				fmt.Sprintf("line %d: %s", location, truncate(matched, 160)),
				"matched a /dev/tcp or /dev/udp endpoint or a bash -i redirection",
			))
	}

	return findings
}

func isPersistenceContentTarget(candidate string) bool {
	if isInCronLocation(candidate) ||
		isInSystemdLocation(candidate) ||
		isUserSystemdLocation(candidate) ||
		isRcLocal(candidate) ||
		isInitScript(candidate) ||
		isInAutostartDirectory(candidate) {
		return true
	}
	return isShellProfileName(path.Base(candidate))
}

func firstMatch(text string, pattern *regexp.Regexp) (int, string, bool) {
	for index, line := range strings.Split(text, "\n") {
		if matched := pattern.FindString(line); matched != "" {
			return index + 1, strings.TrimSpace(line), true
		}
	}
	return 0, "", false
}

func truncate(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}
