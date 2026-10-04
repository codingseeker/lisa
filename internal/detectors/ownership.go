package detectors

import (
	"fmt"

	"lisa/internal/model"
)

type ownershipDetector struct{}

func (ownershipDetector) Name() string { return "ownership" }

func (ownershipDetector) Detect(ctx Context) []model.Finding {
	if !ctx.HaveOwner || !ctx.Entry.IsRegular() {
		return nil
	}

	var findings []model.Finding

	if ctx.Identity.userCount() > 0 && !ctx.Identity.knownUser(ctx.UID) {
		findings = append(findings, ctx.base(ruleOrphanedOwner).
			WithDescription(fmt.Sprintf("File %s is owned by uid %d, which has no entry in the system user database.", ctx.Entry.Path, ctx.UID)).
			WithEvidence(
				fmt.Sprintf("uid=%d", ctx.UID),
				"no matching entry in /etc/passwd",
			))
	}

	if ctx.Identity.groupCount() > 0 && !ctx.Identity.knownGroup(ctx.GID) {
		findings = append(findings, ctx.base(ruleOrphanedGroup).
			WithDescription(fmt.Sprintf("File %s is owned by gid %d, which has no entry in the system group database.", ctx.Entry.Path, ctx.GID)).
			WithEvidence(
				fmt.Sprintf("gid=%d", ctx.GID),
				"no matching entry in /etc/group",
			))
	}

	if inSystemOwnedDirectory(ctx.Entry.Path) && ctx.UID >= 1000 {
		findings = append(findings, ctx.base(ruleUnexpectedSystemOwnership).
			WithDescription(fmt.Sprintf("File %s in a system owned directory is owned by the unprivileged account %s (uid %d).", ctx.Entry.Path, ctx.ownerLabel(), ctx.UID)).
			WithEvidence(
				fmt.Sprintf("uid=%d (%s)", ctx.UID, ctx.ownerLabel()),
				fmt.Sprintf("path is under %s", systemScopeLabel(ctx.Entry.Path)),
			))
	}

	return findings
}

func systemScopeLabel(candidate string) string {
	for _, directory := range systemOwnedPrefixes {
		if candidate == directory || isUnder(candidate, directory) {
			return directory
		}
	}
	return "/"
}
