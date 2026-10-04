package detectors

import (
	"fmt"

	"lisa/internal/model"
)

type worldWritableDetector struct{}

func (worldWritableDetector) Name() string { return "permissions" }

func (worldWritableDetector) Detect(ctx Context) []model.Finding {
	bits := ctx.Entry.PermissionBits()
	if !isWorldWritable(bits) {
		return nil
	}

	if ctx.Entry.IsDir() {
		if isSticky(bits) {
			return []model.Finding{ctx.base(ruleStickyWorldWritableDirectory).
				WithDescription(fmt.Sprintf("Directory %s is world-writable and carries the sticky bit (mode %04o).", ctx.Entry.Path, bits)).
				WithEvidence(
					fmt.Sprintf("mode=%04o", bits),
					"sticky=yes",
					"the sticky bit limits deletion and renaming to the file owner, the directory owner and root",
				)}
		}
		return []model.Finding{ctx.base(ruleWorldWritableDirectory).
			WithDescription(fmt.Sprintf("Directory %s is world-writable without the sticky bit (mode %04o), so any local user can create or replace entries.", ctx.Entry.Path, bits)).
			WithEvidence(
				fmt.Sprintf("mode=%04o", bits),
				"sticky=no",
				"any local user can create, delete or replace entries in this directory",
			)}
	}

	if !ctx.Entry.IsRegular() {
		return nil
	}

	if inSystemOwnedDirectory(ctx.Entry.Path) {
		return []model.Finding{ctx.base(ruleWorldWritableSystemFile).
			WithDescription(fmt.Sprintf("Regular file %s inside a system owned directory is world-writable (mode %04o). A local user can alter a file that the system executes or loads.", ctx.Entry.Path, bits)).
			WithEvidence(
				fmt.Sprintf("mode=%04o", bits),
				fmt.Sprintf("located in %s", scopeLabel(ctx.Entry.Path)),
			)}
	}

	if inTemporaryDirectory(ctx.Entry.Path) {
		return []model.Finding{ctx.base(ruleWorldWritableTemporaryFile).
			WithDescription(fmt.Sprintf("Regular file %s in a temporary directory is world-writable (mode %04o). Any local user can replace it before another process reads it.", ctx.Entry.Path, bits)).
			WithEvidence(
				fmt.Sprintf("mode=%04o", bits),
				fmt.Sprintf("located in %s", scopeLabel(ctx.Entry.Path)),
			)}
	}

	return []model.Finding{ctx.base(ruleWorldWritableFile).
		WithDescription(fmt.Sprintf("Regular file %s is world-writable (mode %04o).", ctx.Entry.Path, bits)).
		WithEvidence(fmt.Sprintf("mode=%04o", bits))}
}

type sensitivePermissionDetector struct{}

func (sensitivePermissionDetector) Name() string { return "sensitive-permissions" }

func (sensitivePermissionDetector) Detect(ctx Context) []model.Finding {
	spec, ok := sensitiveSpecFor(ctx.Entry.Path)
	if !ok {
		return nil
	}

	bits := ctx.Entry.PermissionBits()
	level := spec.sensitivity
	reason := spec.reason
	var findings []model.Finding

	unsafe := false
	var reasons []string
	if spec.forbidWorldWrite && isWorldWritable(bits) {
		unsafe = true
		reasons = append(reasons, "writable by other")
	}
	if spec.forbidGroupWrite && isGroupWritable(bits) {
		unsafe = true
		reasons = append(reasons, "writable by group")
	}
	if spec.forbidGroupOrOtherRead && (isGroupReadable(bits) || isWorldReadable(bits)) {
		unsafe = true
		reasons = append(reasons, "readable by group or other")
	}

	if unsafe {
		evidence := []string{fmt.Sprintf("mode=%04o", bits), reason}
		for _, item := range reasons {
			evidence = append(evidence, "violation: "+item)
		}
		findings = append(findings, ctx.base(ruleSensitiveFilePermissions).
			WithSeverity(severityOf(level)).
			WithDescription(fmt.Sprintf("Sensitive file %s has unsafe permissions (mode %04o): it %s.", ctx.Entry.Path, bits, reason)).
			WithEvidence(evidence...))
	}

	if ctx.HaveOwner && ctx.UID != 0 {
		findings = append(findings, ctx.base(ruleSensitiveFileOwnership).
			WithDescription(fmt.Sprintf("Sensitive file %s is owned by %s instead of root.", ctx.Entry.Path, ctx.ownerLabel())).
			WithEvidence(fmt.Sprintf("uid=%d (%s)", ctx.UID, ctx.ownerLabel())))
	}

	return findings
}

type sshKeyDetector struct{}

func (sshKeyDetector) Name() string { return "ssh-keys" }

func (sshKeyDetector) Detect(ctx Context) []model.Finding {
	if !ctx.Entry.IsRegular() {
		return nil
	}
	bits := ctx.Entry.PermissionBits()

	if isPrivateKeyFile(ctx.Entry.Path) {
		if isGroupReadable(bits) || isWorldReadable(bits) || isWorldWritable(bits) || isGroupWritable(bits) {
			return []model.Finding{ctx.base(rulePrivateKeyPermissions).
				WithDescription(fmt.Sprintf("Private key %s has mode %04o. OpenSSH refuses keys readable by group or other.", ctx.Entry.Path, bits)).
				WithEvidence(
					fmt.Sprintf("mode=%04o", bits),
					"sshd and ssh reject group or world readable private keys",
				)}
		}
		return nil
	}

	if isAuthorizedKeysFile(ctx.Entry.Path) && (isWorldReadable(bits) || isGroupReadable(bits) || isWorldWritable(bits)) {
		return []model.Finding{ctx.base(ruleAuthorizedKeysPermissions).
			WithDescription(fmt.Sprintf("authorized_keys file %s has mode %04o, which allows local users to alter the authorised key list.", ctx.Entry.Path, bits)).
			WithEvidence(fmt.Sprintf("mode=%04o", bits))}
	}

	return nil
}

func isGroupReadable(bits uint32) bool {
	return bits&0o040 != 0
}

func severityOf(level sensitivity) model.Severity {
	switch level {
	case sensitivityHigh:
		return model.SeverityHigh
	case sensitivityMedium:
		return model.SeverityMedium
	default:
		return model.SeverityLow
	}
}

func scopeLabel(candidate string) string {
	if inTemporaryDirectory(candidate) {
		return "a temporary directory"
	}
	return "a system owned directory"
}
