package detectors

import "lisa/internal/model"

var ruleWorldWritableFile = model.Rule{
	ID:          "LS-PERM-001",
	Title:       "World-writable regular file",
	Severity:    model.SeverityMedium,
	Confidence:  model.ConfidenceHigh,
	Category:    model.CategoryPermissions,
	Remediation: "Remove write permission for group and other, for example chmod o-w <file>.",
	Technique: &model.Technique{
		ID:     "T1222.002",
		Name:   "Linux and Mac File and Directory Permissions Modification",
		Tactic: "Defense Evasion",
	},
}

var ruleWorldWritableDirectory = model.Rule{
	ID:          "LS-PERM-002",
	Title:       "World-writable directory without sticky bit",
	Severity:    model.SeverityMedium,
	Confidence:  model.ConfidenceHigh,
	Category:    model.CategoryPermissions,
	Remediation: "Restrict the directory mode, for example chmod 0755 <dir>. Add the sticky bit only when shared write access is intended.",
}

var ruleStickyWorldWritableDirectory = model.Rule{
	ID:          "LS-PERM-003",
	Title:       "World-writable directory with sticky bit",
	Severity:    model.SeverityInfo,
	Confidence:  model.ConfidenceHigh,
	Category:    model.CategoryPermissions,
	Remediation: "Confirm the shared directory is intentional. Remove the sticky bit with chmod -t <dir> if it is not.",
}

var ruleSensitiveFilePermissions = model.Rule{
	ID:          "LS-PERM-004",
	Title:       "Unsafe permissions on sensitive system file",
	Severity:    model.SeverityHigh,
	Confidence:  model.ConfidenceHigh,
	Category:    model.CategorySensitiveConfig,
	Remediation: "Restore the vendor documented ownership and mode, for example chown root:root <file> and chmod 0600 <file>.",
}

var ruleSensitiveFileOwnership = model.Rule{
	ID:          "LS-OWN-001",
	Title:       "Sensitive system file not owned by root",
	Severity:    model.SeverityHigh,
	Confidence:  model.ConfidenceHigh,
	Category:    model.CategoryOwnership,
	Remediation: "Restore root ownership with chown root:root <file>.",
}

var rulePrivateKeyPermissions = model.Rule{
	ID:          "LS-PERM-005",
	Title:       "SSH private key with overly broad permissions",
	Severity:    model.SeverityHigh,
	Confidence:  model.ConfidenceHigh,
	Category:    model.CategoryPermissions,
	Remediation: "Restrict the key to the owning user, for example chmod 0600 <file>.",
	Technique: &model.Technique{
		ID:     "T1552.001",
		Name:   "Credentials In Files",
		Tactic: "Credential Access",
	},
}

var ruleAuthorizedKeysPermissions = model.Rule{
	ID:          "LS-PERM-006",
	Title:       "authorized_keys with overly broad permissions",
	Severity:    model.SeverityMedium,
	Confidence:  model.ConfidenceHigh,
	Category:    model.CategoryPermissions,
	Remediation: "Restrict the file to 0600 and its directory to 0700.",
	Technique: &model.Technique{
		ID:     "T1552.001",
		Name:   "Credentials In Files",
		Tactic: "Credential Access",
	},
}

var ruleSetuidBinary = model.Rule{
	ID:          "LS-PRIV-001",
	Title:       "SUID binary present",
	Severity:    model.SeverityLow,
	Confidence:  model.ConfidenceHigh,
	Category:    model.CategoryIndicator,
	Remediation: "Confirm the binary is part of the distribution. Remove the SUID bit from anything unrecognised.",
	Technique: &model.Technique{
		ID:     "T1548.001",
		Name:   "Setuid and Setgid",
		Tactic: "Privilege Escalation",
	},
}

var ruleSetgidBinary = model.Rule{
	ID:          "LS-PRIV-002",
	Title:       "SGID binary present",
	Severity:    model.SeverityLow,
	Confidence:  model.ConfidenceHigh,
	Category:    model.CategoryIndicator,
	Remediation: "Confirm the binary is part of the distribution. Remove the SGID bit from anything unrecognised.",
	Technique: &model.Technique{
		ID:     "T1548.001",
		Name:   "Setuid and Setgid",
		Tactic: "Privilege Escalation",
	},
}

var ruleSetuidOutsideSystemDirectories = model.Rule{
	ID:          "LS-PRIV-003",
	Title:       "SUID binary outside standard system directories",
	Severity:    model.SeverityMedium,
	Confidence:  model.ConfidenceMedium,
	Category:    model.CategoryIndicator,
	Remediation: "Remove the SUID bit and verify the file against the distribution package list.",
}

var ruleGtfoBinsCandidate = model.Rule{
	ID:          "LS-PRIV-004",
	Title:       "SUID or SGID binary with known privilege escalation potential",
	Severity:    model.SeverityMedium,
	Confidence:  model.ConfidenceMedium,
	Category:    model.CategoryIndicator,
	Remediation: "Review GTFOBins entries for this binary. Removing the SUID or SGID bit removes this escalation path.",
	Technique: &model.Technique{
		ID:     "T1548.001",
		Name:   "Setuid and Setgid",
		Tactic: "Privilege Escalation",
	},
}

var ruleOrphanedOwner = model.Rule{
	ID:          "LS-OWN-002",
	Title:       "File owned by a UID absent from the system user database",
	Severity:    model.SeverityMedium,
	Confidence:  model.ConfidenceMedium,
	Category:    model.CategoryOwnership,
	Remediation: "Confirm the file is expected and assign it to a valid account.",
}

var ruleOrphanedGroup = model.Rule{
	ID:          "LS-OWN-003",
	Title:       "File owned by a GID absent from the system group database",
	Severity:    model.SeverityLow,
	Confidence:  model.ConfidenceMedium,
	Category:    model.CategoryOwnership,
	Remediation: "Confirm the file is expected and assign it to a valid group.",
}

var ruleUnexpectedSystemOwnership = model.Rule{
	ID:          "LS-OWN-004",
	Title:       "System file owned by an unprivileged account",
	Severity:    model.SeverityMedium,
	Confidence:  model.ConfidenceMedium,
	Category:    model.CategoryOwnership,
	Remediation: "Restore root ownership with chown root:root <file> unless a package documents a different owner.",
}
var ruleWorldWritableSystemFile = model.Rule{
	ID:          "LS-PERM-007",
	Title:       "World-writable file in a system owned directory",
	Severity:    model.SeverityHigh,
	Confidence:  model.ConfidenceHigh,
	Category:    model.CategoryPermissions,
	Remediation: "Remove write permission for group and other and verify the file against the distribution package list.",
	Technique: &model.Technique{
		ID:     "T1222.002",
		Name:   "Linux and Mac File and Directory Permissions Modification",
		Tactic: "Defense Evasion",
	},
}

var ruleWorldWritableTemporaryFile = model.Rule{
	ID:          "LS-PERM-008",
	Title:       "World-writable file in a temporary directory",
	Severity:    model.SeverityMedium,
	Confidence:  model.ConfidenceHigh,
	Category:    model.CategoryPermissions,
	Remediation: "Restrict the mode and avoid relying on temporary storage for files that must not be replaced by other users.",
}
