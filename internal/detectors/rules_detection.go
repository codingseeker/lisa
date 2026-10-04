package detectors

import "lisa/internal/model"

var ruleCronWorldWritable = model.Rule{
	ID:          "LS-PERS-001",
	Title:       "World-writable cron entry",
	Severity:    model.SeverityHigh,
	Confidence:  model.ConfidenceHigh,
	Category:    model.CategoryPersistence,
	Remediation: "Restore the mode to 0644 for cron drop-ins and 0600 for per-user crontabs.",
	Technique: &model.Technique{
		ID:     "T1053.003",
		Name:   "Cron",
		Tactic: "Persistence",
	},
}

var ruleCronOwnership = model.Rule{
	ID:          "LS-PERS-002",
	Title:       "System cron entry not owned by root",
	Severity:    model.SeverityHigh,
	Confidence:  model.ConfidenceHigh,
	Category:    model.CategoryPersistence,
	Remediation: "Restore root ownership with chown root:root <file>.",
	Technique: &model.Technique{
		ID:     "T1053.003",
		Name:   "Cron",
		Tactic: "Persistence",
	},
}

var ruleSystemdWorldWritable = model.Rule{
	ID:          "LS-PERS-003",
	Title:       "World-writable systemd unit",
	Severity:    model.SeverityHigh,
	Confidence:  model.ConfidenceHigh,
	Category:    model.CategoryPersistence,
	Remediation: "Restore the mode to 0644 and verify the unit against the distribution package list.",
	Technique: &model.Technique{
		ID:     "T1543.002",
		Name:   "Systemd Service",
		Tactic: "Persistence",
	},
}

var ruleSystemdOwnership = model.Rule{
	ID:          "LS-PERS-004",
	Title:       "Systemd unit in a system directory not owned by root",
	Severity:    model.SeverityHigh,
	Confidence:  model.ConfidenceHigh,
	Category:    model.CategoryPersistence,
	Remediation: "Restore root ownership with chown root:root <file>.",
	Technique: &model.Technique{
		ID:     "T1543.002",
		Name:   "Systemd Service",
		Tactic: "Persistence",
	},
}

var ruleShellProfileWorldWritable = model.Rule{
	ID:          "LS-PERS-005",
	Title:       "World-writable shell startup file",
	Severity:    model.SeverityHigh,
	Confidence:  model.ConfidenceHigh,
	Category:    model.CategoryPersistence,
	Remediation: "Restore the mode to 0644 for the file and 0700 for the home directory.",
	Technique: &model.Technique{
		ID:     "T1546.004",
		Name:   "Unix Shell Configuration Modification",
		Tactic: "Persistence",
	},
}

var ruleInitWorldWritable = model.Rule{
	ID:          "LS-PERS-006",
	Title:       "World-writable init script",
	Severity:    model.SeverityHigh,
	Confidence:  model.ConfidenceHigh,
	Category:    model.CategoryPersistence,
	Remediation: "Restore root ownership and remove group and other write permission.",
}

var ruleRcLocalNotExecutable = model.Rule{
	ID:          "LS-PERS-007",
	Title:       "rc.local present without an executable bit",
	Severity:    model.SeverityLow,
	Confidence:  model.ConfidenceMedium,
	Category:    model.CategoryPersistence,
	Remediation: "If the host still uses rc.local, restore the executable bit with chmod +x /etc/rc.local.",
}

var ruleLdSoPreloadUnsafe = model.Rule{
	ID:          "LS-PERS-008",
	Title:       "Unsafe permissions or ownership on /etc/ld.so.preload",
	Severity:    model.SeverityHigh,
	Confidence:  model.ConfidenceHigh,
	Category:    model.CategoryPersistence,
	Remediation: "The dynamic linker loads every library listed here into every process. Keep the file root-owned and mode 0644.",
	Technique: &model.Technique{
		ID:     "T1574.006",
		Name:   "Dynamic-linker Hijacking",
		Tactic: "Persistence",
	},
}

var rulePersistenceTemporaryReference = model.Rule{
	ID:          "LS-PERS-009",
	Title:       "Persistence entry references a temporary directory",
	Severity:    model.SeverityMedium,
	Confidence:  model.ConfidenceMedium,
	Category:    model.CategoryPersistence,
	Remediation: "Confirm the reference is intended. Temporary storage is writable by other users and should not hold code that runs automatically.",
}

var rulePersistenceDownloadPipeShell = model.Rule{
	ID:          "LS-PERS-010",
	Title:       "Persistence entry pipes downloaded content into a shell",
	Severity:    model.SeverityHigh,
	Confidence:  model.ConfidenceHigh,
	Category:    model.CategoryPersistence,
	Remediation: "Remove the entry. Piping network content into a shell executes unreviewed code on every run.",
	Technique: &model.Technique{
		ID:     "T1105",
		Name:   "Ingress Tool Transfer",
		Tactic: "Command and Control",
	},
}

var rulePersistenceReverseShell = model.Rule{
	ID:          "LS-PERS-011",
	Title:       "Persistence entry contains a reverse shell one-liner",
	Severity:    model.SeverityHigh,
	Confidence:  model.ConfidenceHigh,
	Category:    model.CategoryPersistence,
	Remediation: "Remove the entry and investigate how it was created.",
}

var ruleSSHDPermitRootLogin = model.Rule{
	ID:          "LS-SENS-001",
	Title:       "sshd allows direct root login",
	Severity:    model.SeverityHigh,
	Confidence:  model.ConfidenceHigh,
	Category:    model.CategorySensitiveConfig,
	Remediation: "Set PermitRootLogin to no, or to prohibit-password if key based root access is required.",
}

var ruleSSHDEmptyPasswords = model.Rule{
	ID:          "LS-SENS-002",
	Title:       "sshd allows empty passwords",
	Severity:    model.SeverityHigh,
	Confidence:  model.ConfidenceHigh,
	Category:    model.CategorySensitiveConfig,
	Remediation: "Set PermitEmptyPasswords to no.",
}

var ruleSSHDUserEnvironment = model.Rule{
	ID:          "LS-SENS-003",
	Title:       "sshd allows user environment injection",
	Severity:    model.SeverityMedium,
	Confidence:  model.ConfidenceHigh,
	Category:    model.CategorySensitiveConfig,
	Remediation: "Set PermitUserEnvironment to no unless a documented requirement depends on it.",
}

var ruleSSHDPasswordAuthentication = model.Rule{
	ID:          "LS-SENS-004",
	Title:       "sshd allows password authentication",
	Severity:    model.SeverityLow,
	Confidence:  model.ConfidenceHigh,
	Category:    model.CategorySensitiveConfig,
	Remediation: "Prefer PubkeyAuthentication and set PasswordAuthentication to no where password login is not required.",
}

var ruleSudoersNoPassword = model.Rule{
	ID:          "LS-SENS-005",
	Title:       "sudoers entry grants passwordless privilege",
	Severity:    model.SeverityMedium,
	Confidence:  model.ConfidenceMedium,
	Category:    model.CategorySensitiveConfig,
	Remediation: "Remove NOPASSWD unless the entry is required for unattended operation.",
}

var ruleExposedSecret = model.Rule{
	ID:          "LS-SENS-006",
	Title:       "Credential-shaped value stored in a configuration file",
	Severity:    model.SeverityHigh,
	Confidence:  model.ConfidenceMedium,
	Category:    model.CategorySensitiveConfig,
	Remediation: "Move the value to a root-only file or a secret manager and reference it indirectly. Values are redacted in this report.",
	Technique: &model.Technique{
		ID:     "T1552.001",
		Name:   "Credentials In Files",
		Tactic: "Credential Access",
	},
}

var ruleTemporaryExecutable = model.Rule{
	ID:          "LS-IND-001",
	Title:       "Executable file in a temporary directory",
	Severity:    model.SeverityMedium,
	Confidence:  model.ConfidenceHigh,
	Category:    model.CategoryIndicator,
	Remediation: "Confirm the file is expected. Temporary directories are writable by other users and are commonly used to stage payloads.",
}

var ruleMasqueradeDocumentOrImage = model.Rule{
	ID:          "LS-IND-002",
	Title:       "Executable masquerading as a document or image",
	Severity:    model.SeverityHigh,
	Confidence:  model.ConfidenceHigh,
	Category:    model.CategoryIndicator,
	Remediation: "Verify the file against its expected content and remove it if unrecognised.",
	Technique: &model.Technique{
		ID:     "T1036.005",
		Name:   "Match Legitimate Resource Name or Location",
		Tactic: "Defense Evasion",
	},
}

var ruleMasqueradeText = model.Rule{
	ID:          "LS-IND-003",
	Title:       "Executable masquerading as a text or configuration file",
	Severity:    model.SeverityMedium,
	Confidence:  model.ConfidenceHigh,
	Category:    model.CategoryIndicator,
	Remediation: "Verify the file against its expected content and remove it if unrecognised.",
	Technique: &model.Technique{
		ID:     "T1036.005",
		Name:   "Match Legitimate Resource Name or Location",
		Tactic: "Defense Evasion",
	},
}

var ruleScriptInUserFolder = model.Rule{
	ID:          "LS-IND-004",
	Title:       "Script with a non-script extension in a user accessible folder",
	Severity:    model.SeverityMedium,
	Confidence:  model.ConfidenceHigh,
	Category:    model.CategoryIndicator,
	Remediation: "Confirm the file is expected. Scripts in Downloads, Desktop or Documents folders are a common payload delivery pattern.",
}

var ruleExecutableInUserFolder = model.Rule{
	ID:          "LS-IND-005",
	Title:       "Compiled executable in a user downloads folder",
	Severity:    model.SeverityMedium,
	Confidence:  model.ConfidenceMedium,
	Category:    model.CategoryIndicator,
	Remediation: "Confirm the file is expected and remove compiled binaries from user download folders.",
}

func allRules() []model.Rule {
	return []model.Rule{
		ruleWorldWritableFile, ruleWorldWritableDirectory, ruleStickyWorldWritableDirectory,
		ruleSensitiveFilePermissions, rulePrivateKeyPermissions, ruleAuthorizedKeysPermissions,
		ruleWorldWritableSystemFile, ruleWorldWritableTemporaryFile,
		ruleSensitiveFileOwnership, ruleOrphanedOwner, ruleOrphanedGroup, ruleUnexpectedSystemOwnership,
		ruleSetuidBinary, ruleSetgidBinary, ruleSetuidOutsideSystemDirectories, ruleGtfoBinsCandidate,
		ruleCronWorldWritable, ruleCronOwnership, ruleSystemdWorldWritable, ruleSystemdOwnership,
		ruleShellProfileWorldWritable, ruleInitWorldWritable, ruleRcLocalNotExecutable, ruleLdSoPreloadUnsafe,
		rulePersistenceTemporaryReference, rulePersistenceDownloadPipeShell, rulePersistenceReverseShell,
		ruleSSHDPermitRootLogin, ruleSSHDEmptyPasswords, ruleSSHDUserEnvironment, ruleSSHDPasswordAuthentication,
		ruleSudoersNoPassword, ruleExposedSecret,
		ruleTemporaryExecutable, ruleMasqueradeDocumentOrImage, ruleMasqueradeText,
		ruleScriptInUserFolder, ruleExecutableInUserFolder,
	}
}
