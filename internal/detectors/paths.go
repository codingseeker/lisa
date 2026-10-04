package detectors

import (
	"path"
	"strings"
)

const (
	stagingTmp      = "/tmp"
	stagingVarTmp   = "/var/tmp"
	stagingDevShm   = "/dev/shm"
	rootHome        = "/root"
	currentUserHome = "/home"
)

type sensitivity int

const (
	sensitivityLow sensitivity = iota
	sensitivityMedium
	sensitivityHigh
)

type sensitiveFileSpec struct {
	sensitivity            sensitivity
	reason                 string
	forbidWorldWrite       bool
	forbidGroupWrite       bool
	forbidGroupOrOtherRead bool
}

var sensitiveFiles = map[string]sensitiveFileSpec{
	"/etc/shadow": {
		sensitivityHigh, "stores password hashes and must not be readable by group or other",
		true, true, true,
	},
	"/etc/gshadow": {
		sensitivityHigh, "stores group password hashes and must not be readable by group or other",
		true, true, true,
	},
	"/etc/sudoers": {
		sensitivityHigh, "controls privileged command execution and must not be writable by group or other",
		true, true, false,
	},
	"/etc/ssh/sshd_config": {
		sensitivityMedium, "controls remote access policy and must not be writable by group or other",
		true, true, false,
	},
	"/etc/passwd": {sensitivityLow, "must not be writable by other", true, false, false},
	"/etc/group":  {sensitivityLow, "must not be writable by other", true, false, false},
	"/etc/fstab":  {sensitivityLow, "controls filesystem mounting and must not be writable by other", true, false, false},
}

var sudoersDropInSpec = sensitiveFileSpec{
	sensitivityMedium, "controls privileged command execution and must not be writable by group or other",
	true, true, false,
}

var temporaryDirectories = []string{stagingTmp, stagingVarTmp, stagingDevShm}

var systemOwnedPrefixes = []string{
	"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
	"/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/libexec", "/boot", "/etc",
}

var cronDirectories = []string{
	"/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
	"/etc/cron.weekly", "/etc/cron.monthly",
	"/var/spool/cron",
}

var cronControlFiles = []string{"/etc/crontab", "/etc/anacrontab", "/etc/at.allow", "/etc/at.deny"}

var systemdDirectories = []string{
	"/etc/systemd/system", "/run/systemd/system",
	"/usr/lib/systemd/system", "/lib/systemd/system",
}

var systemdUnitSuffixes = []string{
	".service", ".timer", ".socket", ".mount", ".path", ".target", ".slice", ".swap",
}

var shellProfileNames = []string{
	".bashrc", ".bash_profile", ".bash_login", ".bash_logout",
	".profile", ".zshrc", ".zprofile", ".zshenv", ".zlogin",
}

var userSensitiveNames = map[string]struct{}{
	"Downloads": {}, "Desktop": {}, "Documents": {},
	"tmp": {}, "Temp": {}, "temp": {},
}

var documentExtensions = map[string]struct{}{
	".pdf": {}, ".doc": {}, ".docx": {}, ".xls": {}, ".xlsx": {},
	".ppt": {}, ".pptx": {}, ".odt": {}, ".ods": {}, ".rtf": {}, ".docm": {},
}

var imageExtensions = map[string]struct{}{
	".jpg": {}, ".jpeg": {}, ".png": {}, ".gif": {}, ".bmp": {},
	".webp": {}, ".tiff": {}, ".svg": {}, ".ico": {},
}

var textExtensions = map[string]struct{}{
	".txt": {}, ".log": {}, ".conf": {}, ".cfg": {}, ".ini": {},
	".md": {}, ".csv": {}, ".json": {}, ".xml": {}, ".yaml": {}, ".yml": {},
}

var scriptExtensions = map[string]struct{}{
	".sh": {}, ".bash": {}, ".py": {}, ".pl": {}, ".rb": {}, ".php": {}, ".js": {},
}

func isUnder(candidate, directory string) bool {
	return strings.HasPrefix(candidate, directory+"/")
}

func inTemporaryDirectory(candidate string) bool {
	for _, directory := range temporaryDirectories {
		if candidate == directory || isUnder(candidate, directory) {
			return true
		}
	}
	return false
}

func inSystemOwnedDirectory(candidate string) bool {
	for _, directory := range systemOwnedPrefixes {
		if candidate == directory || isUnder(candidate, directory) {
			return true
		}
	}
	return false
}

var systemBinaryDirectories = []string{
	"/bin", "/sbin", "/usr/bin", "/usr/sbin",
	"/usr/local/bin", "/usr/local/sbin", "/lib", "/lib64", "/usr/lib", "/usr/libexec",
}

func isSystemBinaryDirectory(candidate string) bool {
	for _, directory := range systemBinaryDirectories {
		if candidate == directory || isUnder(candidate, directory) {
			return true
		}
	}
	return false
}

func isInCronLocation(candidate string) bool {
	for _, file := range cronControlFiles {
		if candidate == file {
			return true
		}
	}
	for _, directory := range cronDirectories {
		if candidate == directory || isUnder(candidate, directory) {
			return true
		}
	}
	return false
}

func isCronSpoolFile(candidate string) bool {
	return isUnder(candidate, "/var/spool/cron")
}

func isInSystemdLocation(candidate string) bool {
	for _, directory := range systemdDirectories {
		if candidate == directory || isUnder(candidate, directory) {
			return true
		}
	}
	return false
}

var userSystemdPrefixes = []string{
	"/.config/systemd/user/", "/.local/share/systemd/user/",
}

func isUserSystemdLocation(candidate string) bool {
	if !isUnderHomeDirectory(candidate) {
		return false
	}
	for _, prefix := range userSystemdPrefixes {
		if strings.Contains(candidate, prefix) {
			return true
		}
	}
	return false
}

func hasSystemdUnitSuffix(candidate string) bool {
	lowered := strings.ToLower(candidate)
	for _, suffix := range systemdUnitSuffixes {
		if strings.HasSuffix(lowered, suffix) {
			return true
		}
	}
	return false
}

func isShellProfileName(name string) bool {
	for _, candidate := range shellProfileNames {
		if name == candidate {
			return true
		}
	}
	return false
}

func isInAutostartDirectory(candidate string) bool {
	if isUnder(candidate, "/etc/xdg/autostart") {
		return true
	}
	if isUnder(candidate, rootHome) && strings.Contains(candidate, "/.config/autostart/") {
		return true
	}
	return isUnder(candidate, currentUserHome) && strings.Contains(candidate, "/.config/autostart/")
}

func isRcLocal(candidate string) bool {
	return candidate == "/etc/rc.local" || candidate == "/etc/rc.d/rc.local"
}

func isInitScript(candidate string) bool {
	if !isUnder(candidate, "/etc/init.d") {
		return false
	}
	if strings.Contains(candidate, "/init.d.d/") {
		return false
	}
	return true
}

func isLdSoPreload(candidate string) bool {
	return candidate == "/etc/ld.so.preload"
}

func isHomeDirectory(candidate string) bool {
	if candidate == rootHome || isUnder(candidate, rootHome) {
		return true
	}
	if !isUnder(candidate, currentUserHome) {
		return false
	}
	relative := strings.TrimPrefix(candidate, currentUserHome+"/")
	return relative != "" && !strings.Contains(relative, "/")
}

func isUnderHomeDirectory(candidate string) bool {
	return candidate == rootHome ||
		isUnder(candidate, rootHome) ||
		isUnder(candidate, currentUserHome)
}

func isUserSSHDirectory(candidate string) bool {
	if isUnder(candidate, "/etc/ssh") {
		return true
	}
	return isUnderHomeDirectory(candidate) && strings.Contains(candidate, "/.ssh/")
}

var nonPrivateKeyNames = map[string]struct{}{
	"authorized_keys":   {},
	"authorized_keys2":  {},
	"known_hosts":       {},
	"known_hosts2":      {},
	"config":            {},
	"environment":       {},
	"environment.local": {},
}

func isPrivateKeyFile(candidate string) bool {
	base := path.Base(candidate)
	if isUnder(candidate, "/etc/ssh") {
		return strings.HasPrefix(base, "ssh_host_") && strings.HasSuffix(base, "_key")
	}
	if !isUserSSHDirectory(candidate) {
		return false
	}
	if strings.HasSuffix(base, ".pub") {
		return false
	}
	trimmed := strings.TrimSuffix(base, ".old")
	if _, excluded := nonPrivateKeyNames[base]; excluded {
		return false
	}
	if _, excluded := nonPrivateKeyNames[trimmed]; excluded {
		return false
	}
	return true
}

func isAuthorizedKeysFile(candidate string) bool {
	base := path.Base(candidate)
	return base == "authorized_keys" || base == "authorized_keys2"
}

func isSensitiveFile(candidate string) (sensitivity, string, bool) {
	spec, ok := sensitiveFiles[candidate]
	return spec.sensitivity, spec.reason, ok
}

func sensitiveSpecFor(candidate string) (sensitiveFileSpec, bool) {
	if spec, ok := sensitiveFiles[candidate]; ok {
		return spec, true
	}
	if isUnder(candidate, "/etc/sudoers.d") {
		return sudoersDropInSpec, true
	}
	return sensitiveFileSpec{}, false
}

func inUserSensitiveDirectory(candidate string) bool {
	for _, element := range strings.Split(candidate, "/") {
		if _, ok := userSensitiveNames[element]; ok {
			return true
		}
	}
	return false
}

func extensionOf(name string) string {
	lowered := strings.ToLower(name)
	index := strings.LastIndex(lowered, ".")
	if index <= 0 {
		return ""
	}
	return lowered[index:]
}

func isExecutableMode(bits uint32) bool {
	return bits&0o111 != 0
}

func isWorldWritable(bits uint32) bool {
	return bits&0o002 != 0
}

func isGroupWritable(bits uint32) bool {
	return bits&0o020 != 0
}

func isWorldReadable(bits uint32) bool {
	return bits&0o004 != 0
}

func isSetuid(bits uint32) bool {
	return bits&0o4000 != 0
}

func isSetgid(bits uint32) bool {
	return bits&0o2000 != 0
}

func isSticky(bits uint32) bool {
	return bits&0o1000 != 0
}
