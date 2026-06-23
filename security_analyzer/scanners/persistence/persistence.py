import os
import stat
import time
import re
from typing import List
from security_analyzer.scanners.base import BaseScanner
from security_analyzer.core.models import Finding
from security_analyzer.core.severity import Severity
from security_analyzer.baseline.integrity import BaselineManager

class PersistenceScanner(BaseScanner):
    def scan_item(self, filepath: str, file_stat: os.stat_result) -> List[Finding]:
        findings = []
        abs_path = os.path.abspath(filepath)
        filename = os.path.basename(abs_path)
        
        is_persistence = False
        if filename in ["crontab", "rc.local", "profile", ".bashrc", ".profile", ".bash_profile"]:
            is_persistence = True
        elif any(pat in abs_path for pat in ["cron", "rc.local", "profile", "systemd", "bashrc", "init.d", ".config/autostart"]):
            is_persistence = True
        elif filename.endswith(".service"):
            is_persistence = True

        if not is_persistence:
            return findings

        file_type, perm_oct, perm_str, owner, group, size, mtime = self.get_metadata(filepath, file_stat)

        if time.time() - file_stat.st_mtime < 86400:
            findings.append(Finding(
                path=filepath, rule_id="SEC-016", rule_name="Recently Modified Persistence File",
                description=f"Persistence file {filepath} was modified recently (within 24 hours).",
                severity=Severity.HIGH, file_type=file_type, permissions_octal=perm_oct,
                permissions_str=perm_str, owner=owner, group=group, size_bytes=size, modified_time=mtime,
                sha256=self.calculate_sha256(filepath, file_type)
            ))

        if self.config.baseline_path and os.path.exists(self.config.baseline_path):
            baseline_files = BaselineManager.load_baseline(self.config.baseline_path)
            if baseline_files and abs_path not in baseline_files:
                findings.append(Finding(
                    path=filepath, rule_id="SEC-013", rule_name="Newly Created Persistence Entry",
                    description=f"Persistence file {filepath} is not present in the baseline snapshot.",
                    severity=Severity.HIGH, file_type=file_type, permissions_octal=perm_oct,
                    permissions_str=perm_str, owner=owner, group=group, size_bytes=size, modified_time=mtime,
                    sha256=self.calculate_sha256(filepath, file_type)
                ))

        if filename.endswith(".service") or "systemd" in abs_path:
            if file_stat.st_uid >= 1000 and owner != "nobody":
                desc = f"Systemd service file {filepath} is owned by user '{owner}' (UID {file_stat.st_uid}). Service files should be owned by root."
                findings.append(Finding(
                    path=filepath, rule_id="SEC-014", rule_name="Suspicious User-owned Service",
                    description=desc, severity=Severity.HIGH, file_type=file_type, permissions_octal=perm_oct,
                    permissions_str=perm_str, owner=owner, group=group, size_bytes=size, modified_time=mtime,
                    sha256=self.calculate_sha256(filepath, file_type)
                ))

        if stat.S_ISREG(file_stat.st_mode):
            try:
                with open(filepath, "r", errors="ignore") as f:
                    content = f.read(1024 * 1024)

                if "/tmp" in content or "/dev/shm" in content or "/var/tmp" in content:
                    findings.append(Finding(
                        path=filepath, rule_id="SEC-012", rule_name="Startup Entry Points to Temporary Space",
                        description=f"Persistence entry {filepath} references temporary directory (/tmp, /var/tmp or /dev/shm).",
                        severity=Severity.HIGH, file_type=file_type, permissions_octal=perm_oct,
                        permissions_str=perm_str, owner=owner, group=group, size_bytes=size, modified_time=mtime,
                        sha256=self.calculate_sha256(filepath, file_type)
                    ))

                susp_patterns = [
                    r"\bsh\s+-i", r"\bbash\s+-i", r"\bpython\d*\s+-c", r"nc\s+-[e|c]", r"nc\s+\d", r"curl\s+.*\bsh\b",
                    r"wget\s+.*\bsh\b", r"base64\s+-(?:d|-decode)", r"\beval\b", r"\bexec\b"
                ]
                matched = []
                for pat in susp_patterns:
                    if re.search(pat, content, re.IGNORECASE):
                        matched.append(pat)

                if matched:
                    findings.append(Finding(
                        path=filepath, rule_id="SEC-015", rule_name="Suspicious Command Execution in Persistence",
                        description=f"Persistence entry {filepath} contains suspicious command execution patterns: {', '.join(matched)}.",
                        severity=Severity.CRITICAL, file_type=file_type, permissions_octal=perm_oct,
                        permissions_str=perm_str, owner=owner, group=group, size_bytes=size, modified_time=mtime,
                        sha256=self.calculate_sha256(filepath, file_type)
                    ))

                if filename.endswith(".service") or "systemd" in abs_path:
                    user_match = re.search(r"^\s*User\s*=\s*(\w+)", content, re.MULTILINE | re.IGNORECASE)
                    if user_match:
                        svc_user = user_match.group(1)
                        if svc_user != "root" and svc_user != "systemd-network":
                            import pwd
                            try:
                                p_ent = pwd.getpwnam(svc_user)
                                if p_ent.pw_uid >= 1000 and svc_user != "nobody":
                                    findings.append(Finding(
                                        path=filepath, rule_id="SEC-014", rule_name="Suspicious User-owned Service",
                                        description=f"Systemd service file {filepath} runs as non-system user '{svc_user}' (UID {p_ent.pw_uid}).",
                                        severity=Severity.MEDIUM, file_type=file_type, permissions_octal=perm_oct,
                                        permissions_str=perm_str, owner=owner, group=group, size_bytes=size, modified_time=mtime,
                                        sha256=self.calculate_sha256(filepath, file_type)
                                    ))
                            except KeyError:
                                pass
            except Exception:
                pass

        return findings
