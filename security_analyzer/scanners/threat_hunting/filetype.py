import os
import stat
from typing import List
from security_analyzer.scanners.base import BaseScanner
from security_analyzer.core.models import Finding
from security_analyzer.core.severity import Severity


_USER_SENSITIVE_DIRS = frozenset({
    "Downloads", "Desktop", "Documents", "tmp", "Temp",
})

_IMAGE_EXTENSIONS = frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".webp", ".ico",
})

_DOCUMENT_EXTENSIONS = frozenset({
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
})

_TEXT_EXTENSIONS = frozenset({
    ".txt", ".log", ".conf", ".cfg", ".ini", ".md", ".csv",
})

_SCRIPT_EXTENSIONS = frozenset({
    ".sh", ".bash", ".py", ".pl", ".rb", ".php", ".js",
})


def _in_sensitive_dir(abs_path: str) -> bool:
    parts = abs_path.replace("\\", "/").split("/")
    return any(part in _USER_SENSITIVE_DIRS for part in parts)


def _read_header(filepath: str, n: int = 256) -> bytes:
    try:
        with open(filepath, "rb") as f:
            return f.read(n)
    except OSError:
        return b""


class FileTypeScanner(BaseScanner):
    def scan_item(self, filepath: str, file_stat: os.stat_result) -> List[Finding]:
        findings = []
        if not stat.S_ISREG(file_stat.st_mode):
            return findings

        abs_path = os.path.abspath(filepath)
        filename = os.path.basename(abs_path)
        ext = os.path.splitext(filename)[1].lower()

        header = _read_header(filepath)
        if not header:
            return findings

        file_type, perm_oct, perm_str, owner, group, size, mtime = self.get_metadata(filepath, file_stat)
        sha256 = self.calculate_sha256(filepath, file_type)

        is_elf = header[:4] == b"\x7fELF"
        is_script = header[:2] == b"#!"

        if is_elf:
            if _in_sensitive_dir(abs_path):
                findings.append(Finding(
                    path=filepath, rule_id="SEC-033", rule_name="Unexpected ELF in User Folder",
                    description=f"ELF executable detected in user-accessible folder: {filepath}.",
                    severity=Severity.HIGH, file_type=file_type, permissions_octal=perm_oct,
                    permissions_str=perm_str, owner=owner, group=group, size_bytes=size,
                    modified_time=mtime, sha256=sha256,
                ))

            if ext in _DOCUMENT_EXTENSIONS:
                findings.append(Finding(
                    path=filepath, rule_id="SEC-022", rule_name="Executable Masquerading as Document",
                    description=f"ELF binary using document extension ({ext}): {filepath}.",
                    severity=Severity.CRITICAL, file_type=file_type, permissions_octal=perm_oct,
                    permissions_str=perm_str, owner=owner, group=group, size_bytes=size,
                    modified_time=mtime, sha256=sha256,
                ))
            elif ext in _IMAGE_EXTENSIONS:
                findings.append(Finding(
                    path=filepath, rule_id="SEC-034", rule_name="Executable Masquerading as Image",
                    description=f"ELF binary using image extension ({ext}): {filepath}.",
                    severity=Severity.CRITICAL, file_type=file_type, permissions_octal=perm_oct,
                    permissions_str=perm_str, owner=owner, group=group, size_bytes=size,
                    modified_time=mtime, sha256=sha256,
                ))
            elif ext in _TEXT_EXTENSIONS:
                findings.append(Finding(
                    path=filepath, rule_id="SEC-035", rule_name="Executable Masquerading as Text",
                    description=f"ELF binary using text extension ({ext}): {filepath}.",
                    severity=Severity.CRITICAL, file_type=file_type, permissions_octal=perm_oct,
                    permissions_str=perm_str, owner=owner, group=group, size_bytes=size,
                    modified_time=mtime, sha256=sha256,
                ))

        elif is_script:
            if ext in _DOCUMENT_EXTENSIONS:
                findings.append(Finding(
                    path=filepath, rule_id="SEC-040", rule_name="Script Masquerading as Document",
                    description=f"Executable script using document extension ({ext}): {filepath}.",
                    severity=Severity.CRITICAL, file_type=file_type, permissions_octal=perm_oct,
                    permissions_str=perm_str, owner=owner, group=group, size_bytes=size,
                    modified_time=mtime, sha256=sha256,
                ))
            elif ext in _IMAGE_EXTENSIONS:
                findings.append(Finding(
                    path=filepath, rule_id="SEC-034", rule_name="Script Masquerading as Image",
                    description=f"Executable script using image extension ({ext}): {filepath}.",
                    severity=Severity.CRITICAL, file_type=file_type, permissions_octal=perm_oct,
                    permissions_str=perm_str, owner=owner, group=group, size_bytes=size,
                    modified_time=mtime, sha256=sha256,
                ))
            elif ext in _TEXT_EXTENSIONS:
                findings.append(Finding(
                    path=filepath, rule_id="SEC-036", rule_name="Script Masquerading as Text",
                    description=f"Executable script using text extension ({ext}): {filepath}.",
                    severity=Severity.HIGH, file_type=file_type, permissions_octal=perm_oct,
                    permissions_str=perm_str, owner=owner, group=group, size_bytes=size,
                    modified_time=mtime, sha256=sha256,
                ))

            if _in_sensitive_dir(abs_path) and ext not in _SCRIPT_EXTENSIONS:
                findings.append(Finding(
                    path=filepath, rule_id="SEC-041", rule_name="Hidden Script in User Folder",
                    description=f"Executable script with non-script extension found in user folder: {filepath}.",
                    severity=Severity.HIGH, file_type=file_type, permissions_octal=perm_oct,
                    permissions_str=perm_str, owner=owner, group=group, size_bytes=size,
                    modified_time=mtime, sha256=sha256,
                ))

        return findings
