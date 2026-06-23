import os
import stat
import time
import datetime
from dataclasses import dataclass, field
from typing import List, Optional, Set


_CRON_PATHS = (
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
    "/var/spool/cron/crontabs",
)

_SYSTEMD_PATHS = (
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/run/systemd/system",
    "/home",
)

_PERSISTENCE_PATHS = (
    "/etc/rc.local",
    "/etc/init.d",
    "/etc/profile",
    "/etc/profile.d",
    "/etc/environment",
    "/etc/bash.bashrc",
    "/home",
    "/root",
    "/etc/xdg/autostart",
)

_PERSISTENCE_FILENAMES = frozenset({
    ".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile",
    ".bash_logout", ".xsessionrc", ".xinitrc", ".xprofile",
    "rc.local",
})

_STARTUP_PATH_SEGMENTS = ("autostart", "xdg/autostart", ".config/autostart")

_SUID_BIT = stat.S_ISUID
_SGID_BIT = stat.S_ISGID

_PERSISTENCE_PATH_SEGMENTS = (
    "cron", "systemd", "init.d", "profile.d", "autostart",
    "rc.local", "bashrc", "environment", "xdg",
)

_EXEC_BITS = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH

_RECENCY_WINDOW = 86400 * 7


@dataclass(order=True)
class TimelineEvent:
    sort_index: float = field(init=False, repr=False)
    timestamp: float
    timestamp_iso: str
    path: str
    event_type: str
    detail: str
    category: str
    flags: Set[str] = field(default_factory=set, compare=False)

    def __post_init__(self):
        object.__setattr__(self, "sort_index", self.timestamp)

    def format_line(self) -> str:
        hhmm = datetime.datetime.fromtimestamp(self.timestamp).strftime("%H:%M")
        flag_str = f"  [{', '.join(sorted(self.flags))}]" if self.flags else ""
        return f"{hhmm}  {self.path}  {self.detail}{flag_str}"

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp_iso,
            "path": self.path,
            "event_type": self.event_type,
            "detail": self.detail,
            "category": self.category,
            "flags": sorted(self.flags),
        }


def _iso(ts: float) -> str:
    return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%dT%H:%M:%SZ")


def _stat_safe(path: str) -> Optional[os.stat_result]:
    try:
        return os.lstat(path)
    except OSError:
        return None


def _is_executable(st: os.stat_result) -> bool:
    return bool(st.st_mode & _EXEC_BITS)


def _is_regular(st: os.stat_result) -> bool:
    return stat.S_ISREG(st.st_mode)


def _is_recent(ts: float, window: int = _RECENCY_WINDOW) -> bool:
    return (time.time() - ts) <= window


def _walk_path(root: str):
    if not os.path.exists(root):
        return
    if os.path.isfile(root):
        st = _stat_safe(root)
        if st:
            yield root, st
        return
    try:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if not d.startswith(".git")]
            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                st = _stat_safe(fpath)
                if st:
                    yield fpath, st
    except PermissionError:
        pass


class TimelineEngine:
    def __init__(self, scan_paths: Optional[List[str]] = None, window_seconds: int = _RECENCY_WINDOW):
        self._window = window_seconds
        self._scan_paths = scan_paths or self._default_paths()

    @staticmethod
    def _default_paths() -> List[str]:
        paths = list(_CRON_PATHS) + list(_SYSTEMD_PATHS) + list(_PERSISTENCE_PATHS)
        paths += ["/tmp", "/var/tmp", "/dev/shm"]
        seen = []
        for p in paths:
            if p not in seen:
                seen.append(p)
        return seen

    def collect(self) -> List[TimelineEvent]:
        events: List[TimelineEvent] = []
        seen_paths: set = set()

        for root in self._scan_paths:
            for fpath, st in _walk_path(root):
                if fpath in seen_paths:
                    continue
                seen_paths.add(fpath)

                mtime = st.st_mtime
                ctime = st.st_ctime

                if not (_is_recent(mtime, self._window) or _is_recent(ctime, self._window)):
                    continue

                basename = os.path.basename(fpath)
                abs_path = os.path.abspath(fpath)

                events += self._classify(fpath, abs_path, basename, st, mtime, ctime)

        events.sort(key=lambda e: e.timestamp)
        return events

    def _classify(
        self,
        fpath: str,
        abs_path: str,
        basename: str,
        st: os.stat_result,
        mtime: float,
        ctime: float,
    ) -> List[TimelineEvent]:
        found: List[TimelineEvent] = []

        mode = st.st_mode
        is_reg = _is_regular(st)
        is_exec = _is_executable(st)
        is_suid = bool(mode & _SUID_BIT) and is_reg
        is_sgid = bool(mode & _SGID_BIT) and is_reg
        is_cron = self._is_cron_entry(abs_path, basename)
        is_service = basename.endswith(".service") or "systemd" in abs_path
        is_startup = self._is_startup_entry(abs_path, basename)
        is_persistence = self._is_persistence_entry(abs_path, basename)

        creation_ts = min(mtime, ctime)
        flags: Set[str] = set()
        if is_suid:
            flags.add("SUID")
        if is_sgid:
            flags.add("SGID")

        if _is_recent(creation_ts, self._window):
            if is_cron:
                found.append(TimelineEvent(
                    timestamp=creation_ts,
                    timestamp_iso=_iso(creation_ts),
                    path=fpath,
                    event_type="new_cron_job",
                    detail=f"new cron job: {basename}",
                    category="persistence",
                    flags=set(flags),
                ))
            elif is_service:
                found.append(TimelineEvent(
                    timestamp=creation_ts,
                    timestamp_iso=_iso(creation_ts),
                    path=fpath,
                    event_type="new_systemd_service",
                    detail=f"new systemd service: {basename}",
                    category="persistence",
                    flags=set(flags),
                ))
            elif is_startup:
                found.append(TimelineEvent(
                    timestamp=creation_ts,
                    timestamp_iso=_iso(creation_ts),
                    path=fpath,
                    event_type="new_startup_entry",
                    detail=f"new startup entry: {basename}",
                    category="persistence",
                    flags=set(flags),
                ))
            elif is_persistence:
                found.append(TimelineEvent(
                    timestamp=creation_ts,
                    timestamp_iso=_iso(creation_ts),
                    path=fpath,
                    event_type="new_persistence_entry",
                    detail=f"persistence entry created: {basename}",
                    category="persistence",
                    flags=set(flags),
                ))
            elif is_reg and (is_suid or is_sgid):
                label = "/".join(f for f in ("SUID" if is_suid else "", "SGID" if is_sgid else "") if f)
                found.append(TimelineEvent(
                    timestamp=creation_ts,
                    timestamp_iso=_iso(creation_ts),
                    path=fpath,
                    event_type="new_suid_sgid_binary",
                    detail=f"new {label} binary: {basename}",
                    category="execution",
                    flags=set(flags),
                ))
            elif is_reg and is_exec:
                found.append(TimelineEvent(
                    timestamp=creation_ts,
                    timestamp_iso=_iso(creation_ts),
                    path=fpath,
                    event_type="new_executable",
                    detail=f"new executable: {basename}",
                    category="execution",
                    flags=set(flags),
                ))
            else:
                found.append(TimelineEvent(
                    timestamp=creation_ts,
                    timestamp_iso=_iso(creation_ts),
                    path=fpath,
                    event_type="file_created",
                    detail=f"file created: {basename}",
                    category="filesystem",
                    flags=set(flags),
                ))

        if _is_recent(mtime, self._window) and mtime != creation_ts:
            if is_suid or is_sgid:
                label = "/".join(f for f in ("SUID" if is_suid else "", "SGID" if is_sgid else "") if f)
                found.append(TimelineEvent(
                    timestamp=mtime,
                    timestamp_iso=_iso(mtime),
                    path=fpath,
                    event_type="permission_escalation",
                    detail=f"{label} bit set on: {basename} (mode {oct(stat.S_IMODE(mode))})",
                    category="permissions",
                    flags=set(flags),
                ))
            elif is_exec and is_reg:
                found.append(TimelineEvent(
                    timestamp=mtime,
                    timestamp_iso=_iso(mtime),
                    path=fpath,
                    event_type="permission_escalation",
                    detail=f"executable permission added: {basename} (mode {oct(stat.S_IMODE(mode))})",
                    category="permissions",
                    flags=set(flags),
                ))
            elif is_cron or is_service or is_persistence or is_startup:
                found.append(TimelineEvent(
                    timestamp=mtime,
                    timestamp_iso=_iso(mtime),
                    path=fpath,
                    event_type="persistence_modified",
                    detail=f"persistence file modified: {basename}",
                    category="persistence",
                    flags=set(flags),
                ))
            else:
                found.append(TimelineEvent(
                    timestamp=mtime,
                    timestamp_iso=_iso(mtime),
                    path=fpath,
                    event_type="file_modified",
                    detail=f"file modified: {basename}",
                    category="filesystem",
                    flags=set(flags),
                ))

        return found

    @staticmethod
    def _is_cron_entry(abs_path: str, basename: str) -> bool:
        for cp in _CRON_PATHS:
            if abs_path.startswith(cp):
                return True
        return "cron" in abs_path

    @staticmethod
    def _is_startup_entry(abs_path: str, basename: str) -> bool:
        for seg in _STARTUP_PATH_SEGMENTS:
            if seg in abs_path:
                return True
        return basename.endswith(".desktop")

    @staticmethod
    def _is_persistence_entry(abs_path: str, basename: str) -> bool:
        if basename in _PERSISTENCE_FILENAMES:
            return True
        for seg in _PERSISTENCE_PATH_SEGMENTS:
            if seg in abs_path:
                return True
        for pp in _PERSISTENCE_PATHS:
            if abs_path.startswith(pp):
                return True
        return False

    def render(self, events: Optional[List[TimelineEvent]] = None) -> str:
        if events is None:
            events = self.collect()
        if not events:
            return "(no recent activity detected within the scan window)"
        lines = []
        for ev in events:
            lines.append(ev.format_line())
        return "\n".join(lines)

    def render_grouped(self, events: Optional[List[TimelineEvent]] = None) -> str:
        if events is None:
            events = self.collect()
        if not events:
            return "(no recent activity detected within the scan window)"

        category_order = ["filesystem", "execution", "permissions", "persistence"]
        groups: dict = {cat: [] for cat in category_order}
        for ev in events:
            cat = ev.category if ev.category in groups else "filesystem"
            groups[cat].append(ev)

        sections = []
        labels = {
            "filesystem": "FILE ACTIVITY",
            "execution": "EXECUTABLE CREATION",
            "permissions": "PERMISSION CHANGES",
            "persistence": "PERSISTENCE (CRON / SYSTEMD / ENTRIES)",
        }
        for cat in category_order:
            if not groups[cat]:
                continue
            sections.append(f"--- {labels[cat]} ---")
            for ev in groups[cat]:
                sections.append(ev.format_line())
        return "\n".join(sections)
