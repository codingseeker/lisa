import os
import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple
from security_analyzer.timeline.engine import TimelineEvent


_PERSISTENCE_CHAIN_TRIGGERS = frozenset({
    "new_cron_job",
    "new_systemd_service",
    "new_startup_entry",
    "new_persistence_entry",
    "persistence_modified",
})

_EXECUTABLE_TRIGGERS = frozenset({
    "new_executable",
    "new_suid_sgid_binary",
})

_ESCALATION_TRIGGERS = frozenset({
    "permission_escalation",
})


@dataclass
class CorrelationChain:
    chain_id: str
    title: str
    severity: str
    description: str
    events: List[TimelineEvent] = field(default_factory=list)
    executor: Optional[TimelineEvent] = None
    references: List[TimelineEvent] = field(default_factory=list)

    def format_report(self) -> str:
        lines = [
            f"[{self.severity}] {self.title}",
            f"  {self.description}",
        ]
        if self.executor:
            lines.append(f"  Executable:    {self.executor.path}")
        for ref in self.references:
            lines.append(f"  Referenced By: {ref.path}")
        if not self.executor and not self.references:
            for ev in self.events:
                lines.append(f"  Event: {ev.format_line()}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "executor": self.executor.to_dict() if self.executor else None,
            "references": [r.to_dict() for r in self.references],
            "events": [e.to_dict() for e in self.events],
        }


def _read_safe(path: str, max_bytes: int = 512 * 1024) -> str:
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read(max_bytes)
    except OSError:
        return ""


def _basename_no_ext(path: str) -> str:
    return os.path.splitext(os.path.basename(path))[0]


def _paths_cross_reference(exec_path: str, ref_content: str) -> bool:
    name = os.path.basename(exec_path)
    stem = _basename_no_ext(exec_path)
    full = os.path.abspath(exec_path)
    return (
        full in ref_content
        or name in ref_content
        or (len(stem) > 2 and stem in ref_content)
    )


class CorrelationEngine:
    def __init__(self, events: List[TimelineEvent]):
        self._events = events
        self._chains: List[CorrelationChain] = []
        self._chain_counter = 0

    def _next_id(self, prefix: str = "CHAIN") -> str:
        self._chain_counter += 1
        return f"{prefix}-{self._chain_counter:03d}"

    def correlate(self) -> List[CorrelationChain]:
        self._chains = []
        self._detect_persistence_chains()
        self._detect_exec_then_escalation()
        self._detect_multi_persistence()
        self._detect_tmp_exec_chains()
        return list(self._chains)

    def _detect_persistence_chains(self) -> None:
        exec_events = [e for e in self._events if e.event_type in _EXECUTABLE_TRIGGERS]
        persist_events = [e for e in self._events if e.event_type in _PERSISTENCE_CHAIN_TRIGGERS]

        matched_exec: set = set()
        matched_persist: set = set()

        for pe in persist_events:
            content = _read_safe(pe.path)
            for xe in exec_events:
                if _paths_cross_reference(xe.path, content):
                    chain = CorrelationChain(
                        chain_id=self._next_id("PERSIST"),
                        title="Persistence Chain Detected",
                        severity="CRITICAL",
                        description=(
                            f"A newly created executable is directly referenced by a persistence mechanism. "
                            f"This is a strong indicator of an established backdoor or malware install."
                        ),
                        events=[xe, pe],
                        executor=xe,
                        references=[pe],
                    )
                    self._chains.append(chain)
                    matched_exec.add(id(xe))
                    matched_persist.add(id(pe))

    def _detect_exec_then_escalation(self) -> None:
        exec_events = [e for e in self._events if e.event_type in _EXECUTABLE_TRIGGERS]
        escalation_events = [e for e in self._events if e.event_type in _ESCALATION_TRIGGERS]

        for xe in exec_events:
            for ee in escalation_events:
                if ee.path == xe.path and ee.timestamp >= xe.timestamp:
                    chain = CorrelationChain(
                        chain_id=self._next_id("ESCALATE"),
                        title="Executable Created Then Permission Escalated",
                        severity="HIGH",
                        description=(
                            f"A file was created and subsequently had its permissions escalated. "
                            f"This pattern is consistent with staging a payload and then activating it."
                        ),
                        events=[xe, ee],
                        executor=xe,
                        references=[ee],
                    )
                    self._chains.append(chain)

    def _detect_multi_persistence(self) -> None:
        persist_events = [e for e in self._events if e.event_type in _PERSISTENCE_CHAIN_TRIGGERS]
        if len(persist_events) < 2:
            return

        type_groups: Dict[str, List[TimelineEvent]] = {}
        for pe in persist_events:
            type_groups.setdefault(pe.event_type, []).append(pe)

        distinct_types = [t for t, evs in type_groups.items() if evs]
        if len(distinct_types) >= 2:
            all_events = [e for evs in type_groups.values() for e in evs]
            chain = CorrelationChain(
                chain_id=self._next_id("MULTI"),
                title="Multiple Persistence Mechanisms Established",
                severity="CRITICAL",
                description=(
                    f"Multiple distinct persistence mechanisms were detected "
                    f"({', '.join(distinct_types)}). Attackers use redundant persistence "
                    f"to survive reboots and partial remediation."
                ),
                events=sorted(all_events, key=lambda e: e.timestamp),
                executor=None,
                references=sorted(all_events, key=lambda e: e.timestamp),
            )
            self._chains.append(chain)

    def _detect_tmp_exec_chains(self) -> None:
        tmp_prefixes = ("/tmp/", "/var/tmp/", "/dev/shm/")

        tmp_executables = [
            e for e in self._events
            if e.event_type in _EXECUTABLE_TRIGGERS
            and any(e.path.startswith(p) for p in tmp_prefixes)
        ]

        for xe in tmp_executables:
            persist_refs = [
                e for e in self._events
                if e.event_type in _PERSISTENCE_CHAIN_TRIGGERS
                and _paths_cross_reference(xe.path, _read_safe(e.path))
            ]
            chain = CorrelationChain(
                chain_id=self._next_id("TMP"),
                title="Executable in Temporary Directory",
                severity="HIGH" if not persist_refs else "CRITICAL",
                description=(
                    f"An executable was created in a temporary directory ({xe.path}). "
                    + (
                        f"It is referenced by {len(persist_refs)} persistence mechanism(s), "
                        f"indicating active deployment."
                        if persist_refs
                        else "Executables in /tmp are a common indicator of malware staging."
                    )
                ),
                events=[xe] + persist_refs,
                executor=xe,
                references=persist_refs,
            )
            self._chains.append(chain)

    def render(self, chains: Optional[List[CorrelationChain]] = None) -> str:
        if chains is None:
            chains = self.correlate()
        if not chains:
            return "(no correlated attack chains detected)"
        return "\n\n".join(c.format_report() for c in chains)
