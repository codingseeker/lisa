import re
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Any, Dict


@dataclass
class Rule:
    rule_id: str
    name: str
    description: str
    severity: str
    mitre_id: str
    condition: Callable[[Any], bool]
    tags: List[str] = field(default_factory=list)

    def matches(self, event: Any) -> bool:
        try:
            return self.condition(event)
        except Exception:
            return False


@dataclass
class RuleMatch:
    rule: Rule
    event: Any
    context: Dict[str, str] = field(default_factory=dict)

    def format_line(self) -> str:
        path = getattr(self.event, "path", str(self.event))
        return (
            f"[{self.rule.severity}] {self.rule.rule_id} {self.rule.name}\n"
            f"  Path      : {path}\n"
            f"  MITRE     : {self.rule.mitre_id}\n"
            f"  Detail    : {self.rule.description}"
        )

    def to_dict(self) -> dict:
        event_dict = (
            self.event.to_dict()
            if hasattr(self.event, "to_dict")
            else {"raw": str(self.event)}
        )
        return {
            "rule_id": self.rule.rule_id,
            "name": self.rule.name,
            "severity": self.rule.severity,
            "mitre_id": self.rule.mitre_id,
            "description": self.rule.description,
            "tags": self.rule.tags,
            "event": event_dict,
            "context": self.context,
        }


def _has(event: Any, attr: str, value: str) -> bool:
    return value in (getattr(event, attr, "") or "")


def _event_type_is(event: Any, *types: str) -> bool:
    return getattr(event, "event_type", None) in types


def _path_matches(event: Any, pattern: str) -> bool:
    path = getattr(event, "path", "")
    return bool(re.search(pattern, path))


def _has_flag(event: Any, flag: str) -> bool:
    return flag in getattr(event, "flags", set())


BUILTIN_RULES: List[Rule] = [
    Rule(
        rule_id="R-001",
        name="New Executable in Temporary Directory",
        description="An executable was created in /tmp, /var/tmp, or /dev/shm.",
        severity="HIGH",
        mitre_id="T1059",
        tags=["execution", "staging"],
        condition=lambda e: (
            _event_type_is(e, "new_executable")
            and _path_matches(e, r"^(/tmp|/var/tmp|/dev/shm)/")
        ),
    ),
    Rule(
        rule_id="R-002",
        name="New Cron Job Added",
        description="A new scheduled task was registered via cron.",
        severity="HIGH",
        mitre_id="T1053.003",
        tags=["persistence", "scheduled-task"],
        condition=lambda e: _event_type_is(e, "new_cron_job"),
    ),
    Rule(
        rule_id="R-003",
        name="New Systemd Service Installed",
        description="A new systemd service unit file was created.",
        severity="HIGH",
        mitre_id="T1543.002",
        tags=["persistence", "systemd"],
        condition=lambda e: _event_type_is(e, "new_systemd_service"),
    ),
    Rule(
        rule_id="R-004",
        name="SUID Binary Created",
        description="A file with the SUID bit set was created or modified.",
        severity="CRITICAL",
        mitre_id="T1548.001",
        tags=["privilege-escalation", "suid"],
        condition=lambda e: _has_flag(e, "SUID"),
    ),
    Rule(
        rule_id="R-005",
        name="SGID Binary Created",
        description="A file with the SGID bit set was created or modified.",
        severity="HIGH",
        mitre_id="T1548.001",
        tags=["privilege-escalation", "sgid"],
        condition=lambda e: _has_flag(e, "SGID"),
    ),
    Rule(
        rule_id="R-006",
        name="Permission Escalation",
        description="Execute or setuid/setgid permissions were added to a file.",
        severity="HIGH",
        mitre_id="T1222.002",
        tags=["defense-evasion", "permissions"],
        condition=lambda e: _event_type_is(e, "permission_escalation"),
    ),
    Rule(
        rule_id="R-007",
        name="New Startup Entry",
        description="A new autostart or XDG startup entry was created.",
        severity="HIGH",
        mitre_id="T1547.001",
        tags=["persistence", "startup"],
        condition=lambda e: _event_type_is(e, "new_startup_entry"),
    ),
    Rule(
        rule_id="R-008",
        name="Shell RC File Modified",
        description="A shell initialization file (.bashrc, .profile, etc.) was modified.",
        severity="MEDIUM",
        mitre_id="T1546.004",
        tags=["persistence", "shell"],
        condition=lambda e: (
            _event_type_is(e, "new_persistence_entry", "persistence_modified")
            and _path_matches(e, r"\.(bashrc|bash_profile|profile|zshrc|zprofile|xinitrc|xsessionrc)$")
        ),
    ),
    Rule(
        rule_id="R-009",
        name="Executable Created in Home Directory",
        description="A new executable was created directly in a user home directory.",
        severity="MEDIUM",
        mitre_id="T1059",
        tags=["execution", "home"],
        condition=lambda e: (
            _event_type_is(e, "new_executable")
            and _path_matches(e, r"^/home/[^/]+/[^/]+$")
        ),
    ),
    Rule(
        rule_id="R-010",
        name="Script in /dev/shm",
        description="A file was written to /dev/shm, a memory-backed filesystem used for fileless staging.",
        severity="CRITICAL",
        mitre_id="T1059",
        tags=["execution", "fileless"],
        condition=lambda e: _path_matches(e, r"^/dev/shm/"),
    ),
]


class RuleEngine:
    def __init__(self, rules: Optional[List[Rule]] = None):
        self._rules: List[Rule] = list(rules) if rules else list(BUILTIN_RULES)

    def add_rule(self, rule: Rule) -> None:
        self._rules.append(rule)

    def add_rules(self, rules: List[Rule]) -> None:
        self._rules.extend(rules)

    @property
    def rules(self) -> List[Rule]:
        return list(self._rules)

    def evaluate(self, events: List[Any]) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        for event in events:
            for rule in self._rules:
                if rule.matches(event):
                    matches.append(RuleMatch(rule=rule, event=event))
        return matches

    def evaluate_one(self, event: Any) -> List[RuleMatch]:
        return [
            RuleMatch(rule=rule, event=event)
            for rule in self._rules
            if rule.matches(event)
        ]

    def render(self, matches: List[RuleMatch]) -> str:
        if not matches:
            return "(no rule matches)"
        return "\n\n".join(m.format_line() for m in matches)

    def summary(self, matches: List[RuleMatch]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for m in matches:
            counts[m.rule.severity] = counts.get(m.rule.severity, 0) + 1
        return counts
