from typing import Dict, List, Optional


TECHNIQUES: Dict[str, Dict[str, str]] = {
    "T1059":      {"name": "Command and Scripting Interpreter",        "tactic": "Execution"},
    "T1059.003":  {"name": "Windows Command Shell",                    "tactic": "Execution"},
    "T1053":      {"name": "Scheduled Task/Job",                       "tactic": "Persistence"},
    "T1053.003":  {"name": "Cron",                                     "tactic": "Persistence"},
    "T1053.006":  {"name": "Systemd Timers",                           "tactic": "Persistence"},
    "T1543":      {"name": "Create or Modify System Process",          "tactic": "Persistence"},
    "T1543.002":  {"name": "Systemd Service",                          "tactic": "Persistence"},
    "T1546":      {"name": "Event Triggered Execution",                "tactic": "Persistence"},
    "T1546.004":  {"name": "Unix Shell Configuration Modification",    "tactic": "Persistence"},
    "T1547":      {"name": "Boot or Logon Autostart Execution",        "tactic": "Persistence"},
    "T1547.001":  {"name": "Registry Run Keys / Startup Folder",       "tactic": "Persistence"},
    "T1548":      {"name": "Abuse Elevation Control Mechanism",        "tactic": "Privilege Escalation"},
    "T1548.001":  {"name": "Setuid and Setgid",                        "tactic": "Privilege Escalation"},
    "T1222":      {"name": "File and Directory Permissions Modification","tactic": "Defense Evasion"},
    "T1222.002":  {"name": "Linux and Mac File and Directory Permissions Modification", "tactic": "Defense Evasion"},
    "T1036":      {"name": "Masquerading",                             "tactic": "Defense Evasion"},
    "T1036.005":  {"name": "Match Legitimate Name or Location",        "tactic": "Defense Evasion"},
    "T1027":      {"name": "Obfuscated Files or Information",          "tactic": "Defense Evasion"},
    "T1070":      {"name": "Indicator Removal",                        "tactic": "Defense Evasion"},
    "T1105":      {"name": "Ingress Tool Transfer",                    "tactic": "Command and Control"},
    "T1071":      {"name": "Application Layer Protocol",               "tactic": "Command and Control"},
    "T1078":      {"name": "Valid Accounts",                           "tactic": "Persistence"},
    "T1098":      {"name": "Account Manipulation",                     "tactic": "Persistence"},
    "T1003":      {"name": "OS Credential Dumping",                    "tactic": "Credential Access"},
    "T1552":      {"name": "Unsecured Credentials",                    "tactic": "Credential Access"},
    "T1082":      {"name": "System Information Discovery",             "tactic": "Discovery"},
    "T1057":      {"name": "Process Discovery",                        "tactic": "Discovery"},
    "T1083":      {"name": "File and Directory Discovery",             "tactic": "Discovery"},
    "T1049":      {"name": "System Network Connections Discovery",     "tactic": "Discovery"},
    "T1041":      {"name": "Exfiltration Over C2 Channel",             "tactic": "Exfiltration"},
    "T1486":      {"name": "Data Encrypted for Impact",                "tactic": "Impact"},
    "T1489":      {"name": "Service Stop",                             "tactic": "Impact"},
}

_EVENT_TYPE_TO_MITRE: Dict[str, List[str]] = {
    "new_executable":       ["T1059"],
    "new_cron_job":         ["T1053.003"],
    "new_systemd_service":  ["T1543.002", "T1053.006"],
    "new_startup_entry":    ["T1547.001"],
    "new_persistence_entry":["T1546.004"],
    "persistence_modified": ["T1546.004"],
    "permission_escalation":["T1222.002", "T1548.001"],
    "new_suid_sgid_binary": ["T1548.001"],
    "file_created":         [],
    "file_modified":        [],
}

_RULE_ID_TO_MITRE: Dict[str, str] = {
    "R-001": "T1059",
    "R-002": "T1053.003",
    "R-003": "T1543.002",
    "R-004": "T1548.001",
    "R-005": "T1548.001",
    "R-006": "T1222.002",
    "R-007": "T1547.001",
    "R-008": "T1546.004",
    "R-009": "T1059",
    "R-010": "T1059",
    "SEC-012": "T1059",
    "SEC-013": "T1546.004",
    "SEC-014": "T1543.002",
    "SEC-015": "T1059",
    "SEC-016": "T1546.004",
    "SEC-022": "T1036.005",
    "SEC-033": "T1036.005",
    "SEC-034": "T1036.005",
    "SEC-035": "T1036.005",
    "SEC-036": "T1036.005",
    "SEC-040": "T1036.005",
    "SEC-041": "T1036.005",
}


class MitreMapper:
    def technique(self, technique_id: str) -> Optional[Dict[str, str]]:
        return TECHNIQUES.get(technique_id)

    def name(self, technique_id: str) -> str:
        entry = TECHNIQUES.get(technique_id)
        return entry["name"] if entry else technique_id

    def tactic(self, technique_id: str) -> str:
        entry = TECHNIQUES.get(technique_id)
        return entry["tactic"] if entry else "Unknown"

    def from_event_type(self, event_type: str) -> List[str]:
        return list(_EVENT_TYPE_TO_MITRE.get(event_type, []))

    def from_rule_id(self, rule_id: str) -> Optional[str]:
        return _RULE_ID_TO_MITRE.get(rule_id)

    def annotate_event(self, event: object) -> Dict[str, object]:
        event_type = getattr(event, "event_type", "")
        technique_ids = self.from_event_type(event_type)
        techniques = [
            {"id": tid, "name": self.name(tid), "tactic": self.tactic(tid)}
            for tid in technique_ids
        ]
        result = (
            event.to_dict()
            if hasattr(event, "to_dict")
            else {"raw": str(event)}
        )
        result["mitre"] = techniques
        return result

    def annotate_match(self, match: object) -> Dict[str, object]:
        rule = getattr(match, "rule", None)
        mitre_id = getattr(rule, "mitre_id", None) if rule else None
        result = (
            match.to_dict()
            if hasattr(match, "to_dict")
            else {"raw": str(match)}
        )
        if mitre_id:
            result["mitre"] = {
                "id": mitre_id,
                "name": self.name(mitre_id),
                "tactic": self.tactic(mitre_id),
            }
        return result

    def render_technique(self, technique_id: str) -> str:
        entry = TECHNIQUES.get(technique_id)
        if not entry:
            return f"{technique_id} (unknown)"
        return f"{technique_id}: {entry['name']} [{entry['tactic']}]"

    def all_techniques(self) -> List[Dict[str, str]]:
        return [
            {"id": tid, "name": v["name"], "tactic": v["tactic"]}
            for tid, v in TECHNIQUES.items()
        ]
