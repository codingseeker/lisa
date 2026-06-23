# Linux Forensics & Security Analyzer

A lightweight Host-Based Security Auditing, Integrity Monitoring, and Forensic Analysis Framework for Linux systems.

The project is designed to identify security misconfigurations, privilege escalation opportunities, persistence mechanisms, suspicious executables, and system integrity changes through a modular scanning architecture built entirely with the Python Standard Library.



## Overview

Linux Forensics & Security Analyzer is a defensive security tool inspired by host-based intrusion detection systems and integrity monitoring solutions.

The framework performs security auditing, baseline comparison, forensic timeline generation, and threat-hunting activities across Linux hosts while maintaining minimal dependencies and low operational overhead.

The project focuses on practical security visibility rather than enterprise-scale telemetry collection.



## Objectives

* Identify insecure file permissions and ownership anomalies.
* Detect privilege escalation opportunities.
* Audit sensitive Linux configurations.
* Detect persistence mechanisms.
* Monitor system integrity through baselines.
* Generate forensic timelines.
* Correlate security findings into attack chains.
* Provide risk-based host assessments.
* Produce machine-readable and analyst-friendly reports.



## Core Capabilities

### Hardening Audits

Detect:

* World-writable files
* World-writable directories
* 777 permissions
* Insecure SSH key permissions
* Misconfigured sudoers files
* Weak permissions on critical system files

### Privilege Escalation Detection

Identify:

* SUID binaries
* SGID binaries
* GTFOBins matches
* Newly introduced SUID binaries
* Dangerous privilege escalation paths

### Ownership Analysis

Audit:

* Orphaned UID ownership
* Orphaned GID ownership
* Unexpected ownership within critical system directories

### Persistence Detection

Inspect:

* Cron jobs
* User crontabs
* Systemd services
* Startup scripts
* Shell initialization files

Detect:

* New persistence mechanisms
* Temporary-directory execution
* Suspicious startup commands
* Unauthorized service creation

### Threat Hunting

Identify:

* Hidden executables
* Recently modified executables
* Unexpected ELF binaries
* Executables located in suspicious directories
* File-type masquerading

### Integrity Monitoring

Track:

* File hashes
* Permissions
* Ownership
* Size changes
* Newly created files
* Deleted files
* Permission escalation events



## Architecture

text
security_analyzer/
│
├── core/
│   ├── scan_engine.py
│   ├── timeline_engine.py
│   ├── correlation_engine.py
│   ├── risk_engine.py
│   └── models.py
│
├── scanners/
│   ├── hardening/
│   ├── privilege_escalation/
│   ├── persistence/
│   └── threat_hunting/
│
├── baseline/
│
├── reporting/
│
├── alerts/
│
└── utils/

## Scanner Modules

### Permission Scanner

Detects:

* World-writable files
* World-writable directories
* 777 permissions
* Executables in:

  * /tmp
  * /var/tmp
  * /dev/shm

### SUID / SGID Scanner

Detects:

* SUID binaries
* SGID binaries
* GTFOBins entries
* Newly added SUID binaries

### Ownership Analyzer

Detects:

* Orphaned users
* Orphaned groups
* Unauthorized ownership in critical system paths

### Sensitive File Checker

Audits:

* /etc/shadow
* /etc/gshadow
* /etc/passwd
* /etc/group
* /etc/sudoers
* ~/.ssh
* authorized_keys
* Private SSH keys

### Persistence Scanner

Audits:

* /etc/crontab
* /etc/cron.*
* /etc/rc.local
* ~/.bashrc
* ~/.profile
* ~/.bash_profile
* ~/.config/autostart
* Systemd service directories

### Scheduled Task Scanner

Detects:

* Suspicious cron jobs
* Temporary-directory execution
* World-writable scripts
* Recently modified scheduled tasks

### File Type Scanner

Validates:

* ELF
* PDF
* PNG
* JPEG
* GIF
* ZIP

Detects:

* Extension mismatches
* Executable masquerading

### Threat Hunting Scanner

Detects:

* Hidden executables
* New executables
* Unexpected binaries
* Recently modified executables



## Baseline & Integrity Monitoring

The framework can create and compare forensic baselines.

Tracked Attributes:

* SHA256 hash
* Permissions
* Owner
* Group
* Size
* File type
* Modification timestamp

Detected Changes:

* New files
* Deleted files
* Modified files
* New executable permissions
* New SUID permissions
* New persistence entries
* New cron jobs



## Timeline Engine

Generates chronological forensic timelines.

Example:

text
14:22 /tmp/update.sh created
14:25 executable permission added
14:27 cron.daily/update created
14:29 systemd service installed




## Correlation Engine

Correlates related findings to identify attack chains.

Example:

text
CRITICAL

Persistence Chain Detected

Executable:
    /tmp/update.sh

Referenced By:
    /etc/cron.daily/update

Installed By:
    malicious.service


## Risk Scoring

Severity Weights:

| Severity | Weight |
| -------- | ------ |
| Critical | 50     |
| High     | 20     |
| Medium   | 5      |
| Low      | 1      |

Host Risk Levels:

| Score  | Classification |
| ------ | -------------- |
| 0-20   | Healthy        |
| 21-50  | Moderate       |
| 51-100 | High           |
| 100+   | Critical       |


## Reporting

Supported Formats:

* CLI Summary
* JSON Reports
* CSV Reports
* HTML Reports

Reports include:

* Findings
* Risk Score
* Timeline
* Correlated Findings
* Scan Metrics
* Severity Breakdown


## Usage

Scan a target:

bash
python3 main.py /target/path


Generate reports:

bash
python3 main.py /target/path \
--json report.json \
--csv report.csv \
--html report.html


Create a baseline:

bash
python3 main.py /target/path \
--save-baseline baseline.json


Compare against a baseline:
bash
python3 main.py /target/path \
--baseline baseline.json


---

## Testing

Generate a vulnerable sandbox:

bash
python3 test_env.py


Run scans:

bash
python3 main.py ./test_lab


Run unit tests:

bash
python3 run_tests.py



## Target Platforms

Supported Linux distributions:

* Fedora
* Ubuntu
* Debian
* Kali Linux
* Metasploitable 2


## Project Scope

This project is intended to function as:

* Host Security Auditor
* Linux Hardening Validator
* Forensic Triage Utility
* Integrity Monitoring Tool
* Incident Response Helper

This project is not intended to replace enterprise HIDS, EDR, SIEM, or endpoint protection platforms.
