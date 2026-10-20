# Portable Incident-Response USB

## Goal

Make LISA practical to carry on an 8–16 GB USB drive for authorised, offline Linux host triage. The USB is a portable distribution and case workspace; it is not a separate analyser and does not turn LISA into a full disk-forensics suite.

LISA already performs local Linux security auditing, emits structured JSON and terminal reports, supports baseline workflows, and has no runtime network dependency. This feature should compose those capabilities rather than duplicate detectors.

## Non-goals

- No new detector set solely to justify the USB project.
- No automatic execution on insertion, autorun, persistence, or stealth.
- No automatic remediation or deletion of suspicious files.
- No claim that a live-host scan is a forensic disk image or preserves all volatile evidence.
- No runtime plugin loading or downloading tools/rules from the network.
- No promise of Windows/macOS host support; LISA is Linux/Unix-oriented.

## User workflow

1. Prepare the USB on a trusted Linux workstation.
2. Build or copy a pinned, verified LISA binary and its version/license documentation.
3. Start a case with an analyst-supplied case ID and output directory on the USB.
4. Record operator-provided context and host metadata, then run LISA against an explicitly selected target.
5. Save the exact command, LISA version, start/end times, exit status, report, and SHA-256 hashes of generated artifacts.
6. Verify the saved artifact manifest after the case is closed.
7. Export the case directory for review without changing the original evidence.

Example intended interface (illustrative, not implemented):

```sh
lisa fieldkit init-case --id CASE-2026-001 --out /media/usb/LISA/cases/CASE-2026-001
lisa fieldkit collect-host --out /media/usb/LISA/cases/CASE-2026-001
lisa scan / --format json --output /media/usb/LISA/cases/CASE-2026-001/lisa-report.json
lisa fieldkit seal /media/usb/LISA/cases/CASE-2026-001
lisa fieldkit verify /media/usb/LISA/cases/CASE-2026-001
```

The interface must be reconciled with the current CLI architecture before implementation. Avoid introducing a second command parser if existing CLI patterns can be extended cleanly.

## Case layout

```text
LISA/
├── bin/                 # built binaries, with version and digest records
├── docs/                # offline usage, safety notes, supported platform matrix
├── cases/
│   └── CASE-2026-001/
│       ├── case.json    # case metadata and tool/environment information
│       ├── reports/     # LISA reports; never original evidence
│       ├── artifacts/   # explicitly collected copies, if any
│       ├── logs/        # command metadata and operational errors
│       └── manifest.json
└── checksums/
```

Do not commit case data, host identifiers, secrets, or collected evidence to the repository.

## MVP scope

### 1. Portable release packaging

- Build a Linux binary for a documented target architecture.
- Record the release version and SHA-256 digest.
- Keep all runtime resources local; no network calls.
- Provide a preparation script that refuses to format disks or guess device paths.
- Do not bundle third-party tools unless a concrete workflow requires them and their licenses are reviewed.

### 2. Case metadata and artifact manifest

- Require an explicit case ID and output directory.
- Record timestamps in UTC, LISA version, OS/kernel/architecture where available, command arguments, exit status, and scan completeness.
- Hash generated reports and explicitly copied artifacts with SHA-256.
- Write files atomically with restrictive permissions where supported.
- Never include raw secret values in metadata or logs.

### 3. Verification

- Verify the integrity of files listed in the manifest.
- Report missing, changed, and unlisted files.
- Clearly state that a manifest stored beside the case is not tamper-proof: an attacker able to alter both artifacts and manifest can recompute hashes. External signing or a separately protected copy is a future extension.

### 4. Safety controls

- Never execute files from a target or collected evidence.
- Never modify or delete target files.
- Require explicit target and output paths; reject output directories nested inside the target being scanned where that could contaminate results.
- Treat partial scans and unreadable paths as visible case warnings, not clean results.
- Do not claim that ordinary live scanning is read-only at the forensic level; the operating system and filesystem may update metadata, and a live host may already be compromised.

## Critical technical caveat: offline roots

LISA's detectors currently classify several paths using absolute Linux locations such as `/etc`, `/usr`, and systemd/cron paths. Scanning a mounted disk image under a path such as `/mnt/evidence/rootfs` may therefore miss or misclassify host-specific detectors. The MVP must not advertise mounted-root forensic analysis unless LISA gains a separately designed and tested root-prefix mode.

For the first version, the supported workflow is running LISA on a Linux host's live filesystem, with reports written to the USB. If preservation requirements prohibit touching the original system, use a properly acquired image and defer analysis until root-prefix support is designed.

## Acceptance criteria

- Works with networking disabled after the USB is prepared.
- Does not format or repartition a drive as part of normal setup.
- Runs LISA and stores a case on an 8–16 GB USB.
- Case metadata and artifact manifest have documented, versioned schemas.
- Verification detects changed, missing, and additional files.
- Partial scans, permission errors, and failed hashing are explicit.
- Automated tests cover malformed manifests, path traversal, symlink handling, duplicate paths, and interrupted writes.
- Existing LISA behaviour and report schema remain unchanged unless a separately reviewed compatibility change is required.
- `go test ./...`, `go test -race ./...`, and `go vet ./...` pass before merge.

## Implementation sequence

1. Inspect the current CLI, report schema, baseline storage, and build/release workflow.
2. Add design tests for case metadata and manifest verification before wiring commands.
3. Implement a small internal case-manifest package with no new third-party dependencies.
4. Add CLI commands using existing parser conventions.
5. Add release/preparation documentation and a safe packaging script.
6. Test on a clean Linux VM with networking disabled and a disposable test case.
7. Review threat model, privacy implications, and existing report compatibility before opening a PR.
