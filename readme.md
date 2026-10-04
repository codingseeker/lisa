# lisa

A Linux host security auditing and forensic triage CLI written in Go.

`lisa` walks a directory tree, inspects file metadata and a small set of
security-relevant configuration files, and reports **structured, explainable
findings**. It is built for local use on a single host: no agent, no server, no
network access, and no external dependencies.

> **Findings are indicators, not verdicts.** Every finding is derived from
> filesystem metadata and configuration state. A finding means "this property is
> worth reviewing", never "this host is compromised". A world-writable file in
> `/tmp` may be a package manager's staging directory; a SUID binary may be a
> legitimate distribution tool. Triage requires human judgement.

---

## Status

This is an active rewrite. The previous Python prototype has been removed and is
not maintained. The Go implementation is the only supported version.

| Area | State |
| --- | --- |
| Filesystem traversal | Implemented and tested |
| Permission and ownership detectors | Implemented and tested |
| SUID/SGID detectors | Implemented and tested |
| Sensitive configuration detectors | Implemented and tested |
| Secret redaction | Implemented and tested |
| File indicator detectors | Implemented and tested |
| Scan orchestration | Implemented and tested |
| JSON and terminal reporting | Implemented and tested |
| CLI and exit codes | Implemented and tested |
| GTFOBins context (opt-in) | Implemented and tested |
| Baseline create | Implemented and tested |
| Baseline compare | Implemented and tested |
| Baseline reliability policy for partial scans | Implemented and tested |
| Risk scoring and prioritisation | Implemented and tested |
| Finding correlation | Implemented and tested |
| Curated MITRE ATT&CK mapping | Implemented and tested |
| CSV and HTML reporting | Not implemented |
| Aggregate host risk score | Not implemented, and deliberately so |

There is **no claim of parity** with the removed Python implementation. That
code is no longer available and this project was not a line-by-line port.

---

## Requirements

- Go 1.25 or newer (to build)
- A Linux host (the detectors depend on Unix permission bits, `uid`/`gid` and
  systemd/cron layouts)
- No third-party modules. `go.mod` declares no dependencies, so builds work
  offline.

## Build

```bash
go build ./cmd/lisa
```

Or run directly:

```bash
go run ./cmd/lisa --help
```

## Test

```bash
go test ./...                # unit and integration tests
go test -race ./...          # concurrency checks
go vet ./...
```

Benchmarks:

```bash
go test ./internal/fsscan -run '^$' -bench BenchmarkWalk -benchmem
```

---

## Usage

```
lisa <command> [flags] [target]

Commands:
  scan              audit a directory tree and report findings
  baseline create   not implemented in this build
  baseline compare  not implemented in this build
  version           print the version and exit
  help              print help and exit
```

### Examples

```bash
# audit a directory, human readable output
lisa scan /home

# machine readable output for automation
lisa scan /etc --format json > report.json

# write the report to a file (created with mode 0600)
lisa scan /home --output report.json

# only high and critical findings
lisa scan / --min-severity high

# run a subset of detectors
lisa scan /home --detector permissions --detector suid

# skip noisy subtrees
lisa scan / --exclude /proc --exclude /sys --exclude /home/user/vendor

# limit traversal depth and total entries
lisa scan / --max-depth 4 --max-entries 100000

# bound filesystem concurrency
lisa scan / --workers 4

# record a baseline, then later compare against it
lisa baseline create /etc --baseline /root/lisa/etc.json
lisa baseline compare /etc --baseline /root/lisa/etc.json

# annotate SUID/SGID findings whose binary is in the curated GTFOBins subset
lisa scan / --gtfobins
```

### Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--path <dir>` | — | Target directory. May also be given positionally. |
| `--workers <n>` | `min(NumCPU, 16)` | Maximum concurrent filesystem workers (1–256). |
| `--exclude <path>` | — | Path to exclude, repeatable. |
| `--detector <name>` | all | Detector to enable, repeatable. |
| `--min-severity <level>` | `info` | Lowest severity to report. |
| `--output <file>` | stdout | Write the report to a file. |
| `--format <format>` | `text` | `text` or `json`. |
| `--max-depth <n>` | `0` (unlimited) | Maximum directory depth to descend. |
| `--max-entries <n>` | `4000000` | Maximum entries to visit. |
| `--follow-symlinks` | off | Follow symlinks that resolve inside the scan root. |
| `--skip-virtual` | on | Skip `/proc` and `/sys` during traversal. |
| `--gtfobins` | off | Annotate SUID/SGID findings with curated GTFOBins context. |
| `--verbose` | off | Debug logging on **stderr**. |
| `--quiet` | off | Suppress logging on **stderr**. |
| `--risk` | on | Score each finding for review priority. `--risk=false` omits the score. |
| `--sort-risk` | off | Order findings by descending risk instead of by severity. |
| `--correlate` | on | Infer relationships between findings. `--correlate=false` omits them. |
| `--attack` | on | Add ATT&CK technique context to correlations. `--attack=false` omits it. |
| `--baseline <file>` | — | Baseline file to write (`create`) or read (`compare`). |
| `--overwrite` | off | Replace an existing baseline. `create` only. |
| `--recent`, `--recent-window` | — | Accepted and validated; not implemented yet. |

## Detectors

Sixteen detectors run by default. Use `--detector <name>` to select a subset.

| Name | Detects |
| --- | --- |
| `permissions` | World-writable files and directories, with sticky-bit handling |
| `sensitive-permissions` | Unsafe modes and non-root ownership on `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config` and similar |
| `ssh-keys` | Overly permissive private keys and `authorized_keys` |
| `suid` | SUID and SGID binaries, including those outside standard binary directories |
| `ownership` | Files owned by a UID/GID absent from the user database, and unprivileged owners in system directories |
| `systemd` | World-writable or non-root-owned unit files |
| `cron` | World-writable or non-root-owned cron entries |
| `shell-profiles` | World-writable shell startup files and desktop autostart entries |
| `init` | World-writable init scripts, and `rc.local` without an executable bit |
| `ld-preload` | Unsafe permissions or ownership on `/etc/ld.so.preload` |
| `persistence-content` | Persistence entries referencing temporary directories, piping downloads into a shell, or containing reverse-shell patterns |
| `sshd-config` | `PermitRootLogin yes`, `PermitEmptyPasswords yes`, `PermitUserEnvironment yes`, `PasswordAuthentication yes` |
| `sudoers` | `NOPASSWD` grants |
| `secrets` | Credential-shaped values in `/etc` configuration files |
| `temp-executables` | Executable files in `/tmp`, `/var/tmp` and `/dev/shm` |
| `masquerade` | ELF binaries and scripts disguised as documents, images or text files |

### Severity and confidence are independent

**Severity** describes the potential impact: `info`, `low`, `medium`, `high`,
`critical`.

**Confidence** describes how reliable the detection is: `low`, `medium`, `high`.

A finding can be high severity with low confidence. Examples:

- `LS-PRIV-003` (SUID binary outside standard directories) — medium severity,
  high confidence: the fact is certain, the risk needs context.
- `LS-SENS-006` (credential-shaped value) — high severity, medium confidence:
  the pattern may be a placeholder rather than a live secret.

Findings are never escalated by accumulating weak indicators.

### Rule identifiers

Rules use a stable `LS-<CATEGORY>-<NNN>` namespace:

- `LS-PERM-*` permissions
- `LS-OWN-*` ownership
- `LS-PRIV-*` SUID/SGID and privilege context
- `LS-PERS-*` persistence
- `LS-SENS-*` sensitive configuration
- `LS-IND-*` file indicators

---

## GTFOBins context

`--gtfobins` annotates privilege findings with a short, curated description of
the binary they point at. It is **off by default**; the rest of the tool behaves
identically whether the flag is present or not.

```bash
lisa scan /usr --gtfobins
lisa scan /usr --gtfobins --format json
```

### What it is for

The GTFOBins project documents Unix binaries that ship with elevated privilege
and are known to be usable in unintended ways. A short list of those binaries is
useful context during triage: `find` carrying the SUID bit is a different
conversation from an unknown `our-internal-helper` carrying the SUID bit, even
though both are the same detector finding.

### What it is not

> **A GTFOBins match is not evidence of exploitation, compromise or malicious
> intent.** It says the binary is one an attacker would consider, and that a
> privileged copy of it is worth reviewing. It says nothing about whether
> anything happened. Distributions ship `sudo`, `passwd`, `mount` and `tar` with
> elevated bits as a matter of course, and **absence from the dataset is not
> evidence that a binary is safe.**

### Eligible finding types

Only SUID and SGID findings from the `suid` detector are enriched:

| Rule | Finding |
| --- | --- |
| `LS-PRIV-001` | SUID binary present |
| `LS-PRIV-002` | SGID binary present |
| `LS-PRIV-003` | SUID binary outside standard system directories |

World-writable files, ownership findings, persistence entries, sensitive
configuration findings and file indicators are never enriched, even when their
path ends in a listed name. `/etc/find` being world-writable is a permissions
problem, not a GTFOBins problem.

### How matching works

- **Exact binary name, case sensitive.** `/usr/bin/find` matches `find`.
- Full paths are resolved with a pure-string base name extraction. No filesystem
  access, no `stat`, no symlink resolution.
- **No substring, prefix or fuzzy matching.** `findutils`, `xfind`, `ind`,
  `findx`, `notsudo` and `bashrc` do not match. There is no ambiguous match and
  no tie to break.
- Results do not depend on scan order, worker count or traversal direction.

### What it changes, and what it does not

Enrichment is **strictly additive**. A matched finding keeps its original
identifier, rule ID, severity, confidence, category, path, evidence and
remediation. No new finding is created, no severity is raised, and no
finding is suppressed. The supplemental context is attached as one extra
structured field.

Unmatched and unrelated findings are byte-for-byte identical to a run without
the flag, and the field is omitted from the output rather than emitted empty.

### Dataset

The dataset is a small, hand-maintained TSV file compiled into the binary at
build time:

```
internal/gtfo/data/gtfobins.tsv   name <TAB> category <TAB> summary
```

- **Provenance.** The concept, and the list of interesting binaries, comes from
  the [GTFOBins](https://github.com/GTFOBins/GTFOBins) project (MIT licence,
  by the GTFOBins contributors). Every summary sentence in the file is original
  text written for this tool; no third-party prose is reproduced.
- **Coverage.** Around one hundred entries across seven categories (`shell`,
  `interpreter`, `editor`, `archive`, `filesystem`, `network`, `system`),
  restricted to binaries plausibly present on a general-purpose Linux host. It
  is **not exhaustive and not a mirror of GTFOBins**.
- **Limitations.** Entries whose relevance depends on embedded firmware,
  appliance vendor builds or historical vulnerabilities are deliberately omitted.
  The list will never be complete.
- **Validation.** The loader rejects malformed records, duplicate names,
  upper-case names, names containing path separators, empty categories or
  summaries and over-long summaries — each with the offending line number. A
  broken dataset disables enrichment rather than failing a scan.
- **No network.** The data is embedded with `go:embed`. Nothing is downloaded at
  build time or at run time.

**Maintaining it responsibly:** add an entry only when the binary is plausibly
present on a general-purpose Linux host *and* a privileged copy of it is worth an
analyst's time; keep the summary defensive and descriptive, never usage
instructions or exploitation steps; keep the tab-separated shape; and re-run
`go test ./internal/gtfo ./internal/detectors` after editing.

### Output

JSON — an extra `reference` object, present only on matched findings:

```json
{
  "rule_id": "LS-PRIV-001",
  "severity": "low",
  "path": "/usr/bin/find",
  "reference": {
    "source": "gtfobins-curated",
    "binary": "find",
    "category": "filesystem",
    "summary": "Recursive file walker that evaluates an expression supplied on the command line.",
    "attribution": "Concept: GTFOBins (https://github.com/GTFOBins/GTFOBins, MIT licence). Independent curated subset; descriptions are original.",
    "severity": "medium",
    "caveat": "Contextual risk information from a curated GTFOBins subset. A match does not indicate that the binary was exploited, that the host is compromised, or that the binary is malicious. Absence from the dataset is not evidence that a binary is safe."
  }
}
```

The `source` field and the `caveat` are what make the distinction explicit: this
block is **reference material about a binary**, not a detector result. The
`reference.severity` is the severity of the *context*, and is deliberately
separate from the finding's own `severity`.

Terminal — three extra lines on a matched finding only:

```
  [LOW]  LS-PRIV-001  SUID binary present
      path      : /usr/bin/find
      confidence: high
      owner     : root:root
      mode      : 4755
      detail    : File /usr/bin/find carries the SUID bit (mode 4755). It runs with the privileges of its owner.
      gtfo      : find, filesystem
      context   : Recursive file walker that evaluates an expression supplied on the command line.
      note      : Contextual risk information from a curated GTFOBins subset. A match does not indicate that
                  the binary was exploited, that the host is compromised, or that the binary is malicious.
      fix       : Confirm the binary is part of the distribution. Remove the SUID bit from anything unrecognised.
```

Control characters in the dataset are stripped and long lines truncated, so the
supplemental text cannot corrupt the terminal.

### Safety

Enrichment is a string lookup against an embedded table. It executes nothing,
opens no file, resolves no symlink, expands no filesystem scope and makes no
network request. The supplemental metadata contains only the binary name, its
category and the curated sentence — never file contents or host data.

---

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed with no findings at or above the reporting threshold |
| `1` | Scan completed and reportable findings were detected |
| `2` | Invalid arguments or configuration |
| `3` | Operational failure (unusable output format, unwritable report, scan error) |

Risk scores, correlations and ATT&CK context never change an exit code. They are
presentation: the code reflects whether reportable findings exist and whether the
run succeeded, and nothing else.

For `baseline compare`, code `1` means new or changed findings were detected and
code `2` covers an unusable, unsupported or tampered baseline as well as bad
arguments. An unreliable comparison still prints its report and is not an
operational failure: the withheld resolutions are reported in the reliability
block, and a note is printed on stderr.

A **partial** scan — one that hit a configured limit, could not read some paths,
or lost a detector to failure — still exits `0` or `1` based on findings, but the
report is explicit about it: `scan.status` is `"partial"` in JSON, and the text
report prints a `WARNINGS` section. Do not treat a partial scan as complete
coverage.

---

## Reporting

### JSON

Stable, versioned schema: `lisa/report/v1`. Top-level keys:

```
schema, tool, scan, summary, files, detectors, warnings, findings
```

- `schema` — schema identifier, bumped on incompatible changes.
- `scan` — roots, threshold, timestamps, duration and completion status.
- `summary` — totals plus `by_severity` and `by_category` counts.
- `files` — traversal counters, limits reached and inaccessible-path count.
- `detectors` — invocation counters and any detector failures by name.
- `warnings` — explicit `partial`, `limits_reached`, `inaccessible_paths` and
  `detector_failures` flags with human-readable notes.
- `findings` — sorted by severity descending, then path, then rule ID. Each
  finding may carry an optional `reference` object holding supplemental GTFOBins
  context; see [GTFOBins context](#gtfobins-context). The field is omitted
  entirely when there is nothing to add, so existing consumers are unaffected.

Findings are deduplicated by their stable identifier, which is derived from the
rule ID and the affected path, so the same condition keeps the same ID across
runs.

**Logs never appear on stdout.** `--verbose` diagnostics and partial-scan
warnings go to stderr, so `lisa scan / --format json | jq` always receives
valid JSON.

### Terminal

Human-readable, grouped by severity, with rule ID, path, owner, mode, ATT&CK
reference, evidence and remediation. Matched SUID/SGID findings gain a
`gtfo`/`context`/`note` block when `--gtfobins` is enabled. Long evidence values
are truncated and control characters are stripped so untrusted filenames cannot
corrupt the terminal.

---

## Secret handling

Credential-shaped values are **never** written to a finding or a report.

- Values are replaced with `[REDACTED]`; the key name and surrounding context
  are preserved so the finding stays useful.
- Patterns cover password, secret, API key, access key, token, private-key and
  AWS credential assignments, private-key blocks, and bearer tokens.
- `/etc/shadow`, `/etc/gshadow`, `/etc/passwd` and SSH key material are
  **excluded from secret scanning entirely** — those files are never read for
  this purpose.
- Redaction is applied twice: once when the finding is created, and again in the
  report layer as a safety net against a future detector that forgets to redact.
- Redaction is bypassable in principle: an unrecognised credential format will
  not match a pattern. Treat reports as sensitive.

---

## Filesystem safety

- **Nothing is ever executed.** Scanned files are opened read-only, never run.
  There is no `os/exec`, no shell, and no network client anywhere in the code.
- **Symlinks are not followed by default.** With `--follow-symlinks`, a target is
  resolved and rejected unless it stays inside the scan root, so traversal cannot
  escape the requested scope.
- **Metadata comes from `Lstat`**, so a symlink is never mistaken for its target.
- **Special files are classified, not opened.** Sockets, FIFOs and device nodes
  are counted and reported by type; the content reader refuses anything that is
  not a regular file, so a named pipe cannot block the scan.
- **Concurrency is bounded** by `--workers`. Only directory reading and `Lstat`
  run in parallel; detector callbacks are serialised, so detectors need no
  locking.
- **Cancellation is safe.** `SIGINT` context cancellation stops traversal and
  returns partial results; the scan status reports `cancelled`.
- **Excluded paths are skipped entirely**, including the directory entry itself,
  matching `rsync`/`find`/`rg` semantics.
- **`/proc` and `/sys` are skipped by default** because they are unbounded and
  volatile. `--skip-virtual=false` disables this if you need them.

---

## Baselines

A baseline records what a scan reported so a later scan can be compared against
it. It is the answer to "what changed", which recency deliberately cannot give.

```bash
# record the current state
lisa baseline create /etc --baseline /root/lisa/etc.json

# later, compare against it
lisa baseline compare /etc --baseline /root/lisa/etc.json

# machine readable, for automation
lisa baseline compare /etc --baseline /root/lisa/etc.json --format json
```

`baseline create` exits `0`. `baseline compare` exits `1` when anything appeared
or changed, `0` when nothing did, `2` for a usage or baseline problem, and `3` for
an operational failure. An empty baseline is valid: recording a clean host is how
the first finding is detected later.

`baseline create` accepts `--format` and `--output`. With `--format json` the
recorded document is echoed rather than re-rendered, so the printed JSON is the
file byte for byte and cannot drift from what a later comparison reads. With
`--output` the summary goes to that file instead of stdout, created with mode
`0600` like any other report.

### What is stored, and what is not

The file is a diffable record, not a second copy of the report. Per finding it
holds:

| Stored | Purpose |
| --- | --- |
| `id` | Digest of the finding identity |
| `rule_id`, `category`, `path` | The identity itself, in the clear |
| `title` | Descriptive, so a resolved finding can still be explained |
| `severity`, `confidence`, `mode`, `owner`, `group` | Compared attributes |
| `reference` | Curated GTFOBins context, when `--gtfobins` is on |

Deliberately **not** stored: descriptions, remediation text, evidence lines,
ATT&CK technique mappings, related identifiers, detection timestamps and file
contents. Evidence is excluded because it embeds the path and can quote file
content; a baseline is an allowlist of known state and should not become a second
place secrets land. The file is written with mode `0600` for the same reason.

### Finding identity

A finding is identified by `(rule_id, category, path)` and `id` is a digest of that
triple. All three are durable: they do not depend on scan order, timestamps,
worker count or traversal direction, so a finding keeps its identity across runs.

The compared attributes are kept strictly apart from the identity. That is what
makes two useful properties fall out:

- **A rule tuning is a change, not a flood.** Raising `LS-PERM-008` from medium to
  high reports one `changed` finding, not a mass `resolved` plus `new` split.
- **A curated dataset update is a change.** With `--gtfobins` on, a rewritten
  GTFOBins summary is reported as a `reference.summary` attribute change on the
  findings that carry it, never as new findings.

The identity triple is also validated on load. A record whose `id` does not match
its own `rule_id`/`category`/`path` is rejected, so an edited or hand-mangled file
fails loudly instead of silently reporting nonsense.

### Determinism

Output is a pure function of its inputs. Timestamps are supplied by the caller
rather than read from a clock inside the library, findings are ordered by identity
rather than by discovery, every map is sorted before it is written, and JSON
fields are length-prefixed so two different attribute sets cannot render
identically. Recording the same state twice produces byte-identical findings.

### Writes are atomic and non-destructive

The document is encoded and validated in memory, written to a temporary file in
the destination directory, flushed with `fsync`, given mode `0600` explicitly
rather than inheriting a umask, and only then renamed over the final name. A
failure at any step leaves the previous baseline intact and removes the temporary
file, so a reader never sees a half-written baseline.

An existing baseline is **never** replaced unless `--overwrite` is given. A
baseline is the reference point the next comparison is measured against, so
destroying it by re-running a command should not be the default.

### Reliability: when "resolved" is allowed

Only one classification depends on absence: `resolved` means the current scan did
not report a finding the baseline holds. That inference is only sound where the
scan could actually inspect the resource, so `baseline compare` withholds
resolutions it cannot justify and reports each withheld finding as `unverified`.

`new` and `changed` are direct observations of the current state and are reported
regardless of scan quality.

Reliability is scoped as narrowly as the evidence allows:

| Condition | Effect |
| --- | --- |
| Scan cancelled, or the walk stopped early | Suppress all resolutions |
| `--max-entries` or `--max-depth` reached | Suppress all resolutions |
| Non-permission filesystem errors | Suppress all resolutions |
| Unreadable path list was capped | Suppress all resolutions |
| Detector failure | Suppress all resolutions |
| Higher `--min-severity` than the baseline | Suppress all resolutions |
| Narrower `--detector` selection than the baseline | Suppress all resolutions |
| Baseline itself recorded from an incomplete scan | Suppress all resolutions |
| **A named unreadable path** | **Suppress resolutions only at or beneath it** |
| `--gtfobins` enabled on one side only | Advisory: qualify the comparison, suppress nothing |

The last two rows are the point of the design. An unreadable directory does not
invalidate findings elsewhere on the host, so only findings under it are withheld.
And the GTFOBins flag changes how a finding is *described*, never whether it is
reported, so a mismatch is worth a caveat but suppresses nothing.

A scan status of `partial` is a summary the scanner derives from exactly these
signals, so it is only treated as a blanket suppressor when nothing narrower
explains it. Treating it as an independent reason would throw away the scoping
above.

A detector failure suppresses all resolutions because the tool does not record
which rules a detector owns, and a failed detector could have hidden any finding
at all. That is a deliberate choice to be wrong in the safe direction rather than
attribute rules to detectors by guesswork.

### Duplicate and ambiguous findings

Two findings may share an identity: the scan collector deduplicates by rule and
path, but a caller assembling a result by hand can produce the same identity
twice.

- Identical duplicates are collapsed and counted in `duplicates_collapsed`.
- Duplicates whose compared attributes **disagree** are rejected, not resolved.
  Picking a winner would make the file depend on iteration order, which would
  make the comparison non-reproducible. The same rule applies to two baseline
  records that claim one identity, which is why a baseline cannot silently
  misrepresent itself.
- Duplicate identifiers in a loaded baseline are rejected.

### Schema

```json
{
  "schema": "lisa/baseline/v1",
  "version": 1,
  "tool": { "name": "lisa", "version": "0.1.0" },
  "created_at": "2026-03-04T05:06:07Z",
  "roots": ["/etc"],
  "min_severity": "info",
  "gtfobins": false,
  "coverage": {
    "scan_status": "complete",
    "complete": true,
    "detectors": ["cron", "init", "..."],
    "failed_detectors": [],
    "inaccessible_paths": [],
    "limits_reached": false,
    "notes": []
  },
  "summary": { "findings": 4, "by_severity": { "medium": 4 }, "duplicates_collapsed": 0 },
  "findings": [
    {
      "id": "LS-IND-001-1bd2d2e1d0ccb21c",
      "rule_id": "LS-IND-001",
      "category": "indicator",
      "path": "/srv/exposed",
      "title": "Executable file in a temporary directory",
      "severity": "medium",
      "confidence": "high",
      "mode": "0777",
      "owner": "root",
      "group": "root"
    }
  ]
}
```

**Compatibility policy.** Within `v1`, fields may be added but never removed,
renamed, or given a new meaning. Anything else requires a new schema string and a
new numeric version. A reader refuses an unknown schema or version outright
rather than attempting a partial read, and unknown fields are ignored so a newer
baseline can still be read by an older build. Every record is validated before it
is allowed near a report.

Validation errors name the offending record and the field, never the file
contents, so a crafted baseline cannot inject arbitrary text into a terminal or a
log.

### Comparison output

`--format json` emits schema `lisa/baseline-comparison/v1`. Unchanged
findings are counted but not listed, so the report stays proportional to what
changed:

```json
{
  "schema": "lisa/baseline-comparison/v1",
  "baseline": { "path": "...", "schema": "lisa/baseline/v1", "tool": {}, "created_at": "..." },
  "scan": { "status": "complete", "compared_at": "...", "min_severity": "info", "gtfobins": false },
  "summary": { "new": 2, "changed": 2, "resolved": 2, "unverified": 0, "unchanged": 0, "change_count": 4 },
  "reliability": { "complete": true, "reliable": true, "resolutions_suppressed": false },
  "changes": [
    { "rule_id": "LS-PERM-008", "path": "/srv/exposed", "category": "permissions",
      "status": "changed", "severity": "medium",
      "changes": [{ "attribute": "mode", "baseline": "0777", "current": "0666" }] }
  ],
  "unchanged": 0
}
```

Untrusted strings from a baseline reach the terminal report through these records,
so they are flattened and bounded before printing: a crafted value cannot forge a
report line.

---

## Risk scoring

Risk scoring answers a question severity cannot: given everything the scan
found, what should be looked at first?

Severity answers "how bad is this weakness on its own". A world-writable file in
`/tmp` and a world-writable file in `/etc` both score `medium`, because the
detector judges the weakness, not the consequences. Risk scoring adds what the
scan measured about *this* file: its mode, its ownership, and what kind of file
it is. The same weakness in a more consequential place ranks higher.

**A score is not a probability, not a vulnerability rating, and not evidence
that anything was exploited.** `lisa` reads filesystem metadata and
configuration text. It cannot know whether a service is reachable over a network,
whether an account is attacker controlled, or whether any weakness it found has
been used. A high score means "review this first". Nothing more.

### What a score is made of

Every score starts from the detector severity and is then adjusted by factors
that read attributes the finding already carries. Nothing is inferred, nothing
is guessed, and the finding itself is never modified.

**Base.** The severity alone sets the starting score, and it always lands the
finding inside the band its severity implies:

| Detector severity | Base | Band at rest |
| --- | --- | --- |
| critical | 80 | critical |
| high | 60 | high |
| medium | 42 | medium |
| low | 22 | low |
| info | 8 | informational |

This is the property that keeps risk and severity from contradicting each other:
severity alone is enough to reach the right band, and no combination of factors
can move a finding below the band its severity implies.

**Factors.** Each factor measures one distinct property of the finding, applies
at most once, and states an observation rather than a conclusion:

| Factor | Points | Evidence it reads | Why it is included |
| --- | --- | --- | --- |
| `setuid-or-setgid-bit` | +20 | recorded mode has `setuid` or `setgid` | The file runs with the privileges of its owner. This is the single largest privilege exposure the scan can measure directly. |
| `world-writable` | +15 | recorded mode grants write to other | Any local account can replace the content. |
| `group-writable` | +8 | recorded mode grants write to the group, and **not** world-writable | Write access for someone who is not the owner. It does not apply alongside `world-writable`, because that would charge one property twice. |
| `non-root-owner` | +10 | recorded owner exists and is not `root` | The owner already holds privileges over this resource, so the exposure survives a root-owned parent directory. An *unknown* owner scores nothing: absence is not evidence. |
| `access-config-readable-by-others` | +5 | category is `sensitive-config` and mode grants read to other | Read exposure only matters where the file governs host access. A world-readable file is not a weakness in general, so this is deliberately narrow. |
| `automatic-execution` | +10 | category is `persistence` | The host reads the file to run commands, so its content takes effect without an operator choosing to run it. Distinct from write access, so the two legitimately combine. |
| `access-control-configuration` | +8 | category is `sensitive-config` | The file governs access to the host, so a weakness in it is a weakness in the access model. |
| `high-evidence` | +5 | detector confidence is `high` | The condition is measured rather than inferred, so it deserves attention before a pattern match. |

The total is capped at 100. When the cap applies, it is recorded as a
`score-cap` factor holding the negative adjustment, so **the factors always add
up to the score exactly** and a capped score is visible rather than silent.

### Risk bands

| Score | Band |
| --- | --- |
| 0–19 | informational |
| 20–39 | low |
| 40–59 | medium |
| 60–79 | high |
| 80–100 | critical |

Bands are reported, not computed from the score, so a consumer never has to
reproduce the thresholds to interpret a report.

### What scoring deliberately does not do

- **GTFOBins context adds no risk.** A match is a reason to look closer, not
  measured evidence. Two findings identical except for a curated reference score
  identically; this is asserted by test, because it is the easiest way to
  accidentally turn a dataset into a severity knob.
- **No exploitability, reachability or attacker-access assumptions.** Nothing in
  the model asks whether a port is open, whether a user is suspicious, or
  whether a weakness has a public exploit.
- **No scoring of correlations or baselines.** Those are derived documents, not
  observed weaknesses, so they carry no risk of their own.
- **No relationship inference.** Deciding that two findings are related is
  correlation, not scoring. Scoring reads one finding at a time.
- **Credential-specific uplift is not modelled.** The tool knows which paths hold
  credential material, but that knowledge lives in the detectors; duplicating it
  here would create a second, drifting copy of the same table. The cost is that
  a broadly-readable private key scores like any other permissions finding.

Scoring reads no clock, no environment, no filesystem and no random source. It
is a pure function of the finding, so the same finding always scores the same
and two identical scans produce identical reports. Those properties are asserted
by a test that inspects the package's own sources, not merely documented.

### Reading a score

Each finding carries the score, the band, the original severity, every
contributing factor with its reason, and a one-line explanation built from those
same factors:

```
  [MEDIUM] LS-PERM-008  World-writable file in a temporary directory
      risk      : 72/100 HIGH (detector severity medium)
      factors   : world-writable, non-root-owner, high-evidence
      path      : /tmp/app/cache.bin
      confidence: high
      owner     : app:app
      mode      : 0666
```

A score that disagrees with the severity is not a contradiction. A `medium`
finding in a world-writable location owned by a service account is worth
reviewing before a `low` finding on a root-owned system binary, and that is the
entire point of the score. Where a band and a severity disagree sharply, read the
factor list: it says exactly which measurement drove the difference.

Factors state what was measured. "The recorded mode grants write permission to
other users" is an observation the tool can support. "An attacker can replace
this file" is not, because the tool cannot see who is logged in.

### Configuration

Scoring is **on by default**. `--risk=false` turns it off, which is the same
convention as `--skip-virtual=false` elsewhere in the tool.

```bash
lisa scan /etc                      # scored, ordered by severity
lisa scan /etc --risk=false         # severity and confidence only
lisa scan /etc --sort-risk          # scored and ordered by descending risk
```

Disabling scoring does not change any finding: the `risk` object is omitted
entirely, so the JSON is byte identical to what it was before scoring existed.

`--sort-risk` orders findings by descending score. Ties are broken by severity,
then path, then rule, then identifier, so the order is fully determined by the
findings themselves and cannot vary between runs. Ordering by risk requires
scoring; `--sort-risk --risk=false` is rejected rather than silently ignored.
The default order is unchanged.

### JSON and text

The score is nested in each finding and summarised once:

```json
{
  "summary": {
    "total": 3,
    "by_severity": { "info": 0, "low": 1, "medium": 2, "high": 0, "critical": 0 },
    "by_category": { "permissions": 2, "indicator": 1 },
    "by_risk_band": { "informational": 0, "low": 0, "medium": 1, "high": 2, "critical": 0 }
  },
  "findings": [
    {
      "rule_id": "LS-PERM-008",
      "severity": "medium",
      "path": "/tmp/app/cache.bin",
      "risk": {
        "score": 72,
        "band": "high",
        "severity": "medium",
        "base": 42,
        "factors": [
          { "name": "severity-base", "points": 42, "reason": "the detector rates this finding medium" },
          { "name": "world-writable", "points": 15, "reason": "the recorded mode grants write permission to other users" },
          { "name": "non-root-owner", "points": 10, "reason": "the recorded owner is not root, so the owner already holds privileges over this resource" },
          { "name": "high-evidence", "points": 5, "reason": "the detector is highly confident the condition is present" }
        ],
        "explanation": "Base 42 from detector severity medium; +15 world-writable, +10 non-root-owner, +5 high-evidence. The score indicates review priority, not evidence of exploitation."
      }
    }
  ]
}
```

`by_risk_band` and `risk` are both additive and omitted when scoring is off, so
existing consumers see an unchanged document.

### Risk and baselines

Risk metadata is **never written to a baseline**. A baseline records identity and
the compared attributes, and a score is a derived judgement that would change
whenever the scoring model is revised. Recording it would mean every model change
reported as a wave of changed findings.

Consequently a baseline recorded with scoring on is byte identical to one
recorded with `--risk=false`, and finding identifiers are identical either way.
This is asserted by test. Risk appears in scan reports only.

### Limitations

- The score ranks findings against each other within one scan. It is not
  comparable between hosts, and it is not a measurement of risk to the
  organisation.
- Every factor is a property of a single finding. A host with five thousand
  world-writable files in `/tmp` scores each of them the same, and the report
  says nothing about the aggregate. Volume is not modelled.
- The model encodes one opinion about what matters. The weights are documented so
  they can be argued with and changed, but they are still a judgement, not a
  measurement.
- Scores are only as complete as the scan. A partial scan may rank a subset and
  say nothing about what it never read, exactly as the baseline reliability block
  does.

---

## Finding correlation

Two findings on the same file often describe one weakness from two angles. A cron
entry that is world-writable is reported both as a persistence problem and as a
permissions problem. A setuid binary owned by an unprivileged account is reported
both as a privilege indicator and as an ownership problem. Correlation names that
relationship, which is more useful to an analyst than leaving the two findings to
be joined by hand.

**Correlation does not claim that an adversary did anything.** The tool reads
filesystem metadata and configuration text. It has no access to process history,
network state, log data or user behaviour, so it cannot distinguish a
misconfiguration an administrator left behind from one that was introduced
deliberately. Every explanation states what was observed; none states what anyone
intended.

A correlation is a derived record. It names the findings it relates by identifier
and it never edits them: severity, risk and identity stay exactly as detection
produced them.

### Rules

Four rules ship, each matching on explicit finding attributes. Every rule records
what it assumes and what it cannot show.

| Rule | Relationship | Confidence | Assumes |
| --- | --- | --- | --- |
| `LS-COR-001` | Automatically executed configuration is writable by other users | high | Both findings describe one file. Write access and automatic execution are separately measured properties of it. The rule does not claim anyone wrote to the file. |
| `LS-COR-002` | Privilege-escalating binary is owned by an unprivileged account | high | Both findings describe one file. The rule does not claim the binary was executed. |
| `LS-COR-003` | Payload-shaped artifact in a world-writable staging location | high | Both findings describe one file. Neither finding calls the file malicious; both describe a property a legitimate file could also have. |
| `LS-COR-004` | Weakened remote access policy alongside broadly permitted key material | medium | The findings need not share a path. They are related because both weaken the SSH trust path. The tool cannot show that the key material is reachable under the policy. |

`LS-COR-001` to `LS-COR-003` are **high** confidence because each pairs two
independent measurements of a *single path*. That is what earns the confidence:
not that the relationship is important, but that the evidence directly supports
it.

`LS-COR-004` is **medium** because it deliberately spans paths. Two findings
about SSH access belong to the same trust path, but nothing in the finding model
connects the keys to the policy. The record says so explicitly.

### What correlation deliberately does not do

- **No matching on a shared directory.** Two findings under `/tmp` are not a
  relationship. This is the most common false positive on a real host and is
  excluded by construction.
- **No matching on severity.** Nothing correlates merely because two findings are
  both `medium`.
- **No chains and no campaigns.** Building "this looks like an intrusion path"
  would be inference the evidence cannot support, and a report that assembles
  narratives from unrelated findings is worse than one that does not.
- **No low-confidence rules.** `CorrelationLow` is defined for completeness and
  is never produced. A weak association is worse than no association, because a
  reader cannot tell it apart from a strong one.
- **No use of `RelatedIDs`.** The finding model has the field, but no detector
  populates it. Building a rule on it would be building on data that does not
  exist.

### Confidence is not a probability

`high` and `medium` state how well supported a relationship is by the attributes
the rule matched on. They are not computed from measured frequencies, so they are
not percentages and must not be read as likelihoods. Nothing in this tool
produces a probability.

### Partial scans

Correlation only ever reports relationships it *found*. It never reports the
absence of one, because absence is exactly what an incomplete scan cannot
establish. A record derived from a partial scan is still reported, with a scope
note recording what was missing:

```
  LS-COR-003 [HIGH] Payload-shaped artifact in a world-writable staging location
      id       : LS-COR-003-00f526d168b8
      findings : LS-IND-001-0b081182f4e9, LS-IND-004-e54c53ee5cea
      why      : /tmp/stage/payload is an executable in a directory other users can
                 write to, and its content and name match a pattern associated with
                 staged tooling.
      coverage : The scan covered only part of the target, so related findings may be
                 missing; 1 path(s) could not be read, so related findings may be
                 missing.
```

A scope note appears when the scan was cancelled or partial, a traversal limit
stopped the walk, a detector failed, a path was unreadable, or fewer than all
detectors ran. This mirrors the baseline reliability policy: the tool says what
it does not know instead of letting silence read as a clean result.

### Stable identifiers

A correlation identifier is a digest of the rule identifier and the sorted,
deduplicated finding identifiers:

```
LS-COR-001-a6a7876cabef
```

Nothing time, path or report-order dependent is involved, so the same
relationship produces the same identifier on every run and on every host that
exhibits it. Identical records deduplicate automatically, because they hash to
the same value.

---

## MITRE ATT&CK context

Correlations may carry a MITRE ATT&CK technique drawn from a small curated
dataset in `internal/attack/data/techniques.tsv`.

**A technique reference is not evidence that the technique was used.** It says
that an observed configuration weakness is the kind of precondition a documented
technique is associated with. A mapped technique was not necessarily attempted,
no adversary necessarily exists on the host, and nothing was necessarily
exploited.

### Dataset and provenance

The dataset is compiled into the binary. There is no runtime network access, and
the documentation URL recorded against each technique is never fetched; it is
there so a reader can look the technique up themselves.

Each record carries the technique identifier, the technique name and tactic as
published by MITRE, the documentation location, and a relevance note written for
this project. Technique names and tactics are (c) The MITRE Corporation, MITRE
ATT&CK, Apache License 2.0; the mapping choices and relevance notes are original
work.

**On versioning:** the dataset records `lisa-attack-curated v1`, which is
the revision of *this curated subset*, not of MITRE ATT&CK. The tool has no
network access and cannot verify the current ATT&CK release, so it deliberately
does not assert one. A pinned framework version that cannot be checked would be a
false claim of precision. Records should be re-checked against the referenced
pages when the subset is next updated.

The loader rejects a dataset that has a malformed record, an invalid technique
identifier, a missing field, a duplicate rule, a relevance note that is too long,
or a reference that does not point at the page for the technique being cited. A
broken dataset yields *no* mappings rather than partial ones, so a report loses
ATT&CK context instead of gaining a wrong technique.

### Coverage

The dataset holds four mappings, one per correlation rule, and that is
deliberate. Findings already carry a technique from the rule catalogue where one
is defensible, so the curated dataset covers only correlations, and duplicates
nothing.

Most findings carry no technique, and that is correct. Padding the dataset would
assert relationships the evidence does not support, which is worse than an
unmapped record. A future rule with no defensible technique is reported without
ATT&CK context rather than being given one to make a report look comprehensive.

### Configuration

Correlation and ATT&CK context are independent, and both are on by default:

```bash
lisa scan /etc                              # correlated, with ATT&CK context
lisa scan /etc --correlate=false            # findings only
lisa scan /etc --attack=false               # correlations without techniques
```

`--attack=false` never removes a correlation; it removes only the technique. A
report produced with `--attack=false` is still a complete correlation report.

### Report output

```json
{
  "correlations": [
    {
      "id": "LS-COR-003-00f526d168b8",
      "rule_id": "LS-COR-003",
      "title": "Payload-shaped artifact in a world-writable staging location",
      "finding_ids": ["LS-IND-001-0b081182f4e9", "LS-IND-004-e54c53ee5cea"],
      "confidence": "high",
      "explanation": "/tmp/stage/payload is an executable in a directory other users can write to, and its content and name match a pattern associated with staged tooling. Either property alone is common; together they are worth reviewing. The file was not classified as malicious.",
      "technique": {
        "id": "T1036.005",
        "name": "Match Legitimate Resource Name or Location",
        "tactic": "Defense Evasion"
      },
      "attack_relevance": "Executables placed in world-writable staging directories are a documented way to have a file appear where an operator expects only data. The tool observed an executable and a payload-shaped artifact in one staging location, and identified neither as malicious.",
      "scope": { "complete": false, "note": "..." }
    }
  ],
  "correlation_summary": { "total": 1, "by_confidence": { "high": 1, "medium": 0, "low": 0 }, "mapped": 1 },
  "attack": {
    "framework": "MITRE ATT&CK",
    "dataset": "lisa-attack-curated",
    "version": "lisa-attack-curated v1",
    "attribution": "Technique names and tactics (c) The MITRE Corporation, MITRE ATT&CK, Apache License 2.0. Mapping choices and relevance notes are original.",
    "caveat": "A technique mapping describes a documented behaviour this weakness is relevant to. It is not evidence that the technique was attempted, that an adversary is present, or that anything was exploited."
  }
}
```

Correlations reference findings by identifier rather than embedding copies, so
the report stays proportional to what changed rather than to what was found. The
`attack` block publishes provenance so a reader can tell what the mapping is and
where it came from.

In terminal output the section states plainly that these are inferred
relationships, not adversary activity, and every explanation ends by saying what
was *not* observed.

### Correlation, risk and baselines

The three features are independent:

- **Correlation never changes risk.** No factor reads a correlation, and a
  correlation explanation never quotes a score. A finding's risk score is the
  same whether or not any correlation fired. There is deliberately no
  correlation-based risk adjustment: overlapping correlations would inflate scores
  for a single underlying problem, which is the failure mode most worth avoiding.
- **Risk never changes correlation.** Scoring reads one finding at a time and
  knows nothing about relationships. `internal/risk` does not import
  `internal/correlation`, so the dependency cannot exist even by accident.
- **Correlations still appear with `--risk=false`**, and risk scores still appear
  with `--correlate=false`.
- **Baselines record neither.** Correlation records and risk scores are both
  derived judgements that change when the model is revised, so recording them
  would report every model change as a wave of changed findings. A baseline is
  byte identical with correlation and scoring on or off, and finding identifiers
  are unaffected.

---

## Known limitations

- A baseline is an allowlist of known state, so comparing against a stale one
  understates a host. Re-record it on a schedule, and treat a large "resolved"
  count on the first compare as a reason to re-check the baseline rather than as
  an improvement.
- Recency is deliberately **not** treated as evidence of a change: a package
  update rewrites hundreds of files, so a recently-modified-file rule would be
  noise. `baseline compare` is the defensible way to answer "what changed".
- No aggregate host risk score. Each finding carries a prioritisation score, but
  there is deliberately no single number for the host: a total would invite
  summing findings whose risks overlap, and would hide the fact that the tool
  cannot see reachability or attacker access. Prioritise by ranking the findings,
  not by adding them up.
- Risk scoring ranks findings within one scan. A score means nothing across
  hosts, and it says nothing about volume, so a host with many findings of the
  same kind is not distinguished from a host with few.
- Correlation pairs findings on shared paths and on one deliberately thematic
  SSH relationship. It does not group findings into attack chains, infer
  campaigns, or rank which relationships matter most. A correlation is a
  documented association, not an attack path.
- ATT&CK coverage is four mappings, one per correlation rule, and the dataset
  cannot verify the upstream framework version offline. Most findings carry no
  technique, which is the intended state rather than a gap to be filled in.
- No CSV or HTML output yet; `--format csv` and `--format html` exit `3` with an
  explanation rather than emitting nothing.
- SUID/SGID context is presence-based only. Presence of the bit is not evidence
  of exploitation.
- The curated GTFOBins subset is deliberately small and incomplete. A match is
  a reason to look closer, nothing more; a miss is not a clean bill of health.
- `persistence-content` and `secrets` use pattern matching. Expect false
  positives on unusual configurations and review the evidence lines.
- Detectors classify on absolute paths, so scanning a relocated tree (a container
  image unpacked elsewhere, for example) will not match `/etc` and `/usr` rules.
- One goroutine per directory. Concurrency of *work* is bounded, but a path with
  an extreme number of directories will create many goroutines.
- Only Linux and Unix-like filesystems are supported.

## Project layout

```
cmd/lisa/            CLI entry point
internal/model/       finding, rule, severity, confidence, ATT&CK types
internal/config/      configuration parsing and validation
internal/fsscan/      bounded-concurrency filesystem walker
internal/detectors/   compile-time detector registry and the 16 detectors
internal/gtfo/        embedded curated GTFOBins reference dataset
internal/baseline/    baseline schema, atomic storage, comparison, reliability
internal/risk/        deterministic prioritisation scoring
internal/correlation/ curated relationships between findings
internal/attack/      curated MITRE ATT&CK mapping subset
internal/scan/        scan orchestration
internal/report/      JSON and terminal reporting
internal/logging/     stderr logging
internal/cli/         argument parsing and exit codes
```

Detectors are registered **at compile time** in
`internal/detectors/registry.go`. There is no dynamic plugin loading and no
runtime discovery: loading code from a directory at runtime is an arbitrary code
execution primitive, which has no place in a host auditing tool.