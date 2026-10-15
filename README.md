# CAIRN

**CAIRN (Container and Authentication Incident Reconstruction Navigator)** is
an offline, deterministic triage tool for Linux authentication activity and
Docker Compose security posture.

CAIRN reads a small local evidence directory and produces a self-contained
HTML report. It detects repeated SSH failures, a later successful login, and
explicit or potential root escalation. It also audits a focused set of
high-risk Docker Compose settings. No live monitoring, active scanning,
automatic remediation, cloud service, or AI API is required.

## What the MVP answers

- Did one source repeatedly fail SSH authentication?
- Did that source later authenticate successfully?
- Is there explicit evidence of sudo-to-root or a related root session?
- Does the Compose configuration weaken container isolation?
- Which source file and line support each finding?
- What remediation should an operator consider first?

CAIRN is a triage aid, not a complete forensic or detection platform. A
finding is not proof of compromise, and absence of a finding is not proof of
safety.

## Requirements

- Linux with Docker for the container workflow
- Go **1.27.2** for local development and tests
- GNU Make

The Go module is pinned with `go.mod`, `toolchain go1.27.2`, and `.go-version`.
The only non-standard dependency is vendored in `vendor/` and recorded in
`go.sum`.

## Quick start

The following creates the deterministic synthetic incident and writes an
offline report:

```text
make build
./bin/cairn demo --out demo-case
./bin/cairn analyze --case-dir demo-case --output report.html
```

Open `report.html` directly in a browser. It has no external assets and does
not need a local web server or network connection.

The demo contains fictional documentation-network addresses and harmless log
records. It does not perform an exploit or contact a Docker daemon.

To avoid overwriting files, `cairn demo` refuses a non-empty destination. Use
`--force` only when replacing the two known demo files is intended.

## Test

The one supported test command is:

```text
make test
```

It runs unit, integration, input-safety, parser, rule, Compose-audit, report,
and deterministic-output tests. Tests use only repository files and vendored
dependencies; they do not contact the network.

For a local installation, use Go 1.27.2. If Go is installed somewhere other
than `PATH`, set `GO` without changing the test command itself, for example:

```text
GO=/path/to/go make test
```

## Docker build and offline run

The builder image is pinned by tag and digest. Go modules are vendored and the
documented Docker build explicitly uses `--network=none`.
The Dockerfile uses only the default Dockerfile syntax, so BuildKit does not
need to fetch a separate remote frontend image.

Build after the pinned builder image is available locally:

```text
docker build --network=none -t cairn:0.1.0 .
```

Generate a case using the container. The output directory must be writable by
the container user:

```text
mkdir -p demo-case report-out
docker run --rm --network=none --read-only \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/demo-case:/case:ro" \
  -v "$PWD/report-out:/out" \
  cairn:0.1.0 analyze --case-dir /case --output /out/report.html
```

For a host-owned output directory, pass the host UID and GID with Docker's
`--user` option. CAIRN makes no outbound connections at runtime.

On a truly air-gapped machine, the pinned builder image must be transferred or
preloaded before the build; Docker cannot build a `FROM` image that is absent
from its local image store. Once it is cached, the build and application run
above are networkless.

## Analyze a real case

Place supported files directly in a case directory:

```text
case/
├── auth.log                  # or secure
├── sudo.log                  # optional; may also be in auth.log
└── compose.yml               # or docker-compose.yml
```

Run:

```text
./bin/cairn analyze \
  --case-dir case \
  --year 2026 \
  --timezone UTC \
  --output report.html
```

RFC3339 timestamps with an explicit offset are preferred. Traditional syslog
timestamps omit the year, so `--year` is required for reliable correlation of
those records. CAIRN uses UTC by default unless another IANA timezone is
provided. The CLI embeds Go's timezone database, so named zones also work in
the minimal Docker image.

CAIRN reads only these root-level filenames:

- `auth.log`
- `secure`
- `sudo.log`
- `syslog`
- `messages`
- `compose.yml`
- `compose.yaml`
- `docker-compose.yml`
- `docker-compose.yaml`

It refuses symlink inputs, non-regular files, path traversal, and files over
the built-in size limit. Unsupported or malformed lines become warnings in
the report instead of being executed or silently treated as evidence.
The report destination must not be one of the supported input files, an
existing symlink, or another hardlink to input evidence.

## Deterministic rules

Authentication rules use explicit, documented windows:

1. **Repeated SSH failures** — at least five failed or invalid-user attempts
   from one source IP within ten minutes.
2. **Successful login after failures** — a successful login from that same
   source IP within fifteen minutes of a repeated-failure sequence. The
   repeated-failure threshold and ten-minute failure window also apply to
   this finding.
3. **Potential privilege escalation** — explicit sudo-to-root activity or a
   root session that follows a successful login by the same user within
   fifteen minutes. The latter is deliberately described as potential rather
   than confirmed escalation.

Events without reliable timestamps remain visible in the report but are not
used for time-window correlation.

Identical normalized events found in overlapping supported log files count
once for detection thresholds. Their source filenames, line numbers, and raw
lines remain visible in the report as separate evidence references.

The Compose audit currently reports these high-confidence settings:

- `privileged: true`
- Host network, PID, or IPC namespaces
- A Docker socket bind mount
- Sensitive host filesystem mounts
- `SYS_ADMIN`, `NET_ADMIN`, or `ALL` in `cap_add`
- `seccomp=unconfined`
- `apparmor=unconfined`

The audit intentionally does not flag every published port, every omitted
hardening option, or every root user. The MVP favors useful findings over a
large noisy checklist.

## Report contents

The HTML report contains:

- Summary metrics
- Authentication findings with rule explanations
- Evidence source filenames and line numbers
- Source excerpts, safely HTML-escaped
- Per-finding remediation advice
- Docker Compose service and YAML line references
- A chronological authentication timeline
- Input warnings and source-file SHA-256 hashes

The report is rendered with Go's `html/template`, inline CSS, and no external
JavaScript or stylesheet. Untrusted log and Compose values are treated as data.

## Repository layout

```text
cmd/cairn/             CLI entry point
internal/app/          Safe case loading and orchestration
internal/core/         Auth parsing, deterministic rules, timeline
internal/compose/      Compose YAML audit and source locations
internal/demo/         Deterministic synthetic incident
internal/report/       Report model and self-contained HTML renderer
vendor/                Pinned offline dependency sources
Dockerfile             Reproducible static-image build
Makefile               Build, format, vet, and the single test command
```

## Development principles

- Keep all analysis deterministic and explainable.
- Treat evidence as attacker-controlled input.
- Never execute commands found in logs or Compose files.
- Keep the runtime networkless and dependency-light.
- Run `make test` after meaningful changes.
- Keep generated reports and local tools out of Git.
- Commit only working, focused milestones.

## Limitations

CAIRN is intentionally not a live sensor, vulnerability scanner, or incident-
response automation system. It supports a small set of common Linux log forms
and a focused Compose configuration surface. Other log formats are reported
as unsupported or unrecognized rather than guessed. Operators should preserve
the original evidence bundle separately and use CAIRN alongside their normal
incident-response process.

## License

CAIRN is released under the MIT License. The vendored YAML parser retains its
upstream license and notice files in `vendor/gopkg.in/yaml.v3/`.
