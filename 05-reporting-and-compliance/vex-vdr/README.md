# Standalone VEX / VDR Export

Exports a **standalone CycloneDX VEX document** (Vulnerability Disclosure Report) for a Finite State project version — vulnerability and triage data with **no SBOM component inventory**.

The platform's CycloneDX export always embeds `components[]`. This script requests the SBOM with VEX data and strips `components[]`/`dependencies[]`, reproducing the legacy platform's "VDR only" export mode for customers whose downstream consumers require a VEX file rather than a full SBOM.

## Features

- **Standalone VEX output** — `metadata` + `vulnerabilities[]`, no component inventory
- **Full triage data** — each triaged finding carries its VEX `state`, `justification`, `response`, and `detail`
- **Flexible input** — accepts a platform URL, a bare version ID (UUID or int), or project + version names
- **Triage-only filter** — optionally emit only vulnerabilities that have been triaged, cutting noise from routine vulnerability-database updates
- **Self-naming output** — writes a descriptive filename, shortened to stay within filesystem limits
- **No dependencies** — Python 3.8+ standard library only; nothing to install
- **Fails loud** — exits non-zero rather than writing an empty (but technically valid) VEX document
- **Handles export contention** — honors the export endpoint's `503` / `Retry-After` concurrency cap

## Requirements

Python 3.8 or newer. No packages to install.

## Setup

Set your Finite State API token:

```bash
export FS_TOKEN=<your api token>
```

`FINITE_STATE_AUTH_TOKEN` is also accepted (legacy name). If both are set, `FS_TOKEN` wins.

The token can also be passed with `--token`, which overrides both env vars — useful for CI systems that inject secrets as arguments. **Prefer the environment variable where you have the choice:** a command-line argument is visible to other users on the host via `ps` and is written to your shell history.

The token is sent as the `X-Authorization` header.

## Usage

### From a platform URL (recommended)

The API host is taken from the link, so this works on any tenant hostname:

```bash
python3 fs_vex_export.py \
  "https://app.finitestate.io/projects/<projectId>/versions/<versionId>/overview"
```

Writes a file named for the project, version, and UTC timestamp:

```
ACME_Router_v2.0_rc1_4c76b60b_20260903T142200483921.vex.cdx.json
```

### From a version ID

IDs can be a UUID or a plain (possibly negative) integer, depending on tenant:

```bash
export FINITE_STATE_DOMAIN=app.finitestate.io   # or FS_BASE=https://app.finitestate.io
python3 fs_vex_export.py 4c76b60b-1646-4fa5-b279-3902763b891a
```

### From project and version names

Costs every page of `/projects` plus every page of `/projects/{id}/versions` —
neither endpoint's name filter can be relied on for an exact, case-correct match,
so matching happens client-side over the full list. Fails if the name matches
zero or more than one record, rather than guessing:

```bash
export FINITE_STATE_DOMAIN=app.finitestate.io
python3 fs_vex_export.py --project "ACME Router" --version "1.2.3"
```

### Triaged vulnerabilities only

```bash
python3 fs_vex_export.py "<url>" --triaged-only
```

### Choosing where output goes

Override the generated name with `-o`, or send the document to stdout with `--stdout` to pipe it.
The two are mutually exclusive — passing both is a usage error, not a silent choice:

```bash
python3 fs_vex_export.py "<url>" -o vex.json
python3 fs_vex_export.py "<url>" --stdout | jq '.vulnerabilities | length'
```

Progress and warnings always go to stderr, so `--stdout` stays pipe-safe.

## Options

| Option | Description |
|---|---|
| `target` | Platform URL or version ID, UUID or int (positional; mutually exclusive with `--project`/`--version`) |
| `--project NAME` | Project name; requires `--version` |
| `--version NAME` | Version name; requires `--project` |
| `--triaged-only` | Keep only vulnerabilities carrying a VEX analysis block |
| `--base URL` | API base URL, overriding a URL's host, `FS_BASE`, and `FINITE_STATE_DOMAIN` |
| `--token TOKEN` | API token, overriding the env vars (prefer the env var — see Setup) |
| `-o`, `--output FILE` | Write to this path instead of the auto-generated filename |
| `--stdout` | Write the document to stdout instead of a file |
| `--self-test` | Run built-in checks and exit |

## Output

CycloneDX JSON containing:

- `metadata` — timestamp, tooling, manufacturer, and the product component the document describes
- `vulnerabilities[]` — one entry per finding, with `id`, `source`, `ratings`, `cwes`, `affects[]`, and an `analysis` block on triaged findings

Notably absent (by design): `components[]` and `dependencies[]`.

### File naming

By default the script writes to the current directory as:

```
<project>_<version>_<versionId>_<timestamp>.vex.cdx.json
```

Project and version names come from the document's own `metadata.component`, so this
costs no extra API call. Characters that are awkward in filenames are collapsed to
underscores, and the timestamp is UTC in the legacy platform's export format
(`YYYYMMDDTHHmmss`) plus microseconds, so two runs of the same version within the
same second don't overwrite each other's output. The `.vex.cdx.json` extension keeps
the CycloneDX JSON convention while making clear the file is a VEX document rather
than a full SBOM.

**Long names are shortened from the middle.** Firmware build strings are routinely
100+ characters, and left alone they push filenames past the 255-byte limit on
ext4/APFS/NTFS and past Windows' 260-character path limit once nested. Each name is
capped at 40 characters by removing the middle, marked with `~`:

```
BP_ACME1234_R03_BA0~CME9012_ACME1234_R02_BA02_r010_branch_AC~_AP14.0.0.01.012_V01_4c76b60b_20260903T142200483921.vex.cdx.json
```

The middle is dropped rather than the tail because sibling firmware versions share
long common prefixes and differ near the end — cutting the tail would discard the
part that identifies the build. Both the recognizable prefix and the distinguishing
suffix survive.

The first 8 characters of the version id are always included. Two different builds
can shorten to the same text, so this guarantees each filename is unique, and it
ties the file back to the exact platform record it came from.

Use `-o` if you need an exact filename.

### `affects[].ref` does not resolve

Each vulnerability's `affects[].ref` points at a component `bom-ref` that is not present in the document, because the component inventory has been removed. This matches the legacy platform's VDR output and is permitted by the CycloneDX specification. If a downstream consumer rejects it, the SBOM export (with components) is the document to send instead.

## Notes and limitations

**`--triaged-only` includes auto-triage.** The filter keys on the presence of a VEX analysis block, which is set by human triage *and* by the platform's auto-triage. It is not "human-triaged only." Strictly manual triage would require a per-finding activity lookup for every finding. Under `--triaged-only` the script prints `12 vulnerabilities (of 417)` to stderr so you can see how much was filtered.

**Empty results fail.** A version with no vulnerabilities — or none triaged, under `--triaged-only` — exits `1` and writes nothing, rather than producing an empty VEX document that could ship unnoticed. The two cases are reported distinctly:

```
no vulnerabilities for version <id>
no triaged vulnerabilities (417 untriaged) for version <id>
```

**CycloneDX spec version.** Output follows the version the platform emits (currently 1.6). The legacy platform emitted 1.4. Confirm which version a downstream consumer validates against before sending.

**Export contention and transient errors.** The SBOM export endpoint has a global concurrency cap and can return `503` even though this script makes a single call; other transient gateway errors (`429`, `500`, `502`, `504`) are retried the same way. It retries up to three times, honoring `Retry-After` in either its seconds or HTTP-date form, clamped to 5 minutes. The `503` case is a shared cap, not a per-caller rate limit.

**Requests time out after 5 minutes** rather than hanging indefinitely, so a stalled connection fails a pipeline instead of wedging it.

**API host precedence.** An explicit `--base` wins, then the hostname in a platform URL, then `FS_BASE` / `FINITE_STATE_DOMAIN` (checked in that order). A URL's own host deliberately outranks the env vars: hostnames are per-tenant, so a value left over from another tenant must not silently redirect a pasted link. When it is overridden this way the script says so on stderr. `FINITE_STATE_DOMAIN` follows this repo's usual bare-FQDN convention (e.g. `acme.finitestate.io`); `FS_BASE` accepts a bare FQDN too, or a full URL if you need a non-default scheme or port.

**Project/version IDs.** IDs may be a UUID or a plain (possibly negative) integer — this varies by tenant, and either form is accepted wherever an ID is expected.

**One version per run.** No batch mode.

## Roadmap

Tracked internally as **HELIX-1138** — add a first-class components-free CycloneDX export to the API, so this document can be requested directly instead of downloading a full SBOM and discarding the components.
