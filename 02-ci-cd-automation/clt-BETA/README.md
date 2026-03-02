# SBOM Tools

A suite of tools for Software Bill of Materials (SBOM) generation and component detection, with a focus on C/C++ projects.

## Overview

This project contains three main tools:

1. **Scanner** (`scanner/`) - Multi-detector SBOM scanner that combines a manifest parser, Ocean rules, and build-system manifest parsing
2. **Oceandrive** (`ocean/cmd/oceandrive/`) - Standalone rule matcher that scans directories against Ocean YAML rules
3. **Oceandive** (`ocean/cmd/oceandive/`) - Rule generation tool for creating detection rules from Git repositories

## Scanner

The scanner uses multiple detection methods to identify software components in a directory:

### Detection Methods

| Method | Description |
|--------|-------------|
| **Manifest Parser** | Detects packages declared through standard package-manager manifests |
| **Git** | Extracts repository metadata from `.git` directories |
| **Ocean Rules** | Custom YAML-based rules for C/C++ component detection |
| **Build System** | Detects components declared in build-system manifests (OpenWrt, Buildroot, Yocto, Autotools, CMake, Meson, pkg-config, Zephyr west, Microsoft Visual Studio, Bazel) |
| **AUTOSAR** | Extracts AUTOSAR software components from ARXML metadata files |

### Usage

```bash
cd scanner

# Basic scan (auto-saves CycloneDX to a timestamped .cdx.json file)
./scanner --dir /path/to/project --rules ../ocean/rules

# HTML report (auto-saved to <dirname>-sbom.html)
./scanner --dir /path/to/project --rules ../ocean/rules --format html

# JSON to stdout (debug)
./scanner --dir /path/to/project --rules ../ocean/rules --format simple

# Full JSON with all metadata
./scanner --dir /path/to/project --rules ../ocean/rules --format full

# Save to a specific file
./scanner --dir /path/to/project --rules ../ocean/rules --format html --output report.html

# Feedback UI (opens a local browser UI; auto-selects CycloneDX output)
./scanner --dir /path/to/project --rules ../ocean/rules --feedback --output project.cdx.json

# Upload CycloneDX SBOM to Finite State URL (uses FINITE_STATE_AUTH_TOKEN by default)
FINITE_STATE_AUTH_TOKEN=... ./scanner --dir /path/to/project --rules ../ocean/rules \
  --api-url https://fs.example.com/api --project-name "My Project" --project-version "1.0.0" \
  --format cyclonedx --output project.cdx.json

# Upload CycloneDX SBOM while also saving a local HTML report
FINITE_STATE_AUTH_TOKEN=... ./scanner --dir /path/to/project --rules ../ocean/rules \
  --api-url https://fs.example.com/api --project-name "My Project" --project-version "1.0.0" \
  --output report.html

# Or let the domain be auto-derived from FINITE_STATE_DOMAIN
export FINITE_STATE_DOMAIN="customer.finitestate.io"
export FINITE_STATE_AUTH_TOKEN="your-token"
./scanner --dir /path/to/project --rules ../ocean/rules \
  --project-name "My Project" --project-version "1.0.0"

# Full options
./scanner --help
```

> **macOS note:** The pre-built binaries are not Apple-signed. macOS Gatekeeper
> may block execution on first launch. Run `xattr -d com.apple.quarantine ./scanner`
> to clear the quarantine flag.

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--dir` | Directory to scan | `.` |
| `--format` | Output format (see below). When omitted and no `--output` is given, defaults to CycloneDX saved to a timestamped file. | (auto) |
| `--output` | Output file path. If `--format` is not set, the format is inferred from the filename (`.cdx.json` => CycloneDX, `.html` => HTML, `.json` => simple JSON). Uploads always send CycloneDX regardless of local output format. | (none) |
| `--feedback` | Open a feedback UI in your default browser after the scan (implies `--format cyclonedx` unless overridden). Lets you mark missed packages, flag incorrect detections, and add notes. Writes a feedback JSON bundle to the current directory. See [Feedback Mode](#feedback-mode---feedback) for details. | `false` |
| `--config` | Config file path | `config.yaml` |
| `--rules` | Ocean rules directory | (from config) |
| `--top-level` | Only report top-level project detections (overrides config `top_level_only`) | `false` |
| `--verbose` | Enable verbose output (conflict resolution log, progress snapshots) | `false` |
| `--dump-embedded-config` | Write embedded config to a file and exit (`-` for stdout) | (none) |
| `--version` | Print CLI build version and exit | `false` |
| `--api-url` | API base URL including `/api`; auto-derived from `FINITE_STATE_DOMAIN` if set | (none / from env) |
| `--api-token` | API token (overrides `FINITE_STATE_AUTH_TOKEN`) | from env |
| `--project-name` | Project name for upload | (none) |
| `--project-version` | Project version for upload | (none) |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `FINITE_STATE_DOMAIN` | Domain name (e.g. `customer.finitestate.io`). When set and `--api-url` is not provided, the API URL is derived as `https://<domain>/api`. |
| `FINITE_STATE_AUTH_TOKEN` | API authentication token. Used as fallback when `--api-token` is not provided. |

### Output Formats

| Format | Description |
|--------|-------------|
| `simple` | Compact JSON array of detections with core fields (name, version, type, method, locations). Good for piping into other tools. |
| `full` | Complete JSON with all metadata including matched indicators, version files, rule sources, and scan paths. Use for debugging or detailed analysis. |
| `html` | Interactive HTML report with a summary dashboard, expandable directory tree showing where components were detected, and a filterable/searchable component table. Auto-saves to `<dirname>-sbom.html` if no `--output` is specified. |
| `cyclonedx` | CycloneDX JSON SBOM (required for uploads). |

### Feedback Mode (`--feedback`)

The `--feedback` option opens an interactive review UI in your default browser after the scan completes. It is designed for customers who want to provide us with feedback about the scan results so we can improve detection accuracy.

**What you can do in the feedback UI:**

- **Mark missed packages** — right-click any directory or file in the tree and select *Mark missed* to tell us the scanner didn't detect a component that should be there.
- **Flag incorrect detections** — right-click a detection card (or its parent directory) and select *Mark incorrect* to report a false positive, a wrong version, or a misidentified component.
- **Add notes** — right-click and select *Add/edit note…* to attach free-text context (e.g. "this is actually libfoo 2.1, vendored under a different name").
- **Undo** — click *Remove* next to any item in the feedback list to retract it.

**Git-only detections are included automatically.** When the scanner finds a git repository that no other detector (Ocean rules, manifest parser, build system) has covered, it appears in the feedback list as a `git` entry. These entries highlight subprojects where we may need to create or expand detection rules, and they are included in the exported feedback bundle by default so we can prioritise rule development.

**How it works:**

1. The scanner finishes the normal scan and writes the CycloneDX output.
2. A temporary HTTP server starts on `127.0.0.1` (localhost only) and your default browser opens the feedback UI.
3. You review the directory tree, mark items, and click **Generate feedback**.
4. A timestamped JSON file (e.g. `myproject-feedback-20260224-143012.json`) is written to the current working directory. Send this file back to us.
5. The server shuts down automatically after feedback is generated.

**Usage:**

```bash
./scanner --dir /path/to/project --rules ../ocean/rules --feedback --output project.cdx.json
```

> **Note:** `--feedback` automatically sets the output format to CycloneDX. You can still override with an explicit `--format`, but only CycloneDX is supported for feedback.

### API Payload Schema

For a normalized API-ready payload (with deduplicated findings and per-scanner evidence), see `scanner/API_SCHEMA.md`.

### Configuration (`config.yaml`)

```yaml
# Package types to exclude from results
exclude_types:
  - github-action
  - github-action-workflow

# Types considered infrastructure (not application code)
infrastructure_types:
  - binary

output:
  format: html
  include_git_info: true

detectors:
  manifest_parser:
    enabled: true
  git:
    enabled: true
  ocean:
    enabled: true
    rules_dir: ../ocean/rules
  build_system:
    enabled: true
```

---

## Oceandrive (Rule Matcher)

Oceandrive is a lightweight, standalone tool that scans a directory tree against Ocean YAML rules to identify software components. Unlike the full scanner, it does not require any external dependencies — just the Go binary and a rules directory.

It recursively walks the entire directory tree with no depth limit, testing every subdirectory as a potential project root. This means deeply nested third-party components (e.g. `src/thirdparty/mbedtls/`) are found automatically.

### Usage

```bash
cd ocean

# Scan a directory
./oceandrive -rules ./rules /path/to/project

# JSON output
./oceandrive -rules ./rules -format json /path/to/project

# Summary (one line per component)
./oceandrive -rules ./rules -format summary /path/to/project

# Save to file
./oceandrive -rules ./rules -format json -output results.json /path/to/project

# Save to file
./oceandrive -rules ./rules -format json -output results.json /path/to/project
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-dir` | Directory to scan (or use positional arg) | (required) |
| `-rules` | Directory containing YAML rules | `oceandive_rules` |
| `-format` | Output format (see below) | `text` |
| `-output` | Output file path | stdout |

### Output Formats

| Format | Description |
|--------|-------------|
| `text` | Human-readable output with component name, version, matched indicators, version source file, and repo URL. |
| `json` | JSON array of match results with all fields including indicator counts, matched paths, and version file. |
| `summary` | Compact one-line-per-component output: `path: name version`. Good for quick overviews. |

### Build

```bash
cd ocean
go build -o oceandrive ./cmd/oceandrive
```

---

## Build System Detector

The build-system detector identifies software components declared in build-system manifests. It walks the entire directory tree, parsing manifest files for component declarations — package recipes that describe what to download and compile, and project-level metadata that declares names and versions.

### When it helps

The manifest parser analyzes installed packages or lock files, and Ocean rules match against actual source trees. The build-system detector fills two gaps:

1. **Package recipe repos** (OpenWrt, Buildroot, Yocto) — the upstream source isn't present, only download recipes. Scanning [OpenWrt](https://openwrt.org/) with just the manifest parser and Ocean rules finds zero application-level components. With the build-system detector, it discovers **298 components** including OpenSSL, zlib, curl, busybox — each with name, version, license, and CPE.

2. **Source project metadata** (Autotools, CMake, Meson, Bazel, etc.) — these files declare the project's name and version in a structured way, providing a reliable cross-check against other detectors.

### Configuration

The detector is **enabled by default** (it's lightweight — no external dependencies). Disable it in `config.yaml` if not needed:

```yaml
detectors:
  build_system:
    enabled: false
```

### Supported build systems

| Build System | File types | What's extracted |
|--------------|-----------|-----------------|
| **OpenWrt** | `Makefile` | `PKG_NAME`, `PKG_VERSION`, `PKG_SOURCE_URL`, `PKG_LICENSE`, `PKG_CPE_ID` |
| **Buildroot** | `*.mk` | `PKG_*` variables with `$(BR2_EXTERNAL)` / `GENTARGETS` detection |
| **Yocto / BitBake** | `*.bb` | Name/version from filename, `LICENSE`, `SRC_URI`, `CVE_PRODUCT`, `HOMEPAGE`. Skips `.bbappend` overlays and `-native`/`-cross` recipes. |
| **Autotools** | `configure.ac`, `configure.in` | Project name and version from `AC_INIT([name], [version])` |
| **CMake** | `CMakeLists.txt` | Project name and version from `project(name VERSION x.y.z)` |
| **Meson** | `meson.build` | Project name and version from `project('name', version: 'x.y.z')` |
| **pkg-config** | `*.pc`, `*.pc.in` | `Name` and `Version` fields (skips template placeholders) |
| **Zephyr west** | `west.yml`, `west.yaml` | All project dependencies with git URLs and pinned revisions |
| **Bazel (WORKSPACE)** | `WORKSPACE`, `WORKSPACE.bazel` | `http_archive` and `git_repository` deps with name, version (from `strip_prefix` or URLs), and repo URL |
| **Bazel (bzlmod)** | `MODULE.bazel` | `module(name, version)` identity and `bazel_dep(name, version)` dependencies |
| **Visual Studio** | `.sln`, `.dsw` | Solution/workspace project listings |
| **MSBuild** | `.vcxproj` | Project name, configurations, include dirs, defines, link libraries, source files (resolves `.props` imports) |
| **VS Legacy** | `.vcproj`, `.dsp` | Project name, configurations, compiler flags, source files |
| **NMAKE** | `*.mak` | Target name, include dirs, defines, link libraries (when `cl.exe`/`link.exe` detected) |

### Metadata

Each detection includes a `build_system` metadata field identifying the source (`openwrt`, `buildroot`, `yocto`, `autotools`, `cmake`, `meson`, `pkg-config`, `west`, `bazel`, `visual-studio`, `msbuild`, `nmake`), plus system-specific metadata:

- **OpenWrt/Buildroot**: all raw `PKG_*` variables, `cpe_id`, vendor/product parsed from CPE
- **Yocto**: recipe variables, `cve_product`, source URLs
- **Bazel WORKSPACE**: `bazel_name` (canonical Bazel repo name), `bazel_format` (`workspace` or `module`), repo URL
- **Bazel MODULE**: `bazel_name`, `bazel_repo_name` (if different), `bazel_format`
- **Visual Studio/MSBuild**: `msvc_format`, configurations, config-specific include dirs/defines/link libraries, source files, project references
- **Zephyr west**: pinned git revision, install path, repo URL

---

## Oceandive (Rule Generator)

Oceandive generates YAML-based detection rules from Git repositories. It analyzes source code to find:
- Version files and extraction patterns
- Indicator files unique to the project
- Safety checks to prevent false positives

### Usage

```bash
cd ocean

# Generate rule from local Git clone
./oceandive /path/to/git/repo

# With OpenAI review (improves rule quality)
export OPENAI_API_KEY='sk-...'
./oceandive /path/to/git/repo -use-openai

# Specify project name
./oceandive /path/to/git/repo -name myproject

# Custom output directory
./oceandive /path/to/git/repo -out ./my-rules
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-tree` | Directory to analyze | (positional arg) |
| `-name` | Project name | directory name |
| `-out` | Output directory | `rules` |
| `-use-openai` | Enable AI review | `false` |
| `-ai-log` | Log AI modifications | (none) |
| `-json-out` | Output JSON results | (none) |

### Batch Processing

For processing multiple repositories:

```bash
# Create repos.txt with one URL per line
cat > repos.txt << EOF
https://github.com/curl/curl
https://github.com/openssl/openssl
https://github.com/sqlite/sqlite
EOF

# Run batch generation
./batch-generate.sh repos.txt ./rules --blobless --use-openai

# With parallel processing (4 jobs)
./batch-generate.sh repos.txt ./rules --blobless --parallel 4

# Resume interrupted batch (skips existing rules)
./batch-generate.sh repos.txt ./rules --blobless

# Force regeneration
./batch-generate.sh repos.txt ./rules --blobless --force
```

### Batch Options

| Option | Description |
|--------|-------------|
| `--shallow` | Shallow clone (fastest, HEAD only) |
| `--blobless` | Blobless clone (fast, full history) |
| `--full` | Full clone (slowest, everything) |
| `--parallel N` | Run N jobs in parallel |
| `--force` | Regenerate existing rules |
| `--keep` | Keep cloned repos after processing |
| `--use-openai` | Enable AI review |
| `--timeout N` | Kill jobs after N seconds |

### Generated Rule Format

```yaml
components:
  - name: curl
    top_level: true
    vendor: curl
    product: curl
    repo: https://github.com/curl/curl
    purl: pkg:github/curl/curl
    license: MIT
    license_file: COPYING
    type: oss
    
    # Files that indicate this component is present
    indicators:
      any_of:
        - path: lib/urldata.h
        - path: lib/curl_setup.h
        - path: include/curl/curl.h
    min_indicators: 2
    
    # Version extraction
    version:
      candidates:
        - path: include/curl/curlver.h
          regex: ^\s*#define\s+LIBCURL_VERSION\s+"(?P<version>[^"]+)"
    
    # Safety check to prevent false positives
    safety_check:
      path: include/curl/curl.h
      contains: "CURL_EXTERN"
```

### Rule Fields

| Field | Description |
|-------|-------------|
| `name` | Component name (lowercase) |
| `top_level` | Whether this is a top-level project (`true` for standalone projects) |
| `vendor` | Vendor/organization |
| `product` | Product identifier (lowercase) |
| `repo` | Source repository URL |
| `purl` | Package URL (e.g. `pkg:github/owner/repo`) |
| `license` | SPDX license identifier (e.g. `MIT`, `GPL-2.0`, `Apache-2.0`) |
| `license_file` | Path to license file in the repository |
| `type` | Component type (`oss`) |
| `indicators.any_of` | List of indicator file paths (should be project-specific, not generic) |
| `min_indicators` | Minimum indicators required |
| `version.candidates` | Version extraction rules |
| `safety_check` | Content check to verify match |

---

## Generating Detection Rules with AI (MCP Rule Generator)

The `tools/` directory contains an AI-powered rule generator for creating Ocean detection rules from git repositories. It uses the [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) to give an OpenAI model **direct tool access** to a git repository. The AI autonomously explores the repo — listing files, reading content, searching for patterns, and testing regexes — to build detection rules without any manual intervention.

### Architecture

The system consists of two Python scripts:

- **`tools/mcp_git_server.py`** — An MCP server that wraps git operations (`ls-tree`, `show`, `tag`) as callable tools, communicating over stdio.
- **`tools/mcp_rulebot.py`** — The orchestrator that launches the MCP server as a subprocess and runs an OpenAI tool-calling conversation loop, relaying tool calls and results between the AI and the server.

```
┌─────────────┐     tool calls       ┌─────────────────┐    stdio (JSON-RPC)  ┌──────────┐
│   OpenAI    │ ◄──────────────────► │  mcp_rulebot.py │ ◄──────────────────► │ MCP Git  │
│             │   tool results       │  (orchestrator) │                      │  Server  │
└─────────────┘                      └─────────────────┘                      └──────────┘
                                                                                   │
                                                                              git ls-tree
                                                                              git show
                                                                              git tag -l
                                                                                   │
                                                                              ┌──────────┐
                                                                              │ Git Repo │
                                                                              └──────────┘
```

The AI is given a system prompt that instructs it to:

1. Explore the repository structure, tags, and license.
2. Select 4–6 distinctive indicator files and verify their stability across releases. Indicators are scored for project specificity (tier 0 = generic, tier 3 = contains project name) and the AI uses `check_indicator_specificity` to self-check before finalizing.
3. Choose a safety check (file + distinctive string).
4. Find version-defining files, write a regex, and **test it via the `test_regex` tool** before committing to a rule.
5. Output the final YAML rule with `top_level`, `purl` (derived from repo URL), and `license` (SPDX ID).

### Available Tools

The MCP server exposes the following tools to the AI:

| Tool | Description |
|------|-------------|
| `get_repo_info` | Repository name, remote URL, tag count, and detected license (SPDX) |
| `get_tags` | Version-sorted tags with optional limit |
| `list_files` | File tree at any tag, with glob filtering |
| `read_file` | Read file content at a specific tag |
| `search_files` | Regex search across file contents at a tag |
| `test_regex` | Test a regex against a file and return named capture groups |
| `compute_stability` | Check how consistently files appear across recent tags |
| `extract_version_from_tag` | Parse a version string from a tag name (e.g. `v1.2.3` → `1.2.3`) |
| `check_indicator_specificity` | Score indicator paths for project specificity (tiers 0–3) and return an aggregate quality grade (GOOD/ACCEPTABLE/POOR) |

### Setup

**Prerequisites:** Python 3.11+, `git` on PATH, an OpenAI API key.

```bash
# 1. Create a virtual environment
python3 -m venv ~/venv
source ~/venv/bin/activate

# 2. Install dependencies
pip install openai pyyaml mcp

# 3. Set environment variables
export OPENAI_API_KEY="sk-your-key-here"

# Tell the orchestrator which python has the mcp package.
# Only needed if your default python3 is not the venv one.
export MCP_PYTHON="$HOME/venv/bin/python3"

# 4. Verify
python3 -c "from mcp.server.fastmcp import FastMCP; from openai import OpenAI; import yaml; print('OK')"
```

Add the exports to `~/.bashrc` to persist them.

### Usage

```bash
# Single repo (local clone)
python3 tools/mcp_rulebot.py /path/to/repo --out rules/ --verbose

# Single repo (GitHub URL — auto-clones to a temp directory)
python3 tools/mcp_rulebot.py https://github.com/curl/curl --out rules/ --verbose

# With post-generation validation against sampled tags
python3 tools/mcp_rulebot.py /path/to/repo --out rules/ --validate --verbose

# Batch mode: point at a directory of git clones
python3 tools/mcp_rulebot.py /path/to/clones/ --out rules/ --jobs 4 --verbose
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `repo` | Path to git repo, GitHub URL, or directory of repos | (required) |
| `--out` | Output directory for generated YAML rules | `.` |
| `--model` | OpenAI model to use | `gpt-5.2` |
| `--max-turns` | Maximum tool-calling turns per repo | `30` |
| `--validate` | Validate the rule against a sample of tags after generation | off |
| `--min-pass-rate` | Minimum validation pass rate (0.0–1.0) | `0.6` |
| `--jobs` | Parallel jobs for batch mode | `1` |
| `--no-filter` | Disable the C/C++ pre-filter (see below) | off |
| `-v`, `--verbose` | Show tool calls and results as they happen | off |

### C/C++ Pre-Filter

In batch mode the tool automatically skips non-C/C++ repositories before making any API calls. The filter runs three checks:

1. **Root package manager files** — Instant skip if the repo root contains a language-specific manifest such as `pom.xml` (Java), `Cargo.toml` (Rust), `go.mod` (Go), `package.json` (Node), `setup.py`/`pyproject.toml` (Python), `Gemfile` (Ruby), `*.csproj`/`*.sln` (.NET), and others.
2. **Minimum C/C++ file count** — At least 10 files with C/C++ extensions (`.c`, `.h`, `.cpp`, `.hpp`, etc.).
3. **Minimum C/C++ ratio** — C/C++ files must make up at least 15% of the total file tree.

Use `--no-filter` to bypass all three checks.

### Output

Complete rules are saved as `<project>.yaml`. If version extraction fails but identification is sound, a partial rule is saved as `<project>.partial.yaml`:

```
rules/
├── curl.yaml            # Complete rule (indicators + version)
├── ncurses.yaml         # Complete rule
└── mylib.partial.yaml   # Identification only, no version extraction
```

### Multi-Era Version Coverage

The tool automatically checks whether the generated rule covers the full tag history. If older tags fail (due to file layout changes or version file moves), it generates additional component entries targeting those older eras. All eras are merged into the single output YAML under the `components:` list.

- Up to **3 eras** per project (configurable via `MAX_ERAS` in the source).
- Only gaps of 3+ consecutive failing tags trigger a new era.
- Each era rule is validated before being included.

### Validating Rules

The `tools/validate_rules.py` script checks all YAML rules in `ocean/rules/` for correctness and quality. Run it after generating new rules or editing existing ones:

```bash
source ~/tools/venv/bin/activate
python3 tools/validate_rules.py
```

The validator checks for:

- **Structural errors** — missing required fields (`name`, `indicators`, `safety_check`, `version`), invalid regex patterns, malformed YAML.
- **Indicator quality** — each component's indicators are scored for project specificity using a tier system (0 = fully generic, 3 = contains project name). Components graded POOR are flagged.
- **Missing metadata** — warns about missing `top_level`, `purl`, or `license` fields.

The quality grades are:

| Grade | Criteria |
|-------|----------|
| **GOOD** | ≤1 generic indicator, ≥3 specific indicators, directory diversity ≥2 (or ≥3 project-name indicators) |
| **ACCEPTABLE** | ≤2 generic indicators, ≥2 specific indicators |
| **POOR** | Anything worse — too many generic paths or too few specific ones |

The scoring logic lives in `tools/indicator_quality.py` and is shared between the validator, the MCP rule generator (for post-generation checks), and the `check_indicator_specificity` MCP tool (for AI self-correction during generation).

### API Cost Considerations

Each repo requires one or more OpenAI API calls. Understanding the cost profile helps avoid surprises when running at scale.

**Per-repo cost drivers:**

| Phase | API calls | When |
|-------|-----------|------|
| Primary rule generation | 1 conversation, ~8–15 turns | Always |
| Era rule generation | 1 conversation per era, ~8–15 turns each | Only when coverage gaps found (up to 2 extra) |
| Validation | 0 API calls (local git only) | When `--validate` is set |

Each "turn" is one OpenAI request/response round-trip. A typical repo uses 8–15 turns for the primary rule. Projects with restructured histories may use up to 3x that (one conversation per era).

**Rough estimates (GPT-4.1 pricing as reference):**

| Scenario | Estimated cost |
|----------|---------------|
| Single repo, no eras | ~$0.05–0.15 |
| Single repo, 2 extra eras | ~$0.15–0.45 |
| Batch of 50 C/C++ repos | ~$2.50–7.50 |
| Batch of 100 repos (50 skip filter) | ~$2.50–7.50 |

Costs scale with model choice. Using `--model gpt-4.1-mini` is significantly cheaper (~10x) at the expense of some rule quality.

**Tips for controlling cost:**
- Use `--max-turns 15` to cap turns per conversation (default is 30).
- Start with a small batch to verify quality before processing hundreds of repos.
- The C/C++ pre-filter skips non-C/C++ repos at zero API cost.
- Partial rules (`.partial.yaml`) don't trigger era generation.

### Deploying to AWS

```bash
# From your local machine — copy the scripts
scp tools/mcp_git_server.py tools/mcp_rulebot.py tools/indicator_quality.py tools/validate_rules.py user@instance:~/tools/

# On the instance
python3 -m venv ~/venv && source ~/venv/bin/activate
pip install openai pyyaml mcp

echo 'export OPENAI_API_KEY="sk-..."' >> ~/.bashrc
echo 'export MCP_PYTHON="$HOME/venv/bin/python3"' >> ~/.bashrc
source ~/.bashrc

# Generate rules for a directory of cloned repos
python3 ~/tools/mcp_rulebot.py /path/to/clones/ --out ~/rules/ --jobs 4 --verbose
```

---

## Building

### Prerequisites

- Go 1.21+
- For scanner: Local manifest parser source dependency

### Setting up the manifest parser dependency

The scanner requires a local checkout of the manifest parser library (referenced via `replace` directive in `go.mod`):

```bash
# Clone the dependency into the project root
cd syft_mod
git clone https://github.com/anchore/syft.git

# The scanner's go.mod expects it at ../syft relative to scanner/
# This is already configured via:
#   replace github.com/anchore/syft => ../syft
```

### Build Scanner

```bash
cd scanner
go build -o scanner .
```

### Build Ocean Tools

```bash
cd ocean

# Build oceandrive (rule matcher)
go build -o oceandrive ./cmd/oceandrive

# Build oceandive (rule generator)
go build -o oceandive ./cmd/oceandive

# Cross-compile for Linux (AWS)
GOOS=linux GOARCH=amd64 go build -o oceandrive-linux ./cmd/oceandrive
GOOS=linux GOARCH=amd64 go build -o oceandive-linux ./cmd/oceandive
```

---

## Testing

### Scanner Detection Tests

The scanner includes comprehensive unit tests for the detection logic:

```bash
cd scanner/detection
go test -v ./...
```

#### Test Coverage

**Ocean detector tests** (`ocean_detector_test.go`):

| Test Suite | Description |
|------------|-------------|
| `TestMatchOceanPath` | Path matching (exact, suffix, regex patterns) |
| `TestMatchOceanContent` | Content matching (contains, regex with flags) |
| `TestBuildRegexFlags` | Regex flag conversion (MULTILINE, DOTALL, IGNORECASE) |
| `TestExtractVersionFromFile` | Version extraction (single capture, compose, fallback) |
| `TestMultiDetectorResult` | Result container operations |
| `TestOceanDetector` | Detector initialization and configuration |
| `TestOceanDetectorDetect` | Full detection with indicators, version, safety check |
| `TestOceanDetectorSafetyCheckFails` | Safety check failure handling |
| `TestOceanDetectorInsufficientIndicators` | Minimum indicators enforcement |
| `TestDeduplicateDetections` | Detection deduplication logic |
| `TestOceanDetectorMultiEra` | Multi-era rule handling (old + new layout) |
| `TestOceanDetectorMultiEraBothMatch` | Multi-era rules where both eras match |

**Build system detector tests** (`buildsystem_detector_test.go`):

| Test Suite | Description |
|------------|-------------|
| `TestParseMakeVar` | Makefile variable parsing (`:=`, `=`, `+=`, unknown keys) |
| `TestParseCPE` | CPE 2.2 and 2.3 vendor/product extraction |
| `TestCleanMakeVersion` | Version string cleanup (macro stripping, separators) |
| `TestCleanSourceURL` | URL cleanup (`.git` suffix, macros, multi-URL lines) |
| `TestParseBuildSystemMakefile` | Full Makefile parsing (OpenWrt, kernel-version skip, missing PKG_NAME) |
| `TestBuildSystemDetector_Detect` | End-to-end detection of OpenWrt-style directory trees |
| `TestCleanBBVersion` | BitBake version cleanup (`${SRCPV}`, `+git` stripping) |
| `TestExtractBBSourceURL` | BitBake SRC_URI parsing (parameters, file:// skipping) |
| `TestBBRecipeNameRegex` | Recipe filename parsing (`name_version.bb` patterns) |
| `TestParseBitBakeRecipe` | Full BitBake recipe parsing |
| `TestBuildSystemDetector_Yocto` | End-to-end Yocto recipe detection |
| `TestBuildSystemDetector_EmptyDir` | Empty directory produces zero detections |
| `TestIsVersionLike` | Version string validation |
| `TestParseConfigureAC` | Autotools AC_INIT parsing |
| `TestParseCMakeProject` | CMake project() VERSION parsing |
| `TestParseMesonBuild` | Meson project() version parsing |
| `TestParsePkgConfig` | pkg-config Name/Version parsing |
| `TestBuildSystemDetector_SourceMetadata` | End-to-end source metadata detection |
| `TestIsHexString` | Hex string validation for git commits |
| `TestParseWestManifest` | Zephyr west manifest parsing |
| `TestBuildSystemDetector_WestManifest` | End-to-end west manifest detection |
| `TestParseVisualStudioSolution` | .sln project listing |
| `TestParseVCProj` | Legacy .vcproj XML parsing |
| `TestParseVCXProj` | MSBuild .vcxproj parsing (with .props import resolution) |
| `TestParseDSPAndDSW` | Developer Studio .dsp/.dsw parsing |
| `TestParseMSVCMak` | NMAKE .mak file parsing |
| `TestBuildSystemDetector_MicrosoftFormats` | End-to-end Microsoft format detection |
| `TestExtractStarlarkCalls` | Starlark function call extraction (nested parens, comments) |
| `TestExtractStarlarkStringArgs` | Starlark keyword argument parsing |
| `TestExtractStarlarkListItems` | Starlark list argument extraction |
| `TestExtractVersionFromBazelPrefix` | Bazel strip_prefix version extraction |
| `TestExtractNameFromBazelPrefix` | Bazel strip_prefix name extraction |
| `TestExtractVersionFromURL` | Version extraction from download URLs |
| `TestParseBazelWorkspace` | Full WORKSPACE parsing (http_archive, git_repository) |
| `TestParseBazelModule` | MODULE.bazel parsing (module, bazel_dep) |
| `TestParseBazelWorkspace_GitRepositoryCommit` | git_repository with commit hash |
| `TestParseBazelWorkspace_Empty` | Empty WORKSPACE handling |
| `TestBuildSystemDetector_BazelIntegration` | End-to-end Bazel detection |

#### Key Test Scenarios

**Version Extraction Patterns:**
- Simple version capture: `#define VERSION "1.2.3"`
- AC_INIT pattern: `AC_INIT([project], [1.2.3])`
- CMake project(): `project(mylib VERSION 1.2.3)`
- Meson project(): `project('name', version: '1.2.3')`
- Bazel strip_prefix: `grpc-1.30.0` → version `1.30.0`
- Bazel MODULE: `module(name = "...", version = "...")`
- Split version with compose: `#define FOO_VERSION_MAJOR 1` + `MINOR` + `PATCH`
- NEWS file formats (older and newer GNU styles)

**Path Matching:**
- Exact path matching with/without leading slash
- Suffix matching for nested directories
- Regex patterns for flexible file matching

**Safety Checks:**
- Content verification (contains string)
- Regex-based content matching
- Failure when safety check content not found

---

## Deployment

### Deploy to AWS

**MCP Rule Generator (Python):**
```bash
# Copy the scripts
scp -i ~/path/to/key.pem \
  tools/mcp_git_server.py tools/mcp_rulebot.py tools/indicator_quality.py tools/validate_rules.py \
  ubuntu@<ip>:~/tools/

# On the instance: set up Python environment
ssh -i ~/path/to/key.pem ubuntu@<ip>
python3 -m venv ~/venv && source ~/venv/bin/activate
pip install openai pyyaml mcp
echo 'export OPENAI_API_KEY="sk-..."' >> ~/.bashrc
echo 'export MCP_PYTHON="$HOME/venv/bin/python3"' >> ~/.bashrc
source ~/.bashrc
```

**Ocean / oceandive (Go binary):**
```bash
# Deploy oceandive binary
scp -i ~/path/to/key.pem \
  ocean/oceandive-linux \
  ubuntu@<ip>:~/ocean/oceandive

# Deploy batch script
scp -i ~/path/to/key.pem \
  ocean/batch-generate.sh \
  ubuntu@<ip>:~/ocean/

# Deploy rules
scp -i ~/path/to/key.pem -r \
  ocean/rules/ \
  ubuntu@<ip>:~/ocean/
```

---

## Environment Variables

| Variable | Description | Used By |
|----------|-------------|---------|
| `OPENAI_API_KEY` | API key for OpenAI integration | `mcp_rulebot.py`, `oceandive` |
| `MCP_PYTHON` | Python interpreter with `mcp` package installed | `mcp_rulebot.py` |
| `OCEAN_VERBOSE` | Enable verbose output (`1`) | `oceandive` |
| `OCEAN_DEBUG` | Enable debug output for rule matching (`1`) | `oceandive` |

```bash
export OPENAI_API_KEY="sk-..."
export MCP_PYTHON="/path/to/venv/bin/python3"
```

---

## Output Examples

### Scanner JSON Output

```json
[
  {
    "name": "curl",
    "version": "8.5.0",
    "type": "oss",
    "method": "ocean-rules",
    "purl": "pkg:github/curl/curl@8.5.0",
    "locations": ["lib/urldata.h", "include/curl/curl.h"]
  },
  {
    "name": "openssl",
    "version": "3.2.0",
    "type": "go-module",
    "method": "manifest-parser",
    "purl": "pkg:golang/github.com/openssl/openssl@3.2.0",
    "locations": ["go.mod"]
  },
  {
    "name": "zlib",
    "version": "1.3.1",
    "type": "build-system-package",
    "method": "build-system",
    "vendor": "zlib",
    "product": "zlib",
    "licenses": ["Zlib"],
    "locations": ["/tools/zlib/Makefile"],
    "repo": "https://github.com/madler/zlib"
  }
]
```

### Scanner HTML Report

The HTML report is a self-contained, single-file page (no external dependencies) with:
- **Summary dashboard** — total components, unique names, and per-scanner breakdown (Manifest Parser, Ocean Rules, Build System, Git) with color-coded cards
- **Interactive directory tree** — expandable/collapsible tree showing the full scanned directory structure; each directory that contains detected components displays a badge count and inline detection cards with component name, version, and scanner method
- **Filterable component table** — searchable table of all detections with columns for component name, version, type, detection method, and location; filter buttons let you narrow by scanner (e.g. show only Ocean Rules detections)
- **Cross-scanner overlap table** — components detected by more than one scanner are highlighted in a dedicated table showing which scanners agree and the versions each found
- **Color-coded method indicators** — each scanner has a distinct color (blue=Manifest Parser, purple=Ocean, gold=Build System, orange=Git) used consistently across the dashboard, tree, and table

---

## Architecture

```
syft_mod/
├── scanner/           # SBOM scanner
│   ├── main.go        # CLI entry point
│   ├── detection/     # Detector implementations
│   │   ├── types.go              # Common types and interfaces
│   │   ├── manifestparser_detector.go  # Package-manager manifest detection
│   │   ├── git_detector.go       # Git metadata extraction
│   │   ├── ocean_detector.go     # YAML rule-based detection
│   │   ├── buildsystem_detector.go # Build-system manifest detection (OpenWrt, Yocto, CMake, Bazel, VS, etc.)
│   │   ├── autosar_detector.go   # AUTOSAR ARXML component detection
│   │   └── multi_detector.go     # Orchestrates all detectors
│   └── config.yaml    # Configuration
│
├── ocean/             # Rule generator and matcher
│   ├── cmd/oceandive/ # Rule generation CLI
│   ├── cmd/oceandrive/# Rule matching CLI (standalone scanner)
│   ├── matcher/       # Rule matching engine
│   ├── rulegen/       # Rule generation logic
│   │   ├── rulegen.go # Algorithmic detection
│   │   └── openai.go  # AI-assisted review
│   ├── common/        # Shared types and utilities
│   ├── rules/         # Generated YAML rules
│   └── batch-generate.sh
│
└── tools/             # Python utilities
    ├── mcp_git_server.py         # MCP server: git repo tools via stdio
    ├── mcp_rulebot.py            # MCP orchestrator: AI rule generation
    ├── indicator_quality.py      # Shared indicator specificity scoring
    └── validate_rules.py         # Standalone rule validation/linting
```

---

## License

[Add your license here]
