# Clone a Version into a New Project

Branch one version of a project into a **new project**, keeping the triage work done on it:

| Carried over | How |
|---|---|
| Components | The source version is exported as CycloneDX and imported into the new project. Nothing is rescanned and component identities stay the same. |
| Component edits | The export carries the current (edited) values, so the new components start with them. |
| Exclusions | Re-applied with the original comment and "exclude in future versions" setting. Excluded components are added back into the SBOM so that they exist in the new version. |
| Component status | Status and status comment. |
| Finding VEX | Status, justification, response and reason. Applied per finding, matched on CVE **and** component, so one component's decision never spreads to another component with the same CVE. |
| Finding comments | Copied in their original order. Each starts with `[Copied from <project> / <version> - <author>, <date>]`. |
| Version dependencies | Optional, with `--include-dependencies`. |

## Requirements

- Python 3.8+
- An API token with permission to read the source version and to create projects.

Install the dependencies:

```bash
pip install -r requirements.txt
```

Or skip the install and run it with `uv run clone_version.py`, which reads the dependency list from the top of the script.

Set your credentials:

```bash
export FINITE_STATE_AUTH_TOKEN=<your_api_token>
export FINITE_STATE_DOMAIN=<your_fqdn>     # e.g. acme.finitestate.io
```

## Usage

Preview first. A dry run only reads; it creates and changes nothing:

```bash
python clone_version.py --source-version <versionId> --dry-run
```

Then clone:

```bash
python clone_version.py \
  --source-version <versionId> \
  --new-project-name "Gateway 4.2 (customer branch)" \
  --report clone_report.json
```

| Option | Default | Meaning |
|---|---|---|
| `--source-version` | required | ID of the version to branch. It's in the version's URL. |
| `--new-project-name` | required (except with `--dry-run`) | Name of the new project. It must not already exist in the folder. |
| `--version-name` | source version's name | Name of the version in the new project. |
| `--release-type` | `RELEASE` | `RELEASE` or `PRE-RELEASE`. The API doesn't expose the source's release type. |
| `--folder-id` | org default | Folder to create the project in. |
| `--include-dependencies` | off | Also copy the version's links to other project versions. |
| `--skip-comments` | off | Don't copy finding comments. |
| `--target-version` | | Resume a run that stopped after creating the project. Pass the new version ID that the earlier run printed. Re-applying is safe: statuses and VEX are set to the same values again, and comments already copied are not posted twice. It only resumes into a project this script created from the same source version (the source version ID is recorded in the project description). |
| `--force-target` | off | With `--target-version`, skip the check that the target project was created by this script from this source. |
| `--scan-timeout` | `180` | Minutes to wait for the SBOM import to finish. If it is still running, re-run later with `--target-version`. |
| `--dry-run` | off | Read the source and show what would be copied. |
| `--report` | `clone_report_<date-time>.json` | JSON report: counts, anything that couldn't be matched, failed calls, shortened comments, and a check of every copied value. Written even if the run stops part-way. By default each run writes a new file named with its start time, so a later run does not replace an earlier run's report. |
| `--self-test` | | Run the built-in checks and exit. |

The script exits with `0` when all triage that applies to the new version was copied. It exits with `1` when any call failed, any copied value didn't land, or a component or finding that had triage didn't come across. The report lists each one.

## What happens

1. Reads the source version's components and findings, including excluded components and the findings on them, with their comments.
2. Exports the version as CycloneDX **without** VEX. VEX is replayed through the API instead, so it's recorded as real triage.
3. Creates the project and the version. The empty placeholder version that project creation adds is removed.
4. Uploads the SBOM to the new version and waits for processing to finish.
5. Matches components by purl, or by group, name, version and type when there's no purl, and matches findings by CVE plus component.
6. Re-applies exclusions, component statuses, finding VEX and comments.
7. Re-reads the new version and checks every copied value: exclusion and its comment and "exclude in future versions" setting; component status and status comment; finding status, justification, response and reason; and comments.

The API is limited to about 100 requests per minute. The script paces its calls and retries on `429`, `502`, `503` and `504`, honouring the server's `Retry-After`. Expect about one second per triaged component and per finding comment.

Finding VEX is applied 500 at a time. If the API rejects a batch, that batch is retried one finding at a time, so only the finding actually rejected is reported as failed.

Exclusion comments over 1,000 characters and finding comments over 10,000 characters, the API's limits, are shortened. Each one is listed under `truncated` in the report.

## If a run stops part-way

A network error, a failed import, or the import still running after `--scan-timeout` stops the run with a one-line message. The report is still written.

- **Stopped after the project was created and the SBOM import finished or is still running:** re-run with `--target-version <new version ID>`. The ID is printed right after the project is created. The resumed run waits for the import, then copies the triage.
- **Stopped during the SBOM upload itself:** the new version may have an import that never received its SBOM. A resume would wait until `--scan-timeout` and stop. Delete the new project in the Finite State web app, then run the script again without `--target-version`. Until it is deleted, its name blocks a new run with the same `--new-project-name`.

## Not carried over

- **Findings from binary analysis.** File components (configuration files, certificates, carved binaries) and the binary-SAST findings on them come from scanning the original binary. An SBOM import can't recreate them. The script counts them and lists any that were triaged under `not_carried` in the report.
- **The project's own root component.** The source version's root component represents the source project. The new project gets its own root component instead. Triage on the old one is listed under `not_carried`.
- **Edit history.** Edits arrive as values, so the new components don't show the "edited" marker or the original values.
- **Replacements.** A replaced component arrives as its replacement and can't be reverted to the original in the new project.
- **Manually added components** become ordinary components in the new project.
- **Authorship.** Statuses, VEX decisions and comments are recorded as the token's user. The original author and date are kept in each comment's prefix.
- **Lifecycles, Jira ticket links and policy results.** Policies are organization-wide and are evaluated again on the new version.
- **Findings that no longer apply.** The new version is checked against today's vulnerability data, not the data from the original scan. Its finding counts can differ:
  - A CVE whose affected range was corrected so that it no longer covers the component's version doesn't appear in the new version. Any triage on it has nothing to apply to. The report lists these under `unmatched_findings` with `"reason": "no_longer_reported"`, and they don't fail the run.
  - CVEs published or updated since the original scan appear as new, untriaged findings.
