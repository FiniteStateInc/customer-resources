# setup

Establishes authentication and configuration context for downstream Finite State actions in the same job.

## Usage

```yaml
- uses: finite-state/setup@v1
  id: fs
  with:
    api-token: ${{ secrets.FS_API_TOKEN }}
    domain: ${{ vars.FS_DOMAIN }}
    project-id: ${{ vars.FS_PROJECT_ID }}
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `api-token` | **yes** | — | Finite State API token. Store as a repository secret. |
| `domain` | no | `app.finitestate.io` | Platform domain. Override for dedicated deployments. |
| `project-id` | no | — | Default project ID for subsequent actions in this job. |
| `version-id` | no | — | Default version ID for subsequent actions in this job. |

## Outputs

| Output | Description |
|--------|-------------|
| `org-name` | Organization name from the authenticated user |
| `user` | Authenticated username |
| `project-id` | Echoed or resolved project ID |
| `version-id` | Echoed or resolved version ID |

## Behavior

1. Validates the API token by calling `GET /public/v0/authUser`
2. Exports `FS_API_TOKEN`, `FS_DOMAIN`, `FS_PROJECT_ID`, and `FS_VERSION_ID` as environment variables so downstream actions inherit them automatically
3. Sets step outputs so other steps can reference them via `${{ steps.fs.outputs.org-name }}`
4. **Fails fast** with a clear error if authentication is invalid

## Context Inheritance

Once `setup` runs, downstream actions do NOT need `api-token` or `domain` repeated. They read from the environment automatically. Individual inputs can still override the setup context per-step.

```yaml
# setup provides the auth context
- uses: finite-state/setup@v1
  with:
    api-token: ${{ secrets.FS_API_TOKEN }}
    project-id: "12345"

# upload-scan inherits api-token, domain, and project-id
- uses: finite-state/upload-scan@v1
  with:
    type: sca
    file: build/firmware.bin
```

## Finding Your Credentials

- **API Token:** In the Finite State platform, go to **Settings > API Tokens > Generate New Token**
- **Domain:** Your platform URL without the protocol (e.g., `customer.finitestate.io`)
- **Project ID:** Navigate to your project in the platform. The ID is in the URL: `https://app.finitestate.io/projects/{project-id}`
