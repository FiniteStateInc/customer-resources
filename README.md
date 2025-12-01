# Finite State Customer Resources

Welcome to the **Finite State Customer Resources** repository! This repository provides resources, examples, and tools organized by workflow stages to help you get the most out of the Finite State platform.

## Overview

This repository is organized by **workflow stages**, not by internal product names. This makes it easy to find examples and tools based on what you're trying to accomplish.

## Required Environment Variables

All scripts and tools in this repository require the following environment variables:

```bash
export FINITE_STATE_AUTH_TOKEN=<your_api_token>
export FINITE_STATE_DOMAIN=<your_fqdn>
```

For example:

```bash
export FINITE_STATE_AUTH_TOKEN=7rsiswdbjzq264tpmpsugw3gapeq3hvyurb6iy7uwnojgfx5fcpq
export FINITE_STATE_DOMAIN=acme.finitestate.io
```

Note: The domain typically corresponds to your instance and often includes your company name (e.g., `acme.finitestate.io`).

## Repository Structure

Our content is organized into six main workflow stages:

- **[01-onboarding-and-scanning](./01-onboarding-and-scanning/)** - Resources and tools to help you scan devices, applications, and firmware
- **[02-ci-cd-automation](./02-ci-cd-automation/)** - Integrate scanning into your CI/CD pipelines
- **[03-findings-triage-workflows](./03-findings-triage-workflows/)** - Triage, prioritize, and manage findings
- **[04-remediation-and-fixes](./04-remediation-and-fixes/)** - Remediate vulnerabilities and implement fixes
- **[05-reporting-and-compliance](./05-reporting-and-compliance/)** - Generate reports and maintain compliance
- **[06-advanced-integrations-and-demos](./06-advanced-integrations-and-demos/)** - Advanced use cases and end-to-end demonstrations

### Shared Resources

- **[shared/](./shared/)** - Shared API clients, common helpers, and utilities used across examples

## Quick Start

1. **Need to scan something?** Start with [01-onboarding-and-scanning](./01-onboarding-and-scanning/)
2. **Ready to automate?** Check out [02-ci-cd-automation](./02-ci-cd-automation/)
3. **Looking for specific tools?** Browse the workflow stages above or use the search functionality

## Field-Built Tools

This repository serves as a home for field-built tools, including:

- **Reporting System** - Located in [05-reporting-and-compliance](./05-reporting-and-compliance/)
- **Autotriage Script** - Located in [03-findings-triage-workflows](./03-findings-triage-workflows/)
- **Bulk Uploading Script** - Located in [01-onboarding-and-scanning](./01-onboarding-and-scanning/)
- **Vulnerability Report** - Located in [05-reporting-and-compliance](./05-reporting-and-compliance/)
- **Shai-Hulud Detection Scripts** - Located in [06-advanced-integrations-and-demos](./06-advanced-integrations-and-demos/)

## Contributing

We welcome contributions! Please see our [Contributing Guide](./CONTRIBUTING.md) for details on how to submit pull requests, report issues, and suggest improvements.

## Support

Need help? Check out our [Support Guide](./SUPPORT.md) for information on getting assistance.

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

## Code of Conduct

This project adheres to a Code of Conduct. Please review [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) before participating.

## Security

For security-related issues, please see [SECURITY.md](./SECURITY.md).
