# 02 - CI/CD Automation

This section covers integrating scanning into your CI/CD pipelines and automating security checks as part of your development workflow.

## Overview

Automating security scanning in your CI/CD pipeline ensures that vulnerabilities are caught early in the development process. This stage provides examples and tools for integrating scanning into popular CI/CD platforms and automating workflows.

## Goals

By the end of this stage, you should be able to:

- Integrate scanning into your CI/CD pipeline
- Automate scan execution on code changes
- Handle scan results in automated workflows
- Set up automated reporting and notifications
- Configure scan gates and quality checks

## Getting Started

### Prerequisites

- Access to your CI/CD platform (GitHub Actions, GitLab CI, Jenkins, etc.)
- Platform API credentials configured
- Basic understanding of your CI/CD system

### Required Environment Variables

Before running any scripts or tools in this section, ensure you have the required environment variables set:

```bash
export FINITE_STATE_AUTH_TOKEN=<your_api_token>
export FINITE_STATE_DOMAIN=<your_fqdn>
```

**Note for CI/CD**: Configure these as secrets in your CI/CD platform rather than hardcoding them.

### Quick Start

1. **Choose your CI/CD platform** - Select examples for your platform
2. **Configure authentication** - Set up secrets and credentials
3. **Add scan step** - Integrate scanning into your pipeline
4. **Configure results handling** - Set up result processing and notifications

## Common Use Cases

### Pipeline Integration

- **GitHub Actions** - Workflows for GitHub repositories
- **GitLab CI/CD** - Pipeline configurations for GitLab
- **Jenkins** - Jenkinsfile examples for Jenkins pipelines
- **Azure DevOps** - YAML pipelines for Azure DevOps
- **CircleCI** - Configuration examples for CircleCI

### Automation Workflows

- Automated scans on pull requests
- Scheduled scans for compliance
- Post-deployment verification scans
- Multi-stage pipeline integration

### Result Handling

- Automated result processing
- Failure gates and quality checks
- Notification and alerting
- Result storage and archiving

## Available Resources

### CI/CD Platform Examples

Examples are organized by platform:

- **GitHub Actions** - `.github/workflows/` examples
- **GitLab CI** - `.gitlab-ci.yml` examples
- **Jenkins** - Jenkinsfile examples
- **Other platforms** - Additional CI/CD integrations

### Automation Tools

- Pipeline templates
- Result processing scripts
- Notification utilities
- Compliance checking tools

## Integration Patterns

### Pull Request Scanning

Automatically scan code when pull requests are opened or updated.

```yaml
# Example: GitHub Actions workflow
on:
  pull_request:
    branches: [main]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run security scan
        # Add scan step here
```

### Scheduled Scans

Run regular scans on a schedule for compliance and continuous monitoring.

### Deployment Gates

Block deployments based on scan results and security policies.

## Best Practices

- **Fail fast** - Detect issues early in the pipeline
- **Parallel execution** - Run scans in parallel with other checks when possible
- **Caching** - Cache dependencies and intermediate results
- **Notifications** - Set up appropriate alerts for failures
- **Documentation** - Document your pipeline configuration

## Next Steps

After automating your scans:

- Move to **[03 - Findings Triage Workflows](../03-findings-triage-workflows/)** to automate finding management
- Review **[05 - Reporting and Compliance](../05-reporting-and-compliance/)** for automated reporting
- Explore **[Shared Resources](../shared/)** for reusable CI/CD utilities

## Related Resources

- [Shared API Clients](../shared/api-clients/) - For programmatic scan triggers
- [Shared Common Helpers](../shared/common-helpers/) - For result processing utilities
- [Support Guide](../SUPPORT.md) - For integration help

## Troubleshooting

### Common Issues

**Authentication in CI/CD**
- Verify secrets are properly configured
- Check credential permissions
- Ensure tokens don't expire during pipeline runs

**Scan timeouts**
- Adjust timeout settings
- Optimize scan configuration
- Consider parallel execution

**Result handling**
- Verify result parsing logic
- Check notification configurations
- Review error handling

### Getting Help

- Check platform-specific documentation
- Review example configurations
- Open an issue with your pipeline configuration (redact secrets)

