# 01 - Onboarding and Scanning

This section provides resources and tools to help you scan devices, applications, and firmware using the Finite State platform.

## Overview

Welcome to the Finite State Customer Resources repository! The resources in this directory will help you scan things - whether you're scanning firmware, applications, devices, or other targets. Whether you're a developer, security engineer, or operations team member, these resources provide examples and tools for performing scans programmatically and understanding scan results.

## Required Environment Variables

Before running any scripts or tools in this section, ensure you have the required environment variables set:

```bash
export FINITE_STATE_AUTH_TOKEN=<your_api_token>
export FINITE_STATE_DOMAIN=<your_fqdn>
```

## Goals

By the end of this stage, you should be able to:

- Perform scans using the Finite State platform
- Use scanning scripts and tools from this repository
- Configure and customize scan parameters
- Understand scan results and output formats
- Automate scanning workflows

## Getting Started

### Prerequisites

- Finite State platform account with API access
- API token for authentication
- Basic familiarity with command-line tools and environment variables

### Quick Start Guide

1. **Set up environment variables** - Configure your API token and domain
2. **Choose a scanning example** - Select a scanning script or tool that matches your use case
3. **Run a scan** - Execute the scan and review the results
4. **Customize for your needs** - Adapt the examples for your specific scanning requirements

## Common Use Cases

### Scanning Targets

- Scanning firmware images
- Scanning applications and binaries
- Scanning device configurations
- Bulk scanning workflows
- Bulk uploading targets for scanning

### Scan Configuration

- Configuring scan parameters
- Setting scan policies and rules
- Customizing scan depth and scope
- Environment-specific scan configurations

### Scan Results

- Understanding scan output formats
- Interpreting findings and reports
- Exporting scan results
- Tracking scan history and status

## Available Resources

### Examples

- **Basic Scanning Scripts** - Simple examples for scanning common target types
- **Scan Configuration Templates** - Pre-configured scan templates for different use cases
- **Bulk Scanning** - Examples for scanning multiple targets efficiently

### Tools

- **Bulk Uploading Script** - Enables efficient bulk upload operations for scanning multiple targets (see details below)
- **Scanning Utilities** - Tools and scripts for performing scans
- **Result Processors** - Utilities for parsing and analyzing scan results
- **API Clients** - Shared API clients in [shared/api-clients](../shared/api-clients/) for programmatic scanning

#### Bulk Uploading Script

The **Bulk Uploading Script** enables efficient bulk data operations for scanning workflows:

- **Bulk target uploads** - Upload multiple targets for scanning in batch
- **Asset management** - Bulk create or update assets for scanning
- **Scan queue management** - Efficiently queue multiple scans
- **Data import** - Import targets from external sources for scanning

**Use Cases:**

- Bulk uploading firmware images for scanning
- Importing large lists of targets for batch scanning
- Migrating scan targets between instances
- Setting up initial scanning workflows with multiple targets

## Next Steps

Once you're successfully scanning:

- Move to **[02 - CI/CD Automation](../02-ci-cd-automation/)** to integrate scanning into your development workflow
- Review **[03 - Findings Triage Workflows](../03-findings-triage-workflows/)** to automate finding management and prioritization
- Explore **[05 - Reporting and Compliance](../05-reporting-and-compliance/)** for automated reporting tools
- Check out **[Shared Resources](../shared/)** for reusable API clients and utilities

## Related Resources

- [Shared API Clients](../shared/api-clients/) - For programmatic access
- [Support Guide](../SUPPORT.md) - If you need help
- [Contributing Guide](../CONTRIBUTING.md) - To share your examples

## Troubleshooting

### Common Issues

**Authentication errors**
- Verify your API key is correct
- Check token expiration
- Ensure proper permissions

**Scan failures**
- Review scan configuration
- Check target accessibility
- Verify network connectivity

### Getting Help

- Check the [Support Guide](../SUPPORT.md)
- Review existing issues
- Open a new issue with details about your problem

